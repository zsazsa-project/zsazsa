"""Read the logged-in user out of MISP's shared PHP session.

MISP (CakePHP) stores sessions in Redis under the key
``PHPREDIS_SESSION:<session id>``, where ``<session id>`` is the value of
the ``MISP-<uuid>`` cookie. The value is PHP's "php" session serialize
format: a sequence of ``key|value`` pairs where each value is itself
PHP-serialized. After login, CakePHP's AuthComponent stores the full user
record under the ``Auth`` key as ``Auth.User``.

This module talks to that Redis instance directly over a plain socket
(no redis-py dependency) and parses just enough of the PHP serialize
format to pull out ``Auth.User``.
"""

import logging
import socket
import time
from contextlib import contextmanager

from flask import g, request

import config
from webapp.redis_client import RedisError, read_reply as _read_reply, send_command as _send_command

logger = logging.getLogger(__name__)

DEFAULT_USER_EMAIL = "admin@admin.test"

# The prefix PHP's redis session handler uses, unless session.save_path
# overrides it with a ?prefix= parameter.
_SESSION_KEY_PREFIX = "PHPREDIS_SESSION:"


@contextmanager
def _redis_connect():
    """An authenticated socket on MISP's session Redis, on the configured database."""
    host = getattr(config, "MISP_SESSION_REDIS_HOST", "127.0.0.1")
    port = getattr(config, "MISP_SESSION_REDIS_PORT", 6379)
    db = getattr(config, "MISP_SESSION_REDIS_DB", 0)
    username = getattr(config, "MISP_SESSION_REDIS_USERNAME", "")
    password = getattr(config, "MISP_SESSION_REDIS_PASSWORD", "")

    sock = socket.create_connection((host, port), timeout=2)
    try:
        if password:
            if username:
                _send_command(sock, "AUTH", username, password)
            else:
                _send_command(sock, "AUTH", password)
            _read_reply(sock)
        if db:
            _send_command(sock, "SELECT", db)
            _read_reply(sock)
        yield sock
    finally:
        sock.close()


def _redis_get(key):
    """Fetch a single key from MISP's session Redis. Returns bytes or None."""
    with _redis_connect() as sock:
        _send_command(sock, "GET", key)
        return _read_reply(sock)


def _holds_php_sessions():
    """Whether anything is writing PHP sessions to this Redis at all.

    Only key names are read, never values: the value under a session key is the
    session. The scan stops at the first hit and gives up after a few batches, so
    a busy Redis cannot stall the page that asks.
    """
    with _redis_connect() as sock:
        cursor = "0"
        for _ in range(10):
            _send_command(sock, "SCAN", cursor, "MATCH", f"{_SESSION_KEY_PREFIX}*", "COUNT", "200")
            cursor, keys = _read_reply(sock)
            if keys:
                return True
            cursor = cursor.decode()
            if cursor == "0":
                return False
    return False


def _parse_php_value(data, pos):
    """Parse one PHP serialize() value from `data` starting at `pos`.

    Returns (value, next_pos). Covers the types CakePHP uses in session
    data: N (null), b (bool), i (int), d (float), s (string), a (array).
    """
    kind = data[pos:pos + 1]
    if kind == b"N":
        return None, pos + 2
    if kind == b"b":
        end = data.index(b";", pos)
        return data[pos + 2:end] == b"1", end + 1
    if kind == b"i":
        end = data.index(b";", pos)
        return int(data[pos + 2:end]), end + 1
    if kind == b"d":
        end = data.index(b";", pos)
        return float(data[pos + 2:end]), end + 1
    if kind == b"s":
        colon = data.index(b":", pos + 2)
        length = int(data[pos + 2:colon])
        start = colon + 2  # skip ':"'
        end = start + length
        return data[start:end].decode("utf-8", "replace"), end + 2  # skip '";'
    if kind == b"a":
        colon = data.index(b":", pos + 2)
        count = int(data[pos + 2:colon])
        pos = colon + 2  # skip ':{'
        result = {}
        for _ in range(count):
            item_key, pos = _parse_php_value(data, pos)
            item_value, pos = _parse_php_value(data, pos)
            result[item_key] = item_value
        return result, pos + 1  # skip '}'
    raise ValueError(f"unsupported PHP serialize type {kind!r} at offset {pos}")


def _parse_php_session(data):
    """Parse PHP's 'php' session serialize format into a dict of top-level keys."""
    result = {}
    pos = 0
    while pos < len(data):
        sep = data.index(b"|", pos)
        key = data[pos:sep].decode("ascii")
        value, pos = _parse_php_value(data, sep + 1)
        result[key] = value
    return result


def get_misp_user(session_id):
    """Return the MISP Auth.User dict for a session ID, or None.

    This reflects whatever CakePHP wrote to the session at login time, not
    necessarily the live database state (e.g. a user disabled after login
    keeps a session until MISP itself re-checks and rewrites it).
    """
    if not session_id:
        return None

    try:
        raw = _redis_get(f"{_SESSION_KEY_PREFIX}{session_id}")
    except (OSError, RedisError) as e:
        logger.warning("could not read MISP session from Redis: %s", e)
        return None

    if raw is None:
        return None

    try:
        session = _parse_php_session(raw)
    except (ValueError, IndexError) as e:
        logger.warning("could not parse MISP session data: %s", e)
        return None

    user = session.get("Auth", {}).get("User")
    if not user or user.get("disabled"):
        return None

    return user


# The cookie name is asked of MISP once and then kept for the life of the
# process, since an instance UUID does not change. A failed lookup is not
# retried for a while: this runs before every request, so an unreachable MISP
# would otherwise cost each one a connection attempt.
_RETRY_AFTER_SECONDS = 60
_DERIVE_TIMEOUT_S = 5

_cookie_name_cache = {"value": "", "retry_after": 0.0}

# Causes already reported, so a misconfiguration is logged once rather than on
# every request it breaks.
_warned_misses = set()


def derive_cookie_name():
    """Return MISP's session cookie name derived from the server's instance UUID.

    MISP names its session cookie ``MISP-<instance uuid>``, unique per install,
    so the name has to come from the MISP zsazsa is served behind: the one it
    stores its data in, not the misp-scraper instance it only polls. Those are
    often the same server, which is why reading the scraper went unnoticed.
    Returns ``MISP-<uuid>`` on success, or "" if the MISP server could not be
    reached or did not report a UUID.
    """
    try:
        from pymisp import PyMISP
        misp = PyMISP(config.MISP_WEBAPP_URL, config.MISP_WEBAPP_KEY,
                      config.MISP_WEBAPP_VERIFYCERT, timeout=_DERIVE_TIMEOUT_S)
        uuid = (misp.misp_instance_version or {}).get("uuid", "")
        if uuid:
            return f"MISP-{uuid}"
    except Exception as e:
        logger.warning("could not derive MISP session cookie name from %s: %s",
                       getattr(config, "MISP_WEBAPP_URL", ""), e)
    return ""


def _session_cookie_name():
    """Return the name of MISP's session cookie.

    When MISP_SESSION_COOKIE_NAME is set in config it is used as-is (it is stored
    there automatically when single sign-on is enabled). Otherwise the name is
    derived once from the MISP server's instance UUID and cached, so SSO still
    works before the value has been persisted. While MISP is unreachable the
    name stays empty, which leaves the request unidentified rather than failing.
    """
    configured = (getattr(config, "MISP_SESSION_COOKIE_NAME", "") or "").strip()
    if configured:
        return configured
    if not _cookie_name_cache["value"] and time.monotonic() >= _cookie_name_cache["retry_after"]:
        _cookie_name_cache["value"] = derive_cookie_name()
        if not _cookie_name_cache["value"]:
            _cookie_name_cache["retry_after"] = time.monotonic() + _RETRY_AFTER_SECONDS
    return _cookie_name_cache["value"]


def _explain_miss(cookie_name, session_id):
    """Why this request could not be identified, as a sentence for the operator.

    Both of the setups that break single sign-on, MISP naming its cookie
    something other than MISP-<uuid> and PHP not keeping its sessions in Redis,
    look identical from here: no user. Saying which one it was is the difference
    between a five-minute fix and reading the source.
    """
    if not cookie_name:
        return "no-cookie-name", ("could not determine MISP's session cookie name; MISP may be "
                                  "unreachable, or set MISP_SESSION_COOKIE_NAME by hand")
    if not session_id:
        seen = ", ".join(sorted(request.cookies)[:10]) or "none"
        return "no-cookie", (f"the browser sent no {cookie_name} cookie (cookies seen: {seen}); "
                             f"if MISP names its cookie differently, set MISP_SESSION_COOKIE_NAME "
                             f"to that name")
    return "no-session", (f"no session for the {cookie_name} cookie in Redis; check that PHP "
                          f"stores MISP's sessions there (session.save_handler = redis) and that "
                          f"the Redis settings below point at the same instance")


def load_request_user():
    """Look up the MISP user for the current request and cache it on flask.g."""
    cookie_name = _session_cookie_name()
    session_id = request.cookies.get(cookie_name) if cookie_name else None
    g.misp_user = get_misp_user(session_id)

    # Only worth reporting when single sign-on is meant to be working, and only
    # once per cause: this runs in front of every request, and the cause does not
    # change between them. Keyed on the cause rather than the message, which names
    # the cookies the caller sent and would otherwise let anyone grow this set and
    # the log by varying them.
    if g.misp_user is None and getattr(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False):
        cause, reason = _explain_miss(cookie_name, session_id)
        if cause not in _warned_misses:
            _warned_misses.add(cause)
            logger.warning("single sign-on could not identify the request: %s", reason)


def current_user_email():
    """Email of the MISP user identified for this request, or a fallback.

    Also used by standalone scripts that call into webapp.misp_store outside
    of a Flask request, where there is no flask.g to read from at all.
    """
    try:
        user = getattr(g, "misp_user", None)
    except RuntimeError:
        return DEFAULT_USER_EMAIL
    return user["email"] if user else DEFAULT_USER_EMAIL


def diagnose(cookies) -> dict:
    """Check single sign-on against the cookies of a real request.

    `cookies` is the request's cookie mapping. Only cookie *names* are reported:
    the value of MISP's session cookie is a session id, and printing it on a
    settings page would hand over a live session.

    Returns {"checks": [{"label", "ok", "detail"}], "hint"}.
    """
    checks = []
    configured = (getattr(config, "MISP_SESSION_COOKIE_NAME", "") or "").strip()
    cookie_name = _session_cookie_name()
    checks.append({
        "label": "Session cookie name",
        "ok": bool(cookie_name),
        "detail": (f"{cookie_name} ({'set in the configuration' if configured else 'detected from MISP'})"
                   if cookie_name else "not known; MISP could not be reached and none is configured"),
    })

    session_id = cookies.get(cookie_name) if cookie_name else None
    checks.append({
        "label": "Cookie sent by your browser",
        "ok": bool(session_id),
        "detail": (f"{cookie_name} was sent" if session_id
                   else "cookies received: " + (", ".join(sorted(cookies)) or "none")),
    })

    try:
        with _redis_connect():
            pass
        checks.append({"label": "Session Redis", "ok": True, "detail": "reachable"})
        redis_ok = True
    except (OSError, RedisError) as e:
        checks.append({"label": "Session Redis", "ok": False, "detail": str(e)})
        redis_ok = False

    user = get_misp_user(session_id) if session_id and redis_ok else None
    populated = False
    if session_id and redis_ok:
        if user is None:
            # Whether anyone's session is here separates "PHP writes elsewhere"
            # from "PHP writes here and yours has simply gone", which look the
            # same from a single failed lookup and want opposite fixes. A scan
            # that times out just leaves the more general advice standing.
            try:
                populated = _holds_php_sessions()
            except (OSError, RedisError):
                populated = False
        checks.append({
            "label": "MISP session",
            "ok": user is not None,
            "detail": (f"identified {user.get('email', '?')}" if user
                       else "not found, though this Redis does hold PHP sessions" if populated
                       else "not found, and this Redis holds no PHP sessions at all"),
        })

    hint = ""
    if not user:
        failed = next((c for c in checks if not c["ok"]), None)
        label = failed["label"] if failed else ""
        if label == "Cookie sent by your browser":
            hint = ("MISP does not always name its cookie MISP-<uuid>. If one of the cookies "
                    "above is MISP's session cookie, set MISP_SESSION_COOKIE_NAME to that name.")
        elif label == "Session Redis":
            hint = "Check the Redis settings below against the instance MISP writes its sessions to."
        elif label == "MISP session" and populated:
            hint = ("MISP's sessions are in this Redis, so the plumbing is right and this one "
                    "cookie has no session behind it. Log in to MISP again in this browser and "
                    "retry: an expired or logged-out session leaves the cookie in place.")
        elif label == "MISP session":
            hint = ("Nothing is writing PHP sessions to this Redis. Set session.save_handler = redis "
                    "and session.save_path in PHP, and check that session.save_path names the same "
                    "instance and database as the Redis settings below.")
    return {"checks": checks, "hint": hint}


def login_redirect_url():
    """MISP login URL to redirect to, or None if the request can proceed.

    Only returns a URL when MISP_SESSION_REDIRECT_TO_LOGIN is enabled and no
    valid MISP session was found for this request. The login page has to be the
    one on the MISP zsazsa is served behind, whose session cookie the browser
    sends, so it points at MISP_WEBAPP_URL rather than the scraper instance.
    """
    if not getattr(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False):
        return None
    if getattr(g, "misp_user", None):
        return None
    return f"{config.MISP_WEBAPP_URL}/users/login"
