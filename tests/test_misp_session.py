"""Tests for reading the logged-in user out of MISP's session.

The cookie name is looked up from MISP when it is not in the config, and that
lookup sits in front of every request. An unreachable MISP must therefore be
asked again only now and then, not once per request. A session MISP's own
timeout has run out on is no session, and while someone uses zsazsa MISP is
asked to keep their session alive.

    python -m unittest tests.test_misp_session
"""

import contextlib
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import requests
from flask import Flask, g

from webapp import misp_session


def _php_string(text):
    data = text.encode()
    return b's:%d:"%s";' % (len(data), data)


def _php_session(expires_in=600, email="analyst@misp.test", countdown=10):
    """A MISP session as PHP's redis handler stores it, with the expiry CakePHP
    keeps in Config.time `expires_in` seconds from now."""
    config_entry = (b"Config|a:3:{" + _php_string("userAgent") + _php_string("abc")
                    + _php_string("time") + b"i:%d;" % int(time.time() + expires_in)
                    + _php_string("countdown") + b"i:%d;}" % countdown)
    auth = (b"Auth|a:1:{" + _php_string("User") + b"a:2:{" + _php_string("email")
            + _php_string(email) + _php_string("id") + b"i:7;}}")
    return config_entry + auth


class SessionExpiry(unittest.TestCase):
    """The Redis key can outlive MISP's own timeout (MISP gives it
    Session.cookieTimeout), so the key existing is not enough."""

    def user(self, blob):
        with mock.patch.object(misp_session, "_redis_get", return_value=blob):
            return misp_session.get_misp_user("sid")

    def test_a_session_within_misps_timeout_is_accepted(self):
        self.assertEqual(self.user(_php_session(expires_in=600))["email"], "analyst@misp.test")

    def test_a_session_past_misps_timeout_is_refused(self):
        self.assertIsNone(self.user(_php_session(expires_in=-60)))

    def test_a_session_without_an_expiry_is_read_as_before(self):
        auth = _php_session().split(b"Auth|", 1)[1]
        self.assertEqual(self.user(b"Auth|" + auth)["email"], "analyst@misp.test")


class KeepAlive(unittest.TestCase):
    """MISP moves a session's expiry forward on each request it serves; zsazsa
    has it do so every few minutes of use rather than writing the session."""

    def setUp(self):
        misp_session._last_keepalive.clear()
        self.addCleanup(misp_session._last_keepalive.clear)
        for patcher in (mock.patch.object(misp_session.config, "MISP_WEBAPP_URL", "https://misp.test/"),
                        mock.patch.object(misp_session.config, "MISP_WEBAPP_VERIFYCERT", False)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = Flask(__name__)

    def keep_alive(self, get, session_id="sid", session=None):
        """``session`` is what Redis holds for it, an hour left by default."""
        with self.app.test_request_context("/", headers={"User-Agent": "Firefox/140"}), \
             mock.patch.object(misp_session, "_redis_get", return_value=session or _php_session(3600)), \
             mock.patch.object(misp_session.requests, "get", get):
            misp_session.keep_misp_session_alive("MISP-abc", session_id)

    def test_misp_is_asked_for_the_users_own_record_with_their_cookie_and_agent(self):
        get = mock.Mock(return_value=mock.Mock(status_code=200))
        self.keep_alive(get)
        get.assert_called_once_with(
            "https://misp.test/users/view/me.json", cookies={"MISP-abc": "sid"},
            headers={"Accept": "application/json", "User-Agent": "Firefox/140"},
            timeout=misp_session._VIEW_ME_TIMEOUT_S, verify=False, allow_redirects=False)

    def test_a_session_another_request_forgot_first_does_not_fail_this_one(self):
        """Two requests clearing the old sessions at once both deleted the same
        one, and the second answered with a 500."""
        class Forgotten(dict):
            def items(self):
                return [("gone", -misp_session._KEEPALIVE_EVERY_S)]

        get = mock.Mock(return_value=mock.Mock(status_code=200))
        with mock.patch.object(misp_session, "_last_keepalive", Forgotten()):
            self.keep_alive(get)
        get.assert_called_once()

    def test_a_session_is_refreshed_at_most_once_every_few_minutes(self):
        get = mock.Mock(return_value=mock.Mock(status_code=200))
        self.keep_alive(get)
        self.keep_alive(get)
        self.assertEqual(get.call_count, 1)
        misp_session._last_keepalive["sid"] -= misp_session._KEEPALIVE_EVERY_S
        self.keep_alive(get)
        self.assertEqual(get.call_count, 2)

    def test_a_session_about_to_run_out_is_refreshed_without_waiting_its_turn(self):
        """With a Session.timeout of five minutes, waiting five minutes between
        refreshes signed out a user who kept clicking."""
        get = mock.Mock(return_value=mock.Mock(status_code=200))
        self.keep_alive(get, session=_php_session(240))
        self.keep_alive(get, session=_php_session(240))
        self.assertEqual(get.call_count, 2)

    def test_the_request_that_would_renew_the_session_id_is_not_sent(self):
        """With Session.autoRegenerate on, the request that takes Config.countdown
        to zero gets the new session ID, and the browser's one is deleted."""
        get = mock.Mock(return_value=mock.Mock(status_code=200))
        self.keep_alive(get, session=_php_session(3600, countdown=1))
        get.assert_not_called()
        self.keep_alive(get, session=_php_session(3600, countdown=2))
        get.assert_called_once()

    def test_each_session_has_its_own_turn(self):
        get = mock.Mock(return_value=mock.Mock(status_code=200))
        self.keep_alive(get, "one")
        self.keep_alive(get, "two")
        self.assertEqual(get.call_count, 2)

    def test_a_refusal_or_an_unreachable_misp_is_logged_without_the_session_id(self):
        for get in (mock.Mock(return_value=mock.Mock(status_code=403)),
                    mock.Mock(side_effect=requests.ConnectionError("connection refused"))):
            misp_session._last_keepalive.clear()
            with self.assertLogs("webapp.misp_session", level="WARNING") as logs:
                self.keep_alive(get, "s3cr3t-session-id")
            self.assertNotIn("s3cr3t-session-id", "".join(logs.output))

    def refreshed(self, method="GET", headers=None):
        with self.app.test_request_context("/", method=method,
                                           headers={"Cookie": "MISP-abc=sid", **(headers or {})}), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
             mock.patch.object(misp_session, "get_misp_user", return_value={"email": "analyst@misp.test"}), \
             mock.patch.object(misp_session, "keep_misp_session_alive") as keep:
            misp_session.load_request_user()
        return keep.called

    def test_a_background_poll_does_not_keep_an_unattended_session_alive(self):
        """The top bar asks for the job list every few seconds on a visible tab."""
        self.assertFalse(self.refreshed(headers={"Sec-Fetch-Mode": "cors"}))

    def test_a_page_load_or_an_action_does(self):
        self.assertTrue(self.refreshed(headers={"Sec-Fetch-Mode": "navigate"}))
        self.assertTrue(self.refreshed(method="POST", headers={"Sec-Fetch-Mode": "cors"}))
        self.assertTrue(self.refreshed())  # a client that sends no fetch metadata

    def test_only_a_recognised_user_has_the_session_refreshed(self):
        for user, calls in ((None, 0), ({"email": "analyst@misp.test"}, 1)):
            with self.app.test_request_context("/", headers={"Cookie": "MISP-abc=sid"}), \
                 mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
                 mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
                 mock.patch.object(misp_session, "get_misp_user", return_value=user), \
                 mock.patch.object(misp_session, "keep_misp_session_alive") as keep:
                misp_session.load_request_user()
            self.assertEqual(keep.call_count, calls)
            if calls:
                keep.assert_called_once_with("MISP-abc", "sid")


class CookieName(unittest.TestCase):
    def setUp(self):
        misp_session._cookie_name_cache.update({"value": "", "retry_after": 0.0})
        self.addCleanup(misp_session._cookie_name_cache.update,
                        {"value": "", "retry_after": 0.0})

    def _derive(self, result):
        patcher = mock.patch.object(misp_session, "derive_cookie_name",
                                    return_value=result)
        derive = patcher.start()
        self.addCleanup(patcher.stop)
        return derive

    def test_configured_name_is_used_without_asking_misp(self):
        derive = self._derive("MISP-from-server")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME",
                               "MISP-from-config"):
            self.assertEqual(misp_session._session_cookie_name(), "MISP-from-config")
        derive.assert_not_called()

    def test_derived_name_is_asked_once_and_kept(self):
        derive = self._derive("MISP-from-server")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            first = misp_session._session_cookie_name()
            second = misp_session._session_cookie_name()
        self.assertEqual([first, second], ["MISP-from-server"] * 2)
        self.assertEqual(derive.call_count, 1)

    def test_unreachable_misp_is_not_asked_again_until_the_window_passes(self):
        derive = self._derive("")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            self.assertEqual(misp_session._session_cookie_name(), "")
            misp_session._session_cookie_name()
            self.assertEqual(derive.call_count, 1)

            misp_session._cookie_name_cache["retry_after"] = 0.0
            misp_session._session_cookie_name()
            self.assertEqual(derive.call_count, 2)


class HostingInstance(unittest.TestCase):
    """Single sign-on belongs to the MISP zsazsa is served behind, which is the
    one it stores its data in. The misp-scraper instance is only polled, and is
    often a different server, so reading it sent analysts to a login page that
    was not theirs and looked for a session cookie that was never sent."""

    def setUp(self):
        self.split = [
            mock.patch.object(misp_session.config, "MISP_URL", "https://scraper.test"),
            mock.patch.object(misp_session.config, "MISP_KEY", "scraper-key"),
            mock.patch.object(misp_session.config, "MISP_WEBAPP_URL", "https://misp.test"),
            mock.patch.object(misp_session.config, "MISP_WEBAPP_KEY", "webapp-key"),
        ]
        for patcher in self.split:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_login_redirect_points_at_the_hosting_misp(self):
        app = Flask(__name__)
        with app.test_request_context("/"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            self.assertEqual(misp_session.login_redirect_url(),
                             "https://misp.test/users/login")

    def test_no_redirect_when_the_request_already_has_a_user(self):
        app = Flask(__name__)
        with app.test_request_context("/"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            g.misp_user = {"email": "analyst@misp.test"}
            self.assertIsNone(misp_session.login_redirect_url())

    def test_cookie_name_is_derived_from_the_hosting_misp(self):
        uuid = "d3d487f0-82ae-4a17-9165-c144c871c665"
        with mock.patch("pymisp.PyMISP") as PyMISP:
            PyMISP.return_value.misp_instance_version = {"uuid": uuid}
            self.assertEqual(misp_session.derive_cookie_name(), f"MISP-{uuid}")
        url, key = PyMISP.call_args.args[0], PyMISP.call_args.args[1]
        self.assertEqual((url, key), ("https://misp.test", "webapp-key"))

    def test_a_key_without_sync_permission_derives_no_name(self):
        """MISP answers such a key with "-" for its UUID. Saving the settings with
        it stored "MISP--", which no browser sends, and locked everyone out."""
        with mock.patch("pymisp.PyMISP") as PyMISP, \
             self.assertLogs("webapp.misp_session", level="WARNING") as logs:
            PyMISP.return_value.misp_instance_version = {"version": "2.5.50", "uuid": "-"}
            self.assertEqual(misp_session.derive_cookie_name(), "")
        self.assertIn("sync permission", logs.output[0])


class PublishPermission(unittest.TestCase):
    """The publish gate reads MISP's perm_publish off the session user. With
    single sign-on configured, a request without a user is somebody who dropped
    the cookie or hit a Redis that is down, not the one trusted identity of an
    install without SSO, so it has to be refused rather than waved through."""

    def can_publish(self, user, redirect=False, cookie_name="", recognised_before=False):
        app = Flask(__name__)
        with app.test_request_context("/"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", redirect), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", cookie_name), \
             mock.patch.object(misp_session.sso_users, "any_recorded", return_value=recognised_before):
            g.misp_user = user
            return misp_session.current_user_can_publish()

    def test_a_standalone_script_may_publish(self):
        with mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            self.assertTrue(misp_session.current_user_can_publish())

    def test_no_user_without_single_sign_on_is_the_trusted_identity(self):
        self.assertTrue(self.can_publish(None))

    def test_no_user_with_single_sign_on_is_refused(self):
        self.assertFalse(self.can_publish(None, redirect=True))
        self.assertFalse(self.can_publish(None, cookie_name="MISP-abc"))

    def test_no_user_is_refused_once_users_were_recognised_through_a_session(self):
        """With both settings empty zsazsa still derives the cookie name, so an
        analyst could otherwise leave the cookie out to pass for the trusted
        identity."""
        self.assertFalse(self.can_publish(None, recognised_before=True))

    def test_a_role_without_perm_publish_is_refused(self):
        self.assertFalse(self.can_publish({"email": "a@misp.test"}, redirect=True))
        self.assertFalse(self.can_publish({"email": "a@misp.test", "Role": {}}, redirect=True))

    def test_perm_publish_as_misp_stores_it_is_allowed(self):
        for value in (True, 1, "1"):
            with self.subTest(value=value):
                self.assertTrue(self.can_publish({"Role": {"perm_publish": value}}, redirect=True))

    def test_a_false_perm_publish_is_refused_even_when_truthy(self):
        for value in (False, 0, "0", "false", "", None):
            with self.subTest(value=value):
                self.assertFalse(self.can_publish({"Role": {"perm_publish": value}}, redirect=True))


class RecognisedUsers(unittest.TestCase):
    """sso_configured() asks whether anyone was ever recognised, on every page.
    Before the app has created its tables, as in a test or on a fresh install,
    nobody has; once somebody has, the database need not be asked again."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_file = str(Path(tmp.name) / "test.db")
        patcher = mock.patch.object(misp_session.config, "DB_FILE", db_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(misp_session.sso_users._recognised_in.discard, db_file)

    def unreadable(self):
        return mock.patch.object(misp_session.sso_users, "_conn",
                                 side_effect=sqlite3.OperationalError("database is locked"))

    def test_a_database_without_the_table_has_nobody_recorded(self):
        self.assertFalse(misp_session.sso_users.any_recorded())

    def test_a_recorded_user_is_found(self):
        misp_session.sso_users.init_db()
        self.assertFalse(misp_session.sso_users.any_recorded())
        misp_session.sso_users.record_sighting({"email": "analyst@example.org", "id": "7"})
        self.assertTrue(misp_session.sso_users.any_recorded())

    def test_once_somebody_was_recognised_the_database_is_not_asked_again(self):
        misp_session.sso_users.init_db()
        misp_session.sso_users.record_sighting({"email": "analyst@example.org", "id": "7"})
        with self.unreadable() as conn:
            self.assertTrue(misp_session.sso_users.any_recorded())
        conn.assert_not_called()

    def test_a_locked_database_refuses_trust_instead_of_failing_the_page(self):
        """It raised, and every page with it, since the context processor asks."""
        misp_session.sso_users.init_db()
        with self.unreadable(), self.assertLogs(misp_session.sso_users.logger, "WARNING"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""), \
             Flask(__name__).test_request_context("/"):
            g.misp_user = None
            self.assertFalse(misp_session.current_user_can_publish())
        # Only remembered when true: once the lock clears, the empty table answers.
        self.assertFalse(misp_session.sso_users.any_recorded())


@contextlib.contextmanager
def _reachable_redis():
    yield mock.Mock()


class Diagnosis(unittest.TestCase):
    """The setups that break single sign-on, MISP naming its cookie something
    other than MISP-<uuid>, PHP not keeping sessions in Redis, and PHP keeping
    them in another database of it, are indistinguishable from the outside. The
    check has to tell them apart."""

    def setUp(self):
        patcher = mock.patch.object(misp_session, "_session_cookie_name",
                                    return_value="MISP-abc")
        patcher.start()
        self.addCleanup(patcher.stop)

    def diagnose(self, cookies, redis):
        """Run the check against a reachable Redis whose GET answers `redis`.

        The check opens its own connection to report on it, so a test that
        stubs only the lookup connects to whatever Redis the developer has
        configured and reads back its own failure instead of the case at hand.
        """
        with mock.patch.object(misp_session, "_redis_connect", _reachable_redis), \
             mock.patch.object(misp_session, "_redis_get", redis), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIS_DB", 13):
            return misp_session.diagnose(cookies)

    def failed(self, result):
        return [c["label"] for c in result["checks"] if not c["ok"]]

    def detail(self, result, label):
        return next(c["detail"] for c in result["checks"] if c["label"] == label)

    def test_a_different_cookie_name_is_named_and_explained(self):
        result = self.diagnose({"CAKEPHP": "abc"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["Cookie sent by your browser"])
        self.assertIn("CAKEPHP", self.detail(result, "Cookie sent by your browser"))
        self.assertIn("MISP_SESSION_COOKIE_NAME", result["hint"])

    def test_nothing_writing_sessions_points_at_the_php_setting(self):
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=None):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("session.save_handler", result["hint"])

    def test_sessions_in_another_database_name_it_and_the_setting_to_change(self):
        """Copying MISP's own redis_database across reads as "nothing writes
        sessions here", which sends the admin back to a php.ini that was right."""
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=0):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("database 0", self.detail(result, "MISP session"))
        self.assertIn("MISP_SESSION_REDIS_DB to 0", result["hint"])
        self.assertNotIn("session.save_handler", result["hint"])

    def test_other_sessions_present_means_this_one_expired_not_misconfigured(self):
        """PHP writing sessions here and this cookie having none behind it look the
        same from one failed lookup, and want opposite fixes."""
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=13):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("does hold PHP sessions", self.detail(result, "MISP session"))
        self.assertIn("Log in to MISP again", result["hint"])
        self.assertNotIn("session.save_handler", result["hint"])

    def test_an_expired_session_is_named_and_needs_a_new_login(self):
        """Not "not found": the session is there, MISP's timeout ended it."""
        finder = mock.Mock(return_value=13)
        with mock.patch.object(misp_session, "_database_with_sessions", finder):
            result = self.diagnose({"MISP-abc": "sid"},
                                   redis=mock.Mock(return_value=_php_session(expires_in=-60)))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("expired", self.detail(result, "MISP session"))
        self.assertIn("timeout", result["hint"])
        finder.assert_not_called()

    def test_unreachable_redis_is_reported_as_such(self):
        # Redis being down fails the connection, which is what the check opens.
        with mock.patch.object(misp_session, "_redis_connect",
                               side_effect=OSError("connection refused")), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            result = misp_session.diagnose({"MISP-abc": "sid"})
        self.assertEqual(self.failed(result), ["Session Redis"])
        self.assertIn("connection refused", self.detail(result, "Session Redis"))

    def test_a_working_setup_reports_the_user_and_no_hint(self):
        with mock.patch.object(misp_session, "get_misp_user",
                               return_value={"email": "analyst@misp.test"}):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=b"x"))
        self.assertEqual(self.failed(result), [])
        self.assertIn("analyst@misp.test", self.detail(result, "MISP session"))
        self.assertEqual(result["hint"], "")

    def test_the_session_id_is_never_reported_back(self):
        """The cookie value is a live session. Naming it on a settings page would
        hand it to anyone who can read the response."""
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=13):
            result = self.diagnose({"MISP-abc": "s3cr3t-session-id"},
                                   redis=mock.Mock(return_value=None))
        self.assertNotIn("s3cr3t-session-id", repr(result))


class PopulatedDatabases(unittest.TestCase):
    """Reading INFO keyspace, which is how the check finds the database PHP is
    really writing its sessions to."""

    def _databases(self, **read):
        """_populated_databases against an INFO that returns, or one that raises."""
        with mock.patch.object(misp_session, "_send_command"), \
             mock.patch.object(misp_session, "_read_reply", **read), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIS_DB", 13):
            return misp_session._populated_databases(mock.Mock())

    def test_the_configured_database_is_left_out_of_the_ones_to_look_in(self):
        reply = (b"# Keyspace\r\n"
                 b"db0:keys=5,expires=5,avg_ttl=0\r\n"
                 b"db13:keys=812,expires=40,avg_ttl=0\r\n")
        self.assertEqual(self._databases(return_value=reply), [0])

    def test_an_acl_that_refuses_info_leaves_the_rest_of_the_check_standing(self):
        self.assertEqual(
            self._databases(side_effect=misp_session.RedisError("NOPERM")), [])

    def test_a_redis_that_cannot_be_reached_reads_as_not_knowing(self):
        """Both callers are explaining a failure already, so an unreachable Redis
        and a Redis with no sessions in it lead to the same sentence."""
        with mock.patch.object(misp_session, "_redis_connect",
                               side_effect=OSError("connection refused")):
            self.assertIsNone(misp_session._database_with_sessions())


class MissLogging(unittest.TestCase):
    def setUp(self):
        misp_session._warned_misses.clear()
        self.addCleanup(misp_session._warned_misses.clear)

    def load(self, cookies, sso_on=True):
        app = Flask(__name__)
        with app.test_request_context("/", headers={"Cookie": cookies}), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", sso_on), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
             mock.patch.object(misp_session, "get_misp_user", return_value=None), \
             self.assertLogs("webapp.misp_session", level="WARNING") as logs:
            misp_session.load_request_user()
            misp_session.load_request_user()
        return logs.output

    def test_a_missing_cookie_is_reported_once_with_what_was_sent(self):
        output = self.load("CAKEPHP=abc")
        self.assertEqual(len(output), 1, "warned on every request instead of once")
        self.assertIn("CAKEPHP", output[0])

    def test_sessions_in_another_database_are_named_in_the_log(self):
        """With the redirect on, a miss keeps the operator out of the settings page,
        so the log is the only place left that can name the database to point at."""
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=0), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIS_DB", 13):
            output = self.load("MISP-abc=sid")
        self.assertEqual(len(output), 1)
        self.assertIn("database 0", output[0])
        self.assertIn("MISP_SESSION_REDIS_DB to 0", output[0])

    def test_where_the_sessions_are_is_looked_up_once_and_not_per_request(self):
        """The lookup scans Redis and this runs in front of every request, so it
        belongs behind the same guard as the line it is written for."""
        finder = mock.Mock(return_value=0)
        with mock.patch.object(misp_session, "_database_with_sessions", finder), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIS_DB", 13):
            self.load("MISP-abc=sid")
        self.assertEqual(finder.call_count, 1, "scanned Redis on every request")

    def test_an_unreachable_redis_is_not_reported_as_an_empty_one(self):
        """The lookup answers None both when it searched and found nothing and when
        it could not search at all, so the sentence must not claim the first."""
        with mock.patch.object(misp_session, "_database_with_sessions", return_value=None):
            output = self.load("MISP-abc=sid")
        self.assertNotIn("no PHP sessions at all", output[0])
        self.assertIn("session.save_handler", output[0])

    def test_nothing_is_logged_when_single_sign_on_is_off(self):
        app = Flask(__name__)
        with app.test_request_context("/", headers={"Cookie": "CAKEPHP=abc"}), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
             mock.patch.object(misp_session, "get_misp_user", return_value=None):
            with self.assertNoLogs("webapp.misp_session", level="WARNING"):
                misp_session.load_request_user()


if __name__ == "__main__":
    unittest.main()
