"""The zsazsa API, version 1, for other tools to work with zsazsa's records.

A caller signs in with the MISP API key of its own user, in the Authorization
header as MISP takes it, and every MISP call made for it uses that key: MISP
decides what it may see and change, and the audit log names it. Its user has
to be in the organisation of MISP_WEBAPP_KEY, which the records belong to.

Nothing answers unless API_ENABLED is set. Its description, openapi_v1.json,
and a Swagger UI page to try it out are served without a key, as they hold
nothing but the description. API.md documents it.

It has detection engineering requests (create, list, read and update) and
lists of the flash intel alerts, vulnerability advisories and daily threat
briefings. Approval, publishing, delivery, the engineering status, source
events and the linked PIR stay with the web pages.
"""

import json
import logging
from pathlib import Path

import requests
from flask import Blueprint, abort, g, jsonify, render_template, request, url_for
from pymisp import PyMISP
from pymisp.exceptions import PyMISPError
from werkzeug.exceptions import HTTPException

import config
from webapp import audit, misp_session, misp_store
from webapp.utils import matching

logger = logging.getLogger(__name__)

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# What a key's role needs to write a record. perm_modify_org because records
# made on the web pages were saved by MISP_WEBAPP_KEY's user, not the caller's;
# perm_tagger because without it the event is created but not tagged as a
# record, and zsazsa never finds it again.
_WRITE_PERMISSIONS = ("perm_add", "perm_modify_org", "perm_tagger")

_PAGE_LIMIT = 100

_OPENAPI_FILE = Path(__file__).resolve().parent.parent / "openapi_v1.json"
# Read once, with the code: read on each call, an update offered its new calls
# while zsazsa still ran the code from before it was restarted.
_OPENAPI = json.loads(_OPENAPI_FILE.read_text())

# The organisation of MISP_WEBAPP_KEY, by key, asked of MISP once.
_records_org = {}


@bp.errorhandler(HTTPException)
def _http_error(exc):
    return _error(exc.code, exc.name.lower().replace(" ", "-"), exc.description)


# A path or a method the API does not have matches no route, so Flask does not
# know it is the API's and only the application's handlers see it.
@bp.app_errorhandler(404)
@bp.app_errorhandler(405)
def _no_such_route(exc):
    return _http_error(exc) if request.path.startswith("/api/v1/") else exc


@bp.errorhandler(PyMISPError)
@bp.errorhandler(requests.RequestException)
def _misp_unreachable(exc):
    logger.warning("API: MISP could not be reached on %s: %s", request.path, exc)
    return _error(503, "service-unavailable", "MISP cannot be reached. Try again shortly.")


# Anything else is a bug in zsazsa. The caller still gets the API's JSON, and
# the log the traceback.
@bp.errorhandler(Exception)
def _unexpected(exc):
    logger.exception("API: %s %s failed", request.method, request.path)
    return _error(500, "internal-server-error", "Something went wrong in zsazsa. Its log has the details.")


def _error(status, code, message):
    return jsonify({"error": {"code": code, "message": message}}), status


def _users_view_me(key):
    """The user and role of a key, as MISP's /users/view/me has them, or None
    when MISP refuses the key."""
    try:
        reply = requests.get(f"{config.MISP_WEBAPP_URL.rstrip('/')}/users/view/me.json",
                             headers={"Authorization": key, "Accept": "application/json"},
                             timeout=misp_store.HTTP_TIMEOUT, verify=config.MISP_WEBAPP_VERIFYCERT,
                             allow_redirects=False)
    except requests.RequestException as exc:
        logger.warning("API: could not ask MISP who a key belongs to: %s", exc)
        abort(503, "MISP cannot be reached. Try again shortly.")
    if reply.status_code >= 500:
        abort(503, f"MISP answered {reply.status_code}. Try again shortly.")
    if reply.status_code != 200:
        return None
    try:
        me = reply.json()
    except ValueError:
        return None
    return None if me.get("User", {}).get("disabled") else me


def _records_org_id():
    key = config.MISP_WEBAPP_KEY
    if key not in _records_org:
        me = _users_view_me(key)
        if me is None:
            logger.error("API: MISP refuses MISP_WEBAPP_KEY, so no caller's organisation can be checked")
            abort(503, "zsazsa cannot check your organisation at the moment.")
        _records_org[key] = str(me["User"]["org_id"])
    return _records_org[key]


@bp.before_request
def _authenticate():
    if not getattr(config, "API_ENABLED", False):
        abort(404)
    if request.endpoint in ("api_v1.openapi", "api_v1.docs"):
        return
    key = request.headers.get("Authorization", "").strip()
    if not key:
        abort(401, "Send the MISP API key of your user in the Authorization header.")
    me = _users_view_me(key)
    if me is None:
        abort(401, "MISP does not accept this key.")
    if str(me["User"].get("org_id")) != _records_org_id():
        abort(403, "The key's user is not in the organisation zsazsa's records belong to.")
    # As the MISP session would have it, so the audit log and the creator of a
    # request name the caller, and every store call is made with its key.
    g.misp_user = {**me["User"], "Role": me.get("Role") or {}}
    g._webapp_misp = PyMISP(config.MISP_WEBAPP_URL, key, config.MISP_WEBAPP_VERIFYCERT,
                            timeout=misp_store.HTTP_TIMEOUT)


def _refuse_unless_can_write():
    role = g.misp_user["Role"]
    missing = [perm for perm in _WRITE_PERMISSIONS if not misp_session._role_grants(role, perm)]
    if missing:
        abort(403, f"The key's role lacks {', '.join(missing)}.")
    if misp_store.key_is_read_only(role, misp_store._misp().misp_instance_version):
        abort(403, "The key is read-only.")


# ── Detection engineering request fields ─────────────────────────────────────

def _text(name, value):
    if not isinstance(value, str):
        abort(422, f"{name} has to be a string.")
    return value.strip()


def _text_list(name, value):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        abort(422, f"{name} has to be a list of strings.")
    entries = [v.strip() for v in value if v.strip()]
    # Stored a line each, so one with a line break would come back as two.
    if any(len(entry.splitlines()) > 1 for entry in entries):
        abort(422, f"{name}: an entry cannot hold a line break; make each line an entry of its own.")
    return entries


def _one_of(choices):
    def parse(name, value):
        value = _text(name, value)
        if value not in choices:
            abort(422, f"{name} has to be one of: {', '.join(choices)}.")
        return value
    return parse


def _techniques(name, value):
    """Techniques as the web form stores them, "Windows Management
    Instrumentation - T1047", from that or from the bare ID."""
    galaxy = misp_store.galaxy_mitre_attack_patterns()
    # The tactics in it have no T id, so they are only found by their value.
    by_id = {misp_store.technique_id(t): t for t in galaxy if misp_store.technique_id(t)}
    techniques = []
    for given in _text_list(name, value):
        technique = given if given in galaxy else by_id.get(given.upper())
        if technique is None:
            abort(422, f"{name}: {given} is not a MITRE ATT&CK technique.")
        techniques.append(technique)
    return list(dict.fromkeys(techniques))


def _cve_ids(name, value):
    return list(dict.fromkeys(c.upper() for c in _text_list(name, value)))


def _audience(name, value):
    return ", ".join(dict.fromkeys(_text_list(name, value)))


# The fields a caller sets, and how each is read into what create_der() and
# change_der() take. What the values may be is checked afterwards, by
# der_field_errors() as for the web form. The rule and its format are set when
# a request is made; after that only the detail page changes them, which checks
# the rule with Rulezet.
_FIELDS = {
    "title": _text,
    "technique": _techniques,
    "cve_ids": _cve_ids,
    "hypothesis": _text,
    "log_sources": _text_list,
    "expected_output": _text,
    "existing_coverage": _text_list,
    "test_cases": _text_list,
    "priority": _text,
    "tlp": _text,
    "audience": _audience,
    "author": _text,
    "review_state": _one_of((misp_store.DER_REVIEW_DRAFT, misp_store.DER_REVIEW_PENDING)),
}
_CREATE_ONLY_FIELDS = {
    "format": _text,
    "draft_rule": _text,
}
# The filters of each list and the values they take, as its page in zsazsa
# offers them. misp_store.product_filters() matches them for both.
_DER_FILTERS = {
    "review_state": misp_store.DER_REVIEW_STATES,
    "status": misp_store.DER_STATUSES,
    "priority": misp_store.DER_PRIORITIES,
    "tlp": misp_store.FIA_TLP_LEVELS,
    "audience": misp_store.STAKEHOLDER_ROLES,
}
_FIA_FILTERS = {
    "review_state": misp_store.FIA_REVIEW_STATES,
    "tlp": misp_store.FIA_TLP_LEVELS,
    "audience": misp_store.STAKEHOLDER_ROLES,
}
_VEA_FILTERS = {
    "review_state": misp_store.VEA_REVIEW_STATES,
    "exploitation": misp_store.VEA_EXPLOITATION,
    "tlp": misp_store.FIA_TLP_LEVELS,
    "audience": misp_store.STAKEHOLDER_ROLES,
}
_BRIEFING_FILTERS = {
    "review_state": misp_store.BRIEFING_REVIEW_STATES,
    "tlp": misp_store.FIA_TLP_LEVELS,
}


def _fields(creating):
    """The fields of the JSON body, read as create_der() and change_der() take them."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, "The body has to be a JSON object.")
    readers = {**_FIELDS, **_CREATE_ONLY_FIELDS} if creating else _FIELDS
    for name in body:
        if name not in readers:
            abort(422, f"{name} cannot be set{' after creation' if name in _CREATE_ONLY_FIELDS else ''}.")
    fields = {name: readers[name](name, value) for name, value in body.items()}
    errors = misp_store.der_field_errors(fields)
    if errors:
        abort(422, " ".join(errors))
    return fields


def _iso(moment):
    return moment.isoformat() if moment else None


def _audience_list(product):
    return [role for role in product.audience.split(", ") if role]


def _product_json(product, **fields):
    """What the API returns of every product, with the fields of its type."""
    return {"uuid": product.uuid, **fields, "title": product.title, "review_state": product.review_state,
            "tlp": product.tlp, "creator": product.creator, "approved_by": product.approved_by,
            "published": product.published, "published_at": _iso(product.published_at),
            "created_at": _iso(product.created_at), "misp_url": product.misp_url}


def _der_json(der):
    return _product_json(
        der, der_id=der.der_id, technique=der.technique,
        technique_ids=[misp_store.technique_id(t) for t in der.technique if misp_store.technique_id(t)],
        cve_ids=der.cve_ids, hypothesis=der.hypothesis, log_sources=der.log_sources,
        expected_output=der.expected_output, existing_coverage=der.existing_coverage, test_cases=der.test_cases,
        format=der.format, draft_rule=der.draft_rule, priority=der.priority, audience=_audience_list(der),
        author=der.author, status=der.status, rejection_reason=der.rejection_reason,
        source_event_uuids=der.source_event_uuids, linked_pir_uuid=der.linked_pir_uuid)


def _fia_json(fia):
    return _product_json(fia, fia_id=fia.fia_id, summary=fia.summary, audience=_audience_list(fia))


def _vea_json(vea):
    return _product_json(vea, vea_id=vea.vea_id, cve_id=vea.cve_id, cvss=vea.cvss,
                         exploitation=misp_store.vea_exploitation(vea), summary=vea.summary,
                         audience=_audience_list(vea))


def _briefing_json(briefing):
    return _product_json(briefing, date=briefing.date, story_count=briefing.story_count, summary=briefing.summary)


def _as_stored(uuid, der_id):
    """The request as MISP has it after a write. The write went through, so a
    failed read is not an error: the caller gets what it needs to ask again."""
    der = misp_store.get_der(uuid)
    return _der_json(der) if der else {"uuid": uuid, "der_id": der_id}


def _listed(name, list_products, filters, as_json):
    """A page of a list, filtered as its page in zsazsa filters it."""
    chosen = {f: _one_of(choices)(f, request.args[f]) for f, choices in filters.items() if request.args.get(f)}
    page = _positive_int("page", 1)
    limit = min(_positive_int("limit", _PAGE_LIMIT), _PAGE_LIMIT)
    try:
        products = matching(list_products(strict=True), misp_store.product_filters(**chosen))
    except RuntimeError as exc:
        logger.warning("API: could not list the %s: %s", name, exc)
        abort(503, f"MISP could not list the {name}. Try again shortly.")
    start = (page - 1) * limit
    return jsonify({name: [as_json(p) for p in products[start:start + limit]],
                    "page": page, "limit": limit, "total": len(products)})


def _positive_int(name, default):
    value = request.args.get(name, default)
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = 0
    if number < 1:
        abort(422, f"{name} has to be a whole number of 1 or more.")
    return number


# ── Its description ───────────────────────────────────────────────────────────

@bp.route("/openapi.json")
def openapi():
    # Behind a reverse proxy zsazsa can be served under a path, /zsazsa say.
    return jsonify({**_OPENAPI, "servers": [{"url": f"{request.script_root}/api/v1"}]})


@bp.route("/docs")
def docs():
    return render_template("api_docs.html")


# ── Detection engineering requests ────────────────────────────────────────────

@bp.route("/detection-engineering/requests", methods=["POST"])
def create_request():
    _refuse_unless_can_write()
    data = _fields(creating=True)
    if not data.get("title"):
        abort(422, "title is required.")
    try:
        uuid, der_id = misp_store.create_der(data)
    except RuntimeError as exc:
        abort(502, f"MISP did not take the request: {exc}")
    audit.record("create", "detection_eng", entity_id=uuid, entity_label=der_id, details="api")
    return jsonify(_as_stored(uuid, der_id)), 201, {"Location": url_for(".get_request", uuid=uuid)}


@bp.route("/detection-engineering/requests", methods=["GET"])
def list_requests():
    return _listed("requests", misp_store.list_ders, _DER_FILTERS, _der_json)


@bp.route("/detection-engineering/requests/<uuid:uuid>", methods=["GET"])
def get_request(uuid):
    der = misp_store.get_der(str(uuid))
    # One that is not there and one the key cannot see are the same to a caller.
    if der is None:
        abort(404, "No such detection engineering request.")
    return jsonify(_der_json(der))


@bp.route("/detection-engineering/requests/<uuid:uuid>", methods=["PATCH"])
def update_request(uuid):
    _refuse_unless_can_write()
    changes = _fields(creating=False)
    # Sent back to review or to the drafts, a rejected request loses its
    # reason, as it does when it is saved on the edit page.
    if "review_state" in changes:
        changes["rejection_reason"] = ""
    try:
        der = misp_store.change_der(str(uuid), changes, refuse_published=True)
    except ValueError as exc:
        abort(409, str(exc))
    except RuntimeError as exc:
        abort(502, f"MISP did not take all of the change: {exc}")
    if der is None:
        abort(404, "No such detection engineering request.")
    if changes:
        audit.record("update", "detection_eng", entity_id=der.uuid, entity_label=der.der_id, details="api")
    return jsonify(_der_json(der))


# ── Lists of the other products ───────────────────────────────────────────────

@bp.route("/flash-intel-alerts")
def list_flash_intel_alerts():
    return _listed("alerts", misp_store.list_fias, _FIA_FILTERS, _fia_json)


@bp.route("/vulnerability-advisories")
def list_vulnerability_advisories():
    return _listed("advisories", misp_store.list_veas, _VEA_FILTERS, _vea_json)


@bp.route("/daily-briefings")
def list_daily_briefings():
    return _listed("briefings", misp_store.list_briefings, _BRIEFING_FILTERS, _briefing_json)
