"""Client for a Rulezet instance's public API (config.RULEZET_URL).

Rulezet (github.com/ngsoti/rulezet-core) is a community repository of
detection rules (Sigma, YARA, Suricata, Elastic, ...). zsazsa uses three of its
public, unauthenticated endpoints: rule search by CVE ID, rule search by MITRE
ATT&CK technique, and a dry-run syntax validator. None of them needs an
account or saves anything on the Rulezet side.

Everything here is optional enrichment. An empty RULEZET_URL means the
integration is off and no request is made at all; a Rulezet that is down,
slow, or answers with something that is not the expected JSON is logged and
turned into an empty result, never an exception, so a form keeps working when
the instance does not.
"""

import json
import logging
from urllib.parse import quote

import requests

import config as _cfg

logger = logging.getLogger(__name__)

# A search can return hundreds of rules (with their full content), so it gets
# the same budget as the CVE lookup. Validation runs the rule through the
# format's own parser on the Rulezet side, which can take a little longer.
SEARCH_TIMEOUT_S = 10
VALIDATE_TIMEOUT_S = 15


def _base_url() -> str:
    return (getattr(_cfg, "RULEZET_URL", "") or "").rstrip("/")


def _str_list(value) -> list[str]:
    """A field that should be a list of strings, as one. Rulezet has returned
    cve_id as a JSON-encoded string rather than a list, so a string is decoded
    first; anything else that is not a list is dropped rather than trusted."""
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else []
        except ValueError:
            value = [value]
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def _str(value) -> str:
    """A field that should be a string, as one. These records come from a
    community instance and a field can hold anything, so a number where a name
    belongs is dropped here rather than raising three frames later."""
    return value if isinstance(value, str) else ""


def _get_json(url: str, label: str, params: dict | None = None) -> dict | list | None:
    """GET a Rulezet public endpoint and return its parsed JSON, or None.

    None covers every way the call can fail: unreachable, a non-200, or a body
    that is not JSON at all. Each is logged with `label` saying which call it
    was, since the caller only sees that nothing came back.
    """
    try:
        r = requests.get(url, params=params, timeout=SEARCH_TIMEOUT_S,
                         headers={"Accept": "application/json"})
    except requests.RequestException as exc:
        logger.warning("Rulezet %s failed: %s", label, exc)
        return None
    if r.status_code != 200:
        logger.warning("Rulezet %s returned HTTP %s", label, r.status_code)
        return None
    try:
        return r.json()
    except ValueError as exc:
        logger.warning("Rulezet %s returned no JSON: %s", label, exc)
        return None


def _rule_dict(item: dict, base_url: str) -> dict:
    """One Rulezet record, in the shape the rule viewer expects.

    Shared by the searches and by get_rule so the two cannot drift: a field the
    endpoint does not carry comes back empty, and the viewer leaves it out.
    """
    rule_id = item.get("id")
    rule = {
        "id": rule_id,
        "uuid": _str(item.get("uuid")),
        "title": _str(item.get("title")) or f"Rule {rule_id}",
        "format": _str(item.get("format")),
        "source": _str(item.get("source")),
        "license": _str(item.get("license")),
        "author": _str(item.get("author")),
        "last_modif": _str(item.get("formatted_date")) or _str(item.get("last_modif")),
        "cve_ids": _str_list(item.get("cve_id")),
        "matched_techniques": _str_list(item.get("matched_techniques")),
        "quality_score": item.get("quality_score"),
        "content": _str(item.get("to_string")),
        # Rulezet's public API hardcodes detail_url to https://rulezet.org
        # regardless of which instance answered, so it is rebuilt from the
        # configured RULEZET_URL: a local or dev instance then links to itself
        # rather than to production. The id comes from the remote side, so it is
        # quoted rather than pasted into the path.
        "url": f"{base_url}/rule/detail_rule/{quote(str(rule_id), safe='')}" if rule_id else base_url,
    }
    return rule


def _search(endpoint: str, param: str, ids: list[str]) -> list[dict] | None:
    """GET a Rulezet public search endpoint. Returns None on any failure so
    callers can tell "nothing configured/reachable" apart from "no matches"."""
    base_url = _base_url()
    if not base_url or not ids:
        return None
    data = _get_json(f"{base_url}/api/rule/public/{endpoint}",
                     f"lookup ({endpoint}) for {ids}", params={param: ",".join(ids)})
    if data is None:
        return None
    # Valid JSON is not necessarily the object we expect: a proxy or an older
    # Rulezet can answer with a bare list, and .get() on that would be a 500
    # for the analyst instead of an empty result.
    if not isinstance(data, dict) or not isinstance(data.get("results") or [], list):
        logger.warning("Rulezet lookup (%s) for %s returned an unexpected shape", endpoint, ids)
        return None

    return [_rule_dict(item, base_url)
            for item in data.get("results") or [] if isinstance(item, dict)]


def get_rule(rule_id: str) -> dict | None:
    """One rule with its content, by its Rulezet id.

    Used to show a rule that is already referenced on a saved product: only its
    title and URL are stored, so the content is fetched again when an analyst
    asks to see it.

    The public detail endpoint returns less than the search endpoints do, so
    uuid, last_modif, quality_score and matched_techniques come back empty and
    the viewer leaves those fields out. "author" is the Rulezet account that
    submitted the rule, which is the only attribution the endpoint carries.

    Returns None when RULEZET_URL is unset, the id is not a plain number, or
    the instance could not be reached or answered with something else.
    """
    base_url = _base_url()
    rule_id = str(rule_id or "").strip()
    if not base_url or not rule_id.isdigit():
        return None
    item = _get_json(f"{base_url}/api/rule/public/detail/{quote(rule_id, safe='')}",
                     f"detail for rule {rule_id}")
    if item is None:
        # _get_json has already said why; anything else is a reply we cannot use.
        return None
    if not isinstance(item, dict) or not item.get("id"):
        logger.warning("Rulezet detail for rule %s returned an unexpected shape", rule_id)
        return None

    # The detail endpoint carries no author string, only the Rulezet account
    # that submitted the rule. A record that does carry one keeps it rather
    # than losing it to an account with no name on it.
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    submitter = " ".join(p for p in (_str(user.get("first_name")),
                                     _str(user.get("last_name"))) if p)
    rule = _rule_dict(item, base_url)
    if submitter:
        rule["author"] = submitter
    return rule


def search_rules_by_cve(cve_ids: list[str]) -> list[dict]:
    """Query a Rulezet instance's public API for detection rules matching CVE IDs.

    Returns a list of {id, title, format, source, cve_ids, quality_score, url}
    dicts, or an empty list on any failure, when RULEZET_URL is not configured,
    or when no CVE ID is given — so callers can treat this as optional
    enrichment, the same way core.vuln_lookup.fetch_cve_info does.
    """
    return _search("search_rules_by_cve", "cve_ids", cve_ids) or []


def search_rules_by_attack(technique_ids: list[str]) -> list[dict]:
    """Query a Rulezet instance's public API for detection rules mapped to
    MITRE ATT&CK technique IDs (e.g. T1071, T1566.001).

    Same shape and failure handling as search_rules_by_cve.
    """
    return _search("search_rules_by_attack", "technique_ids", technique_ids) or []


def validate_rule(rule_format: str, content: str) -> dict | None:
    """Dry-run a rule's syntax against a Rulezet instance's public validator —
    the same per-format check a rule goes through on creation, without ever
    saving anything.

    Returns {"valid": bool, "errors": [...], "warnings": [...]} on success,
    {"error": "..."} when Rulezet answered but not with a verdict (a 4xx for a
    bad/unknown format or empty content, a 5xx, an HTML error page), or None
    when RULEZET_URL is not configured or the instance could not be reached at
    all. Keeping "answered with an error" apart from "unreachable" matters: the
    analyst fixes the first in the rule and the second in the configuration.
    """
    base_url = _base_url()
    if not base_url or not (rule_format or "").strip() or not (content or "").strip():
        return None
    try:
        r = requests.post(
            f"{base_url}/api/rule/public/validate",
            json={"format": rule_format, "content": content},
            timeout=VALIDATE_TIMEOUT_S,
            headers={"Accept": "application/json"},
        )
    except requests.RequestException as exc:
        logger.warning("Rulezet validate (%s) failed: %s", rule_format, exc)
        return None

    try:
        data = r.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        data = {}

    if r.status_code != 200:
        logger.warning("Rulezet validate (%s) returned HTTP %s", rule_format, r.status_code)
        error = data.get("error")
        return {"error": error if isinstance(error, str) and error else f"Rulezet returned HTTP {r.status_code}"}
    if "valid" not in data:
        logger.warning("Rulezet validate (%s) returned no verdict", rule_format)
        return {"error": "Rulezet returned an unexpected response."}
    return {
        "valid": bool(data.get("valid")),
        "errors": data.get("errors") if isinstance(data.get("errors"), list) else [],
        "warnings": data.get("warnings") if isinstance(data.get("warnings"), list) else [],
    }
