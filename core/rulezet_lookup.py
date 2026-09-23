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


def _search(endpoint: str, param: str, ids: list[str]) -> list[dict] | None:
    """GET a Rulezet public search endpoint. Returns None on any failure so
    callers can tell "nothing configured/reachable" apart from "no matches"."""
    base_url = _base_url()
    if not base_url or not ids:
        return None
    try:
        r = requests.get(
            f"{base_url}/api/rule/public/{endpoint}",
            params={param: ",".join(ids)},
            timeout=SEARCH_TIMEOUT_S,
            headers={"Accept": "application/json"},
        )
    except requests.RequestException as exc:
        logger.warning("Rulezet lookup (%s) for %s failed: %s", endpoint, ids, exc)
        return None
    if r.status_code != 200:
        logger.warning("Rulezet lookup (%s) for %s returned HTTP %s", endpoint, ids, r.status_code)
        return None
    try:
        data = r.json()
    except ValueError as exc:
        logger.warning("Rulezet lookup (%s) for %s returned no JSON: %s", endpoint, ids, exc)
        return None
    # Valid JSON is not necessarily the object we expect: a proxy or an older
    # Rulezet can answer with a bare list, and .get() on that would be a 500
    # for the analyst instead of an empty result.
    if not isinstance(data, dict) or not isinstance(data.get("results") or [], list):
        logger.warning("Rulezet lookup (%s) for %s returned an unexpected shape", endpoint, ids)
        return None

    rules = []
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("id")
        rules.append({
            "id": rule_id,
            "uuid": item.get("uuid") or "",
            "title": item.get("title") or f"Rule {rule_id}",
            "format": item.get("format") or "",
            "source": item.get("source") or "",
            "license": item.get("license") or "",
            "author": item.get("author") or "",
            "last_modif": item.get("formatted_date") or item.get("last_modif") or "",
            "cve_ids": _str_list(item.get("cve_id")),
            "matched_techniques": _str_list(item.get("matched_techniques")),
            "quality_score": item.get("quality_score"),
            "content": item.get("to_string") or "",
            # Rulezet's public search API hardcodes detail_url to
            # https://rulezet.org regardless of which instance answered —
            # rebuild it from the configured RULEZET_URL so a local/dev
            # instance links to itself, not to production. The id comes from
            # the remote side, so it is quoted rather than pasted into the path.
            "url": f"{base_url}/rule/detail_rule/{quote(str(rule_id), safe='')}" if rule_id else base_url,
        })
    return rules


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
