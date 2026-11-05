import logging
import re

import requests

logger = logging.getLogger(__name__)

_CIRCL_URL = "https://vulnerability.circl.lu/api/cve/{}"
_SSVC_EXPLOIT_MAP = {"active": "Weaponised", "poc": "PoC public", "none": "None known"}

# What a CVE ID looks like, for pulling them out of an event title and for
# checking one before it is put in a URL. The word boundaries let the same
# pattern do both: they match at the ends of a string, so fullmatch() works.
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def fetch_cve_info(cve_id: str) -> dict:
    """Fetch and parse CVE details from vulnerability.circl.lu.

    Returns a dict with title, description, products, affected, versions, cwes,
    cvss_score, cvss_severity, cvss_vector, exploit_availability, cisa_kev, and
    references. ``affected`` is the (vendor, product) pairs that make up
    ``products``, for matching against an asset inventory.
    Returns an empty dict on any failure so callers can treat it as optional enrichment.
    """
    return lookup_cve(cve_id) or {}


def lookup_cve(cve_id: str) -> dict | None:
    """The details fetch_cve_info() gives, {} for a CVE the database does not
    have, or None when it could not be asked: a caller that decides from them
    tries again rather than take an outage for a CVE without a score."""
    cve_id = (cve_id or "").strip()
    if not CVE_RE.fullmatch(cve_id):
        logger.debug("Rejected invalid CVE ID format: %r", cve_id)
        return {}
    cve_id = cve_id.upper()
    try:
        r = requests.get(_CIRCL_URL.format(cve_id), timeout=10, headers={"Accept": "application/json"})
        if r.status_code == 404:
            return {}
        if r.status_code != 200:
            logger.warning("CVE lookup for %s answered %s", cve_id, r.status_code)
            return None
        return _parse(r.json())
    except Exception as exc:
        logger.warning("CVE lookup for %s failed: %s", cve_id, exc)
        return None


def _parse(data: dict) -> dict:
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}

    title = cna.get("title") or ""
    descriptions = cna.get("descriptions") or []
    desc = next((d["value"] for d in descriptions if d.get("lang", "").lower().startswith("en")), "")

    products, affected, versions = [], [], []
    for a in cna.get("affected") or []:
        vendor = (a.get("vendor") or "").strip()
        if vendor.lower() in ("n/a", "na"):
            vendor = ""
        product = (a.get("product") or "").strip()
        if product and product.lower() not in ("n/a", "na"):
            label = f"{vendor} {product}".strip() if vendor else product
            if label not in products:
                products.append(label)
                affected.append((vendor, product))
        for v in a.get("versions") or []:
            ver = (v.get("version") or "").strip()
            less_than = (v.get("lessThan") or v.get("lessThanOrEqual") or "").strip()
            if ver and ver not in ("0", "n/a", "*"):
                entry = f"{ver} < {less_than}" if less_than else ver
                if entry not in versions:
                    versions.append(entry)

    cwes = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = (d.get("cweId") or "").strip()
            if cwe and cwe not in cwes:
                cwes.append(cwe)

    refs = []
    for ref in cna.get("references") or []:
        url = (ref.get("url") or "").strip()
        if url and url not in refs:
            refs.append(url)

    cvss_score = cvss_severity = cvss_vector = exploit_availability = ""
    cisa_kev = "No"
    for source in [cna] + (containers.get("adp") or []):
        for m in source.get("metrics") or []:
            if not cvss_score:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                    if key in m:
                        cvss_score = str(m[key].get("baseScore") or "")
                        cvss_severity = str(m[key].get("baseSeverity") or "").upper()
                        cvss_vector = str(m[key].get("vectorString") or "")
                        break
            if "other" in m and isinstance(m["other"], dict) and m["other"].get("type") == "ssvc":
                for opt in (m["other"].get("content") or {}).get("options") or []:
                    if "Exploitation" in opt:
                        exploit_availability = _SSVC_EXPLOIT_MAP.get((opt["Exploitation"] or "").lower(), "")
        for entry in source.get("timeline") or []:
            if "kev" in (entry.get("value") or "").lower():
                cisa_kev = "Yes"

    return {
        "title": title,
        "description": desc[:600],
        "products": products,
        "affected": affected,
        "versions": versions[:8],
        "cwes": cwes[:5],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "exploit_availability": exploit_availability,
        "cisa_kev": cisa_kev,
        "references": refs[:20],
    }
