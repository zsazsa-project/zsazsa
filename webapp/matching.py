"""Match collection events against PIR/GIR scope.

Each SCOPE_CATEGORY defines which attribute on a requirement to check and
which lookup methods to apply against the event. New requirement types (e.g.
stakeholder focal_points) can be supported by extending _SCOPE_CATEGORIES or
by passing a custom categories list to match_event_to_requirement().
"""

import logging
import re
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Scope categories ─────────────────────────────────────────────────────────
# Tuple: (req_attr, search_methods, display_label, score_weight)
# search_methods:
#   "galaxy"    - check event galaxy_names (cluster value list)
#   "tag_value" - check value part of misp-galaxy:X="VALUE" tags
#   "tag_name"  - check full normalized tag string (catches any tag substring,
#                 including tags without a "=" like plain "phishing" tags)
#   "title"     - case-insensitive substring in event info/title
# All methods also try compact-form matching (spaces/hyphens/underscores
# stripped) so "Agent Tesla" matches "AgentTesla" and vice versa.

_SCOPE_CATEGORIES = [
    ("geographic_scope",        ["galaxy", "tag_value", "tag_name", "title"], "Geography",        1.5),
    ("sectors",                 ["galaxy", "tag_value", "tag_name", "title"], "Sector",           1.5),
    ("threat_actors",           ["galaxy", "tag_value", "tag_name", "title"], "Threat actor",     2.0),
    ("threat_types",            ["galaxy", "tag_name", "title"],              "Threat type",      1.0),
    ("technology",              ["title"],                                    "Technology",       1.0),
    ("vendor",                  ["title"],                                    "Vendor",           1.0),
    ("incident",                ["title"],                                    "Incident",         0.8),
    ("campaign",                ["galaxy", "tag_name", "title"],              "Campaign",         1.0),
    ("mitre_attack_techniques", ["galaxy", "tag_value", "tag_name", "title"], "ATT&CK technique", 1.0),
]

# Minimum compact length before compound-word matching is attempted.
# Keeps short terms like "al" from spuriously matching "Israel" after stripping.
_COMPACT_MIN = 5


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class MatchEvidence:
    category: str   # e.g. "threat_actors"
    label: str      # e.g. "Threat actor"
    term: str       # the matched value
    source: str     # "galaxy", "tag_value", "tag_name", or "title"


@dataclass
class ScopeMatch:
    req_type: str    # "pir" or "gir"
    req_id: str      # "PIR-001"
    req_uuid: str
    req_label: str   # question (PIR) or topic (GIR)
    evidence: list   # list[MatchEvidence]
    score: float

    def to_dict(self) -> dict:
        matched = [f"{e.term} ({e.label})" for e in self.evidence]
        return {
            "type": self.req_type,
            "id": self.req_id,
            "uuid": self.req_uuid,
            "label": (self.req_label or "")[:120],
            "score": round(self.score, 2),
            "matched_terms": matched[:8],
        }


# ── Requirement cache ─────────────────────────────────────────────────────────

_req_cache: dict = {"data": None, "ts": 0.0}
_req_cache_lock = threading.Lock()
_REQ_TTL = 300  # 5 minutes


def get_requirements() -> tuple:
    """Return active (pirs, girs) with a 5-minute in-memory cache."""
    now = time.time()
    with _req_cache_lock:
        if _req_cache["data"] is None or (now - _req_cache["ts"]) > _REQ_TTL:
            try:
                from webapp import misp_store
                pirs = [p for p in (misp_store.list_pirs() or []) if getattr(p, "status", None) == "Active"]
                girs = [g for g in (misp_store.list_girs() or []) if getattr(g, "status", None) == "Active"]
                _req_cache["data"] = (pirs, girs)
                _req_cache["ts"] = now
            except Exception as exc:
                logger.warning("Could not load PIRs/GIRs for matching: %s", exc)
                if _req_cache["data"] is not None:
                    return _req_cache["data"]  # return stale on error
                return [], []
        return _req_cache["data"]


def invalidate_cache() -> None:
    """Call after creating, updating, or deleting a PIR or GIR."""
    with _req_cache_lock:
        _req_cache["ts"] = 0.0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(s) -> str:
    return (s or "").lower().strip().strip('"')


def _compact(s: str) -> str:
    """Strip word-separators so 'Agent Tesla' and 'AgentTesla' compare equal."""
    return re.sub(r'[\s\-_]', '', s)


def _tag_values(tags: list) -> list:
    """Extract cluster values from tags like misp-galaxy:X="VALUE"."""
    out = []
    for t in tags:
        if t and "misp-galaxy:" in t and "=" in t:
            out.append(_norm(t.split("=", 1)[1]))
    return out


def _tag_texts(tags: list) -> list:
    """Return full normalized tag strings for broad substring search.

    Covers plain tags ("phishing"), tags without a value, and the full
    text of misp-galaxy tags so a scope term like "phishing" matches
    misp-galaxy:rsit="Fraud:Phishing".
    """
    return [_norm(t) for t in tags if t]


def _matches_term(item_n: str, item_c: str, haystack: str) -> bool:
    """True if a normalized scope term matches a normalized haystack string.

    Long terms (compact form >= _COMPACT_MIN chars) match as substrings, in both
    raw and separator-stripped form, so "Agent Tesla" matches "AgentTesla". Short
    terms match only as whole words, so "ai" matches the token "ai" but not the
    "ai" inside "maintain". The length guard is applied to every comparison path,
    not just the compact one.
    """
    if not item_n or not haystack:
        return False
    if len(item_c) >= _COMPACT_MIN:
        return item_n in haystack or item_c in _compact(haystack)
    # Short term: match only when not flanked by word characters, so "ai" hits
    # the token "ai" but not the "ai" inside "maintain". Lookarounds (rather than
    # \b) keep this working for terms with trailing punctuation such as "c++".
    return re.search(r'(?<!\w)' + re.escape(item_n) + r'(?!\w)', haystack) is not None


def term_in_text(term: str, text: str) -> bool:
    """Whole-word-aware match of a single scope term against a free text blob.

    Used by the scope preview. Reuses the same rules as the event matcher: long
    terms match as substrings (also in separator-stripped form), short terms
    match only as whole words. This stops "gas" from matching inside "gasten".
    """
    item_n = _norm(term)
    if not item_n:
        return False
    return _matches_term(item_n, _compact(item_n), _norm(text))


# ── Core matching ─────────────────────────────────────────────────────────────

def match_event_to_requirement(
    event: dict,
    req,
    req_type: str,
    categories: list | None = None,
) -> "ScopeMatch | None":
    """Match one cached event dict against one PIR or GIR namespace.

    Pass a custom `categories` list to support additional requirement types
    (e.g. stakeholder focal_points) without changing this function.

    Returns None if there is no match or if an exclusion term matches.
    """
    tags = event.get("tags") or []
    galaxy_names = [_norm(g) for g in (event.get("galaxy_names") or [])]
    tag_vals = _tag_values(tags)
    tag_texts = _tag_texts(tags)
    title = _norm(event.get("info") or "")

    # Exclusion: if any out_of_scope term matches anywhere, skip this req.
    for excl in (getattr(req, "out_of_scope", None) or []):
        excl_n = _norm(excl)
        if not excl_n:
            continue
        excl_c = _compact(excl_n)
        if _matches_term(excl_n, excl_c, title):
            return None
        if any(_matches_term(excl_n, excl_c, g) for g in galaxy_names):
            return None
        if any(_matches_term(excl_n, excl_c, tv) for tv in tag_vals):
            return None
        if any(_matches_term(excl_n, excl_c, tt) for tt in tag_texts):
            return None

    cats = categories if categories is not None else _SCOPE_CATEGORIES
    evidence = []
    total_weight = 0.0

    for attr, methods, label, weight in cats:
        scope_items = getattr(req, attr, None) or []
        for item in scope_items:
            item_n = _norm(item)
            if not item_n:
                continue
            item_c = _compact(item_n)
            matched_source = None

            if "galaxy" in methods and any(_matches_term(item_n, item_c, g) for g in galaxy_names):
                matched_source = "galaxy"

            if matched_source is None and "tag_value" in methods and any(
                    _matches_term(item_n, item_c, tv) for tv in tag_vals):
                matched_source = "tag_value"

            if matched_source is None and "tag_name" in methods and any(
                    _matches_term(item_n, item_c, tt) for tt in tag_texts):
                matched_source = "tag_name"

            if matched_source is None and "title" in methods and _matches_term(item_n, item_c, title):
                matched_source = "title"

            if matched_source:
                evidence.append(MatchEvidence(
                    category=attr, label=label, term=item, source=matched_source,
                ))
                total_weight += weight
                break  # one match per scope item is enough

    if not evidence:
        return None

    category_hits = len({e.category for e in evidence})
    score = min(1.0, 0.25 + 0.1 * category_hits + 0.05 * total_weight)

    req_label = getattr(req, "question", None) or getattr(req, "topic", None) or ""
    return ScopeMatch(
        req_type=req_type,
        req_id=getattr(req, "pir_id", None) or getattr(req, "gir_id", None) or "",
        req_uuid=req.uuid,
        req_label=req_label,
        evidence=evidence,
        score=score,
    )


def match_events(events: list, pirs: list, girs: list) -> dict:
    """Return {uuid: [match_dict, ...]} for every event that matches at least one requirement."""
    if not pirs and not girs:
        return {}
    result = {}
    for event in events:
        uuid = event.get("uuid", "")
        matches = []
        for pir in pirs:
            m = match_event_to_requirement(event, pir, "pir")
            if m:
                matches.append(m.to_dict())
        for gir in girs:
            m = match_event_to_requirement(event, gir, "gir")
            if m:
                matches.append(m.to_dict())
        if matches:
            matches.sort(key=lambda x: x["score"], reverse=True)
            result[uuid] = matches
    return result
