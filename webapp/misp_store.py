"""
MISP storage backend for the zsazsa CTI program.

One MISP event per stakeholder, PIR, and GIR. Fields are stored inside a
custom MISP object (zsazsa-stakeholder, zsazsa-pir, zsazsa-gir) whose
definition templates live in webapp/misp_objects/objects/. Focus points are
kept as event-level text attributes with comment 'zsazsa:fp' so they can be
added and deleted independently without rebuilding the whole object.

PIR/GIR ownership is recorded by storing the stakeholder event UUID in the
owner-uuid object attribute, with name and role denormalised so list views
never need a second API call per row.

List-valued scope fields (geographic-scope, sectors, threat-types,
threat-actors, out-of-scope) are stored as JSON arrays inside a single text
attribute.
"""

import json
import logging
import os
import secrets
import threading
import time
import urllib3
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import config
from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP
from webapp import misp_session
from webapp.collection_cache import AI_SUMMARY_PREFIX, source_slug
from webapp.models import STAKEHOLDER_ROLES
from webapp.utils import human_size

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def _extract_uuid(value: str) -> str:
    m = _UUID_RE.search((value or "").strip())
    return m.group(0).lower() if m else ""

_FP_COMMENT = "zsazsa:fp"

# PyMISP resolves templates as {_OBJECTS_PATH}/{name}/definition.json
_OBJECTS_PATH = os.path.join(os.path.dirname(__file__), "misp_objects", "objects")

# Galaxy UUIDs for scope fields
GALAXY_COUNTRY = "84668357-5a8c-4bdd-9f0f-6b50b2aee4c1"
GALAXY_TARGET_INFORMATION = "709ed29c-aa00-11e9-82cd-67ac1a6ee3bc"
GALAXY_SECTOR = "e1bb134c-ae4d-11e7-8aa9-f78a37325439"
GALAXY_THREAT_ACTOR = "698774c7-8022-42c4-917f-8d6e4f06ada3"
GALAXY_MITRE_ATTACK = "d752161c-78f6-11e7-a0ea-bfa79b407ce4"

# Fallback tag prefixes used when the cluster object has no tag_name attribute
_GALAXY_TAG_PREFIX = {
    GALAXY_COUNTRY: 'misp-galaxy:country',
    GALAXY_TARGET_INFORMATION: 'misp-galaxy:target-information',
    GALAXY_SECTOR: 'misp-galaxy:sector',
    GALAXY_THREAT_ACTOR: 'misp-galaxy:threat-actor',
    GALAXY_MITRE_ATTACK: 'misp-galaxy:mitre-attack-pattern',
}

# Used to identify and remove stale scope tags on event update
_SCOPE_TAG_PREFIXES = (
    'misp-galaxy:country=',
    'misp-galaxy:target-information=',
    'misp-galaxy:sector=',
    'misp-galaxy:threat-actor=',
)

_galaxy_cache: dict = {}  # galaxy_uuid -> (timestamp, values_list, tag_map)
_GALAXY_TTL = 600  # seconds


# ── Connection ────────────────────────────────────────────────────────────────

# Per-request timeout (seconds) for MISP calls, so an unreachable or slow server
# cannot hang a page indefinitely. HEALTH_CHECK_TIMEOUT is shorter, used for the
# connection probes on the pipeline page where several servers are checked.
HTTP_TIMEOUT = 30
HEALTH_CHECK_TIMEOUT = 8


def _misp():
    # Cache per Flask request via g; fall back to a fresh connection outside Flask (analyser).
    try:
        from flask import g
        if not hasattr(g, '_webapp_misp'):
            g._webapp_misp = PyMISP(
                config.MISP_WEBAPP_URL,
                config.MISP_WEBAPP_KEY,
                config.MISP_WEBAPP_VERIFYCERT,
                False,
                timeout=HTTP_TIMEOUT,
            )
        return g._webapp_misp
    except RuntimeError:
        return PyMISP(
            config.MISP_WEBAPP_URL,
            config.MISP_WEBAPP_KEY,
            config.MISP_WEBAPP_VERIFYCERT,
            False,
            timeout=HTTP_TIMEOUT,
        )


def _scraper_misp():
    try:
        from flask import g
        if not hasattr(g, '_scraper_misp'):
            g._scraper_misp = PyMISP(
                config.MISP_URL,
                config.MISP_KEY,
                config.MISP_VERIFYCERT,
                False,
                timeout=HTTP_TIMEOUT,
            )
        return g._scraper_misp
    except RuntimeError:
        return PyMISP(
            config.MISP_URL,
            config.MISP_KEY,
            config.MISP_VERIFYCERT,
            False,
            timeout=HTTP_TIMEOUT,
        )


# ── Galaxy cluster fetching ───────────────────────────────────────────────────

def _fetch_galaxy_clusters(galaxy_uuid: str) -> list:
    """Return a sorted list of cluster value strings for the given galaxy UUID.

    Results are cached for _GALAXY_TTL seconds to avoid hammering MISP on
    every form load. The cache also stores a value->tag_name mapping used
    when writing galaxy scope fields as MISP tags.
    """
    now = time.time()
    if galaxy_uuid in _galaxy_cache:
        ts, values, _ = _galaxy_cache[galaxy_uuid]
        if now - ts < _GALAXY_TTL:
            return values
    try:
        m = _misp()
        clusters = m.search_galaxy_clusters(galaxy_uuid, pythonify=True)
        if isinstance(clusters, dict) or not clusters:
            values = []
            tag_map = {}
        else:
            prefix = _GALAXY_TAG_PREFIX.get(galaxy_uuid)
            value_set = set()
            tag_map = {}
            for c in clusters:
                if not hasattr(c, "value"):
                    continue
                value_set.add(c.value)
                tag_name = getattr(c, "tag_name", None)
                if not tag_name and prefix:
                    tag_name = f'{prefix}="{c.value}"'
                if tag_name:
                    tag_map[c.value] = tag_name
            values = sorted(value_set)
        _galaxy_cache[galaxy_uuid] = (now, values, tag_map)
        return values
    except Exception as exc:
        logger.warning("Failed to fetch galaxy %s: %s", galaxy_uuid, exc)
        return []


def _galaxy_tag_map(galaxy_uuid: str) -> dict:
    """Return the value->tag_name mapping for a galaxy, fetching if needed."""
    entry = _galaxy_cache.get(galaxy_uuid)
    if entry:
        ts, _, tag_map = entry
        if time.time() - ts < _GALAXY_TTL:
            return tag_map
    _fetch_galaxy_clusters(galaxy_uuid)
    entry = _galaxy_cache.get(galaxy_uuid)
    return entry[2] if entry else {}


def _build_scope_tags(data: dict) -> list:
    """Return MISP galaxy tag strings for geographic_scope, sectors, threat_actors.

    Lookup is case-insensitive so stored values normalised to a different case
    still resolve to the correct tag.
    """
    tags = []
    geo_maps_ci = [
        {k.lower(): v for k, v in _galaxy_tag_map(GALAXY_COUNTRY).items()},
        {k.lower(): v for k, v in _galaxy_tag_map(GALAXY_TARGET_INFORMATION).items()},
    ]
    for v in data.get("geographic_scope") or []:
        for gm_ci in geo_maps_ci:
            tag = gm_ci.get(v.lower())
            if tag:
                tags.append(tag)
                break
    sector_map_ci = {k.lower(): v for k, v in _galaxy_tag_map(GALAXY_SECTOR).items()}
    for v in data.get("sectors") or []:
        tag = sector_map_ci.get(v.lower())
        if tag:
            tags.append(tag)
    ta_map_ci = {k.lower(): v for k, v in _galaxy_tag_map(GALAXY_THREAT_ACTOR).items()}
    for v in data.get("threat_actors") or []:
        tag = ta_map_ci.get(v.lower())
        if tag:
            tags.append(tag)
    return tags


def _ensure_tag(misp, tag_name: str):
    """Create a MISP tag if it does not already exist."""
    from pymisp import MISPTag
    t = MISPTag()
    t.from_dict(name=tag_name)
    r = misp.add_tag(t)
    if isinstance(r, dict) and "errors" in r:
        logger.debug("add_tag %s: %s (may already exist)", tag_name, r["errors"])


def _apply_scope_tags(misp, event_uuid: str, data: dict, new_info: str = None, _event=None, local=False):
    """Apply scope galaxy tags using individual tag/untag API calls.

    Calls misp.tag()/misp.untag() per tag which is the only reliable path
    for galaxy tags. Falls back to creating missing tags via _ensure_tag.
    Pass _event to avoid a redundant fetch when the caller already has it.
    Pass local=True to attach the galaxy tags as local (not federated).
    """
    event = _event or misp.get_event(event_uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        logger.warning("_apply_scope_tags: could not fetch event %s", event_uuid)
        return
    if new_info:
        misp.update_event({"Event": {"id": event.id, "info": new_info}})
    current_scope = {t.name for t in (getattr(event, "tags", []) or [])
                     if t.name.startswith(_SCOPE_TAG_PREFIXES)}
    wanted = set(_build_scope_tags(data))
    for name in current_scope - wanted:
        r = misp.untag(event_uuid, name)
        if isinstance(r, dict) and "errors" in r:
            logger.warning("untag %s from %s: %s", name, event_uuid, r["errors"])
    for name in wanted - current_scope:
        r = misp.tag(event_uuid, name, local=local)
        if isinstance(r, dict) and "errors" in r:
            logger.warning("tag %s on %s failed, trying to create: %s", name, event_uuid, r["errors"])
            _ensure_tag(misp, name)
            r2 = misp.tag(event_uuid, name, local=local)
            if isinstance(r2, dict) and "errors" in r2:
                logger.error("tag %s still failed after create: %s", name, r2["errors"])


_STORY_TECHNIQUE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_CTI_EVAL_TAG_RE = re.compile(r'^cti-evaluation:([a-z-]+)="([a-z-]+)"$')


def extract_story_context(event) -> dict:
    """Pull reusable scope, source-rating, and CTI-evaluation tags off a source event.

    Used when a story is added to a daily briefing so the original event's
    classification (geographic/sector/threat-actor/technique scope, Admiralty
    Scale ratings, CTI-evaluation taxonomy tags) survives onto the story
    instead of being lost when the article is folded into the briefing.
    """
    geographic_scope, sectors, threat_actors, techniques = [], [], [], []
    source_reliability, information_credibility = "", ""
    cti_evaluation = {}
    for t in getattr(event, "tags", []) or []:
        name = getattr(t, "name", "") or ""
        if name.startswith('misp-galaxy:country=') or name.startswith('misp-galaxy:target-information='):
            v = name.split('=', 1)[1].strip('"')
            if v and v not in geographic_scope:
                geographic_scope.append(v)
        elif name.startswith('misp-galaxy:sector='):
            v = name.split('=', 1)[1].strip('"')
            if v and v not in sectors:
                sectors.append(v)
        elif name.startswith('misp-galaxy:threat-actor='):
            v = name.split('=', 1)[1].strip('"')
            if v and v not in threat_actors:
                threat_actors.append(v)
        elif name.startswith('misp-galaxy:mitre-attack-pattern='):
            m = _STORY_TECHNIQUE_RE.search(name)
            if m and m.group(0) not in techniques:
                techniques.append(m.group(0))
        elif name.startswith('admiralty-scale:source-reliability='):
            source_reliability = name.split('=', 1)[1].strip('"').upper()
        elif name.startswith('admiralty-scale:information-credibility='):
            information_credibility = name.split('=', 1)[1].strip('"')
        else:
            m = _CTI_EVAL_TAG_RE.match(name)
            if m:
                cti_evaluation[m.group(1)] = m.group(2)
    return {
        "geographic_scope": geographic_scope,
        "sectors": sectors,
        "threat_actors": threat_actors,
        "techniques": techniques,
        "source_reliability": source_reliability,
        "information_credibility": information_credibility,
        "cti_evaluation": cti_evaluation,
    }


def galaxy_countries() -> list:
    return _fetch_galaxy_clusters(GALAXY_COUNTRY)


def galaxy_target_information() -> list:
    return _fetch_galaxy_clusters(GALAXY_TARGET_INFORMATION)


def _dedupe_casing(values):
    """Deduplicate strings case-insensitively, keeping the best-cased form.

    The Country and Target Information galaxies sometimes carry the same
    place under different casing (e.g. "Belgium" and "belgium"). Picking one
    canonical entry avoids showing both as separate, selectable options.
    A capitalised form (e.g. "Belgium") is preferred over an all-lowercase one.
    """
    best = {}
    order = []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        key = v.lower()
        if key not in best:
            best[key] = v
            order.append(key)
        elif best[key].islower() and not v.islower():
            best[key] = v
    return [best[key] for key in order]


def galaxy_geography() -> list:
    """Geographic scope = Country galaxy ∪ Target Information galaxy.

    Some event creators tag geographic targets via the Country galaxy and
    others via the Target Information galaxy. We expose both as a single
    combined list so a PIR scope catches either tagging style.
    """
    return sorted(_dedupe_casing(galaxy_countries() + galaxy_target_information()))


def galaxy_sectors() -> list:
    return _fetch_galaxy_clusters(GALAXY_SECTOR)


def galaxy_threat_actors() -> list:
    return _fetch_galaxy_clusters(GALAXY_THREAT_ACTOR)


# Value -> cluster UUID map for the threat-actor galaxy, cached so enrichment
# does not re-list all clusters on every save.
_ta_uuid_cache: dict = {}
_ta_uuid_ts: float = 0.0


def _threat_actor_uuid(value: str):
    """Return the threat-actor galaxy cluster UUID for a value, or None."""
    global _ta_uuid_ts
    now = time.time()
    if not _ta_uuid_cache or now - _ta_uuid_ts >= _GALAXY_TTL:
        try:
            clusters = _misp().search_galaxy_clusters(GALAXY_THREAT_ACTOR, pythonify=True)
            if isinstance(clusters, list):
                _ta_uuid_cache.clear()
                for c in clusters:
                    if getattr(c, "value", None) and getattr(c, "uuid", None):
                        _ta_uuid_cache[c.value.lower()] = c.uuid
                _ta_uuid_ts = now
        except Exception as exc:
            logger.warning("Failed to list threat-actor clusters: %s", exc)
    return _ta_uuid_cache.get((value or "").lower())


def threat_actor_galaxy_meta(value: str) -> dict:
    """Return enrichment data for a threat-actor galaxy cluster.

    Cluster metadata is stored as GalaxyElement key/value rows (capabilities,
    mode-of-operation, synonyms, refs, victimology). Returns each as a list of
    strings; empty dict for a custom (non-galaxy) actor.
    """
    uuid = _threat_actor_uuid(value)
    if not uuid:
        return {}
    try:
        raw = _misp().get_galaxy_cluster(uuid, pythonify=False)
    except Exception as exc:
        logger.warning("get_galaxy_cluster %s failed: %s", uuid, exc)
        return {}
    gc = raw.get("GalaxyCluster", raw) if isinstance(raw, dict) else {}
    agg: dict = {}
    for el in gc.get("GalaxyElement") or []:
        key = el.get("key")
        if key:
            agg.setdefault(key, []).append(el.get("value"))
    return {
        "capabilities": agg.get("capabilities") or [],
        "mode_of_operation": agg.get("mode-of-operation") or [],
        "synonyms": agg.get("synonyms") or [],
        "refs": agg.get("refs") or [],
        "victimology": agg.get("victimology") or [],
        "suspected_origin": agg.get("country") or agg.get("nationality") or [],
        "motivation": agg.get("motive") or agg.get("cfr-type-of-incident") or [],
        "sponsorship": agg.get("cfr-suspected-state-sponsor") or [],
    }


_MITRE_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "mitre-attack-pattern.json")


def scope_galaxy_items() -> dict:
    """Return galaxy items paired with their MISP tag strings for each scope category.

    Used by the data-collection scope-tagging feature. Each category is a list of
    {"value": str, "tag": str} dicts. Items without a resolvable tag are omitted.
    """
    def _pairs(values, *maps, fallback_prefix=None):
        # Look up case-insensitively: galaxy_geography() may return a value in a
        # different casing than the source galaxy used (see _dedupe_casing).
        ci_maps = [{k.lower(): v for k, v in m.items()} for m in maps]
        out = []
        for v in values:
            tag = None
            for m in ci_maps:
                tag = m.get(v.lower())
                if tag:
                    break
            if not tag and fallback_prefix:
                tag = f'{fallback_prefix}="{v}"'
            if tag:
                out.append({"value": v, "tag": tag})
        return out

    geo_map_c = _galaxy_tag_map(GALAXY_COUNTRY)
    geo_map_t = _galaxy_tag_map(GALAXY_TARGET_INFORMATION)
    sec_map = _galaxy_tag_map(GALAXY_SECTOR)
    ta_map = _galaxy_tag_map(GALAXY_THREAT_ACTOR)
    # No tag-map lookup for MITRE: the local JSON file (used when available) does
    # not populate _galaxy_cache, so _galaxy_tag_map would trigger a live API call
    # only to be superseded by the fallback prefix anyway.  The tag format is fixed.

    return {
        "geo": _pairs(galaxy_geography(), geo_map_c, geo_map_t,
                      fallback_prefix="misp-galaxy:country"),
        "sectors": _pairs(galaxy_sectors(), sec_map,
                          fallback_prefix="misp-galaxy:sector"),
        "threat_actors": _pairs(galaxy_threat_actors(), ta_map,
                                fallback_prefix="misp-galaxy:threat-actor"),
        "mitre": _pairs(galaxy_mitre_attack_patterns(),
                        fallback_prefix="misp-galaxy:mitre-attack-pattern"),
    }


def galaxy_mitre_attack_patterns() -> list:
    """Return MITRE ATT&CK technique names.

    Primary source: data/mitre-attack-pattern.json (populate with scripts/fetch_mitre_galaxy.py).
    Falls back to the MISP galaxy cluster query when the local file is missing or empty.
    """
    try:
        path = os.path.normpath(_MITRE_CACHE_FILE)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                return data
    except Exception as exc:
        logger.warning("Could not load local MITRE cache: %s", exc)
    return _fetch_galaxy_clusters(GALAXY_MITRE_ATTACK)


# Technique id -> technique name, refreshed on the same cycle as the galaxies so
# a re-run of scripts/fetch_mitre_galaxy.py is picked up without a restart.
_mitre_name_cache: dict = {}
_mitre_name_ts: float = 0.0


def mitre_technique_label(value: str) -> str:
    """Return "T1566 - Phishing" for a bare ATT&CK technique id.

    Briefing stories store bare ids (that is all the galaxy tag carries), which
    say little on their own; the galaxy list holds "<name> - <id>" strings, so
    the name can be resolved locally. Anything that is not a bare id is returned
    untouched: galaxy picks already carry the name, and analyst-written detection
    notes must not be rewritten.
    """
    global _mitre_name_ts
    raw = (value or "").strip()
    if not _STORY_TECHNIQUE_RE.fullmatch(raw):
        return raw
    now = time.time()
    if not _mitre_name_cache or now - _mitre_name_ts >= _GALAXY_TTL:
        entries = galaxy_mitre_attack_patterns()
        if entries:
            _mitre_name_cache.clear()
            for entry in entries:
                found = _STORY_TECHNIQUE_RE.search(entry or "")
                if found:
                    _mitre_name_cache[found.group(0)] = entry[:found.start()].strip(" -")
            _mitre_name_ts = now
    name = _mitre_name_cache.get(raw)
    return f"{raw} - {name}" if name else raw


def mitre_technique_labels(values) -> list:
    """Map a list of technique references through mitre_technique_label()."""
    return [mitre_technique_label(v) for v in (values or []) if v]


# ── Connectivity tests ────────────────────────────────────────────────────────

def _test_connection(url, key, verify):
    try:
        m = PyMISP(url, key, verify, False, timeout=HEALTH_CHECK_TIMEOUT)
        resp = m.misp_instance_version
        if isinstance(resp, dict) and "version" in resp:
            return {"ok": True, "version": resp["version"], "url": url}
        return {"ok": False, "url": url, "error": "Unexpected response from server"}
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc)}


def test_scraper_misp():
    return _test_connection(config.MISP_URL, config.MISP_KEY, config.MISP_VERIFYCERT)


def test_webapp_misp():
    return _test_connection(
        config.MISP_WEBAPP_URL, config.MISP_WEBAPP_KEY, config.MISP_WEBAPP_VERIFYCERT
    )


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _make_event(info, extra_tags=None):
    e = MISPEvent()
    e.info = info
    # Default to "Your organisation only" (0); an admin can widen this from the
    # System config tab. Guard against a hand-edited config holding a bad value.
    dist = int(getattr(config, "MISP_EVENT_DISTRIBUTION", 0) or 0)
    e.distribution = dist if dist in (0, 1, 2, 3) else 0
    e.threat_level_id = 4
    e.analysis = 2
    for t in extra_tags or []:
        # extra_tags are TLP, admiralty-scale, and similar federation metadata -
        # intentionally not local so they sync to connected MISP instances.
        # zsazsa-namespace tags must never be embedded here (they would attach
        # globally); pass them as local_tags to _add_event instead.
        if str(t).startswith("zsazsa:"):
            logger.warning("zsazsa tag %s passed to _make_event; skipping (apply via _add_event)", t)
            continue
        e.add_tag(t)
    return e


def _tag_local(misp, event_uuid, tag_name):
    """Attach a tag to an event as a local tag, creating it first if needed.

    MISP attaches tags embedded in add_event globally even when the local flag
    is set on the MISPTag, so every zsazsa-namespace tag is applied here via the
    tag endpoint, which honours local correctly.
    """
    if not (event_uuid and tag_name):
        return
    r = misp.tag(event_uuid, tag_name, local=True)
    if isinstance(r, dict) and "errors" in r:
        _ensure_tag(misp, tag_name)
        misp.tag(event_uuid, tag_name, local=True)


def _add_event(misp, event, local_tags=None, label="create event"):
    """Create an event, then attach its zsazsa-namespace tags as local tags."""
    result = _check(misp.add_event(event, pythonify=True), label)
    uuid = _event_uuid(result)
    for name in local_tags or []:
        _tag_local(misp, uuid, name)
    return result


def _tag_scraper_event_as_product_source(src_uuid: str, product_label: str,
                                          misp_client=None) -> None:
    """Tag a source event as having been used to create a product.

    Advances workflow state from 'incomplete' to 'ongoing' and adds a
    zsazsa:product tag. Events already in 'complete' (or any state other than
    'incomplete') are left at their current workflow state so a finished event
    is not regressed when reused as a source.

    misp_client defaults to the scraper MISP. Pass a different client when the
    event lives on another MISP instance (configured server or manual source).
    """
    if not src_uuid:
        return
    try:
        client = misp_client or _scraper_misp()
        event = client.get_event(src_uuid, pythonify=True)
        if not event or isinstance(event, dict):
            return
        current_wf = next(
            (tag.name for tag in (getattr(event, "tags", []) or [])
             if tag.name.startswith('workflow:state=')),
            None,
        )
        if current_wf != 'workflow:state="complete"':
            if current_wf:
                try:
                    client.untag(src_uuid, current_wf)
                except Exception:
                    pass
            client.tag(src_uuid, 'workflow:state="ongoing"', local=True)
        client.tag(src_uuid, f'zsazsa:product="{product_label}"', local=True)
        try:
            from webapp import collection_cache
            add_tags = [f'zsazsa:product="{product_label}"']
            remove_tags = []
            if current_wf != 'workflow:state="complete"':
                if current_wf:
                    remove_tags.append(current_wf)
                add_tags.append('workflow:state="ongoing"')
            collection_cache.patch_event_tags(src_uuid, add_tags, remove_tags)
        except Exception as exc:
            logger.debug("Could not patch cache for %s: %s", src_uuid, exc)
    except Exception as exc:
        logger.warning("Could not tag source event %s: %s", src_uuid, exc)


def _build_obj(name):
    """Create a MISPObject, loading the local template if found.

    strict=False allows creation even when the template path is unreachable,
    which would otherwise raise UnknownMISPObjectError.
    """
    return MISPObject(name, misp_objects_path_custom=_OBJECTS_PATH, strict=False)


def _oa(obj, relation, value):
    """Add a text attribute to a MISPObject, skipping empty/None values.

    Always passes type='text' explicitly so attribute creation succeeds even
    when the template file cannot be read.
    """
    if value in (None, "", [], "[]"):
        return
    obj.add_attribute(relation, value=str(value), type="text", disable_correlation=True)


def _oa_json(obj, relation, lst):
    """Add a list field as a JSON-encoded text attribute."""
    if isinstance(lst, str):
        lst = [lst] if lst else []
    if lst:
        obj.add_attribute(relation, value=json.dumps(lst), type="text", disable_correlation=True)


def _obj_attr(obj, relation):
    if obj is None:
        return None
    attrs = obj.get_attributes_by_relation(relation)
    return attrs[0].value if attrs else None


def _obj_int(obj, relation, default):
    try:
        return int(_obj_attr(obj, relation))
    except (TypeError, ValueError):
        return default


def _get_obj(event, name):
    for o in event.objects:
        if o.name == name:
            return o
    return None


def _sync_object_attributes(misp, event, object_name, new_obj, label="object"):
    """Update an existing single-instance object in place, preserving history.

    The naive approach (delete the object, add a fresh one) wipes the MISP
    attribute history and clutters the event timeline. Instead this diffs the
    existing object against the freshly built ``new_obj`` and lets MISP do the
    minimal work: changed attributes are edited in place, new ones are added,
    and removed ones are soft-deleted. MISP itself skips attributes whose value
    did not change, so the event history only records real edits.

    Every zsazsa object stores at most one attribute per object_relation, so the
    diff is keyed on object_relation. Falls back to a plain add when the object
    does not exist yet.
    """
    old = _get_obj(event, object_name)
    if old is None:
        _check(misp.add_object(_event_ref(event), new_obj), f"add {label} object")
        return

    existing = {}
    for a in getattr(old, "attributes", []) or []:
        if getattr(a, "deleted", False):
            continue  # a soft-deleted attribute is already absent; ignore it
        existing.setdefault(a.object_relation, a)

    # Carry the existing object and attribute UUIDs onto the new object so MISP
    # edits matching attributes in place instead of creating duplicates.
    new_obj.uuid = old.uuid
    desired_relations = set()
    for a in getattr(new_obj, "attributes", []) or []:
        desired_relations.add(a.object_relation)
        old_attr = existing.get(a.object_relation)
        if old_attr is not None:
            a.uuid = old_attr.uuid
    _check(misp.update_object(new_obj), f"update {label} object")

    # Soft-delete attributes whose relation is no longer present. If MISP already
    # considers the attribute gone (404 / "Invalid attribute"), that is the
    # desired end state, so treat it as success rather than failing the edit.
    for relation, old_attr in existing.items():
        if relation not in desired_relations:
            result = misp.delete_attribute(old_attr.uuid)
            if _is_not_found(result):
                continue
            _check(result, f"delete {label} {relation}")


def _get_fp_attrs(event):
    return [a for a in event.attributes if a.comment == _FP_COMMENT]


def _parse_date(s):
    try:
        return date.fromisoformat(s) if s else None
    except ValueError:
        return None


def _parse_dt(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d") if s else None
    except ValueError:
        return None


def _published_at(event):
    """When the MISP event was last published, or None if it never was.

    Normalised to a naive UTC datetime (PyMISP returns it timezone-aware) so the
    values sort consistently against each other and against a plain fallback.
    """
    ts = getattr(event, "publish_timestamp", None)
    if isinstance(ts, datetime):
        dt = ts
    else:
        try:
            epoch = int(ts)
        except (TypeError, ValueError):
            return None
        if epoch <= 0:
            return None
        dt = datetime.utcfromtimestamp(epoch)
    if dt.year <= 1971:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def _check(result, label="MISP"):
    if isinstance(result, dict) and "errors" in result:
        raise RuntimeError(f"{label}: {result['errors']}")
    return result


def _is_not_found(result) -> bool:
    """True when a MISP call failed only because the target no longer exists.

    PyMISP returns the HTTP error as a ``(status_code, body)`` tuple under the
    ``errors`` key, so a 404 here means the attribute or object is already gone.
    """
    if not isinstance(result, dict) or "errors" not in result:
        return False
    err = result["errors"]
    return isinstance(err, (list, tuple)) and bool(err) and err[0] == 404


def _json_list(raw):
    if not raw:
        return []
    try:
        return json.loads(raw)
    except Exception:
        return []


def _json_list_or_str(raw):
    """Like _json_list but treats a bare string as a single-item list (migration aid)."""
    if not raw:
        return []
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else ([str(result)] if result else [])
    except Exception:
        return [raw] if raw.strip() else []


def _json_dict(raw):
    if not raw:
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


SUBSCRIPTION_MODES = ["automated", "after-approval"]
DEFAULT_SUBSCRIPTION_MODE = "after-approval"


def _event_ref(event):
    if isinstance(event, dict):
        ev = event.get("Event", event)
        return ev.get("id") or ev.get("uuid")
    return getattr(event, "id", None) or getattr(event, "uuid", None)


def _event_uuid(event):
    if isinstance(event, dict):
        ev = event.get("Event", event)
        return ev.get("uuid")
    return getattr(event, "uuid", None)


def _event_has_tag(event, tag_name: str) -> bool:
    return tag_name in {
        tag.name for tag in (getattr(event, "tags", []) or []) if getattr(tag, "name", "")
    }


def _stakeholder_event(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return None
    if not _event_has_tag(event, config.TAG_STAKEHOLDER):
        logger.warning("Event %s is not tagged as a stakeholder", uuid)
        return None
    if _get_obj(event, "zsazsa-stakeholder") is None:
        logger.warning("Event %s is missing stakeholder object", uuid)
        return None
    return event


def _replace_focus_points(req_uuid, focus_points):
    if not req_uuid:
        return
    misp = _misp()
    event = misp.get_event(req_uuid, pythonify=True)
    if isinstance(event, dict):
        return
    for old in _get_fp_attrs(event):
        result = misp.delete_attribute(old.id)
        if not _is_not_found(result):
            _check(result, "delete focus point")
    for fp in focus_points or []:
        category = (fp.get("category") or "").strip()
        value = (fp.get("value") or "").strip()
        notes = (fp.get("notes") or "").strip()
        if category and value:
            add_focus_point(req_uuid, category, value, notes)


# ── Namespace builders ────────────────────────────────────────────────────────

def _fp_ns(attr):
    parts = attr.value.split("|", 2)
    return SimpleNamespace(
        id=attr.uuid,
        uuid=attr.uuid,
        category=parts[0] if len(parts) > 0 else "",
        value=parts[1] if len(parts) > 1 else attr.value,
        notes=parts[2] if len(parts) > 2 else "",
    )


def _stakeholder_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-stakeholder")
    event_date = event.date
    created_at = _parse_dt(event_date.isoformat() if event_date else None)
    contacts = _json_list(_obj_attr(obj, "contacts"))
    if not contacts:
        # migrate old single-value fields into the new structure
        old_email = _obj_attr(obj, "email") or ""
        old_contact = _obj_attr(obj, "contact") or ""
        if old_email:
            contacts.append({"type": "Email", "value": old_email, "preferred": True})
        if old_contact:
            contacts.append({"type": "Other", "value": old_contact, "preferred": False})
    # derive convenience email for backward-compat display (e.g. distribution picker)
    preferred = next((c for c in contacts if c.get("preferred")), None)
    email_contact = next((c for c in contacts if c.get("type") == "Email"), None)
    display_email = (preferred or email_contact or {}).get("value", "")
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        name=_obj_attr(obj, "name") or "",
        role=_obj_attr(obj, "role") or "",
        organization=_obj_attr(obj, "organization") or "",
        stakeholder_type=_obj_attr(obj, "stakeholder-type") or "External",
        contacts=contacts,
        email=display_email,
        tlp_clearance=_obj_attr(obj, "tlp-clearance") or "amber",
        products=_json_list(_obj_attr(obj, "products")),
        product_modes=_json_dict(_obj_attr(obj, "product-modes")),
        notification_channels=_json_list(_obj_attr(obj, "notification-channels")),
        notes=_obj_attr(obj, "notes") or "",
        influence=_obj_int(obj, "influence", 5),
        interest=_obj_int(obj, "interest", 5),
        engagement_strategy=_obj_attr(obj, "engagement-strategy") or "",
        created_at=created_at,
    )


def _pir_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-pir")

    owner_uuid = _obj_attr(obj, "owner-uuid") or ""
    owner_name = _obj_attr(obj, "owner-name") or ""
    owner_role = _obj_attr(obj, "owner-role") or ""

    owner_stakeholder = None
    if owner_uuid:
        owner_stakeholder = SimpleNamespace(
            id=owner_uuid, uuid=owner_uuid, name=owner_name, role=owner_role,
        )

    fps = [_fp_ns(a) for a in _get_fp_attrs(event)]
    event_date = event.date
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        pir_id=_obj_attr(obj, "pir-id") or "",
        question=_obj_attr(obj, "question") or "",
        context=_obj_attr(obj, "context") or "",
        intel_level=_json_list_or_str(_obj_attr(obj, "intel-level")),
        owner_id=owner_uuid,
        owner_uuid=owner_uuid,
        owner_name=owner_name,
        owner_stakeholder=owner_stakeholder,
        owner_display=owner_name,
        priority=_obj_attr(obj, "priority") or "Should have",
        status=_obj_attr(obj, "status") or "Pending",
        time_sensitivity=_obj_attr(obj, "time-sensitivity") or "",
        geographic_scope=_json_list(_obj_attr(obj, "geographic-scope")),
        time_frame=_obj_attr(obj, "time-frame") or "",
        threat_types=_json_list(_obj_attr(obj, "threat-types")),
        threat_actors=_json_list(_obj_attr(obj, "threat-actors")),
        sectors=_json_list(_obj_attr(obj, "sectors")),
        out_of_scope=_json_list(_obj_attr(obj, "out-of-scope")),
        technology=_json_list(_obj_attr(obj, "technology")),
        vendor=_json_list(_obj_attr(obj, "vendor")),
        incident=_json_list(_obj_attr(obj, "incident")),
        campaign=_json_list(_obj_attr(obj, "campaign")),
        collection_sources=_json_list(_obj_attr(obj, "collection-sources")),
        output_format=_json_list(_obj_attr(obj, "output-format")),
        distribution=_json_list(_obj_attr(obj, "distribution")),
        resolution_note=_obj_attr(obj, "resolution-note") or "",
        decision_supported=_obj_attr(obj, "decision-supported") or "",
        decision_maker=_json_list_or_str(_obj_attr(obj, "decision-maker")),
        consequence=_json_list_or_str(_obj_attr(obj, "consequence")),
        deadline=_obj_attr(obj, "deadline") or "",
        priority_justification=_obj_attr(obj, "priority-justification") or "",
        sub_questions=_json_list(_obj_attr(obj, "sub-questions")),
        next_review=_parse_date(_obj_attr(obj, "next-review")),
        intake_status=_obj_attr(obj, "intake-status") or "submitted",
        acknowledged_at=_obj_attr(obj, "acknowledged-at") or "",
        acknowledged_by=_obj_attr(obj, "acknowledged-by") or "",
        triaged_at=_obj_attr(obj, "triaged-at") or "",
        triaged_by=_obj_attr(obj, "triaged-by") or "",
        decision_at=_obj_attr(obj, "decision-at") or "",
        decision_by=_obj_attr(obj, "decision-by") or "",
        rejection_reason=_obj_attr(obj, "rejection-reason") or "",
        deferral_reason=_obj_attr(obj, "deferral-reason") or "",
        linked_pir_uuid=_obj_attr(obj, "linked-pir-uuid") or "",
        mitre_attack_techniques=_json_list(_obj_attr(obj, "mitre-attack-techniques")),
        triage_checklist=_json_list(_obj_attr(obj, "triage-checklist")),
        creator=_obj_attr(obj, "creator") or "",
        created_at=_parse_dt(event_date.isoformat() if event_date else None),
        focus_points=fps,
    )


def _gir_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-gir")

    owner_uuid = _obj_attr(obj, "owner-uuid") or ""
    owner_name = _obj_attr(obj, "owner-name") or ""
    owner_role = _obj_attr(obj, "owner-role") or ""

    owner_stakeholder = None
    if owner_uuid:
        owner_stakeholder = SimpleNamespace(
            id=owner_uuid, uuid=owner_uuid, name=owner_name, role=owner_role,
        )

    fps = [_fp_ns(a) for a in _get_fp_attrs(event)]
    event_date = event.date
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        gir_id=_obj_attr(obj, "gir-id") or "",
        topic=_obj_attr(obj, "topic") or "",
        description=_obj_attr(obj, "description") or "",
        owner_id=owner_uuid,
        owner_uuid=owner_uuid,
        owner_name=owner_name,
        owner_stakeholder=owner_stakeholder,
        owner_display=owner_name,
        status=_obj_attr(obj, "status") or "Active",
        review_cycle=_obj_attr(obj, "review-cycle") or "Quarterly",
        collection_sources=_json_list(_obj_attr(obj, "collection-sources")),
        geographic_scope=_json_list(_obj_attr(obj, "geographic-scope")),
        sectors=_json_list(_obj_attr(obj, "sectors")),
        threat_types=_json_list(_obj_attr(obj, "threat-types")),
        threat_actors=_json_list(_obj_attr(obj, "threat-actors")),
        out_of_scope=_json_list(_obj_attr(obj, "out-of-scope")),
        technology=_json_list(_obj_attr(obj, "technology")),
        vendor=_json_list(_obj_attr(obj, "vendor")),
        incident=_json_list(_obj_attr(obj, "incident")),
        campaign=_json_list(_obj_attr(obj, "campaign")),
        output_format=_json_list(_obj_attr(obj, "output-format")),
        distribution=_json_list(_obj_attr(obj, "distribution")),
        deadline=_obj_attr(obj, "deadline") or "",
        priority_justification=_obj_attr(obj, "priority-justification") or "",
        sub_questions=_json_list(_obj_attr(obj, "sub-questions")),
        next_review=_parse_date(_obj_attr(obj, "next-review")),
        intel_level=_json_list_or_str(_obj_attr(obj, "intel-level")),
        mitre_attack_techniques=_json_list(_obj_attr(obj, "mitre-attack-techniques")),
        creator=_obj_attr(obj, "creator") or "",
        created_at=_parse_dt(event_date.isoformat() if event_date else None),
        focus_points=fps,
    )


# ── Object builders ───────────────────────────────────────────────────────────

def _stakeholder_obj(data):
    obj = _build_obj("zsazsa-stakeholder")
    _oa(obj, "name", data.get("name"))
    _oa(obj, "role", data.get("role"))
    _oa(obj, "organization", data.get("organization"))
    _oa(obj, "stakeholder-type", data.get("stakeholder_type", "External"))
    _oa_json(obj, "contacts", data.get("contacts", []))
    _oa(obj, "tlp-clearance", data.get("tlp_clearance", "amber"))
    _oa_json(obj, "products", data.get("products", []))
    _oa_json(obj, "product-modes", data.get("product_modes", {}))
    _oa_json(obj, "notification-channels", data.get("notification_channels", []))
    _oa(obj, "notes", data.get("notes"))
    _oa(obj, "influence", data.get("influence", 5))
    _oa(obj, "interest", data.get("interest", 5))
    _oa(obj, "engagement-strategy", data.get("engagement_strategy"))
    return obj


def _pir_obj(data):
    obj = _build_obj("zsazsa-pir")
    _oa(obj, "pir-id", data.get("pir_id"))
    _oa(obj, "question", data.get("question"))
    _oa(obj, "context", data.get("context"))
    _oa_json(obj, "intel-level", data.get("intel_level", []))
    _oa(obj, "owner-uuid", data.get("owner_uuid"))
    _oa(obj, "owner-name", data.get("owner_name"))
    _oa(obj, "owner-role", data.get("owner_role"))
    _oa(obj, "priority", data.get("priority", "Should have"))
    _oa(obj, "status", data.get("status", "Pending"))
    _oa(obj, "time-sensitivity", data.get("time_sensitivity"))
    _oa_json(obj, "geographic-scope", data.get("geographic_scope", []))
    _oa(obj, "time-frame", data.get("time_frame"))
    _oa_json(obj, "threat-types", data.get("threat_types", []))
    _oa_json(obj, "threat-actors", data.get("threat_actors", []))
    _oa_json(obj, "sectors", data.get("sectors", []))
    _oa_json(obj, "out-of-scope", data.get("out_of_scope", []))
    _oa_json(obj, "technology", data.get("technology", []))
    _oa_json(obj, "vendor", data.get("vendor", []))
    _oa_json(obj, "incident", data.get("incident", []))
    _oa_json(obj, "campaign", data.get("campaign", []))
    _oa_json(obj, "collection-sources", data.get("collection_sources", []))
    _oa_json(obj, "output-format", data.get("output_format", []))
    _oa_json(obj, "distribution", data.get("distribution", []))
    _oa(obj, "resolution-note", data.get("resolution_note"))
    _oa(obj, "decision-supported", data.get("decision_supported"))
    _oa_json(obj, "decision-maker", data.get("decision_maker", []))
    _oa_json(obj, "consequence", data.get("consequence", []))
    _oa(obj, "deadline", data.get("deadline"))
    _oa(obj, "priority-justification", data.get("priority_justification"))
    _oa_json(obj, "sub-questions", data.get("sub_questions", []))
    _oa(obj, "next-review", data.get("next_review"))
    _oa(obj, "intake-status", data.get("intake_status", "submitted"))
    _oa(obj, "acknowledged-at", data.get("acknowledged_at"))
    _oa(obj, "acknowledged-by", data.get("acknowledged_by"))
    _oa(obj, "triaged-at", data.get("triaged_at"))
    _oa(obj, "triaged-by", data.get("triaged_by"))
    _oa(obj, "decision-at", data.get("decision_at"))
    _oa(obj, "decision-by", data.get("decision_by"))
    _oa(obj, "rejection-reason", data.get("rejection_reason"))
    _oa(obj, "deferral-reason", data.get("deferral_reason"))
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    _oa_json(obj, "mitre-attack-techniques", data.get("mitre_attack_techniques", []))
    _oa_json(obj, "triage-checklist", data.get("triage_checklist", []))
    _oa(obj, "creator", data.get("creator"))
    return obj


def _gir_obj(data):
    obj = _build_obj("zsazsa-gir")
    _oa(obj, "gir-id", data.get("gir_id"))
    _oa(obj, "topic", data.get("topic"))
    _oa(obj, "description", data.get("description"))
    _oa(obj, "owner-uuid", data.get("owner_uuid"))
    _oa(obj, "owner-name", data.get("owner_name"))
    _oa(obj, "owner-role", data.get("owner_role"))
    _oa(obj, "status", data.get("status", "Active"))
    _oa(obj, "review-cycle", data.get("review_cycle", "Quarterly"))
    _oa_json(obj, "collection-sources", data.get("collection_sources", []))
    _oa_json(obj, "geographic-scope", data.get("geographic_scope", []))
    _oa_json(obj, "sectors", data.get("sectors", []))
    _oa_json(obj, "threat-types", data.get("threat_types", []))
    _oa_json(obj, "threat-actors", data.get("threat_actors", []))
    _oa_json(obj, "out-of-scope", data.get("out_of_scope", []))
    _oa_json(obj, "technology", data.get("technology", []))
    _oa_json(obj, "vendor", data.get("vendor", []))
    _oa_json(obj, "incident", data.get("incident", []))
    _oa_json(obj, "campaign", data.get("campaign", []))
    _oa_json(obj, "output-format", data.get("output_format", []))
    _oa_json(obj, "distribution", data.get("distribution", []))
    _oa(obj, "deadline", data.get("deadline"))
    _oa(obj, "priority-justification", data.get("priority_justification"))
    _oa_json(obj, "sub-questions", data.get("sub_questions", []))
    _oa(obj, "next-review", data.get("next_review"))
    _oa_json(obj, "intel-level", data.get("intel_level", []))
    _oa_json(obj, "mitre-attack-techniques", data.get("mitre_attack_techniques", []))
    _oa(obj, "creator", data.get("creator"))
    return obj


# ── Sequential ID generation ──────────────────────────────────────────────────

_id_lock = threading.Lock()


def _scan_max_sequence(misp, tag, prefix):
    """Return the highest existing {prefix}-NNN sequence number, scanning event titles.

    Known limitation: the sequence is derived from event info titles. If a title
    is manually edited or the prefix format changes, the scan may produce a
    duplicate or restart from 0. Deleting the most recent record also frees its
    number for the next create, so an id already sent to a stakeholder can come
    back attached to something else.
    """
    events = misp.search(tags=[tag], metadata=True, pythonify=True)
    if not events or isinstance(events, dict):
        return 0
    max_n = 0
    for e in events:
        for token in (e.info or "").split():
            clean = token.rstrip(":")
            if clean.startswith(prefix + "-"):
                try:
                    max_n = max(max_n, int(clean[len(prefix) + 1:]))
                except ValueError:
                    pass
    return max_n


def _next_id(tag, prefix):
    """Return the next {prefix}-NNN id as a non-authoritative suggestion.

    Callers that pass the result back in as an explicit id (e.g. the demo seed
    script) get exactly this value; callers that leave the id blank get one
    allocated atomically at create time under _id_lock. Either way the persisted
    id is unique, so this suggestion can safely go stale.
    """
    with _id_lock:
        return f"{prefix}-{_scan_max_sequence(_misp(), tag, prefix) + 1:03d}"


def _sequence_id(misp, tag, prefix, existing):
    """Return `existing` if it is set, else the next {prefix}-NNN id.

    Must be called while still holding _id_lock for the event write that follows,
    so two near-simultaneous creates cannot allocate the same id. An `existing`
    id (e.g. recreating a deleted event) is reused as-is. This guards a single
    process only; a multi-process deployment would need a counter in MISP.
    """
    existing = (existing or "").strip()
    return existing or f"{prefix}-{_scan_max_sequence(misp, tag, prefix) + 1:03d}"


def next_pir_id():
    return _next_id(config.TAG_PIR, "PIR")


def next_gir_id():
    return _next_id(config.TAG_GIR, "GIR")


# ── Stakeholder CRUD ──────────────────────────────────────────────────────────

def list_stakeholders():
    misp = _misp()
    events = misp.search(tags=[config.TAG_STAKEHOLDER], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_stakeholder_ns(e) for e in events]
    result.sort(key=lambda s: s.name.lower())
    return result


def get_stakeholder(uuid):
    event = _stakeholder_event(uuid)
    if event is None:
        return None
    return _stakeholder_ns(event)


def create_stakeholder(data):
    misp = _misp()
    event = _make_event(f"[zsazsa:stakeholder] {data['name']}")
    result = _add_event(misp, event, [config.TAG_STAKEHOLDER], "create stakeholder")
    _check(misp.add_object(_event_ref(result), _stakeholder_obj(data)), "add stakeholder object")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create stakeholder: missing UUID in MISP response")
    return uuid


def update_stakeholder(uuid, data):
    """Update stakeholder fields. If the MISP event was deleted, recreates it.

    Returns the UUID to use for subsequent redirects (may differ if recreated).
    """
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("Stakeholder event %s not found; recreating", uuid)
        return create_stakeholder(data)
    if not _event_has_tag(event, config.TAG_STAKEHOLDER) or _get_obj(event, "zsazsa-stakeholder") is None:
        raise ValueError(f"Event {uuid} is not a stakeholder")
    _sync_object_attributes(misp, event, "zsazsa-stakeholder", _stakeholder_obj(data), "stakeholder")
    misp.update_event({"Event": {"id": event.id, "info": f"[zsazsa:stakeholder] {data['name']}"}})
    return uuid


def delete_stakeholder(uuid):
    misp = _misp()
    if _stakeholder_event(uuid) is None:
        raise ValueError(f"Stakeholder {uuid} not found")
    _check(misp.delete_event(uuid), "delete stakeholder")


def rename_subscription_product(old_name: str, new_name: str, apply: bool = False) -> list[str]:
    """Rename a product across every stakeholder's subscriptions.

    Rewrites the product in both the ``products`` list and the ``product-modes``
    keys stored on the stakeholder object. Returns the names of affected
    stakeholders. Only writes to MISP when ``apply`` is True (dry-run otherwise).
    """
    misp = _misp()
    events = misp.search(tags=[config.TAG_STAKEHOLDER], limit=1000, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    affected = []
    for event in events:
        obj = _get_obj(event, "zsazsa-stakeholder")
        if obj is None:
            continue
        touched = False
        for attr in (getattr(obj, "attributes", []) or []):
            relation = getattr(attr, "object_relation", "")
            attr_changed = False
            if relation == "products":
                products = _json_list(attr.value)
                if old_name in products:
                    attr.value = json.dumps([new_name if p == old_name else p for p in products])
                    attr_changed = True
            elif relation == "product-modes":
                modes = _json_dict(attr.value)
                if old_name in modes:
                    modes[new_name] = modes.pop(old_name)
                    attr.value = json.dumps(modes)
                    attr_changed = True
            if attr_changed:
                touched = True
                if apply:
                    misp.update_attribute(attr)
        if touched:
            affected.append(_obj_attr(obj, "name") or _event_uuid(event) or "?")
    return affected


# ── PIR CRUD ──────────────────────────────────────────────────────────────────

def list_selectable_pirs(linked_uuid=""):
    """The PIRs a product may be linked to, newest intake state respected.

    A PIR that is still in intake has not been agreed yet, so a product must not
    claim to answer it. The one exception is the PIR a product is already linked
    to: it stays in the list whatever its status has become, or reopening an
    older product and saving it would quietly drop the link.
    """
    return [p for p in list_pirs()
            if p.status == "Active" or (linked_uuid and p.uuid == linked_uuid)]


def list_pirs():
    misp = _misp()
    events = misp.search(tags=[config.TAG_PIR], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_pir_ns(e) for e in events]
    result.sort(key=lambda p: p.pir_id)
    return result


def get_pir(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        return None
    return _pir_ns(event)


def create_pir(data):
    # Mutate the caller's dict in place (don't rebind) so the pir_id allocated
    # below is visible to the caller for the confirmation message.
    data.setdefault("intake_status", "submitted")
    data["creator"] = misp_session.current_user_email()
    misp = _misp()
    with _id_lock:
        data["pir_id"] = _sequence_id(misp, config.TAG_PIR, "PIR", data.get("pir_id"))
        event = _make_event(f"[zsazsa:pir] {data['pir_id']}")
        for t in _build_scope_tags(data):
            event.add_tag(t)
        result = _add_event(misp, event, [config.TAG_PIR], "create PIR")
    _check(misp.add_object(_event_ref(result), _pir_obj(data)), "add PIR object")
    req_uuid = _event_uuid(result)
    if not req_uuid:
        raise RuntimeError("create PIR: missing UUID in MISP response")
    _replace_focus_points(req_uuid, data.get("focus_points", []))
    return req_uuid


def update_pir(uuid, data):
    """Update PIR fields. If the MISP event was deleted, recreates it.

    Returns the UUID to redirect to (may be a new UUID if the event was gone).
    """
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("PIR event %s not found; recreating with pir_id %s", uuid, data.get("pir_id"))
        return create_pir(data)
    old = _get_obj(event, "zsazsa-pir")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
    _sync_object_attributes(misp, event, "zsazsa-pir", _pir_obj(data), "PIR")
    # Only when the caller sent them: saving the form replaces the scope items,
    # but a status change or a Kanban move posts none and must not wipe them.
    if "focus_points" in data:
        _replace_focus_points(uuid, data["focus_points"])
    _apply_scope_tags(misp, uuid, data, new_info=f"[zsazsa:pir] {data['pir_id']}")
    return uuid


def delete_pir(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete PIR")


def update_pir_intake(uuid, intake_status, reason=None, linked_pir_uuid=None, checklist=None):
    """Update intake workflow fields without touching content fields.

    Focus points are preserved explicitly because _pir_data_from_ns does not carry them.
    """
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"PIR event {uuid} not found")
    pir = _pir_ns(event)
    data = _pir_data_from_ns(pir)
    today = date.today().isoformat()
    user = misp_session.current_user_email()
    data["intake_status"] = intake_status
    if intake_status == "acknowledged":
        data["acknowledged_at"] = today
        data["acknowledged_by"] = user
    elif intake_status == "triaged":
        data["triaged_at"] = today
        data["triaged_by"] = user
    elif intake_status in ("approved", "rejected", "deferred", "merged"):
        data["decision_at"] = today
        data["decision_by"] = user
        if intake_status == "approved":
            data["status"] = "Active"
        elif intake_status == "merged":
            data["status"] = "Retired"
    if reason:
        if intake_status == "rejected":
            data["rejection_reason"] = reason
        elif intake_status == "deferred":
            data["deferral_reason"] = reason
    if linked_pir_uuid:
        data["linked_pir_uuid"] = linked_pir_uuid
    if checklist is not None:
        data["triage_checklist"] = checklist
    return update_pir(uuid, data)


# ── GIR CRUD ──────────────────────────────────────────────────────────────────

def list_girs():
    misp = _misp()
    events = misp.search(tags=[config.TAG_GIR], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_gir_ns(e) for e in events]
    result.sort(key=lambda g: g.gir_id)
    return result


def get_gir(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        return None
    return _gir_ns(event)


def create_gir(data):
    data["creator"] = misp_session.current_user_email()
    misp = _misp()
    with _id_lock:
        data["gir_id"] = _sequence_id(misp, config.TAG_GIR, "GIR", data.get("gir_id"))
        event = _make_event(f"[zsazsa:gir] {data['gir_id']}: {data.get('topic', '')}")
        for t in _build_scope_tags(data):
            event.add_tag(t)
        result = _add_event(misp, event, [config.TAG_GIR], "create GIR")
    _check(misp.add_object(_event_ref(result), _gir_obj(data)), "add GIR object")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create GIR: missing UUID in MISP response")
    _replace_focus_points(uuid, data.get("focus_points", []))
    return uuid


def update_gir(uuid, data):
    """Update GIR fields. If the MISP event was deleted, recreates it.

    Returns the UUID to redirect to (may be a new UUID if the event was gone).

    Scope items are replaced only when the caller sends them, as for a PIR: the
    edit form posts every scope list, a status change posts none and leaves them
    alone.
    """
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("GIR event %s not found; recreating with gir_id %s", uuid, data.get("gir_id"))
        return create_gir(data)
    old = _get_obj(event, "zsazsa-gir")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
    _sync_object_attributes(misp, event, "zsazsa-gir", _gir_obj(data), "GIR")
    if "focus_points" in data:
        _replace_focus_points(uuid, data["focus_points"])
    topic = data.get("topic", "")
    gir_id = data.get("gir_id", "")
    _apply_scope_tags(misp, uuid, data, new_info=f"[zsazsa:gir] {gir_id}: {topic}")
    return uuid


def delete_gir(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete GIR")


# ── Focus points ──────────────────────────────────────────────────────────────

def sync_scope_tags_from_store(event_uuid: str):
    """Re-apply scope galaxy tags from the current PIR/GIR object state.

    Called after inline scope edits (focus point add/delete/sync) so galaxy
    tags stay in sync when the user doesn't go through the full edit form.
    """
    misp = _misp()
    event = misp.get_event(event_uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        logger.warning("sync_scope_tags_from_store: could not fetch event %s", event_uuid)
        return
    pir_obj = _get_obj(event, "zsazsa-pir")
    gir_obj = _get_obj(event, "zsazsa-gir")
    obj = pir_obj or gir_obj
    if obj is None:
        return
    data = {
        "geographic_scope": _json_list(_obj_attr(obj, "geographic-scope")),
        "sectors": _json_list(_obj_attr(obj, "sectors")),
        "threat_actors": _json_list(_obj_attr(obj, "threat-actors")),
    }
    _apply_scope_tags(misp, event_uuid, data, _event=event)


def add_focus_point(req_uuid, category, value, notes=""):
    misp = _misp()
    fp_value = f"{category}|{value}|{notes}" if notes else f"{category}|{value}"
    attr = {
        "type": "text",
        "category": "Other",
        "value": fp_value,
        "comment": _FP_COMMENT,
        "to_ids": False,
    }
    result = _check(misp.add_attribute(req_uuid, attr, pythonify=True), "add focus point")
    return result.uuid


def delete_focus_point(attr_uuid):
    misp = _misp()
    result = misp.delete_attribute(attr_uuid)
    if not _is_not_found(result):
        _check(result, "delete focus point")


# Map a focus point category back to the PIR/GIR object scope relation. Every
# category the detail page offers is here, so a scope item is the same thing
# wherever it was typed: it shows on the requirement, it is matched against
# events, and it reaches the notification.
_FP_CATEGORY_TO_RELATION = {
    "Geography": "geographic-scope",
    "Sector": "sectors",
    "Threat Actor": "threat-actors",
    "Threat Type": "threat-types",
    "Technology": "technology",
    "Vendor": "vendor",
    "Incident": "incident",
    "Campaign": "campaign",
}
_RELATION_TO_FP_CATEGORY = {v: k for k, v in _FP_CATEGORY_TO_RELATION.items()}

# Categories backed by a MISP galaxy.
GALAXY_FP_CATEGORIES = {"Geography", "Sector", "Threat Actor"}


def _pir_data_from_ns(ns):
    return {
        "pir_id": ns.pir_id, "question": ns.question, "context": ns.context,
        "intel_level": ns.intel_level, "owner_uuid": ns.owner_uuid,
        "owner_name": ns.owner_name, "owner_role": getattr(ns, "owner_role", "") or "",
        "priority": ns.priority, "status": ns.status,
        "time_sensitivity": ns.time_sensitivity,
        "geographic_scope": list(ns.geographic_scope),
        "time_frame": ns.time_frame,
        "threat_types": list(ns.threat_types),
        "threat_actors": list(ns.threat_actors),
        "sectors": list(ns.sectors),
        "out_of_scope": list(ns.out_of_scope),
        "technology": list(getattr(ns, "technology", []) or []),
        "vendor": list(getattr(ns, "vendor", []) or []),
        "incident": list(getattr(ns, "incident", []) or []),
        "campaign": list(getattr(ns, "campaign", []) or []),
        "collection_sources": list(ns.collection_sources),
        "output_format": list(ns.output_format) if isinstance(ns.output_format, list) else ([ns.output_format] if ns.output_format else []),
        "distribution": list(ns.distribution),
        "resolution_note": ns.resolution_note,
        "decision_supported": ns.decision_supported,
        "decision_maker": ns.decision_maker,
        "consequence": ns.consequence,
        "deadline": getattr(ns, "deadline", "") or "",
        "priority_justification": getattr(ns, "priority_justification", "") or "",
        "sub_questions": list(getattr(ns, "sub_questions", []) or []),
        "next_review": ns.next_review.isoformat() if ns.next_review else "",
        "intake_status": getattr(ns, "intake_status", "submitted") or "submitted",
        "acknowledged_at": getattr(ns, "acknowledged_at", "") or "",
        "acknowledged_by": getattr(ns, "acknowledged_by", "") or "",
        "triaged_at": getattr(ns, "triaged_at", "") or "",
        "triaged_by": getattr(ns, "triaged_by", "") or "",
        "decision_at": getattr(ns, "decision_at", "") or "",
        "decision_by": getattr(ns, "decision_by", "") or "",
        "rejection_reason": getattr(ns, "rejection_reason", "") or "",
        "deferral_reason": getattr(ns, "deferral_reason", "") or "",
        "linked_pir_uuid": getattr(ns, "linked_pir_uuid", "") or "",
        "triage_checklist": list(getattr(ns, "triage_checklist", []) or []),
        "mitre_attack_techniques": list(getattr(ns, "mitre_attack_techniques", []) or []),
    }


def _gir_data_from_ns(ns):
    return {
        "gir_id": ns.gir_id, "topic": ns.topic, "description": ns.description,
        "owner_uuid": ns.owner_uuid, "owner_name": ns.owner_name,
        "owner_role": getattr(ns, "owner_role", "") or "",
        "status": ns.status, "review_cycle": ns.review_cycle,
        "collection_sources": list(ns.collection_sources),
        "geographic_scope": list(ns.geographic_scope),
        "sectors": list(ns.sectors),
        "threat_types": list(ns.threat_types),
        "threat_actors": list(ns.threat_actors),
        "out_of_scope": list(ns.out_of_scope),
        "technology": list(getattr(ns, "technology", []) or []),
        "vendor": list(getattr(ns, "vendor", []) or []),
        "incident": list(getattr(ns, "incident", []) or []),
        "campaign": list(getattr(ns, "campaign", []) or []),
        "output_format": list(getattr(ns, "output_format", []) or []),
        "distribution": list(getattr(ns, "distribution", []) or []),
        "deadline": getattr(ns, "deadline", "") or "",
        "priority_justification": getattr(ns, "priority_justification", "") or "",
        "sub_questions": list(getattr(ns, "sub_questions", []) or []),
        "next_review": ns.next_review.isoformat() if ns.next_review else "",
        "intel_level": ns.intel_level,
        "mitre_attack_techniques": list(getattr(ns, "mitre_attack_techniques", []) or []),
    }


def pir_to_data(pir) -> dict:
    """Return a full PIR payload dict suitable for update_pir()."""
    return _pir_data_from_ns(pir)


def gir_to_data(gir) -> dict:
    """Return a full GIR payload dict suitable for update_gir()."""
    return _gir_data_from_ns(gir)


def _rewrite_parent_scope(misp, event, relation, new_values):
    """Rewrite the scope list ``relation`` on the parent PIR/GIR object
    of ``event`` to ``new_values``. Re-fetches afterwards so callers can
    keep working with a consistent view."""
    pir_obj = _get_obj(event, "zsazsa-pir")
    gir_obj = _get_obj(event, "zsazsa-gir")
    field = relation.replace("-", "_")
    if pir_obj:
        data = _pir_data_from_ns(_pir_ns(event))
        data["creator"] = _obj_attr(pir_obj, "creator") or ""
        data[field] = list(new_values)
        _sync_object_attributes(misp, event, "zsazsa-pir", _pir_obj(data), "PIR scope")
    elif gir_obj:
        data = _gir_data_from_ns(_gir_ns(event))
        data["creator"] = _obj_attr(gir_obj, "creator") or ""
        data[field] = list(new_values)
        _sync_object_attributes(misp, event, "zsazsa-gir", _gir_obj(data), "GIR scope")


def remove_focus_point_with_scope(req_uuid, attr_uuid):
    """Delete a focus point attribute and also drop its value from the
    matching scope list on the parent PIR/GIR object."""
    misp = _misp()
    event = misp.get_event(req_uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        delete_focus_point(attr_uuid)
        return

    fp_attr = next((a for a in event.attributes if a.uuid == attr_uuid), None)
    if fp_attr is None:
        return

    category, value, _ = (fp_attr.value.split("|", 2) + ["", "", ""])[:3]
    relation = _FP_CATEGORY_TO_RELATION.get(category)

    if relation:
        field = relation.replace("-", "_")
        pir_obj = _get_obj(event, "zsazsa-pir")
        gir_obj = _get_obj(event, "zsazsa-gir")
        if pir_obj or gir_obj:
            current = (_pir_ns(event) if pir_obj else _gir_ns(event))
            new_values = [v for v in getattr(current, field) if v != value]
            _rewrite_parent_scope(misp, event, relation, new_values)

    result = misp.delete_attribute(attr_uuid)
    if not _is_not_found(result):
        _check(result, "delete focus point")


def sync_focus_points_category(req_uuid, category, values, notes=""):
    """Replace all focus points of ``category`` for the PIR/GIR with
    ``values`` (deduplicated, trimmed) and align the parent scope list.
    Use for galaxy-backed categories where the user picks from a
    multi-select."""
    misp = _misp()
    event = misp.get_event(req_uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return

    cleaned = []
    seen = set()
    for v in values:
        v = (v or "").strip()
        key = v.lower()
        if not v or key in seen:
            continue
        seen.add(key)
        cleaned.append(v)

    for a in _get_fp_attrs(event):
        ns = _fp_ns(a)
        if ns.category == category:
            result = misp.delete_attribute(a.uuid)
            if not _is_not_found(result):
                _check(result, "delete focus point")

    for v in cleaned:
        add_focus_point(req_uuid, category, v, notes)

    relation = _FP_CATEGORY_TO_RELATION.get(category)
    if relation:
        # Re-fetch so the scope rewrite runs against the updated event.
        event = misp.get_event(req_uuid, pythonify=True)
        if not isinstance(event, dict):
            _rewrite_parent_scope(misp, event, relation, cleaned)


def add_focus_point_with_scope(req_uuid, category, value, notes=""):
    """Add a single focus point and append its value to the matching
    parent scope list (if applicable)."""
    add_focus_point(req_uuid, category, value, notes)
    relation = _FP_CATEGORY_TO_RELATION.get(category)
    if not relation:
        return
    misp = _misp()
    event = misp.get_event(req_uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return
    pir_obj = _get_obj(event, "zsazsa-pir")
    gir_obj = _get_obj(event, "zsazsa-gir")
    if not (pir_obj or gir_obj):
        return
    current = _pir_ns(event) if pir_obj else _gir_ns(event)
    field = relation.replace("-", "_")
    existing = list(getattr(current, field))
    if value not in existing:
        existing.append(value)
        _rewrite_parent_scope(misp, event, relation, existing)


# ── RFI CRUD ──────────────────────────────────────────────────────────────────

# SLA targets in business days, indexed by priority
RFI_SLA_DAYS = {"High": 2, "Medium": 5, "Low": 10}


def _build_output_format_list(obj):
    """Read output-format-list, falling back to legacy single-format fields."""
    raw = _obj_attr(obj, "output-format-list")
    if raw:
        lst = _json_list(raw)
        return [x for x in lst if isinstance(x, dict) and x.get("format")]
    old_fmt = _obj_attr(obj, "output-format") or ""
    old_tlp = _obj_attr(obj, "deliverable-tlp") or "amber"
    return [{"format": old_fmt, "tlp": old_tlp}] if old_fmt else []


def _rfi_obj(data):
    obj = _build_obj("zsazsa-rfi")
    _oa(obj, "rfi-id", data.get("rfi_id"))
    _oa(obj, "question", data.get("question"))
    _oa(obj, "context", data.get("context"))
    _oa(obj, "requester-name", data.get("requester_name"))
    _oa(obj, "requester-team", data.get("requester_team"))
    _oa(obj, "owner-uuid", data.get("owner_uuid"))
    _oa(obj, "owner-name", data.get("owner_name"))
    _oa(obj, "priority", data.get("priority", "Medium"))
    _oa(obj, "status", data.get("status", "New"))
    _oa(obj, "assigned-analyst", data.get("assigned_analyst"))
    _oa(obj, "due-date", data.get("due_date"))
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    _oa(obj, "linked-gir-uuid", data.get("linked_gir_uuid"))
    _oa_json(obj, "output-format-list", data.get("output_format_list", []))
    _oa(obj, "response", data.get("response"))
    _oa(obj, "response-confidence", data.get("response_confidence"))
    _oa(obj, "feedback-requirement-met", data.get("feedback_requirement_met"))
    _oa(obj, "feedback-on-time", data.get("feedback_on_time"))
    _oa(obj, "feedback-usefulness", data.get("feedback_usefulness"))
    _oa(obj, "feedback-suggestions", data.get("feedback_suggestions"))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "triaged-by", data.get("triaged_by"))
    _oa(obj, "triaged-at", data.get("triaged_at"))
    _oa_json(obj, "triage-checklist", data.get("triage_checklist", []))
    _oa(obj, "rejection-reason", data.get("rejection_reason"))
    return obj


def _rfi_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-rfi")
    owner_uuid = _obj_attr(obj, "owner-uuid") or ""
    owner_name = _obj_attr(obj, "owner-name") or ""
    event_date = event.date
    fmt_list = _build_output_format_list(obj)
    attachments = [
        SimpleNamespace(uuid=a.uuid, id=a.uuid, filename=a.value)
        for a in (getattr(event, "attributes", []) or [])
        if getattr(a, "comment", "") == "zsazsa:rfi-attachment"
    ]
    notes = [
        SimpleNamespace(
            id=er.id,
            uuid=getattr(er, "uuid", str(er.id)),
            title=(getattr(er, "name", "") or "")[6:],
            content=getattr(er, "content", "") or "",
            date=report_date(er),
        )
        for er in (getattr(event, "event_reports", []) or [])
        if (getattr(er, "name", "") or "").startswith("note: ")
    ]
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        rfi_id=_obj_attr(obj, "rfi-id") or "",
        question=_obj_attr(obj, "question") or "",
        context=_obj_attr(obj, "context") or "",
        requester_name=_obj_attr(obj, "requester-name") or "",
        requester_team=_obj_attr(obj, "requester-team") or "",
        owner_uuid=owner_uuid,
        owner_name=owner_name,
        priority=_obj_attr(obj, "priority") or "Medium",
        status=_obj_attr(obj, "status") or "New",
        assigned_analyst=_obj_attr(obj, "assigned-analyst") or "",
        due_date=_parse_date(_obj_attr(obj, "due-date")),
        linked_pir_uuid=_obj_attr(obj, "linked-pir-uuid") or "",
        linked_gir_uuid=_obj_attr(obj, "linked-gir-uuid") or "",
        output_format_list=fmt_list,
        deliverable_tlp=fmt_list[0]["tlp"] if fmt_list else "amber",
        response=_obj_attr(obj, "response") or "",
        response_confidence=_obj_attr(obj, "response-confidence") or "",
        feedback_requirement_met=_obj_attr(obj, "feedback-requirement-met") or "",
        feedback_on_time=_obj_attr(obj, "feedback-on-time") or "",
        feedback_usefulness=_obj_attr(obj, "feedback-usefulness") or "",
        feedback_suggestions=_obj_attr(obj, "feedback-suggestions") or "",
        creator=_obj_attr(obj, "creator") or "",
        triaged_by=_obj_attr(obj, "triaged-by") or "",
        triaged_at=_obj_attr(obj, "triaged-at") or "",
        triage_checklist=_json_list(_obj_attr(obj, "triage-checklist")),
        rejection_reason=_obj_attr(obj, "rejection-reason") or "",
        # A New RFI has not been triaged; any other status means it has.
        triaged=(_obj_attr(obj, "status") or "New") != "New",
        created_at=_parse_dt(event_date.isoformat() if event_date else None),
        attachments=attachments,
        notes=notes,
    )


def next_rfi_id():
    return _next_id(config.TAG_RFI, "RFI")


def list_rfis():
    misp = _misp()
    events = misp.search(tags=[config.TAG_RFI], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_rfi_ns(e) for e in events]
    result.sort(key=lambda r: r.rfi_id, reverse=True)
    return result


def get_rfi(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        return None
    return _rfi_ns(event)


def create_rfi(data):
    data["creator"] = misp_session.current_user_email()
    misp = _misp()
    with _id_lock:
        data["rfi_id"] = _sequence_id(misp, config.TAG_RFI, "RFI", data.get("rfi_id"))
        info = f"[zsazsa:rfi] {data['rfi_id']}: {data.get('question', '')[:80]}"
        event = _make_event(info)
        result = _add_event(misp, event, [config.TAG_RFI], "create RFI")
    _check(misp.add_object(_event_ref(result), _rfi_obj(data)), "add RFI object")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create RFI: missing UUID in MISP response")
    return uuid


def update_rfi(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("RFI event %s not found; recreating", uuid)
        return create_rfi(data)
    old = _get_obj(event, "zsazsa-rfi")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
        # The id is the RFI's identity: dropping it here would delete the
        # attribute and rewrite the event title without it.
        data.setdefault("rfi_id", _obj_attr(old, "rfi-id") or "")
        # Triage fields are set only through update_rfi_triage; a plain content
        # edit or a Kanban move must not wipe them, so carry them over unless the
        # caller supplied a value.
        for key, rel in (("triaged_by", "triaged-by"), ("triaged_at", "triaged-at"),
                         ("rejection_reason", "rejection-reason")):
            data.setdefault(key, _obj_attr(old, rel) or "")
        data.setdefault("triage_checklist", _json_list(_obj_attr(old, "triage-checklist")))
    _sync_object_attributes(misp, event, "zsazsa-rfi", _rfi_obj(data), "RFI")
    rfi_id = data.get("rfi_id", "")
    info = f"[zsazsa:rfi] {rfi_id}: {data.get('question', '')[:80]}"
    misp.update_event({"Event": {"id": event.id, "info": info}})
    return uuid


def delete_rfi(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete RFI")


def add_rfi_attachment(event_uuid, filename, file_bytes):
    import base64
    misp = _misp()
    attr = MISPAttribute()
    attr.type = "attachment"
    attr.category = "External analysis"
    attr.value = filename
    attr.data = base64.b64encode(file_bytes).decode("utf-8")
    attr.comment = "zsazsa:rfi-attachment"
    attr.to_ids = False
    result = _check(misp.add_attribute(event_uuid, attr, pythonify=True), "add RFI attachment")
    return result.uuid


def delete_rfi_attachment(attr_uuid):
    misp = _misp()
    result = misp.delete_attribute(attr_uuid)
    if not _is_not_found(result):
        _check(result, "delete RFI attachment")


def fetch_attachment(attr_uuid):
    """Return one attachment attribute with the file itself attached.

    with_attachments is what makes MISP send the bytes along; a plain attribute
    fetch describes the attachment without carrying it.
    """
    misp = _misp()
    found = misp.search(controller="attributes", uuid=attr_uuid,
                        with_attachments=True, pythonify=True)
    if isinstance(found, dict) or not found:
        raise RuntimeError(f"Attachment {attr_uuid} not found")
    attr = found[0]
    if attr.data is None:
        raise RuntimeError(f"Attachment {attr_uuid} carries no file")
    return attr


def get_rfi_attachment_content(attr_uuid):
    attr = fetch_attachment(attr_uuid)
    return attr.data.getvalue(), attr.value


def add_rfi_note(event_uuid, title, content):
    from pymisp import MISPEventReport
    misp = _misp()
    er = MISPEventReport()
    er.name = f"note: {title}"
    er.content = content
    result = _check(misp.add_event_report(event_uuid, er), "add RFI note")
    if isinstance(result, dict):
        return result.get("EventReport", {}).get("id")
    return getattr(result, "id", None)


def delete_rfi_note(report_id):
    # Hard delete: a soft-deleted event report is still returned by get_event,
    # so the note would keep appearing after deletion.
    misp = _misp()
    _check(misp.delete_event_report(report_id, hard=True), "delete RFI note")


# ── Indicator feeds (saved MISP indicator searches) ──────────────────────────

def _indicator_feed_obj(data):
    obj = _build_obj("zsazsa-indicator-feed")
    _oa(obj, "feed-id", data.get("feed_id"))
    _oa(obj, "name", data.get("name"))
    _oa(obj, "description", data.get("description"))
    _oa(obj, "query", json.dumps(data.get("query") or {}))
    _oa(obj, "tlp", data.get("tlp", "clear"))
    _oa(obj, "audience", data.get("audience"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "feedback-by", data.get("feedback_by"))
    _oa(obj, "token", data.get("token"))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    return obj


def _indicator_feed_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-indicator-feed")
    event_date = event.date
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        feed_id=_obj_attr(obj, "feed-id") or "",
        name=_obj_attr(obj, "name") or "",
        description=_obj_attr(obj, "description") or "",
        query=_json_dict(_obj_attr(obj, "query")),
        tlp=_obj_attr(obj, "tlp") or "clear",
        audience=_obj_attr(obj, "audience") or "",
        author=_obj_attr(obj, "author") or "",
        feedback_by=_parse_date(_obj_attr(obj, "feedback-by")),
        token=_obj_attr(obj, "token") or "",
        creator=_obj_attr(obj, "creator") or "",
        linked_pir_uuid=_obj_attr(obj, "linked-pir-uuid") or "",
        created_at=_parse_dt(event_date.isoformat() if event_date else None),
    )


def next_indicator_feed_id():
    return _next_id(config.TAG_INDICATOR_FEED, "FEED")


def list_indicator_feeds():
    misp = _misp()
    events = misp.search(tags=[config.TAG_INDICATOR_FEED], limit=500, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_indicator_feed_ns(e) for e in events]
    result.sort(key=lambda f: f.name.lower())
    return result


def get_indicator_feed(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        return None
    return _indicator_feed_ns(event)


def create_indicator_feed(data):
    data["creator"] = misp_session.current_user_email()
    data.setdefault("tlp", "clear")
    # Unguessable capability token for the public export URL.
    data["token"] = data.get("token") or secrets.token_urlsafe(16)
    misp = _misp()
    with _id_lock:
        data["feed_id"] = _sequence_id(misp, config.TAG_INDICATOR_FEED, "FEED", data.get("feed_id"))
        info = f"[zsazsa:indicator-feed] {data['feed_id']}: {(data.get('name') or '')[:80]}"
        event = _make_event(info)
        result = _add_event(misp, event, [config.TAG_INDICATOR_FEED], "create indicator feed")
    _check(misp.add_object(_event_ref(result), _indicator_feed_obj(data)), "add indicator feed object")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create indicator feed: missing UUID in MISP response")
    return uuid


def update_indicator_feed(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("Indicator feed event %s not found; recreating", uuid)
        return create_indicator_feed(data)
    old = _get_obj(event, "zsazsa-indicator-feed")
    if old:
        data.setdefault("creator", _obj_attr(old, "creator") or "")
        # Keep the capability token stable across edits so saved URLs keep working.
        data.setdefault("token", _obj_attr(old, "token") or secrets.token_urlsafe(16))
    _sync_object_attributes(misp, event, "zsazsa-indicator-feed", _indicator_feed_obj(data), "indicator feed")
    info = f"[zsazsa:indicator-feed] {data.get('feed_id', '')}: {(data.get('name') or '')[:80]}"
    misp.update_event({"Event": {"id": event.id, "info": info}})
    return uuid


def delete_indicator_feed(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete indicator feed")


def get_indicator_feed_by_token(token):
    """Look up a feed by its public capability token, or None."""
    token = (token or "").strip()
    if not token:
        return None
    return next((f for f in list_indicator_feeds() if f.token == token), None)


# ── Threat actor profiles (saved MISP-backed actor write-ups) ────────────────

def galaxy_enrichment(actors) -> dict:
    """Merge threat-actor galaxy context for one or more actors.

    Returns capabilities/mode_of_operation/synonyms as joined strings and refs as
    a list, for the interactive "complete profile" button. victimology is returned
    as (actor, text) pairs since it is recorded as a note rather than a field.
    """
    caps, modes, syns, refs, victimology = [], [], [], [], []
    origin, motivation, sponsorship = [], [], []
    seen_syn = set()
    for actor in actors:
        meta = threat_actor_galaxy_meta(actor)
        if not meta:
            continue
        caps += [c for c in meta["capabilities"] if c]
        modes += [m for m in meta["mode_of_operation"] if m]
        for s in meta["synonyms"]:
            if s and s.strip().lower() not in seen_syn:
                syns.append(s.strip())
                seen_syn.add(s.strip().lower())
        for r in meta["refs"]:
            if r and r not in refs:
                refs.append(r)
        origin += [o for o in meta["suspected_origin"] if o]
        motivation += [m for m in meta["motivation"] if m]
        sponsorship += [s for s in meta["sponsorship"] if s]
        vic = "\n".join(meta["victimology"]).strip()
        if vic:
            victimology.append((actor, vic))
    # De-duplicate the single-line fields while keeping order.
    def _uniq_join(items, sep=", "):
        out = []
        for i in items:
            if i not in out:
                out.append(i)
        return sep.join(out)
    return {
        "capabilities": "\n".join(caps),
        "mode_of_operation": "\n".join(modes),
        "synonyms": ", ".join(syns),
        "refs": refs,
        "suspected_origin": _uniq_join(origin),
        "motivation": _uniq_join(motivation),
        "sponsorship": _uniq_join(sponsorship),
        "victimology": victimology,
    }


def _add_victimology_notes(uuid, victimology):
    for actor, text in victimology:
        add_rfi_note(uuid, f"Victimology: {actor} (from MISP galaxy)", text)


def _tap_obj(data):
    obj = _build_obj("zsazsa-threat-actor-profile")
    _oa(obj, "tap-id", data.get("tap_id"))
    _oa(obj, "title", data.get("title"))
    _oa(obj, "summary", data.get("summary"))
    _oa_json(obj, "threat-actors", data.get("threat_actors", []))
    _oa(obj, "audience", data.get("audience"))
    _oa(obj, "tlp", data.get("tlp", "amber"))
    _oa(obj, "status", data.get("status", "Draft"))
    _oa(obj, "published-at", data.get("published_at"))
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    _oa(obj, "source-reliability", data.get("source_reliability"))
    _oa(obj, "source-credibility", data.get("source_credibility"))
    _oa(obj, "attribution-rationale", data.get("attribution_rationale"))
    _oa(obj, "assessment-confidence", data.get("assessment_confidence"))
    _oa(obj, "review-date", data.get("review_date"))
    _oa_json(obj, "actor-types", data.get("actor_types", []))
    _oa(obj, "synonyms", data.get("synonyms"))
    _oa(obj, "suspected-origin", data.get("suspected_origin"))
    _oa(obj, "origin-confidence", data.get("origin_confidence"))
    _oa(obj, "motivation", data.get("motivation"))
    _oa(obj, "sponsorship", data.get("sponsorship"))
    _oa(obj, "capabilities", data.get("capabilities"))
    _oa(obj, "mode-of-operation", data.get("mode_of_operation"))
    _oa(obj, "infrastructure", data.get("infrastructure"))
    _oa(obj, "rec-prevention", data.get("rec_prevention"))
    _oa(obj, "rec-detection", data.get("rec_detection"))
    _oa(obj, "rec-response", data.get("rec_response"))
    _oa_json(obj, "indicator-feeds", data.get("indicator_feeds", []))
    _oa_json(obj, "geographic-scope", data.get("geographic_scope", []))
    _oa_json(obj, "sectors", data.get("sectors", []))
    _oa_json(obj, "mitre-attack-techniques", data.get("mitre_attack_techniques", []))
    _oa_json(obj, "threat-types", data.get("threat_types", []))
    _oa(obj, "time-frame", data.get("time_frame"))
    _oa_json(obj, "technology", data.get("technology", []))
    _oa_json(obj, "vendor", data.get("vendor", []))
    _oa(obj, "external-references", _join_lines(data.get("external_references")))
    _oa(obj, "feedback-deadline", data.get("feedback_deadline"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "creator", data.get("creator"))
    return obj


def _tap_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-threat-actor-profile")
    notes = [
        SimpleNamespace(
            id=er.id,
            uuid=getattr(er, "uuid", str(er.id)),
            title=(getattr(er, "name", "") or "")[6:],
            content=getattr(er, "content", "") or "",
            date=report_date(er),
        )
        for er in (getattr(event, "event_reports", []) or [])
        if (getattr(er, "name", "") or "").startswith("note: ")
    ]
    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        tap_id=_obj_attr(obj, "tap-id") or "",
        title=_obj_attr(obj, "title") or "",
        summary=_obj_attr(obj, "summary") or "",
        threat_actors=_json_list(_obj_attr(obj, "threat-actors")),
        audience=_obj_attr(obj, "audience") or "",
        tlp=_obj_attr(obj, "tlp") or "amber",
        status=_obj_attr(obj, "status") or "Draft",
        published_at=_parse_dt(_obj_attr(obj, "published-at")),
        linked_pir_uuid=_obj_attr(obj, "linked-pir-uuid") or "",
        source_reliability=_obj_attr(obj, "source-reliability") or "",
        source_credibility=_obj_attr(obj, "source-credibility") or "",
        attribution_rationale=_obj_attr(obj, "attribution-rationale") or "",
        assessment_confidence=_obj_attr(obj, "assessment-confidence") or "",
        review_date=_parse_date(_obj_attr(obj, "review-date")),
        actor_types=_json_list(_obj_attr(obj, "actor-types")),
        synonyms=_obj_attr(obj, "synonyms") or "",
        suspected_origin=_obj_attr(obj, "suspected-origin") or "",
        origin_confidence=_obj_attr(obj, "origin-confidence") or "",
        motivation=_obj_attr(obj, "motivation") or "",
        sponsorship=_obj_attr(obj, "sponsorship") or "",
        capabilities=_obj_attr(obj, "capabilities") or "",
        mode_of_operation=_obj_attr(obj, "mode-of-operation") or "",
        infrastructure=_obj_attr(obj, "infrastructure") or "",
        rec_prevention=_obj_attr(obj, "rec-prevention") or "",
        rec_detection=_obj_attr(obj, "rec-detection") or "",
        rec_response=_obj_attr(obj, "rec-response") or "",
        indicator_feeds=_json_list(_obj_attr(obj, "indicator-feeds")),
        geographic_scope=_json_list(_obj_attr(obj, "geographic-scope")),
        sectors=_json_list(_obj_attr(obj, "sectors")),
        mitre_attack_techniques=_json_list(_obj_attr(obj, "mitre-attack-techniques")),
        threat_types=_json_list(_obj_attr(obj, "threat-types")),
        time_frame=_obj_attr(obj, "time-frame") or "",
        technology=_json_list(_obj_attr(obj, "technology")),
        vendor=_json_list(_obj_attr(obj, "vendor")),
        external_references=(_obj_attr(obj, "external-references") or "").splitlines(),
        feedback_deadline=_parse_date(_obj_attr(obj, "feedback-deadline")),
        author=_obj_attr(obj, "author") or "",
        creator=_obj_attr(obj, "creator") or "",
        notes=notes,
        created_at=_parse_dt(event.date.isoformat() if event.date else None),
    )


def list_threat_actor_profiles(status=None):
    misp = _misp()
    events = misp.search(tags=[config.TAG_THREAT_ACTOR_PROFILE], limit=500, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_tap_ns(e) for e in events]
    if status:
        result = [t for t in result if t.status == status]
    result.sort(key=lambda t: t.tap_id)
    return result


def get_threat_actor_profile(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        return None
    return _tap_ns(event)


def create_threat_actor_profile(data):
    data["creator"] = misp_session.current_user_email()
    data.setdefault("status", "Draft")
    # Text fields are filled interactively via the "complete profile" button;
    # only victimology is recorded server-side (it becomes a note).
    victimology = galaxy_enrichment(data.get("threat_actors") or [])["victimology"]
    misp = _misp()
    with _id_lock:
        data["tap_id"] = _sequence_id(misp, config.TAG_THREAT_ACTOR_PROFILE, "TAP", data.get("tap_id"))
        info = f"[zsazsa:threat-actor-profile] {data['tap_id']}: {(data.get('title') or '')[:80]}"
        event = _make_event(info)
        result = _add_event(misp, event, [config.TAG_THREAT_ACTOR_PROFILE], "create threat actor profile")
    _check(misp.add_object(_event_ref(result), _tap_obj(data)), "add threat actor profile object")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create threat actor profile: missing UUID in MISP response")
    # Add the selected threat actors (and other scope) as local galaxy tags.
    _apply_scope_tags(misp, uuid, data, local=True)
    _add_victimology_notes(uuid, victimology)
    return uuid


def update_threat_actor_profile(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict):
        logger.warning("Threat actor profile event %s not found; recreating", uuid)
        return create_threat_actor_profile(data)
    old = _get_obj(event, "zsazsa-threat-actor-profile")
    old_actors = _json_list(_obj_attr(old, "threat-actors")) if old else []
    if old:
        # Provenance and lifecycle are set elsewhere; carry them over on a plain edit.
        data.setdefault("creator", _obj_attr(old, "creator") or "")
        data.setdefault("status", _obj_attr(old, "status") or "Draft")
        data.setdefault("published_at", _obj_attr(old, "published-at") or "")
    # Enrich only from newly added actors so a manual edit is not overwritten on
    # every save and victimology notes are not duplicated.
    seen = {a.lower() for a in old_actors}
    new_actors = [a for a in (data.get("threat_actors") or []) if a.lower() not in seen]
    victimology = galaxy_enrichment(new_actors)["victimology"]
    _sync_object_attributes(misp, event, "zsazsa-threat-actor-profile", _tap_obj(data), "threat actor profile")
    info = f"[zsazsa:threat-actor-profile] {data.get('tap_id', '')}: {(data.get('title') or '')[:80]}"
    _apply_scope_tags(misp, uuid, data, new_info=info, _event=event, local=True)
    _add_victimology_notes(uuid, victimology)
    return uuid


def publish_threat_actor_profile(uuid):
    tap = get_threat_actor_profile(uuid)
    if tap is None:
        raise RuntimeError("threat actor profile not found")
    data = {
        "tap_id": tap.tap_id, "title": tap.title, "summary": tap.summary,
        "threat_actors": tap.threat_actors, "audience": tap.audience, "tlp": tap.tlp,
        "linked_pir_uuid": tap.linked_pir_uuid, "source_reliability": tap.source_reliability,
        "source_credibility": tap.source_credibility,
        "attribution_rationale": tap.attribution_rationale,
        "assessment_confidence": tap.assessment_confidence,
        "review_date": tap.review_date.isoformat() if tap.review_date else "",
        "actor_types": tap.actor_types, "synonyms": tap.synonyms,
        "suspected_origin": tap.suspected_origin, "origin_confidence": tap.origin_confidence,
        "motivation": tap.motivation, "sponsorship": tap.sponsorship,
        "capabilities": tap.capabilities, "mode_of_operation": tap.mode_of_operation,
        "infrastructure": tap.infrastructure,
        "rec_prevention": tap.rec_prevention, "rec_detection": tap.rec_detection,
        "rec_response": tap.rec_response, "indicator_feeds": tap.indicator_feeds,
        "geographic_scope": tap.geographic_scope, "sectors": tap.sectors,
        "mitre_attack_techniques": tap.mitre_attack_techniques, "threat_types": tap.threat_types,
        "time_frame": tap.time_frame, "technology": tap.technology, "vendor": tap.vendor,
        "external_references": tap.external_references,
        "feedback_deadline": tap.feedback_deadline.isoformat() if tap.feedback_deadline else "",
        "author": tap.author, "creator": tap.creator,
        "status": "Published", "published_at": date.today().isoformat(),
    }
    update_threat_actor_profile(uuid, data)


def delete_threat_actor_profile(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete threat actor profile")


# ── Indicator-feed MISP servers (the data-collection sources) ────────────────

def indicator_feed_servers():
    """Selectable MISP servers for the indicator feed: the configured data
    collection servers (config.MISP_SERVERS) that have a URL and API key.

    Returns dicts with id, label, url and enabled (no secrets).
    """
    servers = []
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not (s.get("url") and s.get("api_key")):
            continue
        servers.append({
            "id": s.get("id") or s.get("label") or s.get("url"),
            "label": s.get("label") or s.get("url"),
            "url": s.get("url"),
            "enabled": bool(s.get("enabled", True)),
        })
    return servers


def _indicator_feed_clients(server_ids=None):
    """Build (id, label, url, client) for the selected servers.

    `server_ids` selects specific servers; when falsy, all enabled servers are
    used. Servers that cannot be reached are skipped (logged).
    """
    wanted = set(server_ids or [])
    clients = []
    for s in getattr(config, "MISP_SERVERS", []) or []:
        sid = s.get("id") or s.get("label") or s.get("url")
        if not (s.get("url") and s.get("api_key")):
            continue
        if wanted:
            if sid not in wanted:
                continue
        elif not s.get("enabled", True):
            continue
        try:
            client = PyMISP(s["url"], s["api_key"], s.get("verify_tls", True), False, timeout=HTTP_TIMEOUT)
        except Exception as exc:
            logger.warning("Indicator feed: cannot connect to MISP server %r (%s): %s", sid, s.get("url"), exc)
            continue
        clients.append((sid, s.get("label") or s["url"], s["url"].rstrip("/"), client))
    return clients


# ── MISP metadata pulls for the indicator-feed query builder ──────────────────

def _union_over_servers(extract):
    """Apply `extract(client)` to every enabled indicator-feed server and union
    the resulting iterables into one sorted, de-duplicated list."""
    values = set()
    for _sid, _label, _url, client in _indicator_feed_clients():
        try:
            values.update(v for v in (extract(client) or []) if v)
        except Exception:
            logger.exception("Indicator feed metadata pull failed for a server")
    return sorted(values, key=str.lower)


def fetch_misp_organisations():
    """Organisation names across all enabled indicator-feed MISP servers."""
    def _orgs(client):
        orgs = client.organisations(scope="all", pythonify=True)
        return [] if not orgs or isinstance(orgs, dict) else [getattr(o, "name", "") for o in orgs]
    return _union_over_servers(_orgs)


def fetch_misp_tags():
    """Tag names across all enabled indicator-feed MISP servers."""
    def _tags(client):
        tags = client.tags(pythonify=True)
        return [] if not tags or isinstance(tags, dict) else [getattr(t, "name", "") for t in tags]
    return _union_over_servers(_tags)


def local_attribute_types():
    """MISP attribute types from the PyMISP-bundled describeTypes.json (no network)."""
    import pymisp as _pymisp
    path = os.path.join(os.path.dirname(_pymisp.__file__), "data", "describeTypes.json")
    try:
        with open(path) as fh:
            data = json.load(fh)
        types = (data.get("result", data) or {}).get("types", [])
        return sorted(set(types), key=str.lower)
    except Exception:
        logger.exception("Could not load local MISP attribute types")
        return []


def _attr_tag_names(attr, event):
    names = [t.get("name", "") for t in (attr.get("Tag") or [])]
    names += [t.get("name", "") for t in (event.get("Tag") or [])]
    return [n for n in names if n]


def _indicator_search_kwargs(filters):
    """Build the PyMISP attribute-search kwargs from a feed's filter dict.

    Shared by search_indicators (execution) and pymisp_query_string (display)
    so the query shown to the user is exactly the one that runs.
    """
    kwargs = {
        "controller": "attributes",
        "pythonify": False,
        "include_context": True,
        "limit": max(1, min(int(filters.get("limit") or 100), 10000)),
    }
    if filters.get("types"):
        kwargs["type_attribute"] = list(filters["types"])
    if filters.get("to_ids") in ("yes", "no"):
        kwargs["to_ids"] = 1 if filters["to_ids"] == "yes" else 0
    if filters.get("published") in ("yes", "no"):
        kwargs["published"] = filters["published"] == "yes"
    if filters.get("enforce_warninglist") == "yes":
        kwargs["enforce_warninglist"] = True
    org_terms = list(filters.get("orgs_include") or []) + [f"!{o}" for o in filters.get("orgs_exclude") or []]
    if org_terms:
        kwargs["org"] = org_terms
    tag_terms = list(filters.get("tags_include") or []) + [f"!{t}" for t in filters.get("tags_exclude") or []]
    if tag_terms:
        kwargs["tags"] = tag_terms
    event_terms = list(filters.get("events_include") or []) + [f"!{e}" for e in filters.get("events_exclude") or []]
    if event_terms:
        kwargs["eventid"] = event_terms

    # Attribute timestamp window: a relative quick value wins; otherwise a date range.
    quick = filters.get("attr_last") or ""
    attr_after = filters.get("attr_after") or ""
    attr_before = filters.get("attr_before") or ""
    if quick:
        kwargs["timestamp"] = quick
    elif attr_after and attr_before:
        kwargs["timestamp"] = [attr_after, attr_before]
    elif attr_after:
        kwargs["timestamp"] = attr_after
    elif attr_before:
        kwargs["timestamp"] = ["1970-01-01", attr_before]

    # Event date window (the event's `date` field). Unlike `timestamp`, MISP's
    # event-date `from`/`to` do NOT accept relative shorthand, so a quick range
    # (number of days back) is converted to an absolute date here.
    event_last = filters.get("event_last")
    if event_last:
        try:
            kwargs["date_from"] = (date.today() - timedelta(days=int(event_last))).isoformat()
        except (TypeError, ValueError):
            pass
    else:
        if filters.get("event_after"):
            kwargs["date_from"] = filters["event_after"]
        if filters.get("event_before"):
            kwargs["date_to"] = filters["event_before"]

    # No sort/direction: MISP attribute restSearch does not honour them, so the
    # newest-first ordering is applied to the fetched rows in search_indicators.
    return kwargs


def pymisp_query_string(filters):
    """A copy-pasteable representation of the PyMISP call the feed will run."""
    kwargs = _indicator_search_kwargs(filters)
    order = ["controller", "type_attribute", "to_ids", "published", "enforce_warninglist",
             "org", "tags", "eventid", "timestamp", "date_from", "date_to",
             "limit", "include_context", "pythonify"]
    lines = ["misp.search("]
    for key in order:
        if key in kwargs:
            lines.append(f"    {key}={kwargs[key]!r},")
    lines.append(")")
    return "\n".join(lines)


def _parse_attribute_rows(raw, server_id, server_label, server_url, filters):
    if isinstance(raw, dict):
        attrs = raw.get("Attribute")
        if attrs is None and "response" in raw:
            attrs = (raw["response"] or {}).get("Attribute", [])
        attrs = attrs or []
    else:
        attrs = raw or []

    tags_inc = filters.get("tags_include") or []
    tags_exc = filters.get("tags_exclude") or []
    rows = []
    for a in attrs:
        if isinstance(a, dict) and "Attribute" in a:
            a = a["Attribute"]
        event = a.get("Event") or {}
        tag_names = _attr_tag_names(a, event)
        # MISP tag filtering is OR, so enforce "must have all" and exclusion here.
        if tags_inc and not all(t in tag_names for t in tags_inc):
            continue
        if tags_exc and any(t in tag_names for t in tags_exc):
            continue
        ts = a.get("timestamp")
        try:
            ts_epoch = int(ts) if ts else 0
            ts_display = datetime.utcfromtimestamp(ts_epoch).strftime("%Y-%m-%d %H:%M") if ts_epoch else ""
        except (TypeError, ValueError):
            ts_epoch, ts_display = 0, ""
        event_id = a.get("event_id") or event.get("id", "")
        event_uuid = event.get("uuid", "")
        rows.append({
            "server_id": server_id,
            "server_label": server_label,
            "attribute_id": a.get("id", ""),
            "event_id": event_id,
            "event_uuid": event_uuid,
            "event_url": f"{server_url}/events/view/{event_uuid or event_id}" if (event_uuid or event_id) else "",
            "event_title": event.get("info", ""),
            "creator_org": (event.get("Orgc") or {}).get("name", ""),
            "event_date": event.get("date", ""),
            "attribute_timestamp": ts_display,
            "_ts": ts_epoch,
            "type": a.get("type", ""),
            "value": a.get("value", ""),
            "to_ids": str(a.get("to_ids")).lower() in ("1", "true"),
            "tags": tag_names,
        })
    return rows


# Column order for indicator-feed result exports (CSV). Single source of truth,
# reused by the indicator-feed views and the threat-actor-profile embed.
INDICATOR_FEED_COLUMNS = [
    ("server_label", "Server"),
    ("event_id", "Event ID"),
    ("event_title", "Event title"),
    ("creator_org", "Creator org"),
    ("event_date", "Event date"),
    ("attribute_timestamp", "Attribute timestamp"),
    ("type", "Type"),
    ("value", "Value"),
    ("to_ids", "to_ids"),
]


def indicator_feed_csv_text(feed) -> str:
    """Run a saved feed's query and return its results as CSV text."""
    import csv
    import io
    query = feed.query or {}
    rows = search_indicators(query, server_ids=query.get("servers"))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([header for _, header in INDICATOR_FEED_COLUMNS])
    for r in rows:
        writer.writerow([r.get(key, "") for key, _ in INDICATOR_FEED_COLUMNS])
    return buf.getvalue()


def search_indicators(filters, server_ids=None):
    """Run the attribute search across the selected MISP servers and merge.

    `server_ids` selects which configured servers to query (default: all
    enabled). Rows from every server are merged and sorted by attribute
    timestamp, newest first. Each row carries its originating server and a
    server-specific event URL.
    """
    kwargs = _indicator_search_kwargs(filters)
    rows = []
    for sid, label, url, client in _indicator_feed_clients(server_ids):
        try:
            raw = client.search(**kwargs)
        except Exception:
            logger.exception("Indicator search failed on server %s", sid)
            continue
        rows.extend(_parse_attribute_rows(raw, sid, label, url, filters))
    rows.sort(key=lambda r: r["_ts"], reverse=True)
    return rows


def count_indicators(filters, server_ids=None, cap=100000):
    """Total attributes matching the query across the selected servers.

    MISP cannot sort attribute search, so the result table only sorts the
    fetched page. This count tells the analyst how many match in total (so they
    know whether the limit truncates the set). It counts attributes (not unique
    values - the `text` format de-duplicates) without the heavier event context,
    bounded by `cap`; returns (total, capped). Server-side filters only (the
    local tag AND/exclude refinement isn't applied), so it is the MISP-level total.
    """
    kwargs = _indicator_search_kwargs(filters)
    for key in ("include_context", "limit"):
        kwargs.pop(key, None)
    kwargs["limit"] = cap
    total, capped = 0, False
    for sid, _label, _url, client in _indicator_feed_clients(server_ids):
        try:
            raw = client.search(**kwargs)
        except Exception:
            logger.exception("Indicator count failed on server %s", sid)
            continue
        if isinstance(raw, dict):
            attrs = raw.get("Attribute")
            if attrs is None and "response" in raw:
                attrs = (raw["response"] or {}).get("Attribute", [])
            attrs = attrs or []
        else:
            attrs = raw or []
        n = len(attrs)
        total += n
        if n >= cap:
            capped = True
    return total, capped


# ── Feedback (event reports tagged curation:feedback) ────────────────────────

TAG_FEEDBACK = 'curation:feedback'


def list_product_feedback(event_uuid):
    """Return event reports tagged or named as feedback for the given event."""
    misp = _misp()
    try:
        event = misp.get_event(event_uuid, pythonify=True)
    except Exception as exc:
        logger.warning("get_event %s for feedback failed: %s", event_uuid, exc)
        return []
    if not event or isinstance(event, dict):
        return []
    reports = []
    for er in getattr(event, "event_reports", []) or []:
        name = getattr(er, "name", "") or ""
        if name.startswith("feedback"):
            ts = getattr(er, "timestamp", None)
            reports.append(SimpleNamespace(
                id=er.id,
                uuid=er.uuid,
                name=name,
                content=getattr(er, "content", "") or "",
                timestamp=ts,
                created_at=_report_timestamp(ts),
            ))
    reports.sort(key=lambda r: r.created_at or datetime.min)
    return reports


def _report_timestamp(ts):
    """Parse a MISP event-report timestamp (datetime, epoch int or str) to a
    naive UTC datetime, or None. Normalising to naive keeps values comparable
    when sorting (PyMISP returns tz-aware datetimes, the epoch path is naive)."""
    if isinstance(ts, datetime):
        return ts.replace(tzinfo=None) if ts.tzinfo else ts
    if ts in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return None


def report_date(report) -> str:
    """Date shown next to an event report title, empty when it has none.

    A report carries only a timestamp, which MISP moves on every edit, so this
    is when it was last written rather than when it was first attached.
    """
    ts = _report_timestamp(getattr(report, "timestamp", None))
    return ts.strftime("%Y-%m-%d") if ts else ""


def add_product_feedback(event_uuid, author, rating, comment):
    """Append a feedback event report and tag the event."""
    from pymisp import MISPEventReport

    misp = _misp()
    er = MISPEventReport()
    er.name = f"feedback: {author or 'anonymous'} ({rating or 'n/a'})"
    body_lines = [
        f"**Rating:** {rating or 'n/a'}",
        f"**Author:** {author or 'anonymous'}",
        "",
        comment or "",
    ]
    er.content = "\n".join(body_lines)
    _check(misp.add_event_report(event_uuid, er), "add feedback report")
    # Tag the event so it is easy to discover in MISP
    try:
        misp.tag(event_uuid, TAG_FEEDBACK)
    except Exception as exc:
        logger.warning("tag %s with feedback failed: %s", event_uuid, exc)


def list_pending_feedback_products():
    """Published flash intel alerts and vulnerability advisories that asked for
    feedback by a deadline but have not received any yet.

    Products without a feedback deadline are never included. "Received" is judged
    from the feedback tag on the event, so this stays to a few MISP searches
    rather than one lookup per product.
    """
    misp = _misp()
    have_feedback = set()
    try:
        fb_events = misp.search(tags=[TAG_FEEDBACK], limit=1000, metadata=True, pythonify=True)
        if fb_events and not isinstance(fb_events, dict):
            have_feedback = {e.uuid for e in fb_events}
    except Exception:
        logger.exception("feedback-tag search failed")

    today = datetime.now(timezone.utc).date()
    pending = []
    for kind, items in (("flash-intel", list_fias()), ("vea", list_veas())):
        for p in items:
            if not p.feedback_deadline or not p.published or p.uuid in have_feedback:
                continue
            pending.append(SimpleNamespace(
                kind=kind,
                uuid=p.uuid,
                product_id=p.fia_id if kind == "flash-intel" else p.vea_id,
                title=p.title or "(untitled)",
                deadline=p.feedback_deadline,
                days_left=(p.feedback_deadline - today).days,
                overdue=p.feedback_deadline < today,
            ))
    pending.sort(key=lambda p: p.deadline)
    return pending


# ── Cross-entity queries ──────────────────────────────────────────────────────

def pirs_for_stakeholder(stakeholder_uuid):
    return [p for p in list_pirs() if p.owner_uuid == stakeholder_uuid]


def girs_for_stakeholder(stakeholder_uuid):
    return [g for g in list_girs() if g.owner_uuid == stakeholder_uuid]


def _matches_distribution_entry(entries, stakeholder_uuid, stakeholder_name="", stakeholder_email=""):
    """Return True when a stakeholder is explicitly listed in a distribution list.

    Distribution entries are now stakeholder UUIDs, but legacy data may still
    contain names or contact values.
    """
    values = {
        (stakeholder_uuid or "").strip().lower(),
        (stakeholder_name or "").strip().lower(),
        (stakeholder_email or "").strip().lower(),
    }
    values.discard("")
    if not values:
        return False
    for raw in entries or []:
        if (raw or "").strip().lower() in values:
            return True
    return False


def pirs_distributed_to_stakeholder(stakeholder_uuid, stakeholder_name="", stakeholder_email=""):
    return [
        p for p in list_pirs()
        if p.owner_uuid != stakeholder_uuid
        and _matches_distribution_entry(p.distribution, stakeholder_uuid, stakeholder_name, stakeholder_email)
    ]


def girs_distributed_to_stakeholder(stakeholder_uuid, stakeholder_name="", stakeholder_email=""):
    return [
        g for g in list_girs()
        if g.owner_uuid != stakeholder_uuid
        and _matches_distribution_entry(g.distribution, stakeholder_uuid, stakeholder_name, stakeholder_email)
    ]


def products_for_stakeholder(stakeholder_uuid, stakeholder_name="", stakeholder_email="", limit=20):
    """Return analyser-MISP product events whose linked PIR/GIR ID appears
    in the event info or as a tag value, where the PIR/GIR is either owned by
    the given stakeholder or distributed to that stakeholder.
    """
    owned_pirs = pirs_for_stakeholder(stakeholder_uuid)
    owned_girs = girs_for_stakeholder(stakeholder_uuid)
    distributed_pirs = pirs_distributed_to_stakeholder(stakeholder_uuid, stakeholder_name, stakeholder_email)
    distributed_girs = girs_distributed_to_stakeholder(stakeholder_uuid, stakeholder_name, stakeholder_email)
    all_pirs = owned_pirs + distributed_pirs
    all_girs = owned_girs + distributed_girs

    needles = [
        value
        for value in (
            [p.pir_id for p in all_pirs if p.pir_id]
            + [g.gir_id for g in all_girs if g.gir_id]
            + [p.uuid for p in all_pirs if p.uuid]
            + [g.uuid for g in all_girs if g.uuid]
        )
    ]
    needles = list(dict.fromkeys(needles))
    if not needles:
        return []
    misp = _misp()
    try:
        events = misp.search(
            tags=['zsazsa:ctiproduct="%"'], limit=500,
            metadata=False, pythonify=True,
        )
    except Exception as exc:
        logger.warning("products_for_stakeholder MISP search failed: %s", exc)
        return []
    if not events or isinstance(events, dict):
        return []

    matches = []
    for ev in events:
        info = ev.info or ""
        ev_tags = [t.name for t in (getattr(ev, "tags", []) or [])]
        if any(n in info for n in needles) or any(n in t for n in needles for t in ev_tags):
            ptype = ""
            for t in ev_tags:
                if t.startswith('zsazsa:ctiproduct='):
                    ptype = t.split('=', 1)[1].strip('"')
                    break
            matches.append(SimpleNamespace(
                uuid=ev.uuid,
                info=info,
                date=str(ev.date) if ev.date else "",
                product_type=ptype,
                misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{ev.uuid}",
            ))
    # Include directly delivered products for subscribed product types.
    stakeholder = get_stakeholder(stakeholder_uuid)
    subscribed_products = set(getattr(stakeholder, "products", []) or [])

    if "Daily threat briefing" in subscribed_products:
        for briefing in list_briefings():
            if getattr(briefing, "review_state", "") != BRIEFING_REVIEW_PUBLISHED:
                continue
            title = (getattr(briefing, "title", "") or "").strip()
            date_value = getattr(briefing, "date", "") or ""
            info = f"[zsazsa:briefing] {title}" if title else f"[zsazsa:briefing] Daily threat briefing {date_value}"
            matches.append(SimpleNamespace(
                uuid=briefing.uuid,
                info=info,
                date=date_value,
                product_type="daily-briefing",
                misp_url=briefing.misp_url,
            ))

    if "Flash intel alert" in subscribed_products:
        for fia in list_fias(review_state=FIA_REVIEW_APPROVED):
            title = (getattr(fia, "title", "") or "").strip()
            info = f"[zsazsa:fia] {title}" if title else f"[zsazsa:fia] {fia.fia_id}"
            date_value = ""
            created_at = getattr(fia, "created_at", None)
            if created_at:
                date_value = created_at.strftime("%Y-%m-%d")
            matches.append(SimpleNamespace(
                uuid=fia.uuid,
                info=info,
                date=date_value,
                product_type="flash-intel",
                misp_url=fia.misp_url,
            ))

    if "Vulnerability advisory" in subscribed_products:
        for vea in list_veas(review_state=VEA_REVIEW_APPROVED):
            title = (getattr(vea, "title", "") or "").strip()
            info = f"[zsazsa:vea] {title}" if title else f"[zsazsa:vea] {vea.vea_id}"
            date_value = ""
            created_at = getattr(vea, "created_at", None)
            if created_at:
                date_value = created_at.strftime("%Y-%m-%d")
            matches.append(SimpleNamespace(
                uuid=vea.uuid,
                info=info,
                date=date_value,
                product_type="vea",
                misp_url=vea.misp_url,
            ))

    # De-duplicate by UUID and keep the newest items first.
    deduped = []
    seen = set()
    for item in sorted(matches, key=lambda r: (r.date or ""), reverse=True):
        if item.uuid in seen:
            continue
        seen.add(item.uuid)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


# ── Flash Intel Alert (FIA) CRUD ──────────────────────────────────────────────

# Workflow review states for FIA drafts
FIA_REVIEW_DRAFT = "draft"
FIA_REVIEW_PENDING = "pending-review"
FIA_REVIEW_APPROVED = "approved"
FIA_REVIEW_REJECTED = "rejected"
FIA_REVIEW_STATES = [
    FIA_REVIEW_DRAFT,
    FIA_REVIEW_PENDING,
    FIA_REVIEW_APPROVED,
    FIA_REVIEW_REJECTED,
]

FIA_AUDIENCES = list(STAKEHOLDER_ROLES)
FIA_TLP_LEVELS = ["clear", "green", "amber", "amber+strict", "red"]
# Least to most restrictive, so a clearance covers every level at or below its own.
_TLP_RANK = {level: i for i, level in enumerate(FIA_TLP_LEVELS)}
FIA_RELIABILITIES = ["A", "B", "C", "D", "E", "F"]
FIA_CREDIBILITIES = ["1", "2", "3", "4", "5", "6"]

# Estimative-language confidence, from the MISP estimative-language taxonomy
# (confidence-in-analytic-judgment predicate). Stored as the lower-case value;
# the description is shown as help text.
ESTIMATIVE_CONFIDENCE = [
    ("low", "Low", "Uncorroborated information from good or marginal sources. Many assumptions. Mostly weak logical inferences."),
    ("moderate", "Moderate", "Partially corroborated information from good sources. Several assumptions. Mix of strong and weak inferences."),
    ("high", "High", "Well-corroborated information from proven sources. Minimal assumptions. Strong logical inferences and methods."),
]

_ROLE_ALIASES = {
    "soc": "SOC",
    "ir": "Incident Response",
    "incident response": "Incident Response",
    "cti": "Cyber Threat Intelligence",
    "cyber threat intelligence": "Cyber Threat Intelligence",
    "threat hunting": "Threat Hunting",
    "detection eng.": "Detection Engineering",
    "detection engineering": "Detection Engineering",
    "vm": "Vulnerability Management",
    "vulnerability management": "Vulnerability Management",
    "third party risk management": "Third Party Risk Management",
    "it security": "IT Security",
    "executive": "CISO / Leadership",
    "ciso / leadership": "CISO / Leadership",
    "other": "Other",
}


def _canonical_role(value: str) -> str:
    if not value:
        return ""
    v = value.strip()
    if not v:
        return ""
    if v in STAKEHOLDER_ROLES:
        return v
    return _ROLE_ALIASES.get(v.lower(), v)


def _split_lines(s):
    """Split a textarea value into a stripped non-empty list of lines."""
    if not s:
        return []
    return [ln.strip() for ln in s.splitlines() if ln.strip()]


def _clean_source_hints(raw, allowed_uuids):
    """Filter a raw {uuid: source_id} mapping to the allowed UUID set."""
    out = {}
    if not isinstance(raw, dict):
        return out
    allowed = set(allowed_uuids or [])
    for key, value in raw.items():
        uid = _extract_uuid(str(key))
        source_id = str(value or "").strip()
        if uid and source_id and uid in allowed:
            out[uid] = source_id
    return out


def _parse_source_uuid_blob(raw):
    """Parse the stored source-event-uuid attribute, which may be a JSON list or a single UUID."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return [u for u in [_extract_uuid(raw)] if u]
    if isinstance(parsed, list):
        items = parsed
    elif parsed:
        items = [str(parsed)]
    else:
        items = []
    return [u for u in (_extract_uuid(v) for v in items) if u]


def _normalise_source_uuids_and_hints(source_uuids_raw, source_event_uuid_raw, source_hints_raw):
    """Return cleaned source UUID list and UUID->source_id hints map."""
    source_uuids = [_extract_uuid(str(v)) for v in (source_uuids_raw or [])]
    source_uuids = [u for u in source_uuids if u]
    if not source_uuids and source_event_uuid_raw:
        first = _extract_uuid(str(source_event_uuid_raw))
        if first:
            source_uuids = [first]
    return source_uuids, _clean_source_hints(source_hints_raw, source_uuids)


def _all_source_clients():
    """Build an ordered (source_id, misp_client, label) list: scraper, MISP_SERVERS, webapp."""
    from pymisp import PyMISP as _PyMISP
    clients = [("scraper", _scraper_misp(), "MISP scraper")]
    for s in getattr(config, "MISP_SERVERS", []) or []:
        sid = s.get("id") or s.get("label") or ""
        url = s.get("url")
        api_key = s.get("api_key")
        if url and api_key:
            try:
                clients.append((sid, _PyMISP(url, api_key, s.get("verify_tls", True), False),
                                s.get("label") or url))
            except Exception as exc:
                logger.warning("skipping MISP server %r (%s): could not connect: %s",
                               sid, url, exc)
    if (config.MISP_WEBAPP_URL != config.MISP_URL
            and config.MISP_WEBAPP_KEY != config.MISP_KEY):
        try:
            clients.append(("webapp", _misp(), "MISP webapp"))
        except Exception as exc:
            logger.warning("skipping MISP webapp store (%s): could not connect: %s",
                           config.MISP_WEBAPP_URL, exc)
    return clients


def _order_clients_by_hint(clients, hinted_sid="", strict_source=False):
    """Reorder a client list so the hinted source is tried first (or only, if strict).

    Manual collection sources (ids starting with "manual-") live on the webapp
    MISP and are not part of the base client list, so an unmatched hint falls
    back to _misp().
    """
    if not hinted_sid:
        return clients
    hinted = [(sid, cl, lbl) for sid, cl, lbl in clients if sid == hinted_sid]
    if not hinted:
        try:
            hinted = [(hinted_sid, _misp(), hinted_sid)]
        except Exception:
            hinted = []
    if strict_source:
        return hinted
    return hinted + [(sid, cl, lbl) for sid, cl, lbl in clients if sid != hinted_sid]


def _try_fetch_event(misp_client, uuid):
    """Try get_event, fall back to search if it returns a 404-style error.

    Some MISP instances allow bulk search but reject direct UUID lookups due
    to distribution restrictions, so search(uuid=...) is a useful fallback.
    """
    # get_event failing is an expected case (distribution restrictions), so this
    # falls through to the search() path below rather than treating it as an error.
    try:
        fetched = misp_client.get_event(uuid, pythonify=True)
        if fetched and not isinstance(fetched, dict):
            return fetched
    except Exception as exc:
        logger.debug("get_event(%s) failed, trying search fallback: %s", uuid, exc)
    try:
        results = misp_client.search(uuid=uuid, pythonify=True, metadata=False)
        if results and not isinstance(results, dict) and len(results) > 0:
            return results[0]
    except Exception as exc:
        logger.debug("search(uuid=%s) fallback failed: %s", uuid, exc)
    return None


def resolve_source_event(ev_uuid, source_hint=""):
    """Fetch a MISP event by UUID, trying the hinted source's client first.

    Unlike fetch_source_events (which flattens events into plain dicts for the
    product-wizard accordions), this returns the live MISPEvent object together
    with the client it came from, so callers can use helpers such as
    extract_source_url / extract_story_context that expect MISPEvent
    attribute/tag objects.

    Returns (event, misp_client, source_id), or (None, None, "") when the
    event cannot be retrieved from any configured MISP instance.
    """
    uuid = _extract_uuid(str(ev_uuid))
    if not uuid:
        return None, None, ""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ordered = _order_clients_by_hint(_all_source_clients(), source_hint)
    for sid, misp_client, _label in ordered:
        ev = _try_fetch_event(misp_client, uuid)
        if ev is not None:
            return ev, misp_client, sid
    return None, None, ""


def live_reports(event) -> list:
    """Event reports minus the deleted ones, which MISP keeps on the event.

    Everything that counts or shows reports has to skip those, or a report
    someone removed comes back as content on a page or as a number on a button.
    """
    return [r for r in (getattr(event, "event_reports", []) or [])
            if not getattr(r, "deleted", False)]


def format_event_attributes_text(event) -> str:
    """Render an event's attributes and any report content as markdown text.

    The attributes are emitted as a markdown table so they stay structured in
    the briefing story body, while report content is appended below it.
    """
    rows = []
    for a in getattr(event, "attributes", []) or []:
        rows.append((a.value, a.type, bool(getattr(a, "to_ids", False)), ""))
    for obj in getattr(event, "objects", []) or []:
        obj_name = getattr(obj, "name", "") or "object"
        for a in getattr(obj, "attributes", []) or []:
            rows.append((a.value, a.type, bool(getattr(a, "to_ids", False)), obj_name))

    def _cell(value) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ").strip()

    table_lines = []
    if rows:
        table_lines.append("| Value | Type | To IDS | Object |")
        table_lines.append("| --- | --- | --- | --- |")
        for value, type_, to_ids, obj_name in rows:
            table_lines.append(
                f"| {_cell(value)} | {_cell(type_)} | {'Yes' if to_ids else 'No'} | {_cell(obj_name)} |"
            )

    report_texts = []
    for r in live_reports(event):
        content = (getattr(r, "content", "") or "").strip()
        if content:
            report_texts.append(content)

    parts = []
    if table_lines:
        parts.append("\n".join(table_lines))
    if report_texts:
        parts.append("\n\n".join(report_texts))
    return "\n\n".join(parts)


def fetch_source_events(source_uuids, source_hints=None, strict_source=False):
    """Fetch event data for display in product wizard source event accordions.

    source_hints is an optional dict mapping uuid -> source_id.
    When provided, the matching MISP client is tried first.
    If strict_source=True, only the hinted client is queried for that UUID.

    For each UUID we try get_event first, then search(uuid=...) as a fallback
    because some MISP instances (e.g. those with distribution restrictions)
    allow bulk search but reject direct UUID lookups.

    Returns a list of dicts with keys: uuid, info, date, orgc, source_id, source_label, source_url,
    tags, reports, attributes, objects.
    """
    raw_values = list(source_uuids or [])
    source_uuids = []
    for raw in raw_values:
        uid = _extract_uuid(str(raw))
        if uid:
            source_uuids.append(uid)
    if not source_uuids:
        return []
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    hints = source_hints or {}
    all_clients = _all_source_clients()

    result = []
    for uuid in source_uuids:
        ev = ev_misp = None
        ev_source_id = ""
        ev_source_label = ""
        hinted_sid = hints.get(uuid, "")
        ordered = _order_clients_by_hint(all_clients, hinted_sid, strict_source)

        for sid, misp_client, label in ordered:
            fetched = _try_fetch_event(misp_client, uuid)
            if fetched is not None:
                ev, ev_misp, ev_source_id, ev_source_label = fetched, misp_client, sid, label
                break

        if ev is None:
            logger.debug("fetch_source_events: could not retrieve %s from any MISP client", uuid)
            continue
        orgc_name = ""
        orgc_obj = getattr(ev, "Orgc", None) or getattr(ev, "orgc", None)
        if orgc_obj:
            orgc_name = getattr(orgc_obj, "name", "") or ""
        try:
            reports = ev_misp.get_event_reports(ev.id, pythonify=True) or []
        except Exception:
            reports = []
        tags = [t.name for t in getattr(ev, "tags", []) or []]
        attrs = []
        for a in getattr(ev, "attributes", []) or []:
            attrs.append({
                "type": a.type,
                "category": getattr(a, "category", "") or "",
                "value": a.value,
                "comment": getattr(a, "comment", "") or "",
                "to_ids": bool(getattr(a, "to_ids", False)),
            })
        objects = []
        for obj in getattr(ev, "objects", []) or []:
            obj_attrs = []
            for a in getattr(obj, "attributes", []) or []:
                obj_attrs.append({
                    "relation": getattr(a, "object_relation", "") or "",
                    "type": a.type,
                    "value": a.value,
                })
            objects.append({"name": getattr(obj, "name", "") or "", "attributes": obj_attrs})
        result.append({
            "uuid": uuid,
            "info": ev.info or "",
            "date": str(ev.date) if ev.date else "",
            "orgc": orgc_name,
            "source_id": ev_source_id,
            "source_label": ev_source_label,
            "source_url": (getattr(ev_misp, "root_url", "") or "").rstrip("/"),
            "tags": tags,
            "attributes": attrs,
            "objects": objects,
            "reports": [
                {"name": getattr(r, "name", "") or "Report",
                 "content": getattr(r, "content", "") or "",
                 "date": report_date(r)}
                for r in reports
            ],
        })
    return result


# ── Manual collection source registry ───────────────────────────────────────

TAG_COLLECTION_SOURCE = 'zsazsa:type="collection-source"'


_ADMIRALTY_SOURCE_TAGS = {
    "A": 'admiralty-scale:source-reliability="a"',
    "B": 'admiralty-scale:source-reliability="b"',
    "C": 'admiralty-scale:source-reliability="c"',
    "D": 'admiralty-scale:source-reliability="d"',
    "E": 'admiralty-scale:source-reliability="e"',
    "F": 'admiralty-scale:source-reliability="f"',
}


def _collection_source_ns(event):
    """Extract a CollectionSource namespace from a MISP event."""
    obj = _get_obj(event, "zsazsa-collection-source")
    if obj is None:
        return None
    ev_tags = [t.name for t in (getattr(event, "tags", []) or [])]
    source_reliability = ""
    for tag in ev_tags:
        if tag.startswith("admiralty-scale:source-reliability="):
            val = tag.split("=", 1)[1].strip('"')
            source_reliability = val[0].upper() if val else ""
            break
    if not source_reliability:
        raw = _obj_attr(obj, "source-reliability")
        if raw:
            source_reliability = raw[0].upper()
    misp_url = (getattr(config, "MISP_WEBAPP_URL", "") or
                getattr(config, "MISP_URL", "")).rstrip("/")
    ns = SimpleNamespace(
        uuid=event.uuid,
        misp_url=f"{misp_url}/events/view/{event.uuid}",
        name=_obj_attr(obj, "name"),
        owner=_obj_attr(obj, "owner"),
        location=_obj_attr(obj, "location"),
        description=_obj_attr(obj, "description"),
        enabled=_obj_attr(obj, "enabled") != "false",
        source_reliability=source_reliability,
    )
    return ns


def list_collection_sources():
    """Return all manual collection source registry entries."""
    misp = _misp()
    try:
        events = misp.search(tags=[TAG_COLLECTION_SOURCE], limit=200,
                             metadata=False, pythonify=True)
        if isinstance(events, dict):
            return []
    except Exception:
        return []
    result = []
    for ev in events or []:
        ns = _collection_source_ns(ev)
        if ns:
            result.append(ns)
    result.sort(key=lambda s: (s.name or "").lower())
    return result


def get_collection_source(uuid):
    """Fetch a single collection source entry. Returns namespace or None."""
    misp = _misp()
    try:
        ev = misp.get_event(uuid, pythonify=True)
        if not ev or isinstance(ev, dict):
            return None
        return _collection_source_ns(ev)
    except Exception:
        return None


def _collection_source_obj(data: dict, enabled: bool = True):
    obj = _build_obj("zsazsa-collection-source")
    _oa(obj, "name", (data.get("name") or "").strip())
    _oa(obj, "owner", data.get("owner", ""))
    _oa(obj, "location", data.get("location", ""))
    _oa(obj, "description", data.get("description", ""))
    _oa(obj, "source-reliability", data.get("source_reliability", ""))
    _oa(obj, "enabled", "true" if enabled else "false")
    return obj


def _apply_admiralty_tag(misp, event_uuid, source_reliability: str):
    """Remove any existing admiralty source-reliability tag and apply the new one."""
    ev = misp.get_event(event_uuid, pythonify=True)
    if not ev or isinstance(ev, dict):
        return
    for tag in list(getattr(ev, "tags", []) or []):
        if getattr(tag, "name", "").startswith("admiralty-scale:source-reliability="):
            try:
                misp.untag(event_uuid, tag.name)
            except Exception:
                pass
    if source_reliability and source_reliability.upper() in _ADMIRALTY_SOURCE_TAGS:
        misp.tag(event_uuid, _ADMIRALTY_SOURCE_TAGS[source_reliability.upper()])


def create_collection_source(data: dict) -> str:
    """Create a manual collection source registry event. Returns the new UUID."""
    misp = _misp()
    name = (data.get("name") or "").strip()
    reliability = (data.get("source_reliability") or "").strip().upper()
    extra_tags = ["tlp:amber"]
    if reliability and reliability in _ADMIRALTY_SOURCE_TAGS:
        extra_tags.append(_ADMIRALTY_SOURCE_TAGS[reliability])
    event = _make_event(
        f"Collection source: {name}",
        extra_tags=extra_tags,
    )
    event = _add_event(misp, event, [TAG_COLLECTION_SOURCE], "create collection source")
    _check(misp.add_object(event.uuid, _collection_source_obj(data), pythonify=True),
           "add collection source object")
    return event.uuid


def update_collection_source(uuid, data: dict):
    """Update a collection source: replace the MISP object with new field values."""
    misp = _misp()
    ev = misp.get_event(uuid, pythonify=True)
    if not ev or isinstance(ev, dict):
        raise ValueError(f"Collection source {uuid} not found")
    old_enabled = True
    old_obj = _get_obj(ev, "zsazsa-collection-source")
    if old_obj is not None:
        old_enabled = _obj_attr(old_obj, "enabled") != "false"
        misp.delete_object(old_obj.id)
    new_enabled = data["enabled"] if "enabled" in data else old_enabled
    _check(misp.add_object(uuid, _collection_source_obj(data, enabled=new_enabled),
                            pythonify=True), "update collection source object")
    new_info = f"Collection source: {(data.get('name') or '').strip()}"
    misp.update_event({"Event": {"id": ev.id, "info": new_info}})
    _apply_admiralty_tag(misp, uuid, data.get("source_reliability", ""))


def toggle_collection_source(uuid, enabled: bool):
    """Enable or disable a collection source."""
    misp = _misp()
    ev = misp.get_event(uuid, pythonify=True)
    if not ev or isinstance(ev, dict):
        raise ValueError(f"Collection source {uuid} not found")
    old_obj = _get_obj(ev, "zsazsa-collection-source")
    if old_obj is None:
        raise ValueError("Object not found on collection source event")
    data = {
        "name": _obj_attr(old_obj, "name"),
        "owner": _obj_attr(old_obj, "owner"),
        "location": _obj_attr(old_obj, "location"),
        "description": _obj_attr(old_obj, "description"),
        "source_reliability": _obj_attr(old_obj, "source-reliability"),
    }
    misp.delete_object(old_obj.id)
    _check(misp.add_object(uuid, _collection_source_obj(data, enabled=enabled),
                            pythonify=True), "toggle collection source")


def delete_collection_source(uuid):
    """Delete a collection source registry event from MISP."""
    misp = _misp()
    _check(misp.delete_event(uuid), "delete collection source")


def imap_source_labels() -> list[str]:
    """Collection sources defined in IMAP mailboxes, as "<mailbox>/<source>".

    These mailboxes feed their events into the scraper MISP. Only enabled
    mailboxes and enabled sources are included.
    """
    labels = []
    for mailbox in getattr(config, "IMAP_SOURCES", []) or []:
        if not mailbox.get("enabled", True):
            continue
        mailbox_name = (mailbox.get("name") or "").strip()
        for source in mailbox.get("sources", []) or []:
            if not source.get("enabled", True):
                continue
            source_name = (source.get("name") or "").strip()
            if not source_name:
                continue
            labels.append(f"{mailbox_name}/{source_name}" if mailbox_name else source_name)
    return labels


def get_all_collection_source_labels() -> list[str]:
    """Return a combined list of all collection source labels.

    Includes the fixed scraper source, configured MISP servers (enabled only),
    MISP-stored manual sources (enabled only), and each enabled IMAP mailbox
    source listed as "<mailbox>/<source>".
    """
    labels = ["misp-scraper"]
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if s.get("enabled", True):
            label = (s.get("label") or "").strip()
            if label and label not in labels:
                labels.append(label)
    for label in imap_source_labels():
        if label not in labels:
            labels.append(label)
    try:
        for src in list_collection_sources():
            if src.enabled and src.name and src.name not in labels:
                labels.append(src.name)
    except Exception:
        pass
    return labels


def create_manual_collection_event(data: dict) -> str:
    """Create a manually-entered collection event on the webapp MISP server.

    Returns the new event UUID.
    """
    from pymisp import MISPEventReport
    misp = _misp()

    tlp = data.get("tlp", "amber")
    source = (data.get("source") or "").strip()
    slug = source_slug(source)

    info = (data.get("title") or "").strip()
    event = _make_event(
        info,
        extra_tags=[f"tlp:{tlp}"],
    )
    if data.get("date"):
        event.date = data["date"]

    created = misp.add_event(event, pythonify=True)
    if isinstance(created, dict):
        raise RuntimeError(f"MISP error: {created.get('errors') or created}")

    uuid = created.uuid

    _tag_local(misp, uuid, 'zsazsa:source-type="manual"')
    if slug:
        _tag_local(misp, uuid, f'zsazsa:source="{slug}"')

    for t in _build_scope_tags(data):
        try:
            misp.tag(uuid, t)
        except Exception:
            # The scope tags are what matches this entry against a PIR or GIR
            # later, so a lost one is worth knowing about.
            logger.warning("manual entry %s: could not apply scope tag %s", uuid, t)

    try:
        misp.tag(uuid, 'workflow:state="incomplete"', local=True)
    except Exception:
        logger.warning("manual entry %s: could not set its workflow state", uuid)

    source_reference = (data.get("source_reference") or "").strip()
    if source_reference:
        a = MISPAttribute()
        a.type = "link"
        a.category = "External analysis"
        a.value = source_reference
        a.comment = "Source reference"
        a.to_ids = False
        _check(misp.add_attribute(created.id, a), "add source reference")

    source_provider = (data.get("source_provider") or "").strip()
    if source_provider:
        a = MISPAttribute()
        a.type = "text"
        a.category = "Other"
        a.value = source_provider
        a.comment = "Source provider"
        a.to_ids = False
        _check(misp.add_attribute(created.id, a), "add source provider")

    # "link" rather than "url": these point at the article or advisory this entry
    # was written from, which is a reference and not an indicator. It is also the
    # type every reader of a source event looks for, so a reference stored as
    # "url" never reaches a product's reference list.
    for reference in data.get("references") or []:
        reference = reference.strip()
        if reference:
            a = MISPAttribute()
            a.type = "link"
            a.category = "External analysis"
            a.value = reference
            a.comment = "External reference"
            a.to_ids = False
            _check(misp.add_attribute(created.id, a), "add external reference")

    description = (data.get("description") or "").strip()
    if description:
        report = MISPEventReport()
        report.name = info or "Manual entry"
        report.content = description
        report.distribution = 5
        _check(misp.add_event_report(created.id, report), "add manual entry report")

    summary = (data.get("summary") or "").strip()
    if summary:
        ai_report = MISPEventReport()
        ai_report.name = f"{AI_SUMMARY_PREFIX} {(info or 'Manual entry')[:80]}"
        ai_report.content = summary
        ai_report.distribution = 5
        _check(misp.add_event_report(created.id, ai_report), "add AI summary report")

    return uuid


NEWSLETTER_PENDING_TAG = 'zsazsa:newsletter-status="pending-review"'
_NEWSLETTER_REPORT_PREFIX = "Newsletter source: "
# Records which parser produced a newsletter, so the review screen can re-parse
# even when the source name differs from the parser name.
_NEWSLETTER_PARSER_TAG_PREFIX = 'zsazsa:newsletter-parser='


def _add_scraper_link(misp, event_ref, url: str) -> None:
    """Add a 'pushed to scraper' link attribute to an event (id or uuid)."""
    a = MISPAttribute()
    a.type = "link"
    a.category = "External analysis"
    a.value = url
    a.comment = "Pushed to scraper"
    a.to_ids = False
    _check(misp.add_attribute(event_ref, a), "add scraper link")


def create_newsletter_event(source: str, raw_email: str, report_title: str = "",
                            tlp: str = "", reliability: str = "", parser: str = "",
                            article_urls: list | None = None,
                            status: str = "processed") -> str:
    """Archive a newsletter as an event on the webapp MISP server.

    `source` is the collection-source name; it is recorded so the newsletter can
    always be found back, and the pushed article URLs are added as link
    attributes so MISP correlates this event with the scraper events created from
    them. `parser` records which parser produced it, so the review screen can
    re-parse even when the source name differs from the parser name. With
    status="pending-review" the event is tagged for the review queue before its
    articles are pushed. Returns the new event UUID.
    """
    from pymisp import MISPEventReport
    misp = _misp()

    title = (report_title or "").strip() or f"{source} newsletter"
    extra_tags = [f"tlp:{tlp}"] if tlp else []
    rel = (reliability or "").strip().upper()
    if rel in _ADMIRALTY_SOURCE_TAGS:
        extra_tags.append(_ADMIRALTY_SOURCE_TAGS[rel])
    event = _make_event(f"[zsazsa:newsletter] {title}", extra_tags=extra_tags)
    created = misp.add_event(event, pythonify=True)
    if isinstance(created, dict):
        raise RuntimeError(f"MISP error: {created.get('errors') or created}")
    uuid = created.uuid

    _tag_local(misp, uuid, 'zsazsa:source-type="newsletter"')
    _tag_local(misp, uuid, f'zsazsa:source="{source_slug(source)}"')
    if parser:
        _tag_local(misp, uuid, f'{_NEWSLETTER_PARSER_TAG_PREFIX}"{parser}"')
    if status == "pending-review":
        _tag_local(misp, uuid, NEWSLETTER_PENDING_TAG)

    if raw_email.strip():
        report = MISPEventReport()
        report.name = f"{_NEWSLETTER_REPORT_PREFIX}{source}"
        report.content = raw_email
        report.distribution = 5
        _check(misp.add_event_report(created.id, report), "add newsletter report")

    for url in article_urls or []:
        if url.strip():
            _add_scraper_link(misp, created.id, url.strip())

    return uuid


def list_pending_newsletters() -> list[dict]:
    """Newsletter events archived but awaiting manual review before their articles
    are pushed. Returns lightweight dicts (uuid, info, date)."""
    misp = _misp()
    try:
        events = misp.search(tags=[NEWSLETTER_PENDING_TAG], limit=200,
                             metadata=True, pythonify=True)
        if isinstance(events, dict):
            logger.warning("could not list pending newsletters: %s", events.get("errors") or events)
            return []
    except Exception:
        # An empty queue and an unreachable MISP look the same on the page, and
        # one of them means newsletters are waiting that nobody will see.
        logger.exception("could not list pending newsletters")
        return []
    out = [
        {"uuid": ev.uuid, "info": getattr(ev, "info", ""), "date": str(getattr(ev, "date", ""))}
        for ev in events or []
    ]
    out.sort(key=lambda n: n["date"], reverse=True)
    return out


def get_newsletter_for_review(uuid: str) -> dict | None:
    """Return {uuid, feed, parser, raw_email} for an archived newsletter, or None.

    `feed` is the source name (recovered from the report) used when pushing to
    the scraper; `parser` is the parser to re-parse with. Older newsletters
    archived before sources were named carry no parser tag, so the feed name
    (which then equalled the parser) is used as the fallback.
    """
    misp = _misp()
    try:
        event = misp.get_event(uuid, pythonify=True)
        if not event or isinstance(event, dict):
            return None
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        logger.exception("could not read newsletter %s for review", uuid)
        return None
    parser = ""
    for tag in getattr(event, "tags", []) or []:
        name = getattr(tag, "name", "") or ""
        if name.startswith(_NEWSLETTER_PARSER_TAG_PREFIX):
            parser = name[len(_NEWSLETTER_PARSER_TAG_PREFIX):].strip().strip('"')
            break
    for rep in reports:
        name = getattr(rep, "name", "") or ""
        if name.startswith(_NEWSLETTER_REPORT_PREFIX):
            feed = name[len(_NEWSLETTER_REPORT_PREFIX):].strip()
            return {"uuid": uuid, "feed": feed, "parser": parser or feed,
                    "raw_email": getattr(rep, "content", "") or ""}
    return None


def mark_newsletter_pending(uuid: str) -> None:
    """Flag an already-archived newsletter for manual review (e.g. when the
    automatic scraper push found no listener)."""
    _tag_local(_misp(), uuid, NEWSLETTER_PENDING_TAG)


def finalize_newsletter(uuid: str, article_urls: list | None = None) -> None:
    """Clear the pending-review flag and record the pushed article URLs."""
    misp = _misp()
    try:
        misp.untag(uuid, NEWSLETTER_PENDING_TAG)
    except Exception:
        logger.warning("could not clear pending tag on newsletter %s", uuid)
    for url in article_urls or []:
        if (url or "").strip():
            _add_scraper_link(misp, uuid, url.strip())


_DATA_COLLECTION_SOURCE_TAG_PREFIX = "scraper:data-collection-source:"


def data_collection_source_counts() -> list[dict]:
    """Live event count per data-collection-source on the scraper MISP.

    Returns ``[{"source_feed": name, "n": count}, ...]`` sorted by count, read
    from MISP's tag statistics in a single call so it reflects the actual events
    carrying each ``scraper:data-collection-source`` tag rather than the
    analyser's processing log. Returns ``[]`` if the instance is unreachable.
    """
    try:
        stats = _scraper_misp().tags_statistics()
    except Exception as exc:
        logger.warning("data_collection_source_counts failed: %s", exc)
        return []
    tags = stats.get("tags") if isinstance(stats, dict) else None
    if not isinstance(tags, dict):
        return []
    rows = []
    for name, count in tags.items():
        if not name.startswith(_DATA_COLLECTION_SOURCE_TAG_PREFIX):
            continue
        try:
            n = int(count)
        except (TypeError, ValueError):
            continue
        rows.append({"source_feed": name[len(_DATA_COLLECTION_SOURCE_TAG_PREFIX):], "n": n})
    rows.sort(key=lambda r: r["n"], reverse=True)
    return rows


def add_manual_collection_attachment(event_uuid: str, filename: str, file_bytes: bytes) -> str:
    """Add a file attachment to a manually-entered collection event on the webapp MISP.

    Returns the new attribute UUID.
    """
    import base64
    misp = _misp()
    attr = MISPAttribute()
    attr.type = "attachment"
    attr.category = "External analysis"
    attr.value = filename
    attr.data = base64.b64encode(file_bytes).decode("utf-8")
    attr.to_ids = False
    result = _check(misp.add_attribute(event_uuid, attr, pythonify=True), "add manual attachment")
    return result.uuid


def get_manual_collection_event(uuid: str):
    """Fetch a manual collection event from the webapp MISP. Returns a plain dict or None."""
    misp = _misp()
    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception:
        return None
    if not event or isinstance(event, dict):
        return None
    tags = [t.name for t in getattr(event, "tags", []) or []]
    attrs = []
    for a in getattr(event, "attributes", []) or []:
        attrs.append({
            "uuid": a.uuid,
            "type": a.type,
            "category": getattr(a, "category", "") or "",
            "value": a.value,
            "comment": getattr(a, "comment", "") or "",
        })
    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        reports = []
    source_provider = next(
        (a["value"] for a in attrs if a.get("comment") == "Source provider"),
        "",
    )
    return {
        "uuid": event.uuid,
        "id": event.id,
        "info": event.info or "",
        "date": str(event.date) if event.date else "",
        "tags": tags,
        "attributes": attrs,
        "source_provider": source_provider,
        "reports": [
            {"name": getattr(r, "name", "") or "Report",
             "content": getattr(r, "content", "") or "",
             "date": report_date(r)}
            for r in reports
        ],
    }


def _join_lines(items):
    return "\n".join(items or [])


def _fia_obj(data):
    obj = _build_obj("zsazsa-flash-intel")
    _oa(obj, "fia-id", data.get("fia_id"))
    _oa(obj, "title", data.get("title"))
    _oa(obj, "audience", data.get("audience"))
    _oa(obj, "tlp", data.get("tlp", "amber"))
    _oa(obj, "summary", data.get("summary"))
    _oa(obj, "action-required", data.get("action_required"))
    _oa(obj, "what-happened", _join_lines(data.get("what_happened")))
    _oa(obj, "source-description", data.get("source_description"))
    _oa(obj, "source-reliability", data.get("source_reliability"))
    _oa(obj, "information-credibility", data.get("information_credibility"))
    _oa(obj, "likely-impact", data.get("likely_impact"))
    _oa(obj, "affected-assets", data.get("affected_assets"))
    _oa_json(obj, "actor-types", data.get("actor_types", []))
    _oa(obj, "actor-context", data.get("actor_context"))
    _oa(obj, "write-up", data.get("write_up"))
    _oa_json(obj, "mitre-attack-techniques", data.get("mitre_attack_techniques", []))
    _oa_json(obj, "geographic-scope", data.get("geographic_scope", []))
    _oa_json(obj, "sectors", data.get("sectors", []))
    _oa_json(obj, "threat-actors", data.get("threat_actors", []))
    _oa_json(obj, "threat-types", data.get("threat_types", []))
    _oa_json(obj, "technology", data.get("technology", []))
    _oa_json(obj, "vendor", data.get("vendor", []))
    _oa_json(obj, "incident", data.get("incident", []))
    _oa_json(obj, "campaign", data.get("campaign", []))
    _oa(obj, "actions-immediate", _join_lines(data.get("actions_immediate")))
    _oa(obj, "actions-near-term", _join_lines(data.get("actions_near_term")))
    _oa(obj, "mitre-techniques", _join_lines(data.get("mitre_techniques")))
    _oa(obj, "hunting-hypotheses", _join_lines(data.get("hunting_hypotheses")))
    _oa(obj, "external-references", _join_lines(data.get("external_references")))
    _oa(obj, "intelligence-gaps", data.get("intelligence_gaps"))
    _oa(obj, "feedback-deadline", data.get("feedback_deadline"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "review-state", data.get("review_state", FIA_REVIEW_DRAFT))
    _oa(obj, "rejection-reason", data.get("rejection_reason"))
    src_uuids, src_hints = _normalise_source_uuids_and_hints(
        data.get("source_event_uuids"),
        data.get("source_event_uuid"),
        data.get("source_event_hints"),
    )
    _oa_json(obj, "source-event-uuid", src_uuids)
    _oa_json(obj, "source-event-hints", src_hints)
    _oa_json(obj, "context-tags", data.get("context_tags", []))
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "approved-by", data.get("approved_by"))
    return obj


def _fia_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-flash-intel")

    def g(rel):
        return _obj_attr(obj, rel) or ""

    review_state = g("review-state") or FIA_REVIEW_DRAFT
    source_event_uuids = _parse_source_uuid_blob(g("source-event-uuid"))
    try:
        _src_hints_parsed = json.loads(g("source-event-hints") or "{}")
    except Exception:
        _src_hints_parsed = {}
    source_event_hints = _clean_source_hints(_src_hints_parsed, source_event_uuids)

    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        fia_id=g("fia-id"),
        title=g("title"),
        audience=g("audience"),
        tlp=g("tlp") or "amber",
        summary=g("summary"),
        action_required=g("action-required"),
        what_happened=g("what-happened").splitlines(),
        source_description=g("source-description"),
        source_reliability=g("source-reliability"),
        information_credibility=g("information-credibility"),
        likely_impact=g("likely-impact"),
        affected_assets=g("affected-assets"),
        actor_types=_json_list(g("actor-types")),
        actor_context=g("actor-context"),
        write_up=g("write-up"),
        mitre_attack_techniques=_json_list(g("mitre-attack-techniques")),
        geographic_scope=_json_list(g("geographic-scope")),
        sectors=_json_list(g("sectors")),
        threat_actors=_json_list(g("threat-actors")),
        threat_types=_json_list(g("threat-types")),
        technology=_json_list(g("technology")),
        vendor=_json_list(g("vendor")),
        incident=_json_list(g("incident")),
        campaign=_json_list(g("campaign")),
        actions_immediate=g("actions-immediate").splitlines(),
        actions_near_term=g("actions-near-term").splitlines(),
        mitre_techniques=g("mitre-techniques").splitlines(),
        hunting_hypotheses=g("hunting-hypotheses").splitlines(),
        external_references=g("external-references").splitlines(),
        intelligence_gaps=g("intelligence-gaps"),
        feedback_deadline=_parse_date(g("feedback-deadline")),
        author=g("author"),
        review_state=review_state,
        rejection_reason=g("rejection-reason"),
        source_event_uuids=source_event_uuids,
        source_event_hints=source_event_hints,
        source_event_uuid=source_event_uuids[0] if source_event_uuids else "",
        context_tags=_json_list(g("context-tags")),
        linked_pir_uuid=g("linked-pir-uuid"),
        creator=g("creator"),
        approved_by=g("approved-by"),
        attachments=_fia_attachments(event),
        published=bool(getattr(event, "published", False)),
        published_at=_published_at(event),
        created_at=_parse_dt(event.date.isoformat() if event.date else None),
    )


def _fia_id_from_event_id(event_id):
    return f"FIA-{int(event_id):05d}"


def _source_server_url_map():
    """Map a source-event server id to its MISP web URL, from config (no network)."""
    mapping = {"scraper": config.MISP_URL, "webapp": config.MISP_WEBAPP_URL}
    for server in getattr(config, "MISP_SERVERS", []) or []:
        sid = server.get("id") or server.get("label") or ""
        if sid and server.get("url"):
            mapping[sid] = server["url"].rstrip("/")
    return mapping


def source_event_urls(uuids, hints=None):
    """Build MISP event URLs that point at the server each event came from.

    `hints` maps a source-event UUID to the server id it was collected from, so
    events pulled from another MISP server link back to that server rather than
    the local web instance.
    """
    hints = hints or {}
    url_map = _source_server_url_map()
    urls = []
    for uid in uuids or []:
        if not uid:
            continue
        base = url_map.get(hints.get(uid, ""), config.MISP_WEBAPP_URL).rstrip("/")
        urls.append(f"{base}/events/view/{uid}")
    return urls


def event_link_attributes(event) -> list:
    """Return the link-typed attribute values of an event from fetch_source_events().

    A source event usually carries the article, advisory or vendor bulletin it
    was built from as a link attribute, which is a reference in its own right.
    """
    return [
        a["value"] for a in (event.get("attributes") or [])
        if a.get("type") == "link" and a.get("value")
    ]


def source_event_link_urls(uuids, hints=None):
    """Return the link attributes of the given source events, deduplicated.

    Fetches the events from MISP; unreachable ones are skipped rather than
    failing the caller's render.
    """
    if not uuids:
        return []
    try:
        events = fetch_source_events(list(uuids), dict(hints or {}), strict_source=bool(hints))
    except Exception as exc:
        logger.warning("Could not fetch source events for link references: %s", exc)
        return []
    links = [link for ev in events for link in event_link_attributes(ev)]
    return list(dict.fromkeys(links))


FIA_ASSESSMENT_FIELDS = [
    ("likely_impact", "Likely impact"),
    ("affected_assets", "Affected assets"),
    ("actor_types", "Threat actor types"),
    ("actor_context", "Threat actor context"),
]


def fia_assessment_rows(fia):
    """Return the (label, value) pairs of "Why it matters" that were filled in.

    An assessment left blank says nothing, so it is dropped rather than carried
    as "unspecified". The alert page, the review queue, the PDF and the markdown
    every notification is built from all show the same four, so they decide what
    to leave out here rather than each repeating the rule.
    """
    rows = []
    for field, label in FIA_ASSESSMENT_FIELDS:
        value = getattr(fia, field, "") or ""
        if isinstance(value, list):
            value = ", ".join(value)
        if value:
            rows.append((label, value))
    return rows


def render_fia_markdown(fia, fia_id=None, include_source_links=False):
    """Render an FIA namespace into the markdown report content.

    By default this is deterministic and uses only fields already present on the
    FIA namespace. include_source_links adds the source events' link attributes
    to the references, at the cost of reading them from MISP, which is worth it
    on the notification paths but not when re-writing the stored report.
    """
    fid = fia_id or fia.fia_id or "FIA-#####"
    date_str = (fia.created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")

    def bullets(items):
        return "\n".join(f"- {ln}" for ln in items) if items else "- (none recorded)"

    source_uuids = getattr(fia, "source_event_uuids", []) or []
    source_hints = getattr(fia, "source_event_hints", {}) or {}
    source_refs = source_event_urls(source_uuids, source_hints)
    source_links = source_event_link_urls(source_uuids, source_hints) if include_source_links else []

    # The write-up is markdown the analyst wrote, and follows the bullets it
    # expands on. With neither, the section has nothing to say and is dropped.
    why_it_matters = [f"- **{label}:** {value}" for label, value in fia_assessment_rows(fia)]
    write_up = (fia.write_up or "").strip()
    if write_up:
        if why_it_matters:
            why_it_matters.append("")
        why_it_matters.append(write_up)
    why_it_matters_section = (
        ["## Why it matters", "", *why_it_matters, "", "---", ""] if why_it_matters else []
    )

    parts = [
        f"# Flash intel alert: {fia.title or '(untitled)'}",
        "",
        f"**ID:** {fid}",
        f"**Classification:** tlp:{fia.tlp}",
        f"**Date:** {date_str}",
        f"**Author:** {fia.author or 'unknown'}",
        f"**Audience:** {fia.audience or 'unspecified'}",
        "",
        "---",
        "",
        "## Summary",
        "",
        fia.summary or "_No summary provided._",
        "",
        f"**Action required:** {fia.action_required or '_To be defined._'}",
        "",
        "---",
        "",
        "## What happened",
        "",
        bullets(fia.what_happened),
        "",
        f"**Source:** {fia.source_description or 'unspecified'}",
        f"**Source reliability:** {fia.source_reliability or 'F'}",
        f"**Information credibility:** {fia.information_credibility or '6'}",
        "",
        "---",
        "",
        *why_it_matters_section,
        "## Scope",
        "",
        *([f"- **Geographic scope:** {', '.join(fia.geographic_scope)}"] if fia.geographic_scope else []),
        *([f"- **Sector:** {', '.join(fia.sectors)}"] if fia.sectors else []),
        *([f"- **Threat actor:** {', '.join(fia.threat_actors)}"] if fia.threat_actors else []),
        *([f"- **Techniques:** {', '.join(mitre_technique_labels(getattr(fia, 'mitre_attack_techniques', [])))}"] if getattr(fia, 'mitre_attack_techniques', []) else []),
        *([f"- **Threat types:** {', '.join(getattr(fia, 'threat_types', []) or [])}"] if getattr(fia, 'threat_types', []) else []),
        *([f"- **Technology:** {', '.join(getattr(fia, 'technology', []) or [])}"] if getattr(fia, 'technology', []) else []),
        *([f"- **Vendor:** {', '.join(getattr(fia, 'vendor', []) or [])}"] if getattr(fia, 'vendor', []) else []),
        *([f"- **Incident:** {', '.join(getattr(fia, 'incident', []) or [])}"] if getattr(fia, 'incident', []) else []),
        *([f"- **Campaign:** {', '.join(getattr(fia, 'campaign', []) or [])}"] if getattr(fia, 'campaign', []) else []),
        *(['_(No scope data recorded.)_'] if not any([
            fia.geographic_scope, fia.sectors, fia.threat_actors,
            getattr(fia, 'mitre_attack_techniques', []),
            getattr(fia, 'threat_types', []), getattr(fia, 'technology', []),
            getattr(fia, 'vendor', []), getattr(fia, 'incident', []), getattr(fia, 'campaign', []),
        ]) else []),
        "",
        "---",
        "",
        "## Recommended actions",
        "",
        "### Immediate (0-24 hours)",
        "",
        bullets(fia.actions_immediate),
        "",
        "### Near-term (1-7 days)",
        "",
        bullets(fia.actions_near_term),
        "",
        "---",
        "",
        "## Detection guidance",
        "",
        "**Techniques:**",
        "",
        bullets(mitre_technique_labels(fia.mitre_techniques)),
        "",
        "**Hunting hypotheses:**",
        "",
        bullets(fia.hunting_hypotheses),
        "",
        "---",
        "",
        "## References",
        "",
        bullets(list(dict.fromkeys((fia.external_references or []) + source_links + source_refs))),
    ]
    attachments = getattr(fia, "attachments", []) or []
    if attachments:
        parts.extend([
            "", "---", "", "## Attachments", "",
            *[f"- {a.filename} ({a.content_type or 'unknown type'}, {human_size(a.size)})"
              for a in attachments],
        ])
    intelligence_gaps = (getattr(fia, "intelligence_gaps", "") or "").strip()
    if intelligence_gaps:
        parts.extend(["", "---", "", "## Intelligence gaps", "", intelligence_gaps])
    if fia.feedback_deadline:
        parts.extend([
            "",
            "---",
            "",
            "## Feedback requested",
            "",
            f"Please report findings to the CTI team by {fia.feedback_deadline.isoformat()}.",
        ])
    return "\n".join(parts)


def _delete_fia_reports(misp, event):
    """Remove rendered FIA reports (name starts with 'FIA-') from the event.

    Hard-delete: a soft delete leaves the report attached with deleted=True,
    where it would linger and accumulate on every re-render.
    """
    for r in getattr(event, "event_reports", []) or []:
        if getattr(r, "deleted", False):
            continue
        name = getattr(r, "name", "") or ""
        if name.startswith("FIA-"):
            try:
                misp.delete_event_report(r.id, hard=True)
            except Exception as exc:
                logger.warning("delete event report %s failed: %s", r.id, exc)


def _write_fia_report(misp, event_uuid, fia_id, content):
    from pymisp import MISPEventReport
    er = MISPEventReport()
    er.name = fia_id
    er.content = content
    er.distribution = 0
    _check(misp.add_event_report(event_uuid, er), "add FIA report")


def list_fias(review_state=None):
    misp = _misp()
    events = misp.search(tags=[config.TAG_FLASH_INTEL], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_fia_ns(e) for e in events]
    if review_state:
        result = [f for f in result if f.review_state == review_state]
    result.sort(key=lambda f: f.fia_id, reverse=True)
    return result


def get_fia(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return None
    return _fia_ns(event)


def create_fia(data):
    """Create a Flash Intel Alert as a draft MISP event.

    Returns (uuid, fia_id). The FIA id is derived from the MISP event id so
    it is unique without a separate counter.
    """
    misp = _misp()
    title = (data.get("title") or "").strip() or "Untitled"
    info = f"[zsazsa:fia] {title}"
    extra = [f'tlp:{data.get("tlp", "amber")}', 'workflow:state="draft"']
    if data.get("source_reliability"):
        extra.append(f'admiralty-scale:source-reliability="{data["source_reliability"].lower()}"')
    if data.get("information_credibility"):
        extra.append(f'admiralty-scale:information-credibility="{data["information_credibility"]}"')

    event = _make_event(info, extra_tags=extra)
    src_uuids, src_hints = _normalise_source_uuids_and_hints(
        data.get("source_event_uuids") or [],
        data.get("source_event_uuid"),
        data.get("source_event_hints"),
    )
    if src_uuids:
        event.extends_uuid = src_uuids[0]

    result = _add_event(misp, event, [config.TAG_FLASH_INTEL], "create FIA")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create FIA: missing UUID in MISP response")

    fia_id = _fia_id_from_event_id(result.id)
    data["fia_id"] = fia_id
    data.setdefault("review_state", FIA_REVIEW_DRAFT)
    data["creator"] = misp_session.current_user_email()
    if data["review_state"] == FIA_REVIEW_APPROVED:
        data["approved_by"] = misp_session.current_user_email()
    _check(misp.add_object(_event_ref(result), _fia_obj(data)), "add FIA object")

    fia = _fia_ns(result)
    fia.fia_id = fia_id
    _write_fia_report(misp, uuid, fia_id, render_fia_markdown(fia, fia_id))
    for src_uuid in src_uuids:
        source_id = src_hints.get(src_uuid, "")
        if source_id and source_id != "scraper":
            continue
        _tag_scraper_event_as_product_source(src_uuid, "flash-intel")
    return uuid, fia_id


def update_fia(uuid, data):
    """Replace the FIA object on the event and re-render the report."""
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"FIA event {uuid} not found")

    old = _get_obj(event, "zsazsa-flash-intel")
    fia_id = (data.get("fia_id") or (_obj_attr(old, "fia-id") if old else None)
              or _fia_id_from_event_id(event.id))
    data["fia_id"] = fia_id
    old_review_state = _obj_attr(old, "review-state") if old else None
    new_review_state = data.get("review_state", FIA_REVIEW_DRAFT)
    if new_review_state == FIA_REVIEW_APPROVED and old_review_state != FIA_REVIEW_APPROVED:
        data["approved_by"] = misp_session.current_user_email()
    else:
        data.setdefault("approved_by", _obj_attr(old, "approved-by") or "")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
        misp.delete_object(old.id)
    _check(misp.add_object(_event_ref(event), _fia_obj(data)), "update FIA object")

    title = (data.get("title") or "").strip() or "Untitled"
    misp.update_event({"Event": {"id": event.id, "info": f"[zsazsa:fia] {title}"}})

    # Sync TLP and admiralty tags
    tlp = data.get("tlp", "amber")
    for tag in list(getattr(event, "tags", []) or []):
        if tag.name.startswith("tlp:"):
            try:
                misp.untag(event.uuid, tag.name)
            except Exception as exc:
                logger.warning("untag %s from %s failed: %s", tag.name, event.uuid, exc)
    try:
        misp.tag(event.uuid, f"tlp:{tlp}")
    except Exception as exc:
        logger.warning("tag tlp:%s on %s failed: %s", tlp, event.uuid, exc)
    for tag in list(getattr(event, "tags", []) or []):
        if tag.name.startswith("admiralty-scale:"):
            try:
                misp.untag(event.uuid, tag.name)
            except Exception as exc:
                logger.warning("untag %s from %s failed: %s", tag.name, event.uuid, exc)
    if data.get("source_reliability"):
        try:
            misp.tag(event.uuid, f'admiralty-scale:source-reliability="{data["source_reliability"].lower()}"')
        except Exception as exc:
            logger.warning("tag admiralty source-reliability on %s failed: %s", event.uuid, exc)
    if data.get("information_credibility"):
        try:
            misp.tag(event.uuid, f'admiralty-scale:information-credibility="{data["information_credibility"]}"')
        except Exception as exc:
            logger.warning("tag admiralty information-credibility on %s failed: %s", event.uuid, exc)

    # Re-render report
    refreshed = misp.get_event(uuid, pythonify=True)
    _delete_fia_reports(misp, refreshed)
    fia = _fia_ns(refreshed)
    _write_fia_report(misp, uuid, fia_id, render_fia_markdown(fia, fia_id))
    return uuid, fia_id


def set_fia_review_state(uuid, state, reason=None):
    """Update the FIA's review-state attribute and the workflow:state tag."""
    if state not in FIA_REVIEW_STATES:
        raise ValueError(f"invalid review state: {state}")
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"FIA event {uuid} not found")
    fia = _fia_ns(event)
    payload = {
        "fia_id": fia.fia_id,
        "title": fia.title,
        "audience": fia.audience,
        "tlp": fia.tlp,
        "summary": fia.summary,
        "action_required": fia.action_required,
        "what_happened": fia.what_happened,
        "source_description": fia.source_description,
        "source_reliability": fia.source_reliability,
        "information_credibility": fia.information_credibility,
        "likely_impact": fia.likely_impact,
        "affected_assets": fia.affected_assets,
        "actor_types": list(getattr(fia, "actor_types", []) or []),
        "actor_context": fia.actor_context,
        "write_up": fia.write_up,
        "mitre_attack_techniques": list(getattr(fia, "mitre_attack_techniques", []) or []),
        "actions_immediate": fia.actions_immediate,
        "actions_near_term": fia.actions_near_term,
        "mitre_techniques": fia.mitre_techniques,
        "hunting_hypotheses": fia.hunting_hypotheses,
        "external_references": fia.external_references,
        "intelligence_gaps": fia.intelligence_gaps,
        "feedback_deadline": fia.feedback_deadline.isoformat() if fia.feedback_deadline else "",
        "author": fia.author,
        "source_event_uuids": list(getattr(fia, "source_event_uuids", []) or []),
        "source_event_hints": dict(getattr(fia, "source_event_hints", {}) or {}),
        "linked_pir_uuid": getattr(fia, "linked_pir_uuid", "") or "",
        "context_tags": list(getattr(fia, "context_tags", []) or []),
        "geographic_scope": list(getattr(fia, "geographic_scope", []) or []),
        "sectors": list(getattr(fia, "sectors", []) or []),
        "threat_actors": list(getattr(fia, "threat_actors", []) or []),
        "threat_types": list(getattr(fia, "threat_types", []) or []),
        "technology": list(getattr(fia, "technology", []) or []),
        "vendor": list(getattr(fia, "vendor", []) or []),
        "incident": list(getattr(fia, "incident", []) or []),
        "campaign": list(getattr(fia, "campaign", []) or []),
        "review_state": state,
        "rejection_reason": reason or fia.rejection_reason,
    }
    update_fia(uuid, payload)

    # Sync workflow:state tag
    workflow_map = {
        FIA_REVIEW_DRAFT: "draft",
        FIA_REVIEW_PENDING: "ongoing",
        FIA_REVIEW_APPROVED: "complete",
        FIA_REVIEW_REJECTED: "rejected",
    }
    new_wf = f'workflow:state="{workflow_map[state]}"'
    for tag in list(getattr(event, "tags", []) or []):
        if tag.name.startswith("workflow:state="):
            try:
                misp.untag(event.uuid, tag.name)
            except Exception as exc:
                logger.warning("untag %s failed: %s", tag.name, exc)
    try:
        misp.tag(event.uuid, new_wf, local=True)
    except Exception as exc:
        logger.warning("tag %s with %s failed: %s", event.uuid, new_wf, exc)


def publish_fia(uuid):
    """Mark the FIA approved, set workflow=complete, publish the MISP event."""
    set_fia_review_state(uuid, FIA_REVIEW_APPROVED)
    misp = _misp()
    try:
        misp.publish(uuid)
    except Exception as exc:
        logger.warning("publish FIA %s failed: %s", uuid, exc)


def reject_fia(uuid, reason=""):
    set_fia_review_state(uuid, FIA_REVIEW_REJECTED, reason=reason)


def delete_fia(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete FIA")


# ── Flash intel attachments ──────────────────────────────────────────────────
#
# The file itself is a MISP attachment attribute, as on an RFI. What MISP does
# not carry back on an event fetch is how large the file is or what type it is,
# and the notifications have to name both without downloading every attachment
# first, so they are recorded in the comment when the file is stored:
#
#     zsazsa:fia-attachment|application/pdf|20841

FIA_ATTACHMENT_COMMENT = "zsazsa:fia-attachment"


def _fia_attachment_comment(content_type: str, size: int) -> str:
    return f"{FIA_ATTACHMENT_COMMENT}|{content_type or 'application/octet-stream'}|{int(size)}"


def _parse_fia_attachment_comment(comment: str) -> tuple[str, int]:
    """Return (content_type, size) from an attachment comment, tolerating older ones."""
    parts = (comment or "").split("|")
    content_type = parts[1].strip() if len(parts) > 1 else ""
    try:
        size = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        size = 0
    return content_type, size


def _fia_attachments(event) -> list:
    attachments = []
    for a in (getattr(event, "attributes", []) or []):
        comment = getattr(a, "comment", "") or ""
        if not comment.startswith(FIA_ATTACHMENT_COMMENT) or getattr(a, "deleted", False):
            continue
        content_type, size = _parse_fia_attachment_comment(comment)
        attachments.append(SimpleNamespace(uuid=a.uuid, filename=a.value,
                                           content_type=content_type, size=size))
    return attachments


def add_fia_attachment(event_uuid, filename, file_bytes, content_type=""):
    """Attach a file to a flash intel alert. Returns the new attribute UUID."""
    import base64
    misp = _misp()
    attr = MISPAttribute()
    attr.type = "attachment"
    attr.category = "External analysis"
    attr.value = filename
    attr.data = base64.b64encode(file_bytes).decode("utf-8")
    attr.comment = _fia_attachment_comment(content_type, len(file_bytes))
    attr.to_ids = False
    result = _check(misp.add_attribute(event_uuid, attr, pythonify=True), "add FIA attachment")
    return result.uuid


def delete_fia_attachment(attr_uuid):
    misp = _misp()
    result = misp.delete_attribute(attr_uuid)
    if not _is_not_found(result):
        _check(result, "delete FIA attachment")


def get_fia_attachment_content(attr_uuid):
    """Return (bytes, filename, content_type) for one flash intel attachment."""
    attr = fetch_attachment(attr_uuid)
    content_type, _size = _parse_fia_attachment_comment(attr.comment or "")
    return attr.data.getvalue(), attr.value, content_type


def fia_attachment_files(attachments) -> list[tuple]:
    """Download a flash intel alert's attachments as e-mail attachment tuples.

    Takes the attachment list off an FIA namespace and returns
    [(filename, bytes, maintype, subtype)], the shape notifier.email expects. An
    attachment that cannot be downloaded is left out rather than failing the
    delivery: the alert itself still has to go.
    """
    files = []
    for att in attachments or []:
        try:
            content, filename, content_type = get_fia_attachment_content(att.uuid)
        except Exception as exc:
            logger.warning("Could not download FIA attachment %s: %s", att.uuid, exc)
            continue
        maintype, _, subtype = (content_type or "application/octet-stream").partition("/")
        files.append((filename, content, maintype or "application", subtype or "octet-stream"))
    return files


def counts():
    misp = _misp()

    def _count(tag):
        events = misp.search(tags=[tag], metadata=True, limit=1000, pythonify=True)
        if not events or isinstance(events, dict):
            return 0
        return len(events)

    return {
        "pir": _count(config.TAG_PIR),
        "gir": _count(config.TAG_GIR),
        "stakeholder": _count(config.TAG_STAKEHOLDER),
        "rfi": _count(config.TAG_RFI),
        "fia": _count(config.TAG_FLASH_INTEL),
    }


# Scope categories shared by requirements (PIR/GIR) and products, in display order.
SCOPE_CATEGORIES = [
    ("Geographic scope", "geographic_scope"),
    ("Sector scope", "sectors"),
    ("MITRE ATT&CK techniques", "mitre_attack_techniques"),
    ("Threat types", "threat_types"),
    ("Technology", "technology"),
    ("Vendor", "vendor"),
    ("Incident", "incident"),
    ("Campaign", "campaign"),
]


def scope_stats() -> list[dict]:
    """Frequency of each scope value across all entities that carry scope (PIRs,
    GIRs, threat actor profiles and daily briefings).

    Returns one entry per category: {"label", "attr", "items", "total", "distinct"},
    where items is [{"value", "count", "entries"}] sorted by count descending and
    entries is the [{"kind", "label", "uuid"}] the value was counted from.
    """
    # Entity types that carry scope, with the description shown in the drill-down
    # list. The kind is what the template maps to a detail page.
    sources = [
        ("pir", list_pirs, lambda e: f"{e.pir_id} {e.question}"),
        ("gir", list_girs, lambda e: f"{e.gir_id} {e.topic}"),
        ("tap", list_threat_actor_profiles, lambda e: f"{e.tap_id} {e.title}"),
        ("briefing", list_briefings, lambda e: f"{e.date} {e.title}"),
    ]

    entities = []
    for kind, fetch, describe in sources:
        try:
            for entity in fetch() or []:
                entities.append((entity, {
                    "kind": kind,
                    "label": describe(entity).strip() or entity.uuid,
                    "uuid": entity.uuid,
                }))
        except Exception:
            logger.warning("scope_stats: %s failed", fetch.__name__)

    result = []
    for label, attr in SCOPE_CATEGORIES:
        entries = defaultdict(list)
        for entity, ref in entities:
            for value in (getattr(entity, attr, None) or []):
                value = (value or "").strip()
                if value:
                    entries[value].append(ref)
        items = [{"value": v, "count": len(refs), "entries": refs} for v, refs in entries.items()]
        items.sort(key=lambda i: (-i["count"], i["value"].lower()))
        result.append({
            "label": label,
            "attr": attr,
            "items": items,
            "total": sum(i["count"] for i in items),
            "distinct": len(items),
        })
    return result


def product_counts_by_threat_actor_type() -> list[dict]:
    """Count daily briefings, flash intel alerts and threat actor profiles per
    threat actor type.

    Each row is {"actor_type", "daily_briefings", "flash_intel_alerts",
    "threat_actor_profiles", "total"}. A product with no actor type counts under
    "Unspecified", which sorts last. Used by the statistics page and dashboard.
    """
    try:
        briefings = list_briefings()
    except Exception:
        briefings = []
    try:
        fias = list_fias()
    except Exception:
        fias = []
    try:
        taps = list_threat_actor_profiles()
    except Exception:
        taps = []

    briefing_counter = Counter()
    for briefing in briefings or []:
        types = {
            (t or "").strip()
            for story in (getattr(briefing, "stories", []) or [])
            for t in (getattr(story, "threat_actor_types", []) or [])
            if (t or "").strip()
        }
        for actor_type in (types or {"Unspecified"}):
            briefing_counter[actor_type] += 1

    fia_counter = Counter()
    for fia in fias or []:
        types = {(t or "").strip() for t in (getattr(fia, "actor_types", []) or []) if (t or "").strip()}
        for actor_type in (types or {"Unspecified"}):
            fia_counter[actor_type] += 1

    tap_counter = Counter()
    for tap in taps or []:
        types = {(t or "").strip() for t in (getattr(tap, "actor_types", []) or []) if (t or "").strip()}
        for actor_type in (types or {"Unspecified"}):
            tap_counter[actor_type] += 1

    all_types = sorted(
        set(briefing_counter) | set(fia_counter) | set(tap_counter),
        key=lambda x: (x.lower() == "unspecified", x.lower()),
    )
    rows = []
    for actor_type in all_types:
        briefing_n = briefing_counter.get(actor_type, 0)
        fia_n = fia_counter.get(actor_type, 0)
        tap_n = tap_counter.get(actor_type, 0)
        rows.append({
            "actor_type": actor_type,
            "daily_briefings": briefing_n,
            "flash_intel_alerts": fia_n,
            "threat_actor_profiles": tap_n,
            "total": briefing_n + fia_n + tap_n,
        })
    return rows


# ── Stakeholder subscription helpers ────────────────────────────────────────

def stakeholders_subscribed_to(product_type: str) -> list:
    """Return stakeholders whose product list includes the given product type."""
    return [s for s in list_stakeholders() if product_type in (s.products or [])]


def _tlp_cleared(clearance: str, tlp: str) -> bool:
    """Whether a stakeholder's clearance covers a product's classification.

    Both sides fall back to amber when unset or unrecognised, the default the
    stakeholder and product forms already use.
    """
    amber = _TLP_RANK["amber"]
    return _TLP_RANK.get((clearance or "amber").lower(), amber) >= _TLP_RANK.get((tlp or "amber").lower(), amber)


def stakeholders_cleared_for(product_type: str, tlp: str) -> list:
    """Subscribers to `product_type` whose clearance covers its classification.

    For a product that names no audience, the daily briefing being the only one:
    recipient_preview() blocks every stakeholder once the audience is empty, so it
    cannot pick the recipients, but the classification still has to be honoured.
    """
    return [s for s in stakeholders_subscribed_to(product_type)
            if _tlp_cleared(s.tlp_clearance, tlp)]


def stakeholders_on_automated_mode(product_type: str, tlp: str) -> list:
    """Stakeholders who take `product_type` unattended and are cleared for its TLP.

    The audience test recipient_preview() applies is left out here on purpose: a
    product the analyser publishes has no analyst to pick an audience, and putting
    a product on automated mode is the stakeholder's own statement that they want
    every one of them. TLP clearance still decides.
    """
    return [s for s in stakeholders_cleared_for(product_type, tlp)
            if (s.product_modes or {}).get(product_type) == "automated"]


def recipient_preview(product_type: str, tlp: str, audience_str: str) -> list:
    """Return eligibility data for all stakeholders for a given product.

    Each entry is a dict with keys: name, role, uuid, status ('green'/'yellow'/'grey'), reason.
    Green = all conditions met. Yellow = subscribed but TLP or audience blocks delivery.
    Grey = not subscribed to this product type.
    """
    audiences = {
        _canonical_role(a)
        for a in (audience_str or "").split(",")
        if _canonical_role(a)
    }
    result = []
    for s in list_stakeholders():
        subscribed = product_type in (s.products or [])
        tlp_ok = _tlp_cleared(s.tlp_clearance, tlp)
        audience_ok = bool(audiences) and (_canonical_role(s.role or "") in audiences)
        if subscribed and tlp_ok and audience_ok:
            status = "green"
            reason = "Receives this product (subscribed, TLP ok, audience match)"
        elif subscribed and not tlp_ok:
            status = "yellow"
            reason = f"Subscribed but TLP clearance ({s.tlp_clearance}) is below product TLP ({tlp or 'amber'})"
        elif subscribed and not audience_ok:
            status = "yellow"
            reason = f"Subscribed but role '{s.role or 'none'}' not in product audience ({audience_str or 'none'})"
        else:
            status = "grey"
            reason = f"Not subscribed to {product_type}"
        result.append({
            "name": s.name,
            "role": s.role,
            "uuid": s.uuid,
            "status": status,
            "reason": reason,
        })
    result.sort(key=lambda x: ({"green": 0, "yellow": 1, "grey": 2}[x["status"]], x["role"], x["name"]))
    return result


def export_focus_points_to_file():
    """Build focus points from active PIR/GIR requirements.

    Maps focus point categories to the organisation-wide keys used by AI helpers:
      Geography  -> geographies
      Sector     -> sectors
      Technology -> technologies
      Threat Type -> threat_types
      Threat Actor -> threat_actors
    """
    cat_map = {
        "Geography": "geographies",
        "Sector": "sectors",
        "Technology": "technologies",
        "Threat Type": "threat_types",
        "Threat Actor": "threat_actors",
    }
    result = {v: [] for v in cat_map.values()}
    seen = {v: set() for v in cat_map.values()}

    for req in list_pirs() + list_girs():
        if getattr(req, "status", "") == "Retired":
            continue
        for fp in getattr(req, "focus_points", []):
            key = cat_map.get(fp.category)
            if not key:
                continue
            v = (fp.value or "").strip()
            if v and v.lower() not in seen[key]:
                seen[key].add(v.lower())
                result[key].append(v)

    logger.info("focus points rebuilt from requirements: %s", {k: len(v) for k, v in result.items()})
    return result


# ── Vulnerability Exploitation Advisory (VEA) ────────────────────────────────


VEA_REVIEW_DRAFT = "draft"
VEA_REVIEW_PENDING = "pending-review"
VEA_REVIEW_APPROVED = "approved"
VEA_REVIEW_REJECTED = "rejected"
VEA_REVIEW_STATES = [VEA_REVIEW_DRAFT, VEA_REVIEW_PENDING, VEA_REVIEW_APPROVED, VEA_REVIEW_REJECTED]

VEA_EXPLOIT_AVAILABILITY = ["Weaponised", "PoC public", "None known", "Unknown"]
VEA_EXPLOIT_COMPLEXITY = ["Low", "Medium", "High", "Unknown"]
VEA_ACTOR_INTEREST = ["Ransomware", "APT", "Opportunistic", "Multiple", "None observed", "Unknown"]
VEA_CISA_KEV = ["Yes", "No", "Unknown"]


def _vea_obj(data):
    obj = _build_obj("zsazsa-vea")
    _oa(obj, "vea-id", data.get("vea_id"))
    _oa(obj, "cve-id", data.get("cve_id"))
    _oa(obj, "summary", data.get("summary"))
    _oa(obj, "cvss", data.get("cvss"))
    _oa(obj, "cwe", data.get("cwe"))
    _oa(obj, "title", data.get("title"))
    _oa(obj, "tlp", data.get("tlp", "amber"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "audience", data.get("audience"))
    _oa(obj, "affected-product", data.get("affected_product"))
    _oa(obj, "affected-versions", data.get("affected_versions"))
    _oa(obj, "fixed-version", data.get("fixed_version"))
    _oa(obj, "exposure", data.get("exposure"))
    _oa(obj, "observed-exploitation", data.get("observed_exploitation"))
    _oa(obj, "exploit-availability", data.get("exploit_availability"))
    _oa(obj, "exploitation-complexity", data.get("exploitation_complexity"))
    _oa(obj, "threat-actor-interest", data.get("threat_actor_interest"))
    _oa(obj, "cisa-kev", data.get("cisa_kev"))
    _oa(obj, "source-description", data.get("source_description"))
    _oa(obj, "source-reliability", data.get("source_reliability"))
    _oa(obj, "information-credibility", data.get("information_credibility"))
    _oa(obj, "worst-case", data.get("worst_case"))
    _oa(obj, "most-likely", data.get("most_likely"))
    _oa(obj, "immediate-actions", _join_lines(data.get("immediate_actions")))
    _oa(obj, "patch-sla-internet", data.get("patch_sla_internet"))
    _oa(obj, "patch-sla-internal", data.get("patch_sla_internal"))
    _oa(obj, "target-patch-version", data.get("target_patch_version"))
    _oa(obj, "exploitation-indicators", _join_lines(data.get("exploitation_indicators")))
    _oa(obj, "detection-rules", _join_lines(data.get("detection_rules")))
    _oa(obj, "references", _join_lines(data.get("references")))
    _oa(obj, "feedback-deadline", data.get("feedback_deadline"))
    _oa(obj, "review-state", data.get("review_state", VEA_REVIEW_DRAFT))
    _oa(obj, "rejection-reason", data.get("rejection_reason"))
    src_uuids, src_hints = _normalise_source_uuids_and_hints(
        data.get("source_event_uuids"),
        data.get("source_event_uuid"),
        data.get("source_event_hints"),
    )
    _oa_json(obj, "source-event-uuid", src_uuids)
    _oa_json(obj, "source-event-hints", src_hints)
    _oa(obj, "linked-pir-uuid", data.get("linked_pir_uuid"))
    _oa_json(obj, "context-tags", data.get("context_tags", []))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "approved-by", data.get("approved_by"))
    return obj


def _vea_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-vea")

    def g(rel):
        return _obj_attr(obj, rel) or ""

    source_event_uuids = _parse_source_uuid_blob(g("source-event-uuid"))
    try:
        _src_hints_parsed = json.loads(g("source-event-hints") or "{}")
    except Exception:
        _src_hints_parsed = {}
    source_event_hints = _clean_source_hints(_src_hints_parsed, source_event_uuids)

    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        vea_id=g("vea-id"),
        cve_id=g("cve-id"),
        summary=g("summary"),
        cvss=g("cvss"),
        cwe=g("cwe"),
        title=g("title"),
        tlp=g("tlp") or "amber",
        author=g("author"),
        audience=g("audience"),
        affected_product=g("affected-product"),
        affected_versions=g("affected-versions"),
        fixed_version=g("fixed-version"),
        exposure=g("exposure"),
        observed_exploitation=g("observed-exploitation"),
        exploit_availability=g("exploit-availability"),
        exploitation_complexity=g("exploitation-complexity"),
        threat_actor_interest=g("threat-actor-interest"),
        cisa_kev=g("cisa-kev"),
        source_description=g("source-description"),
        source_reliability=g("source-reliability"),
        information_credibility=g("information-credibility"),
        worst_case=g("worst-case"),
        most_likely=g("most-likely"),
        immediate_actions=g("immediate-actions").splitlines(),
        patch_sla_internet=g("patch-sla-internet"),
        patch_sla_internal=g("patch-sla-internal"),
        target_patch_version=g("target-patch-version"),
        exploitation_indicators=g("exploitation-indicators").splitlines(),
        detection_rules=g("detection-rules").splitlines(),
        references=g("references").splitlines(),
        feedback_deadline=_parse_date(g("feedback-deadline")),
        review_state=g("review-state") or VEA_REVIEW_DRAFT,
        rejection_reason=g("rejection-reason"),
        source_event_uuids=source_event_uuids,
        source_event_hints=source_event_hints,
        source_event_uuid=source_event_uuids[0] if source_event_uuids else "",
        linked_pir_uuid=g("linked-pir-uuid"),
        context_tags=_json_list(g("context-tags")),
        creator=g("creator"),
        approved_by=g("approved-by"),
        published=bool(getattr(event, "published", False)),
        published_at=_published_at(event),
        created_at=_parse_dt(event.date.isoformat() if event.date else None),
    )


def _vea_id_from_event_id(event_id):
    return f"VEA-{int(event_id):05d}"


def render_vea_markdown(vea, vea_id=None, preview_url: str = ""):
    vid = vea_id or vea.vea_id or "VEA-#####"
    date_str = (vea.created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d")

    def bullets(items):
        return "\n".join(f"- {ln}" for ln in items) if items else "- (none recorded)"

    source_refs = source_event_urls(getattr(vea, "source_event_uuids", []) or [],
                                    getattr(vea, "source_event_hints", {}) or {})

    lines = [
        f"# Vulnerability advisory: {vea.cve_id or vid}",
        "",
        f"**ID:** {vid}",
        f"**Classification:** tlp:{vea.tlp}",
        f"**Date:** {date_str}",
        f"**Author:** {vea.author or 'unknown'}",
        f"**Audience:** {vea.audience or 'vulnerability management, SOC, application owners'}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"{vea.cve_id or 'This vulnerability'} affects {vea.affected_product or 'affected product'}.",
        f"We assess with confidence that this vulnerability {vea.observed_exploitation or 'status unknown'}.",
        "",
        f"**Action required:** {vea.most_likely or '_To be defined._'}",
        "",
        "---",
        "",
        "## Affected technology",
        "",
        "| Field | Details |",
        "|-------|---------|",
        f"| **Product** | {vea.affected_product or '-'} |",
        f"| **Affected versions** | {vea.affected_versions or '-'} |",
        f"| **Fixed version** | {vea.fixed_version or '-'} |",
        f"| **Our exposure** | {vea.exposure or '-'} |",
        "",
        "---",
        "",
        "## Exploitation status",
        "",
        "| Factor | Assessment |",
        "|--------|------------|",
        f"| **Observed exploitation** | {vea.observed_exploitation or '-'} |",
        f"| **Exploit availability** | {vea.exploit_availability or '-'} |",
        f"| **Exploitation complexity** | {vea.exploitation_complexity or '-'} |",
        f"| **Threat actor interest** | {vea.threat_actor_interest or '-'} |",
        f"| **CISA KEV listed** | {vea.cisa_kev or '-'} |",
        "",
        f"**Source:** {vea.source_description or 'unspecified'}",
        f"**Source reliability:** {vea.source_reliability or '-'}",
        f"**Information credibility:** {vea.information_credibility or '-'}",
        "",
        "---",
        "",
        "## Risk assessment",
        "",
        f"**Worst case:** {vea.worst_case or '-'}",
        "",
        f"**Most likely:** {vea.most_likely or '-'}",
        "",
        "---",
        "",
        "## Recommended actions",
        "",
        "### Immediate",
        "",
        bullets(vea.immediate_actions),
        "",
        "### Patch timeline",
        "",
        "| Asset category | Target SLA | Owner |",
        "|----------------|------------|-------|",
        f"| Internet-facing production | {vea.patch_sla_internet or 'TBD'} | - |",
        f"| Internal production | {vea.patch_sla_internal or 'TBD'} | - |",
        "",
        f"**Target patch version:** {vea.target_patch_version or '-'}",
        "",
        "---",
        "",
        "## Detection guidance",
        "",
        "**Indicators of exploitation:**",
        "",
        bullets(vea.exploitation_indicators),
        "",
        "**Detection rules:**",
        "",
        bullets(vea.detection_rules),
        "",
        "---",
        "",
        "## References",
        "",
        bullets(list(dict.fromkeys((vea.references or []) + source_refs))),
    ]
    if getattr(vea, "feedback_deadline", None):
        lines.extend([
            "",
            "---",
            "",
            "## Feedback requested",
            "",
            f"Please report findings to the CTI team by {vea.feedback_deadline.isoformat()}.",
        ])
    if preview_url:
        lines += ["", f"[Open advisory]({preview_url})"]
    return "\n".join(lines)


def _delete_vea_reports(misp, event):
    """Hard-delete: a soft delete leaves the report attached with deleted=True,
    where it would linger and accumulate on every re-render."""
    for r in getattr(event, "event_reports", []) or []:
        if getattr(r, "deleted", False):
            continue
        name = getattr(r, "name", "") or ""
        if name.startswith("VEA-"):
            try:
                misp.delete_event_report(r.id, hard=True)
            except Exception as exc:
                logger.warning("delete VEA report %s failed: %s", r.id, exc)


def _write_vea_report(misp, event_uuid, vea_id, content):
    from pymisp import MISPEventReport
    er = MISPEventReport()
    er.name = vea_id
    er.content = content
    er.distribution = 0
    _check(misp.add_event_report(event_uuid, er), "add VEA report")


def list_veas(review_state=None):
    misp = _misp()
    events = misp.search(tags=[config.TAG_VEA], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_vea_ns(e) for e in events]
    if review_state:
        result = [v for v in result if v.review_state == review_state]
    result.sort(key=lambda v: v.vea_id, reverse=True)
    return result


def get_vea(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return None
    return _vea_ns(event)


def create_vea(data):
    misp = _misp()
    cve = (data.get("cve_id") or "").strip()
    title = (data.get("title") or cve or "Untitled").strip()
    info = f"[zsazsa:vea] {cve}: {title}" if cve else f"[zsazsa:vea] {title}"
    extra = [f'tlp:{data.get("tlp", "amber")}', 'workflow:state="draft"']
    if data.get("source_reliability"):
        extra.append(f'admiralty-scale:source-reliability="{data["source_reliability"].lower()}"')

    event = _make_event(info, extra_tags=extra)
    src_uuids, src_hints = _normalise_source_uuids_and_hints(
        data.get("source_event_uuids") or [],
        data.get("source_event_uuid"),
        data.get("source_event_hints"),
    )
    if src_uuids:
        event.extends_uuid = src_uuids[0]

    result = _add_event(misp, event, [config.TAG_VEA], "create VEA")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create VEA: missing UUID in MISP response")

    vea_id = _vea_id_from_event_id(result.id)
    data["vea_id"] = vea_id
    data.setdefault("review_state", VEA_REVIEW_DRAFT)
    data["creator"] = misp_session.current_user_email()
    if data["review_state"] == VEA_REVIEW_APPROVED:
        data["approved_by"] = misp_session.current_user_email()
    _check(misp.add_object(_event_ref(result), _vea_obj(data)), "add VEA object")

    vea = _vea_ns(result)
    vea.vea_id = vea_id
    _write_vea_report(misp, uuid, vea_id, render_vea_markdown(vea, vea_id))
    for uid in src_uuids:
        source_id = src_hints.get(uid, "")
        if source_id and source_id != "scraper":
            continue
        _tag_scraper_event_as_product_source(uid, "vea")
    return uuid, vea_id


def update_vea(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"VEA event {uuid} not found")

    old = _get_obj(event, "zsazsa-vea")
    vea_id = (data.get("vea_id") or (_obj_attr(old, "vea-id") if old else None)
              or _vea_id_from_event_id(event.id))
    data["vea_id"] = vea_id
    old_review_state = _obj_attr(old, "review-state") if old else None
    new_review_state = data.get("review_state", VEA_REVIEW_DRAFT)
    if new_review_state == VEA_REVIEW_APPROVED and old_review_state != VEA_REVIEW_APPROVED:
        data["approved_by"] = misp_session.current_user_email()
    else:
        data.setdefault("approved_by", _obj_attr(old, "approved-by") or "")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
        misp.delete_object(old.id)
    _check(misp.add_object(_event_ref(event), _vea_obj(data)), "update VEA object")

    cve = (data.get("cve_id") or "").strip()
    title = (data.get("title") or cve or "Untitled").strip()
    info = f"[zsazsa:vea] {cve}: {title}" if cve else f"[zsazsa:vea] {title}"
    misp.update_event({"Event": {"id": event.id, "info": info}})

    refreshed = misp.get_event(uuid, pythonify=True)
    _delete_vea_reports(misp, refreshed)
    vea = _vea_ns(refreshed)
    _write_vea_report(misp, uuid, vea_id, render_vea_markdown(vea, vea_id))
    return uuid, vea_id


def set_vea_review_state(uuid, state, reason=None):
    if state not in VEA_REVIEW_STATES:
        raise ValueError(f"invalid VEA review state: {state}")
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"VEA event {uuid} not found")
    vea = _vea_ns(event)

    def _vea_data(v, state, reason):
        return {
            "vea_id": v.vea_id, "cve_id": v.cve_id, "title": v.title, "tlp": v.tlp,
            "author": v.author, "audience": v.audience,
            "affected_product": v.affected_product, "affected_versions": v.affected_versions,
            "fixed_version": v.fixed_version, "exposure": v.exposure,
            "observed_exploitation": v.observed_exploitation,
            "exploit_availability": v.exploit_availability,
            "exploitation_complexity": v.exploitation_complexity,
            "threat_actor_interest": v.threat_actor_interest, "cisa_kev": v.cisa_kev,
            "source_description": v.source_description,
            "source_reliability": v.source_reliability,
            "information_credibility": v.information_credibility,
            "worst_case": v.worst_case, "most_likely": v.most_likely,
            "immediate_actions": v.immediate_actions,
            "patch_sla_internet": v.patch_sla_internet,
            "patch_sla_internal": v.patch_sla_internal,
            "target_patch_version": v.target_patch_version,
            "exploitation_indicators": v.exploitation_indicators,
            "detection_rules": v.detection_rules,
            "references": v.references,
            "feedback_deadline": v.feedback_deadline.isoformat() if getattr(v, "feedback_deadline", None) else "",
            "source_event_uuids": list(getattr(v, "source_event_uuids", []) or []),
            "source_event_hints": dict(getattr(v, "source_event_hints", {}) or {}),
            "source_event_uuid": v.source_event_uuid,
            "linked_pir_uuid": v.linked_pir_uuid,
            "review_state": state,
            "rejection_reason": reason or v.rejection_reason,
        }

    update_vea(uuid, _vea_data(vea, state, reason))

    workflow_map = {
        VEA_REVIEW_DRAFT: "draft",
        VEA_REVIEW_PENDING: "ongoing",
        VEA_REVIEW_APPROVED: "complete",
        VEA_REVIEW_REJECTED: "rejected",
    }
    new_wf = f'workflow:state="{workflow_map[state]}"'
    for tag in list(getattr(event, "tags", []) or []):
        if tag.name.startswith("workflow:state="):
            try:
                misp.untag(event.uuid, tag.name)
            except Exception as exc:
                logger.warning("untag %s failed: %s", tag.name, exc)
    try:
        misp.tag(event.uuid, new_wf, local=True)
    except Exception as exc:
        logger.warning("tag %s with %s failed: %s", event.uuid, new_wf, exc)


def publish_vea(uuid):
    set_vea_review_state(uuid, VEA_REVIEW_APPROVED)
    misp = _misp()
    try:
        misp.publish(uuid)
    except Exception as exc:
        logger.warning("publish VEA %s failed: %s", uuid, exc)


def reject_vea(uuid, reason=""):
    set_vea_review_state(uuid, VEA_REVIEW_REJECTED, reason=reason)


def delete_vea(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete VEA")


# ── Daily Threat Briefing ────────────────────────────────────────────────────


def extract_source_url(event) -> str:
    """Return the article URL from a MISP scraper event's link attributes.

    Scraper events carry the RSS feed URL first, then the article URL.
    Feed-like URLs (ending .xml / .rss / .atom / .json) are skipped;
    the last remaining link is returned.
    """
    feed_suffixes = (".xml", ".rss", ".atom", ".json")
    links = [
        a.value
        for a in (getattr(event, "attributes", []) or [])
        if a.type in ("url", "link")
        and not any((a.value or "").lower().endswith(s) for s in feed_suffixes)
    ]
    return links[-1] if links else ""


BRIEFING_REVIEW_DRAFT = "draft"
BRIEFING_REVIEW_PUBLISHED = "published"
BRIEFING_REVIEW_STATES = [BRIEFING_REVIEW_DRAFT, BRIEFING_REVIEW_PUBLISHED]

_STORY_REPORT_PREFIX = "[story-"


def _briefing_obj(data):
    obj = _build_obj("zsazsa-daily-briefing")
    _oa(obj, "date", data.get("date"))
    _oa(obj, "title", data.get("title"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "tlp", data.get("tlp", "clear"))
    _oa(obj, "review-state", data.get("review_state", BRIEFING_REVIEW_DRAFT))
    count = data["story_count"] if "story_count" in data else len(data.get("stories", []))
    _oa(obj, "story-count", str(count))
    _oa(obj, "escalations", data.get("escalations"))
    _oa(obj, "notes", data.get("notes"))
    _oa_json(obj, "geographic-scope", data.get("geographic_scope", []))
    _oa_json(obj, "sectors", data.get("sectors", []))
    _oa_json(obj, "threat-actors", data.get("threat_actors", []))
    _oa_json(obj, "mitre-attack-techniques", data.get("mitre_attack_techniques", []))
    _oa_json(obj, "threat-types", data.get("threat_types", []))
    _oa_json(obj, "technology", data.get("technology", []))
    _oa_json(obj, "vendor", data.get("vendor", []))
    _oa_json(obj, "incident", data.get("incident", []))
    _oa_json(obj, "campaign", data.get("campaign", []))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "approved-by", data.get("approved_by"))
    _oa(obj, "summary", data.get("summary"))
    # Only written when there is a summary for it to be about, and only when it
    # is true, so a briefing whose summary still matches its stories carries no
    # attribute at all. Everything downstream can then trust the flag on its own.
    if data.get("summary") and data.get("summary_stale"):
        _oa(obj, "summary-stale", "true")
    return obj


# Everything the briefing object carries, under the same name on the write dict
# _briefing_obj() takes and on the namespace _briefing_ns() reads back. Changing
# the object means changing all three, so publishing a briefing rebuilds its
# write dict from this rather than listing the fields again.
_BRIEFING_FIELDS = (
    "date", "title", "author", "tlp", "review_state", "story_count",
    "escalations", "notes", "summary", "summary_stale",
    "geographic_scope", "sectors", "threat_actors", "mitre_attack_techniques",
    "threat_types", "technology", "vendor", "incident", "campaign",
    "creator", "approved_by",
)


def _briefing_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-daily-briefing")

    def g(rel):
        return _obj_attr(obj, rel) or ""

    stories = []
    for er in sorted(
        [r for r in live_reports(event)
         if (getattr(r, "name", "") or "").startswith(_STORY_REPORT_PREFIX)],
        key=lambda r: r.name,
    ):
        try:
            s = json.loads(getattr(er, "content", "") or "{}")
        except Exception:
            s = {}
        s["_report_id"] = er.id
        stories.append(SimpleNamespace(**s) if isinstance(s, dict) else s)

    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        history_url=f"{config.MISP_WEBAPP_URL}/audit_logs/eventIndex/{uuid}",
        date=g("date"),
        title=g("title"),
        author=g("author"),
        tlp=g("tlp") or "clear",
        review_state=g("review-state") or BRIEFING_REVIEW_DRAFT,
        story_count=int(g("story-count") or "0"),
        escalations=g("escalations"),
        notes=g("notes"),
        geographic_scope=_json_list(_obj_attr(obj, "geographic-scope")),
        sectors=_json_list(_obj_attr(obj, "sectors")),
        threat_actors=_json_list(_obj_attr(obj, "threat-actors")),
        mitre_attack_techniques=_json_list(_obj_attr(obj, "mitre-attack-techniques")),
        threat_types=_json_list(_obj_attr(obj, "threat-types")),
        technology=_json_list(_obj_attr(obj, "technology")),
        vendor=_json_list(_obj_attr(obj, "vendor")),
        incident=_json_list(_obj_attr(obj, "incident")),
        campaign=_json_list(_obj_attr(obj, "campaign")),
        creator=g("creator"),
        approved_by=g("approved-by"),
        summary=g("summary"),
        # Set when a story was added, removed or rewritten after the summary was
        # written, so every view can say the summary no longer covers what is
        # underneath it.
        summary_stale=g("summary-stale") == "true",
        stories=stories,
        published=bool(getattr(event, "published", False)),
        published_at=_published_at(event),
        created_at=event.timestamp if getattr(event, "timestamp", None) else _parse_dt(event.date.isoformat() if event.date else None),
    )


_SCOPE_SUMMARY_FIELDS = [
    ("geographic_scope", "Geographic"),
    ("sectors", "Sector"),
    ("threat_actors", "Threat actor"),
    ("techniques", "Techniques"),
    ("threat_actor_types", "Threat actor type"),
    ("vendor", "Vendor"),
]


def briefing_scope_summary(stories):
    """Aggregate scope elements and threat actor types across briefing stories.

    Returns an ordered list of (field, label, [(value, count), ...]) tuples,
    counts sorted highest-first. Kept as a separate, structured function so the
    same counts can later feed graphs/statistics without re-parsing the stories.
    Values are as the stories hold them, techniques included: the briefing form
    has to match a chip back to the story it came from, and it is the `mitre`
    template filter that turns a bare id into its ATT&CK name for display.
    """
    summary = []
    for field, label in _SCOPE_SUMMARY_FIELDS:
        counter = Counter()
        for s in stories:
            value = s.get(field) if isinstance(s, dict) else getattr(s, field, None)
            items = value if isinstance(value, list) else ([value] if value else [])
            for item in items:
                if item:
                    counter[item] += 1
        if counter:
            summary.append((field, label,
                            sorted(counter.items(), key=lambda kv: (-kv[1], kv[0].lower()))))
    return summary


_STORY_TO_BRIEFING_SCOPE_FIELDS = [
    ("geographic_scope", "geographic_scope"),
    ("sectors", "sectors"),
    ("threat_actors", "threat_actors"),
    ("techniques", "mitre_attack_techniques"),
]


def briefing_story_scope_values(stories):
    """Collect, per briefing-level scope category, the values already present on the stories.

    Maps story-level field names onto the matching briefing-level field names
    (story "techniques" become briefing "mitre_attack_techniques") so the edit
    form can pre-select the corresponding galaxy items, deduplicated
    case-insensitively while keeping first-occurrence casing.
    """
    result = {}
    for story_field, briefing_field in _STORY_TO_BRIEFING_SCOPE_FIELDS:
        seen_lower = set()
        values = []
        for s in stories:
            value = s.get(story_field) if isinstance(s, dict) else getattr(s, story_field, None)
            items = value if isinstance(value, list) else ([value] if value else [])
            for item in items:
                key = (item or "").strip().lower()
                if key and key not in seen_lower:
                    seen_lower.add(key)
                    values.append(item.strip())
        result[briefing_field] = values
    return result


_COMBINED_SCOPE_FIELDS = [
    ("geographic_scope", "geographic_scope", "Geographic scope"),
    ("sectors", "sectors", "Sectors"),
    ("threat_actors", "threat_actors", "Threat actors"),
    ("techniques", "mitre_attack_techniques", "Techniques"),
    ("threat_actor_types", None, "Threat actor types"),
    (None, "threat_types", "Threat types"),
    (None, "technology", "Technology"),
    (None, "vendor", "Vendor"),
    (None, "incident", "Incident"),
    (None, "campaign", "Campaign"),
]


def briefing_combined_scope_summary(briefing):
    """Merge per-story scope occurrences with briefing-level scope additions into one summary.

    Returns an ordered list of (label, [(value, count), ...]) tuples, counts
    sorted highest-first, deduplicated case-insensitively across both sources
    so the same item (e.g. story-derived "china" and briefing-level "China")
    appears only once. Briefing-level casing wins on conflicts since those
    values are picked from the canonical galaxy lists.
    """
    summary = []
    for story_field, briefing_field, label in _COMBINED_SCOPE_FIELDS:
        counter = Counter()
        canonical = {}
        if story_field:
            for s in briefing.stories:
                value = s.get(story_field) if isinstance(s, dict) else getattr(s, story_field, None)
                items = value if isinstance(value, list) else ([value] if value else [])
                for item in items:
                    if item:
                        key = item.lower()
                        counter[key] += 1
                        canonical.setdefault(key, item)
        if briefing_field:
            for item in (getattr(briefing, briefing_field, None) or []):
                if not item:
                    continue
                key = item.lower()
                if key not in counter:
                    counter[key] = 1
                canonical[key] = item
        if counter:
            ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
            values = [(canonical[key], count) for key, count in ranked]
            if story_field == "techniques":
                values = [(mitre_technique_label(v), count) for v, count in values]
            summary.append((label, values))
    return summary


# The scope categories a briefing story carries, in the order every surface
# renders them: this markdown, the HTML e-mail and the story_scope template macro.
BRIEFING_STORY_SCOPE_FIELDS = [
    ("geographic_scope", "Geographic scope"),
    ("sectors", "Sector"),
    ("threat_actors", "Threat actor"),
    ("techniques", "Techniques"),
    ("threat_actor_types", "Threat actor type"),
]


def briefing_story_scope_rows(story):
    """Return the (label, values) pairs a story has scope for, empties dropped.

    Takes a story off a saved briefing, where _briefing_ns() has already turned
    it into a namespace. The compose form's story dicts would come back empty
    here; those go through briefing_scope_summary() instead.
    """
    rows = []
    for field, label in BRIEFING_STORY_SCOPE_FIELDS:
        values = getattr(story, field, None) or []
        if field == "techniques":
            values = mitre_technique_labels(values)
        if values:
            rows.append((label, values))
    return rows


def render_briefing_markdown(briefing, preview_url: str = ""):
    date_str = briefing.date or (briefing.created_at.strftime("%Y-%m-%d") if briefing.created_at else "unknown")
    lines = [
        f"# Daily threat briefing - {date_str}",
        "",
        f"**Prepared by:** {briefing.author or 'analyst'}",
        f"**Classification:** tlp:{briefing.tlp}",
        "",
        "---",
        "",
    ]
    if briefing.summary:
        lines.extend([
            "## Briefing summary",
            "",
            briefing.summary,
            "",
            "---",
            "",
        ])
    lines.extend([
        f"## Today's stories ({len(briefing.stories)} items)",
        "",
    ])
    for i, s in enumerate(briefing.stories, 1):
        title = getattr(s, "title", "") or f"Story {i}"
        content = getattr(s, "content", "") or ""
        source_url = getattr(s, "source_url", "") or ""
        lines.extend([
            f"### {i}. {title}",
            "",
            content,
            "",
            f"**Source:** {source_url or '-'}",
        ])
        for label, values in briefing_story_scope_rows(s):
            lines.append(f"**{label}:** {', '.join(values)}")
        reliability = getattr(s, "source_reliability", "") or ""
        credibility = getattr(s, "information_credibility", "") or ""
        if reliability or credibility:
            lines.append(
                f"**Admiralty scale:** source reliability {reliability or '-'}, "
                f"information credibility {credibility or '-'}"
            )
        cti_eval = getattr(s, "cti_evaluation", None) or {}
        if cti_eval:
            cti_str = ", ".join(f"{k}={v}" for k, v in cti_eval.items())
            lines.append(f"**CTI evaluation:** {cti_str}")
        lines.extend([
            "",
            "---",
            "",
        ])
    scope_summary = briefing_combined_scope_summary(briefing)
    if scope_summary:
        lines.extend(["## Scope summary", ""])
        for label, ranked in scope_summary:
            lines.append(f"**{label}:**")
            for value, count in ranked:
                if count > 1:
                    lines.append(f"- {value} ({count} occurrences)")
                else:
                    lines.append(f"- {value}")
            lines.append("")
        lines.extend(["---", ""])
    esc = briefing.escalations or "None today."
    lines.extend([
        "## Escalations",
        "",
        esc,
        "",
    ])
    if briefing.notes:
        lines.extend([
            "## Notes",
            "",
            briefing.notes,
        ])
    if preview_url:
        lines += ["", f"[Open briefing]({preview_url})"]
    return "\n".join(lines)


def _delete_briefing_reports(misp, event):
    """Permanently remove old story/summary reports before writing fresh ones.

    A plain delete_event_report() only soft-deletes: the report stays in
    event.event_reports (with deleted=True) and would be counted again
    alongside the freshly written one on the next edit, doubling the
    apparent story count. Hard-delete so the slate is actually clean.
    """
    for r in getattr(event, "event_reports", []) or []:
        if getattr(r, "deleted", False):
            continue
        name = getattr(r, "name", "") or ""
        if name.startswith(_STORY_REPORT_PREFIX) or name.startswith("briefing-"):
            try:
                misp.delete_event_report(r.id, hard=True)
            except Exception as exc:
                logger.warning("delete briefing report %s failed: %s", r.id, exc)


def _write_briefing_story_report(misp, event_uuid, index, story):
    from pymisp import MISPEventReport
    er = MISPEventReport()
    er.name = f"{_STORY_REPORT_PREFIX}{index:02d}]"
    er.content = json.dumps({
        "title": story.get("title", ""),
        "content": story.get("content", ""),
        "source_url": story.get("source_url", ""),
        "source_event_uuid": story.get("source_event_uuid", ""),
        "source_id": story.get("source_id", ""),
        "geographic_scope": story.get("geographic_scope", []),
        "sectors": story.get("sectors", []),
        "threat_actors": story.get("threat_actors", []),
        "techniques": story.get("techniques", []),
        "source_reliability": story.get("source_reliability", ""),
        "information_credibility": story.get("information_credibility", ""),
        "cti_evaluation": story.get("cti_evaluation", {}),
        "threat_actor_types": story.get("threat_actor_types", []),
        "vendor": story.get("vendor", []),
        # "ai" when a model wrote the text and nobody has touched it since,
        # "ai-edited" once an analyst has, empty when written by hand. The
        # compose form shows it as the state of each story.
        "drafted_by": story.get("drafted_by", ""),
    })
    er.distribution = 0
    _check(misp.add_event_report(event_uuid, er), f"add briefing story {index}")


def _write_briefing_report(misp, event_uuid, briefing):
    """Store the whole briefing as one readable markdown report on its event.

    Not to be confused with the briefing's summary, which is the paragraph
    render_briefing_markdown() puts at the top of what this writes.
    """
    from pymisp import MISPEventReport
    er = MISPEventReport()
    er.name = f"briefing-{briefing.date or 'unknown'}"
    er.content = render_briefing_markdown(briefing)
    er.distribution = 0
    _check(misp.add_event_report(event_uuid, er), "add briefing report")


def list_briefings():
    misp = _misp()
    events = misp.search(tags=[config.TAG_BRIEFING], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_briefing_ns(e) for e in events]
    result.sort(key=lambda b: b.date or "", reverse=True)
    return result


def get_briefing(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return None
    return _briefing_ns(event)


def create_briefing(data):
    misp = _misp()
    bdate = data.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    info = f"[zsazsa:briefing] Daily threat briefing {bdate}"
    extra = [f'tlp:{data.get("tlp", "clear")}', 'workflow:state="draft"']
    event = _make_event(info, extra_tags=extra)
    result = _add_event(misp, event, [config.TAG_BRIEFING], "create briefing")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create briefing: missing UUID in MISP response")

    try:
        data["date"] = bdate
        data.setdefault("review_state", BRIEFING_REVIEW_DRAFT)
        data["creator"] = misp_session.current_user_email()
        _check(misp.add_object(_event_ref(result), _briefing_obj(data)), "add briefing object")

        for i, story in enumerate(data.get("stories", []), 1):
            _write_briefing_story_report(misp, uuid, i, story)

        refreshed = misp.get_event(uuid, pythonify=True)
        briefing = _briefing_ns(refreshed)
        _write_briefing_report(misp, uuid, briefing)
    except Exception:
        # Clean up the shell event so it doesn't appear as a dateless entry.
        try:
            misp.delete_event(uuid)
        except Exception:
            pass
        raise
    for story in data.get("stories", []):
        src = story.get("source_event_uuid", "")
        if src:
            _tag_scraper_event_as_product_source(src, "daily-briefing")
    return uuid


def update_briefing(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"Briefing event {uuid} not found")

    existing = _briefing_ns(event)
    existing_sources = {
        getattr(s, "source_event_uuid", "") for s in existing.stories
        if getattr(s, "source_event_uuid", "")
    }
    new_sources = {
        s.get("source_event_uuid", "") for s in data.get("stories", [])
        if s.get("source_event_uuid", "")
    }
    added_sources = new_sources - existing_sources

    old = _get_obj(event, "zsazsa-daily-briefing")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
        data.setdefault("approved_by", _obj_attr(old, "approved-by") or "")
        misp.delete_object(old.id)
    _check(misp.add_object(_event_ref(event), _briefing_obj(data)), "update briefing object")

    _delete_briefing_reports(misp, event)
    for i, story in enumerate(data.get("stories", []), 1):
        _write_briefing_story_report(misp, uuid, i, story)

    refreshed = misp.get_event(uuid, pythonify=True)
    briefing = _briefing_ns(refreshed)
    _write_briefing_report(misp, uuid, briefing)

    for src in added_sources:
        _tag_scraper_event_as_product_source(src, "daily-briefing")

    return uuid


def publish_briefing(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"Briefing event {uuid} not found")
    briefing = _briefing_ns(event)

    old = _get_obj(event, "zsazsa-daily-briefing")
    if old:
        misp.delete_object(old.id)
    # The object is rebuilt from scratch, so everything it held has to be
    # carried across; only the review state and the approver change here.
    data = {field: getattr(briefing, field) for field in _BRIEFING_FIELDS}
    data["review_state"] = BRIEFING_REVIEW_PUBLISHED
    data["approved_by"] = misp_session.current_user_email()
    _check(misp.add_object(_event_ref(event), _briefing_obj(data)), "publish briefing object")
    for tag in list(getattr(event, "tags", []) or []):
        if tag.name.startswith("workflow:state="):
            try:
                misp.untag(event.uuid, tag.name)
            except Exception:
                pass
    try:
        misp.tag(event.uuid, 'workflow:state="complete"', local=True)
    except Exception as exc:
        logger.warning("tag briefing %s complete failed: %s", uuid, exc)
    try:
        misp.publish(uuid)
    except Exception as exc:
        logger.warning("publish briefing %s failed: %s", uuid, exc)


def delete_briefing(uuid):
    misp = _misp()
    _check(misp.delete_event(uuid), "delete briefing")


def scraper_existing_uuids(uuids):
    """Return subset of UUIDs that currently exist in scraper/analyser MISP."""
    candidates = [u for u in set(uuids or []) if u]
    if not candidates:
        return set()

    misp = _scraper_misp()
    existing = set()
    chunk_size = 100

    for i in range(0, len(candidates), chunk_size):
        chunk = candidates[i:i + chunk_size]
        events = misp.search(uuid=chunk, metadata=True, pythonify=True)
        if isinstance(events, dict):
            # The caller hides activity rows whose event is missing, so a failed
            # search would quietly hide the lot as orphaned.
            logger.warning("scraper existence check failed for %d uuid(s): %s",
                           len(chunk), events.get("errors") or events)
            continue
        if not events:
            continue
        for e in events:
            ev_uuid = getattr(e, "uuid", None)
            if ev_uuid:
                existing.add(ev_uuid)

    return existing


# ── Scope preview against scraper collection ──────────────────────────────────

def _event_text(ev):
    parts = [ev.info or ""]
    for r in getattr(ev, "event_reports", []) or []:
        if getattr(r, "name", None):
            parts.append(r.name)
        if getattr(r, "content", None):
            parts.append(r.content)
    return " \n ".join(parts)


def preview_scope_matches(scope_terms, limit=200, max_results=50, timeframe_hours=None):
    """Return cached scraper events matching scope terms.

    Whole-word-aware match (case-insensitive) over cached event fields, so a
    term like "gas" does not match inside "gasten". When ``timeframe_hours`` is
    set, only events whose MISP event date falls within that window are kept.
    """
    from webapp import collection_cache
    from webapp import matching as _matching

    terms = []
    seen = set()
    for t in scope_terms or []:
        t = (t or "").strip()
        if not t or len(t) < 2:
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        terms.append(t)

    if not terms:
        return []

    # Pull from local cache, this keeps the preview snappy and avoids live MISP
    # calls each time the user opens the preview page.
    events = collection_cache.get_events(["scraper"], [], limit=limit)
    if not events:
        return []

    # Filter on the event date rather than the cache fetch time: the cache
    # worker rewrites fetched_at for every row on each refresh, so it does not
    # reflect how recent an event actually is.
    cutoff_date = None
    if timeframe_hours is not None:
        cutoff_date = (datetime.now() - timedelta(hours=float(timeframe_hours))).date()

    rows = []
    for e in events:
        if cutoff_date is not None:
            event_date = _parse_date(e.get("date"))
            if event_date is None or event_date < cutoff_date:
                continue

        text = " ".join([
            e.get("info") or "",
            e.get("org") or "",
            e.get("orgc") or "",
            " ".join(e.get("tags") or []),
            " ".join(e.get("galaxy_names") or []),
            " ".join(e.get("vulnerability_ids") or []),
        ])
        matched = [t for t in terms if _matching.term_in_text(t, text)]
        if not matched:
            continue
        rows.append({
            "uuid": e.get("uuid"),
            "id": e.get("id"),
            "info": e.get("info"),
            "date": e.get("date") or "",
            "matched_terms": matched,
            "score": len(matched),
        })

    rows.sort(key=lambda r: (-r["score"], r["info"] or ""))
    return rows[:max_results]


def pir_collection_gap(pir) -> dict:
    """Return a coverage summary for a PIR against the recent scraper collection.

    Uses the PIR's focus point values as search terms against the scraper MISP.
    Returns a dict with total matching events, the most recent match date, and
    up to 5 sample rows so the detail page can show a quick gap indicator without
    a second page load.
    """
    fp_values = [fp.value for fp in getattr(pir, "focus_points", []) if fp.value]
    if not fp_values:
        return {"recent_matches": 0, "last_match_date": None, "sample": []}
    matches = preview_scope_matches(fp_values)
    last_date = None
    if matches:
        dates = [r["date"] for r in matches if r.get("date")]
        last_date = max(dates) if dates else None
    return {
        "recent_matches": len(matches),
        "last_match_date": last_date,
        "sample": matches[:5],
    }


# ── Threat Landscape Report ──────────────────────────────────────────────────

TLR_REVIEW_DRAFT = "draft"
TLR_REVIEW_PUBLISHED = "published"
TLR_REVIEW_STATES = [TLR_REVIEW_DRAFT, TLR_REVIEW_PUBLISHED]

TLR_TLP_LEVELS = ["clear", "green", "amber", "amber+strict", "red"]


def _tlr_obj(data):
    obj = _build_obj("zsazsa-threat-landscape-report")
    _oa(obj, "tlr-id", data.get("tlr_id"))
    _oa(obj, "title", data.get("title"))
    _oa(obj, "reporting-period", data.get("reporting_period"))
    _oa(obj, "tlp", data.get("tlp", "amber"))
    _oa(obj, "author", data.get("author"))
    _oa(obj, "audience", data.get("audience"))
    _oa(obj, "top-threats", data.get("top_threats"))
    _oa(obj, "trending-actors", data.get("trending_actors"))
    _oa(obj, "key-incidents", data.get("key_incidents"))
    _oa(obj, "recommendations", data.get("recommendations"))
    _oa(obj, "outlook", data.get("outlook"))
    _oa(obj, "review-state", data.get("review_state", TLR_REVIEW_DRAFT))
    _oa(obj, "creator", data.get("creator"))
    _oa(obj, "approved-by", data.get("approved_by"))
    return obj


def _tlr_ns(event):
    uuid = event.uuid
    obj = _get_obj(event, "zsazsa-threat-landscape-report")

    def g(rel):
        return _obj_attr(obj, rel) or ""

    return SimpleNamespace(
        id=uuid,
        uuid=uuid,
        misp_url=f"{config.MISP_WEBAPP_URL}/events/view/{uuid}",
        tlr_id=g("tlr-id"),
        title=g("title"),
        reporting_period=g("reporting-period"),
        tlp=g("tlp") or "amber",
        author=g("author"),
        audience=g("audience"),
        top_threats=g("top-threats"),
        trending_actors=g("trending-actors"),
        key_incidents=g("key-incidents"),
        recommendations=g("recommendations"),
        outlook=g("outlook"),
        review_state=g("review-state") or TLR_REVIEW_DRAFT,
        creator=g("creator"),
        approved_by=g("approved-by"),
        published=bool(getattr(event, "published", False)),
        created_at=_parse_dt(event.date.isoformat() if event.date else None),
    )


def render_tlr_markdown(tlr):
    lines = [
        f"# Threat Landscape Report - {tlr.reporting_period or tlr.tlr_id}",
        "",
        f"**Prepared by:** {tlr.author or 'analyst'}",
        f"**Audience:** {tlr.audience or '-'}",
        f"**Classification:** TLP:{(tlr.tlp or 'AMBER').upper()}",
        "",
        "---",
        "",
    ]
    sections = [
        ("Top threats", tlr.top_threats),
        ("Trending threat actors", tlr.trending_actors),
        ("Key incidents", tlr.key_incidents),
        ("Recommendations", tlr.recommendations),
        ("Outlook", tlr.outlook),
    ]
    for heading, content in sections:
        if content:
            lines += [f"## {heading}", "", content, ""]
    return "\n".join(lines)


def _next_tlr_id():
    with _id_lock:
        misp = _misp()
        events = misp.search(tags=[config.TAG_TLR], metadata=True, pythonify=True)
        if not events or isinstance(events, dict):
            return "TLR-001"
        max_n = 0
        for e in events:
            for token in (e.info or "").split():
                clean = token.rstrip(":")
                if clean.startswith("TLR-"):
                    try:
                        max_n = max(max_n, int(clean[4:]))
                    except ValueError:
                        pass
        return f"TLR-{max_n + 1:03d}"


def list_tlrs():
    misp = _misp()
    events = misp.search(tags=[config.TAG_TLR], limit=200, pythonify=True)
    if not events or isinstance(events, dict):
        return []
    result = [_tlr_ns(e) for e in events]
    result.sort(key=lambda t: t.tlr_id or "", reverse=True)
    return result


def get_tlr(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        return None
    return _tlr_ns(event)


def create_tlr(data):
    misp = _misp()
    tlr_id = data.get("tlr_id") or _next_tlr_id()
    title = data.get("title", "")
    info = f"[zsazsa:tlr] {tlr_id}: {title}"
    extra = [f'tlp:{data.get("tlp", "amber")}', 'workflow:state="draft"']
    event = _make_event(info, extra_tags=extra)
    result = _add_event(misp, event, [config.TAG_TLR], "create TLR")
    uuid = _event_uuid(result)
    if not uuid:
        raise RuntimeError("create TLR: missing UUID in MISP response")
    data["tlr_id"] = tlr_id
    data.setdefault("review_state", TLR_REVIEW_DRAFT)
    data["creator"] = misp_session.current_user_email()
    _check(misp.add_object(_event_ref(result), _tlr_obj(data)), "add TLR object")
    return uuid


def update_tlr(uuid, data):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"TLR event {uuid} not found")
    old = _get_obj(event, "zsazsa-threat-landscape-report")
    if old:
        data["creator"] = _obj_attr(old, "creator") or ""
        data.setdefault("approved_by", _obj_attr(old, "approved-by") or "")
        misp.delete_object(old.id)
    title = data.get("title", "")
    tlr_id = data.get("tlr_id", "")
    misp.edit_event(uuid, info=f"[zsazsa:tlr] {tlr_id}: {title}")
    _check(misp.add_object(_event_ref(event), _tlr_obj(data)), "update TLR object")
    return uuid


def publish_tlr(uuid):
    misp = _misp()
    event = misp.get_event(uuid, pythonify=True)
    if isinstance(event, dict) or event is None:
        raise RuntimeError(f"TLR event {uuid} not found")
    tlr = _tlr_ns(event)
    old = _get_obj(event, "zsazsa-threat-landscape-report")
    if old:
        misp.delete_object(old.id)
    data = {
        "tlr_id": tlr.tlr_id, "title": tlr.title,
        "reporting_period": tlr.reporting_period, "tlp": tlr.tlp,
        "author": tlr.author, "audience": tlr.audience,
        "top_threats": tlr.top_threats, "trending_actors": tlr.trending_actors,
        "key_incidents": tlr.key_incidents, "recommendations": tlr.recommendations,
        "outlook": tlr.outlook, "review_state": TLR_REVIEW_PUBLISHED,
        "creator": tlr.creator,
        "approved_by": misp_session.current_user_email(),
    }
    _check(misp.add_object(_event_ref(event), _tlr_obj(data)), "publish TLR object")
    for tag in list(getattr(event, "tags", []) or []):
        name = getattr(tag, "name", "") or ""
        if name.startswith('workflow:state='):
            try:
                misp.untag(uuid, name)
            except Exception:
                pass
    misp.tag(uuid, 'workflow:state="published"', local=True)
    misp.publish(event)


def delete_tlr(uuid):
    _check(_misp().delete_event(uuid), "delete TLR")


def find_products_using_source(src_uuid: str) -> list:
    """Return all products (briefings, FIAs, VEAs) that reference src_uuid as a source event."""
    results = []
    try:
        for b in list_briefings():
            for s in (b.stories or []):
                if getattr(s, "source_event_uuid", "") == src_uuid:
                    results.append({
                        "type": "daily-briefing",
                        "uuid": b.uuid,
                        "title": b.title or f"Daily briefing {b.date}",
                        "date": b.date or "",
                    })
                    break
    except Exception as exc:
        logger.warning("find_products_using_source briefings failed: %s", exc)
    try:
        for f in list_fias():
            uuids = []
            for value in getattr(f, "source_event_uuids", []) or []:
                uid = _extract_uuid(value)
                if uid:
                    uuids.append(uid)
            if src_uuid in uuids:
                results.append({
                    "type": "flash-intel",
                    "uuid": f.uuid,
                    "title": f.title or f"Flash Intel {f.fia_id}",
                    "date": (f.created_at.strftime("%Y-%m-%d") if f.created_at else ""),
                })
    except Exception as exc:
        logger.warning("find_products_using_source FIAs failed: %s", exc)
    try:
        for v in list_veas():
            if getattr(v, "source_event_uuid", "") == src_uuid:
                results.append({
                    "type": "vea",
                    "uuid": v.uuid,
                    "title": v.title or f"VEA {v.vea_id}",
                    "date": (v.created_at.strftime("%Y-%m-%d") if v.created_at else ""),
                })
    except Exception as exc:
        logger.warning("find_products_using_source VEAs failed: %s", exc)
    return results
