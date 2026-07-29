"""Browse MISP collection events without opening MISP.

The list page reads from the local SQLite cache populated by
webapp.collection_cache (background worker). The detail page fetches
one event live - a single event fetch is fast; querying hundreds is not.
"""

import concurrent.futures
import logging
import re
import time
from collections import Counter

_TECH_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

import urllib3
import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from pymisp import PyMISP, MISPEventReport

import config
from webapp import audit, collection_cache, matching as _matching, misp_store, newsletter_ingest, newsletter_parsers
from webapp.rate_limit import rate_limited
from webapp.utils import json_body as _json_object

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

bp = Blueprint("data_collection", __name__, url_prefix="/collection")

_DEFAULT_LIMIT = 100
_SCRAPER_SOURCE_ID = "scraper"

_THREAT_LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
_ANALYSIS_STATES = {0: "Initial", 1: "Ongoing", 2: "Completed"}


def _split_tags(s: str) -> list[str]:
    if not s:
        return []
    parts = []
    for chunk in s.split(","):
        for tok in chunk.split():
            tok = tok.strip()
            if tok:
                parts.append(tok)
    return parts


def _source_slug(name: str) -> str:
    return misp_store.source_slug(name)


def _sources() -> list[dict]:
    out = [{
        "id": _SCRAPER_SOURCE_ID,
        "label": "MISP scraper",
        "kind": "scraper",
        "url": config.MISP_URL,
        # IMAP mailbox sources feed into the scraper, so list them under it.
        "imap_sources": misp_store.imap_source_labels(),
    }]
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not s.get("enabled", True):
            continue
        out.append({
            "id": s.get("id") or s.get("label"),
            "label": s.get("label") or s.get("id"),
            "kind": "misp",
            "url": s.get("url"),
            "api_key": s.get("api_key"),
            "verify_tls": s.get("verify_tls", True),
            "tags": _split_tags(s.get("tags", "")),
            "tags_and": _split_tags(s.get("tags_and", "")),
            "tags_not": _split_tags(s.get("tags_not", "")),
            "org_filter_type": s.get("org_filter_type", "") or "",
            "org_filter": _split_tags(s.get("org_filter", "")),
            "since_days": int(s.get("since_days") or 7),
        })
    try:
        for src in misp_store.list_collection_sources():
            if src.enabled:
                slug = _source_slug(src.name)
                out.append({
                    "id": f"manual-{slug}",
                    "label": src.name,
                    "kind": "manual",
                    "url": config.MISP_WEBAPP_URL,
                    "source_uuid": src.uuid,
                })
    except Exception as exc:
        logger.warning("Could not load manual collection sources from MISP: %s", exc)
    return out


def _find_source(source_id: str) -> dict | None:
    for s in _sources():
        if s["id"] == source_id:
            return s
    return None


def _misp_response_errors(resp) -> str | None:
    if isinstance(resp, dict) and resp.get("errors"):
        return str(resp["errors"])
    if isinstance(resp, list):
        for item in resp:
            if isinstance(item, dict) and item.get("errors"):
                return str(item["errors"])
    return None


def _extract_event_detail(event) -> dict:
    """Pull rich display fields from a fully-loaded MISPEvent object."""
    org_name = orgc_name = ""
    org_obj = getattr(event, "Org", None) or getattr(event, "org", None)
    orgc_obj = getattr(event, "Orgc", None) or getattr(event, "orgc", None)
    if org_obj:
        org_name = getattr(org_obj, "name", "") or ""
    if orgc_obj:
        orgc_name = getattr(orgc_obj, "name", "") or ""

    tags = []
    for t in getattr(event, "tags", []) or []:
        tags.append({"name": t.name, "colour": getattr(t, "colour", "#aaa") or "#aaa"})

    galaxies = []
    for g in getattr(event, "galaxies", []) or []:
        clusters = []
        for cl in getattr(g, "clusters", []) or []:
            clusters.append({
                "value": getattr(cl, "value", "") or "",
                "description": (getattr(cl, "description", "") or "")[:200],
            })
        if clusters:
            galaxies.append({"name": getattr(g, "name", "") or "", "clusters": clusters})

    attributes = []
    for a in getattr(event, "attributes", []) or []:
        attributes.append({
            "type": a.type,
            "category": getattr(a, "category", "") or "",
            "value": a.value,
            "comment": getattr(a, "comment", "") or "",
            "to_ids": bool(getattr(a, "to_ids", False)),
        })

    objects = []
    for obj in getattr(event, "objects", []) or []:
        obj_attrs = []
        for a in getattr(obj, "attributes", []) or []:
            obj_attrs.append({
                "relation": getattr(a, "object_relation", "") or "",
                "type": a.type,
                "value": a.value,
                "comment": getattr(a, "comment", "") or "",
            })
        objects.append({
            "name": getattr(obj, "name", "") or "",
            "meta_category": getattr(obj, "meta_category", "") or "",
            "comment": getattr(obj, "comment", "") or "",
            "attributes": obj_attrs,
        })

    return {
        "uuid": event.uuid,
        "id": event.id,
        "info": event.info,
        "date": str(event.date) if event.date else "",
        "org": org_name,
        "orgc": orgc_name,
        "tags": tags,
        "galaxies": galaxies,
        "attributes": attributes,
        "objects": objects,
        "threat_level": _THREAT_LEVELS.get(int(getattr(event, "threat_level_id", 4) or 4), "Undefined"),
        "analysis": _ANALYSIS_STATES.get(int(getattr(event, "analysis", 0) or 0), "Initial"),
        "attribute_count": int(getattr(event, "attribute_count", 0) or 0),
    }


def _build_list_context() -> dict:
    sources = _sources()
    label_map = {s["id"]: s["label"] for s in sources}
    all_source_ids = [s["id"] for s in sources]

    events = collection_cache.get_events(all_source_ids, [], 2000)
    kind_map = {s["id"]: s["kind"] for s in sources}
    for ev in events:
        ev["source_label"] = label_map.get(ev["source_id"], ev["source_id"])
        ev["source_kind"] = kind_map.get(ev["source_id"], "misp")

    try:
        pirs, girs = _matching.get_requirements()
        req_matches = _matching.match_events(events, pirs, girs)
        for ev in events:
            ev["req_matches"] = req_matches.get(ev["uuid"], [])
    except Exception as exc:
        logger.warning("PIR/GIR matching error: %s", exc)
        for ev in events:
            ev["req_matches"] = []

    cache_status = collection_cache.get_source_status()
    source_errors = {sid: st["error"] for sid, st in cache_status.items() if st.get("error")}
    now = time.time()
    cache_ages = {}
    last_fetch_ts = 0.0
    for sid, st in cache_status.items():
        if st.get("last_fetch"):
            cache_ages[sid] = int((now - st["last_fetch"]) / 60)
            if st["last_fetch"] > last_fetch_ts:
                last_fetch_ts = st["last_fetch"]
    cache_interval_s = int(getattr(config, "COLLECTION_CACHE_INTERVAL", 15)) * 60

    counter = Counter()
    for ev in events:
        for t in ev["tags"]:
            if t and t != config.SCRAPER_MARKER_TAG:
                counter[t] += 1
    all_tags = sorted(counter.keys(), key=str.casefold)

    org_map: dict[str, dict[str, str]] = {}
    for ev in events:
        org = (ev.get("orgc") or "").strip()
        if org:
            if org not in org_map:
                org_map[org] = {}
            sid = ev["source_id"]
            org_map[org][sid] = label_map.get(sid, sid)
    org_list = sorted(
        [{"name": k, "sources": v} for k, v in org_map.items()],
        key=lambda x: x["name"].lower(),
    )

    # Daily briefing title exclusion matching
    excl_raw = getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", []) or []
    if isinstance(excl_raw, str):
        excl_raw = excl_raw.splitlines()
    excl_patterns = [str(p).strip().lower() for p in excl_raw if str(p).strip()]
    briefing_excluded_uuids: set[str] = set()
    briefing_pending_reject_uuids: set[str] = set()
    if excl_patterns:
        for ev in events:
            title = (ev.get("info") or "").lower()
            if any(p in title for p in excl_patterns):
                briefing_excluded_uuids.add(ev["uuid"])
                if not _is_set_aside(ev.get("tags", [])):
                    briefing_pending_reject_uuids.add(ev["uuid"])

    return dict(
        events=events,
        all_tags=all_tags,
        org_list=org_list,
        limit=_DEFAULT_LIMIT,
        marker_tag=config.SCRAPER_MARKER_TAG,
        followup_tag=getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"'),
        dismissed_tag=_dismissed_tag(),
        total_reports=sum(ev.get("report_count", 0) for ev in events),
        sources=sources,
        has_manual_sources=any(s.get("kind") == "manual" for s in sources),
        source_errors=source_errors,
        cache_ages=cache_ages,
        cache_status=cache_status,
        cache_interval_s=cache_interval_s,
        cache_last_fetch_ts=last_fetch_ts or None,
        tag_briefing=config.TAG_BRIEFING,
        tag_flash_intel=config.TAG_FLASH_INTEL,
        tag_vea=config.TAG_VEA,
        flagged_uuids=collection_cache.get_flagged_uuids(),
        briefing_excluded_uuids=briefing_excluded_uuids,
        briefing_pending_reject_uuids=briefing_pending_reject_uuids,
        collection_tag_strip_prefixes=getattr(config, "COLLECTION_TAG_STRIP_PREFIXES", []) or [],
        collection_tag_hide_prefixes=getattr(config, "COLLECTION_TAG_HIDE_PREFIXES", []) or [],
        scope_galaxy=misp_store.scope_galaxy_items(),
        draft_briefings=_draft_briefings(),
    )


def _draft_briefings():
    """Draft daily briefings, for the "add to existing briefing" picker."""
    try:
        return [b for b in misp_store.list_briefings() if b.review_state == misp_store.BRIEFING_REVIEW_DRAFT]
    except Exception as exc:
        logger.warning("Could not load draft briefings: %s", exc)
        return []


@bp.route("/")
def index():
    return render_template("data_collection/list.html", **_build_list_context())


@bp.route("/refresh", methods=["POST"])
def refresh():
    queued = collection_cache.trigger_refresh()
    if not queued:
        return jsonify({"ok": False, "error": "Cache worker is not running"}), 503
    return jsonify({"ok": True, "message": "Refresh triggered"})


_PULL_TIMEOUT = 10  # seconds


def _resolve_pull_source(source_id: str):
    """Build source info from config only - no MISP network calls."""
    if source_id == _SCRAPER_SOURCE_ID:
        return {"id": source_id, "kind": "scraper"}
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not s.get("enabled", True):
            continue
        sid = s.get("id") or s.get("label")
        if sid == source_id:
            return {
                "id": sid, "kind": "misp",
                "url": s.get("url"), "api_key": s.get("api_key"),
                "verify_tls": s.get("verify_tls", True),
            }
    return None


def _fetch_event_timed(misp, uuid, timeout):
    """Run get_event + get_event_reports in a thread with a hard wall-clock timeout."""
    def _work():
        event = misp.get_event(uuid, pythonify=True)
        if not event or isinstance(event, dict):
            return None, []
        try:
            reports = misp.get_event_reports(event.id, pythonify=True) or []
        except Exception as exc:
            logger.warning("pull: could not load reports for %s: %s", uuid, exc)
            reports = []
        return event, reports

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_work)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"MISP did not respond within {timeout}s")


@bp.route("/pull", methods=["POST"])
@rate_limited("collection_pull", limit=30, window_s=60)
def pull():
    data, err = _json_object()
    if err:
        return err
    uuid = (data.get("uuid") or "").strip()
    source_id = (data.get("source_id") or "").strip()

    if not uuid:
        return jsonify({"ok": False, "error": "UUID is required"}), 400
    if not source_id:
        return jsonify({"ok": False, "error": "Source is required"}), 400
    if not _UUID_RE.match(uuid):
        return jsonify({"ok": False, "error": f"'{uuid}' is not a valid MISP UUID"}), 400

    src = _resolve_pull_source(source_id)
    if src is None:
        return jsonify({"ok": False, "error": "Unknown or unsupported source"}), 400

    logger.info("pull: requesting %s from source '%s'", uuid, source_id)

    if src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured (missing API key)"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                          timeout=_PULL_TIMEOUT)
        except Exception as exc:
            logger.warning("pull: could not connect to %s: %s", source_id, exc)
            return jsonify({"ok": False, "error": "Could not connect to source."}), 502
    else:
        misp = misp_store._scraper_misp()

    try:
        event, reports = _fetch_event_timed(misp, uuid, _PULL_TIMEOUT)
    except TimeoutError as exc:
        logger.warning("pull: %s from %s: %s", uuid, source_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 504
    except Exception as exc:
        logger.warning("pull: %s from %s failed: %s", uuid, source_id, exc)
        return jsonify({"ok": False, "error": "Could not fetch event."}), 502

    if event is None:
        return jsonify({"ok": False, "error": "Event not found"}), 404

    row = collection_cache._extract_row(event, source_id)
    row["report_count"] = len(reports)
    collection_cache.insert_event(row)

    audit.record(
        "pull", "misp-event",
        entity_id=uuid,
        entity_label=event.info or uuid,
        details=f"Manually pulled into cache from source '{source_id}'",
    )

    return jsonify({"ok": True, "message": f"Event '{event.info}' pulled into cache", "uuid": uuid})


@bp.route("/<string:uuid>")
def detail(uuid):
    source_id = request.args.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    if src and src["kind"] == "manual":
        misp = misp_store._misp()
        misp_url_base = config.MISP_WEBAPP_URL.rstrip("/")
    elif src and src["kind"] == "misp":
        if not src.get("api_key"):
            return "Source not configured (missing API key)", 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("Could not connect to MISP server %s: %s", source_id, exc)
            return "Source not available", 502
        misp_url_base = src["url"].rstrip("/")
    else:
        misp = misp_store._scraper_misp()
        misp_url_base = config.MISP_URL.rstrip("/")

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("MISP get_event %s failed: %s", uuid, exc)
        return "Event not available", 502

    if not event or isinstance(event, dict):
        return "Event not found", 404

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception as exc:
        logger.warning("Could not load event reports for %s: %s", uuid, exc)
        reports = []

    report_views = []
    for r in reports:
        report_views.append({
            "name": getattr(r, "name", "") or "Report",
            "content": getattr(r, "content", "") or "",
            "tags": [t.name for t in getattr(r, "tags", []) or []],
        })

    event_data = _extract_event_detail(event)
    misp_url = f"{misp_url_base}/events/view/{event.uuid}"
    source_label = (src or {}).get("label", source_id)

    return render_template(
        "data_collection/detail.html",
        event=event_data,
        reports=report_views,
        misp_url=misp_url,
        source_label=source_label,
        source_id=source_id,
        draft_briefings=_draft_briefings(),
    )


def _parse_scope_from_summary(text):
    """Extract sectors, geo names, and MITRE T-numbers from the LLM summary output."""
    sectors, geo, techniques = [], [], []
    for line in text.split('\n'):
        s = line.strip()
        sl = s.lower()
        if sl.startswith('- targeted sector'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                sectors = [v.strip() for v in val.split(',') if v.strip()]
        elif sl.startswith('- geographic scope'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                geo = [v.strip() for v in val.split(',') if v.strip()]
        elif sl.startswith('- mitre att'):
            val = s.split(':', 1)[1].strip() if ':' in s else ''
            if val and val.lower() != 'none identified':
                techniques = _TECH_RE.findall(val)
    return sectors, geo, techniques


def _apply_scope_tags(misp, event, sectors, geo, techniques):
    """Resolve extracted scope values to MISP galaxy tags and tag the event."""
    existing = {t.name for t in getattr(event, 'tags', []) or []}
    tags_to_apply = misp_store._build_scope_tags({
        'geographic_scope': geo,
        'sectors': sectors,
    })
    # Resolve MITRE T-numbers to galaxy tag names
    if techniques:
        mitre_map = misp_store._galaxy_tag_map(misp_store.GALAXY_MITRE_ATTACK)
        for cluster_value, tag_name in mitre_map.items():
            m = _TECH_RE.search(cluster_value)
            if m and m.group(0) in techniques:
                tags_to_apply.append(tag_name)
    applied = []
    for tag_name in tags_to_apply:
        if tag_name and tag_name not in existing:
            try:
                misp.tag(event, tag_name)
                existing.add(tag_name)
                applied.append(tag_name)
            except Exception as exc:
                logger.warning("Could not apply tag '%s' to %s: %s", tag_name, event.uuid, exc)
    return applied


def _generate_ai_summary(misp, event, source_id):
    """Generate an LLM summary from an event's first MISP report and save it back to MISP.

    Shared by the single-event and bulk summarisation routes.
    Returns (ok, message_or_error, http_status).
    """
    uuid = event.uuid

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception as exc:
        logger.warning("Could not load reports for %s: %s", uuid, exc)
        return False, "Could not load event reports", 502

    if not reports:
        return False, "No reports attached to this event", 400

    report_content = getattr(reports[0], "content", "") or ""
    if not report_content.strip():
        return False, "First report has no content", 400

    ev_tags = [t.name for t in getattr(event, "tags", []) or []]

    try:
        from analyser import llm
        summary = llm.summarise_report(report_content, event_info=event.info or "", tags=ev_tags)
    except Exception as exc:
        logger.warning("LLM summarise failed for %s: %s", uuid, exc)
        return False, "Failed to generate summary.", 502

    if not summary.strip():
        return False, "The model returned an empty summary. Check the LLM settings and the analyser log.", 502

    if summary.upper().startswith("QUALITY:"):
        return False, summary, 400

    try:
        er = MISPEventReport()
        er.name = f"[AI-Summary] {(event.info or uuid)[:80]}"
        er.content = summary
        er.distribution = 5
        misp.add_event_report(event.id, er)
    except Exception as exc:
        logger.warning("Could not add summary report to %s: %s", uuid, exc)
        return False, "Could not save summary to MISP.", 502

    collection_cache.mark_ai_summary(uuid, source_id)

    try:
        from analyser import tagger
        tagger.set_workflow_state(misp, event, "draft")
    except Exception as exc:
        logger.warning("Could not update workflow state for %s: %s", uuid, exc)

    sectors, geo, techniques = _parse_scope_from_summary(summary)
    applied_tags = []
    if sectors or geo or techniques:
        try:
            applied_tags = _apply_scope_tags(misp, event, sectors, geo, techniques)
            if applied_tags:
                logger.info("Applied scope tags to %s: %s", uuid, applied_tags)
        except Exception as exc:
            logger.warning("Could not apply scope tags to %s: %s", uuid, exc)

    # Refresh cache row so new tags/galaxies are immediately visible without a manual refresh
    _refresh_cached_event(
        uuid,
        source_id,
        misp,
        context="summarise",
        row_mutator=lambda row: row.__setitem__("has_ai_summary", True),
    )

    tag_note = f"; tagged: {', '.join(applied_tags)}" if applied_tags else ""
    audit.record(
        "summarise", "misp-event",
        entity_id=uuid,
        entity_label=event.info or uuid,
        details=f"LLM summary created from first MISP report; workflow state updated to draft{tag_note}",
    )

    return True, "Summary created and added to MISP event", 200


@bp.route("/<string:uuid>/summarise", methods=["POST"])
@rate_limited("collection_summarise", limit=15, window_s=60)
def summarise(uuid):
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    if source_id != _SCRAPER_SOURCE_ID:
        return jsonify({"ok": False, "error": "Summarisation is only available for scraper events"}), 400

    misp = misp_store._scraper_misp()
    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("MISP get_event %s failed: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not fetch event from MISP"}), 502

    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    ok, message, status = _generate_ai_summary(misp, event, source_id)
    if not ok:
        return jsonify({"ok": False, "error": message}), status
    return jsonify({"ok": True, "message": message})


@bp.route("/<string:uuid>/preview")
def preview(uuid):
    source_id = request.args.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    if src and src["kind"] == "manual":
        misp = misp_store._misp()
        misp_url_base = config.MISP_WEBAPP_URL.rstrip("/")
    elif src and src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("preview: could not connect to source %s: %s", source_id, exc)
            return jsonify({"ok": False, "error": "Source not available"}), 502
        misp_url_base = src["url"].rstrip("/")
    else:
        misp = misp_store._scraper_misp()
        misp_url_base = config.MISP_URL.rstrip("/")

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("preview: get_event %s failed: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not fetch event."}), 502

    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    try:
        reports = misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        reports = []

    report_views = [
        {
            "name": getattr(r, "name", "") or "Report",
            "content": getattr(r, "content", "") or "",
            "tags": [t.name for t in getattr(r, "tags", []) or []],
        }
        for r in reports
    ]

    event_data = _extract_event_detail(event)
    src_label = (src or {}).get("label", source_id)

    return jsonify({
        "ok": True,
        "event": event_data,
        "reports": report_views,
        "misp_url": f"{misp_url_base}/events/view/{uuid}",
        "detail_url": f"{misp_url_base}/events/view/{uuid}",
        "source_label": src_label,
    })


@bp.route("/manual/new", methods=["GET", "POST"])
def manual_new():
    manual_sources = []
    try:
        manual_sources = [
            src.name.strip()
            for src in misp_store.list_collection_sources()
            if src.enabled and (src.name or "").strip()
        ]
    except Exception as exc:
        logger.warning("Could not load manual collection sources: %s", exc)

    if not manual_sources:
        flash("No enabled manual sources configured. Add them under Configuration > Collection sources > Manual sources.", "warning")
        return redirect(url_for("data_collection.index"))

    if request.method == "POST":
        selected_source = (request.form.get("source", "") or "").strip()
        data = {
            "source": selected_source,
            "title": request.form.get("title", "").strip(),
            "date": request.form.get("date", "").strip() or str(datetime.date.today()),
            "tlp": request.form.get("tlp", "amber"),
            "source_reference": request.form.get("source_reference", "").strip(),
            "source_provider": request.form.get("source_provider", "").strip(),
            "summary": request.form.get("summary", "").strip(),
            "description": request.form.get("description", ""),
            "references": [u for u in request.form.getlist("reference") if u.strip()],
            "geographic_scope": request.form.getlist("geographic_scope"),
            "sectors": request.form.getlist("sectors"),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": request.form.getlist("threat_actors"),
        }
        if selected_source not in manual_sources:
            flash("Please select a valid enabled manual source.", "warning")
        elif not data["title"]:
            flash("Title is required.", "warning")
        else:
            try:
                uuid = misp_store.create_manual_collection_event(data)
                audit.record("create", "manual-collection-event", entity_id=uuid, entity_label=data["title"])
                flash(f"Event '{data['title']}' created. You can add attachments below.", "success")
                return redirect(url_for("data_collection.manual_detail", uuid=uuid))
            except Exception as exc:
                logger.exception("manual_new failed")
                audit.record("create", "manual-collection-event", entity_label=data["title"], details="failed")
                flash("Could not create event.", "warning")

    ctx = {
        "manual_sources": manual_sources,
        "today": str(datetime.date.today()),
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "galaxy_countries": misp_store.galaxy_geography(),
        "galaxy_sectors": misp_store.galaxy_sectors(),
        "galaxy_threat_actors": misp_store.galaxy_threat_actors(),
    }
    return render_template("data_collection/manual_entry.html", **ctx)


def _group_by_section(articles: list) -> list:
    """Group articles into [(section, [articles])], preserving first-seen order."""
    groups = {}
    for article in articles:
        groups.setdefault(article.get("section") or "Uncategorised", []).append(article)
    return list(groups.items())


@bp.route("/newsletter/new", methods=["GET", "POST"])
def newsletter_new():
    """Paste a newsletter e-mail, then review and select articles to collect."""
    sources = newsletter_parsers.available_sources()

    if request.method == "POST" and (request.form.get("action") or "") == "push":
        return _newsletter_push((request.form.get("source") or "").strip())

    if request.method == "POST":
        source = (request.form.get("source") or "").strip()
        raw = request.form.get("raw", "")
        if source not in sources:
            flash("Please choose a newsletter to parse.", "warning")
        elif not raw.strip():
            flash("Paste the newsletter e-mail first.", "warning")
        else:
            try:
                parsed = newsletter_parsers.parse(source, raw)
            except Exception:
                logger.exception("newsletter parse failed for %s", source)
                flash("Could not parse this newsletter.", "warning")
            else:
                if not parsed["articles"]:
                    flash("No articles found in the pasted text.", "warning")
                else:
                    for idx, article in enumerate(parsed["articles"]):
                        article["idx"] = idx
                    return render_template(
                        "data_collection/newsletter_review.html",
                        source=source,
                        raw=raw,
                        report_title=parsed.get("report_title", ""),
                        tlp=parsed.get("tlp") or "",
                        articles=parsed["articles"],
                        sections=_group_by_section(parsed["articles"]),
                    )

    return render_template("data_collection/newsletter_new.html", sources=sources)


@bp.route("/newsletter/pending")
def newsletter_pending():
    """List newsletters archived by the IMAP collector that await manual review."""
    pending = misp_store.list_pending_newsletters()
    return render_template("data_collection/newsletter_pending.html", pending=pending)


@bp.route("/newsletter/pending/<string:uuid>", methods=["GET", "POST"])
def newsletter_review_pending(uuid):
    """Review one pending newsletter and push the selected articles."""
    item = misp_store.get_newsletter_for_review(uuid)
    if item is None:
        flash("Pending newsletter not found.", "warning")
        return redirect(url_for("data_collection.newsletter_pending"))
    feed = item["feed"]

    if request.method == "POST":
        articles = _selected_articles(feed)
        if not articles:
            flash("No articles were selected.", "warning")
            return redirect(url_for("data_collection.newsletter_review_pending", uuid=uuid))
        counts = newsletter_ingest.publish_articles(feed, articles)
        try:
            misp_store.finalize_newsletter(uuid, [a["url"] for a in articles])
        except Exception:
            logger.exception("could not finalize newsletter %s", uuid)
        audit.record(
            "push", "newsletter-import", entity_id=uuid, entity_label=feed,
            details=f"reviewed selected={len(articles)} published={counts['published']} "
                    f"failed={counts['failed']} no_subscriber={counts['no_subscriber']}",
        )
        if counts["published"] == 0:
            flash("Could not reach the scraper queue. Check the Redis settings.", "warning")
        else:
            flash(f"Sent {counts['published']} article(s) to the scraper queue.", "success")
        return redirect(url_for("data_collection.newsletter_pending"))

    try:
        parsed = newsletter_parsers.parse(item["parser"], item["raw_email"])
    except Exception:
        logger.exception("could not parse pending newsletter %s (%s)", uuid, item["parser"])
        flash("Could not parse this newsletter.", "warning")
        return redirect(url_for("data_collection.newsletter_pending"))
    for idx, article in enumerate(parsed["articles"]):
        article["idx"] = idx
    return render_template(
        "data_collection/newsletter_review.html",
        source=feed,
        raw=item["raw_email"],
        report_title=parsed.get("report_title", ""),
        tlp=parsed.get("tlp") or "",
        articles=parsed["articles"],
        sections=_group_by_section(parsed["articles"]),
        form_action=url_for("data_collection.newsletter_review_pending", uuid=uuid),
    )


def _selected_articles(source: str) -> list[dict]:
    """Collect the articles ticked on the review screen as ingest article dicts."""
    articles = []
    for idx in request.form.getlist("selected"):
        url = request.form.get(f"url-{idx}", "").strip()
        if not url:
            continue
        articles.append({
            "url": url,
            "title": request.form.get(f"title-{idx}", "").strip(),
            "section": request.form.get(f"section-{idx}", "").strip(),
            "priority": request.form.get(f"priority-{idx}", "").strip(),
        })
    return articles


def _newsletter_push(source: str):
    """Publish the selected articles to the misp-scraper Redis channel."""
    articles = _selected_articles(source)
    if not articles:
        flash("No articles were selected.", "warning")
        return redirect(url_for("data_collection.newsletter_new"))

    # Archive the newsletter itself (raw e-mail as a report), so it can always be
    # found back and correlates with the scraper events via the article URLs.
    stored = False
    try:
        misp_store.create_newsletter_event(
            source, request.form.get("raw", ""),
            report_title=request.form.get("report_title", ""),
            tlp=request.form.get("tlp", ""),
            parser=source,
            article_urls=[a["url"] for a in articles],
        )
        stored = True
    except Exception:
        logger.exception("could not archive newsletter source event for %s", source)

    counts = newsletter_ingest.publish_articles(source, articles)
    published, failed, no_subscriber = counts["published"], counts["failed"], counts["no_subscriber"]

    audit.record(
        "push", "newsletter-import", entity_label=source,
        details=f"selected={len(articles)} published={published} failed={failed} "
                f"no_subscriber={no_subscriber} archived={'yes' if stored else 'no'}",
    )

    archived = " The newsletter itself was archived in MISP." if stored else ""
    if published == 0:
        flash(
            "Could not reach the scraper queue. Check the Redis settings under "
            "Collection sources > Manual sources pushing to scraper." + archived,
            "warning",
        )
    elif no_subscriber == published:
        flash(
            f"Sent {published} article(s) to the scraper channel, but no subscriber is listening. "
            "Start the misp-scraper 'subscribe' service or the messages are dropped." + archived,
            "warning",
        )
    else:
        msg = f"Sent {published} article(s) to the scraper queue."
        if failed:
            msg += f" {failed} could not be sent."
        if no_subscriber:
            msg += f" {no_subscriber} had no subscriber listening."
        flash(msg + archived, "success")
    return redirect(url_for("data_collection.index"))


@bp.route("/manual/<string:uuid>")
def manual_detail(uuid):
    event = misp_store.get_manual_collection_event(uuid)
    if event is None:
        return "Event not found", 404
    misp_url = f"{config.MISP_WEBAPP_URL.rstrip('/')}/events/view/{uuid}"
    return render_template("data_collection/manual_detail.html", event=event, misp_url=misp_url)


@bp.route("/manual/<string:uuid>/attach", methods=["POST"])
def manual_attach(uuid):
    f = request.files.get("attachment")
    if not f or not f.filename:
        flash("No file selected.", "warning")
        return redirect(url_for("data_collection.manual_detail", uuid=uuid))
    try:
        file_bytes = f.read()
        misp_store.add_manual_collection_attachment(uuid, f.filename, file_bytes)
        audit.record("attach", "manual-collection-event", entity_id=uuid, entity_label=f.filename)
        flash(f"Attachment '{f.filename}' added.", "success")
    except Exception as exc:
        logger.exception("manual_attach failed for %s", uuid)
        audit.record("attach", "manual-collection-event", entity_id=uuid, entity_label=f.filename, details="failed")
        flash("Could not add attachment.", "warning")
    return redirect(url_for("data_collection.manual_detail", uuid=uuid))


_CTI_EVAL_NAMESPACE = "cti-evaluation"
_CTI_EVAL_PREDICATES = [
    "overall-score", "relevance", "accuracy", "timeliness", "clarity",
    "specificity", "usefulness", "format-validity", "conversion-fidelity",
    "source-reliability", "evidence-strength", "confidence",
]
_CTI_EVAL_VALUES = ["very-low", "low", "moderate", "high", "very-high"]


def _misp_for_source(source_id):
    """Return a connected PyMISP instance for the given source_id, or None on error."""
    src = _find_source(source_id)
    if src is None:
        return None, "Unknown source"
    if src["kind"] == "misp":
        if not src.get("api_key"):
            return None, "Source not configured (missing API key)"
        try:
            return PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False), None
        except Exception as exc:
            logger.warning("_misp_for_source %s: %s", source_id, exc)
            return None, "Could not connect to source"
    return misp_store._scraper_misp(), None


def _is_remote_source(source_id: str) -> bool:
    """True when the source is another MISP server, whose workflow states are
    not ours to change. Scraper and manual events live on our own MISP."""
    return (_find_source(source_id) or {}).get("kind") == "misp"


def _refresh_cached_event(uuid: str, source_id: str, misp, context: str = "", row_mutator=None) -> None:
    """Refresh one event row in the local collection cache after a MISP write."""
    try:
        fresh = misp.get_event(uuid, pythonify=True)
        if fresh and not isinstance(fresh, dict):
            row = collection_cache._extract_row(fresh, source_id)
            if row_mutator is not None:
                row_mutator(row)
            collection_cache.insert_event(row)
    except Exception as exc:
        suffix = f" after {context}" if context else ""
        logger.warning("Could not refresh cache for %s%s: %s", uuid, suffix, exc)


@bp.route("/<string:uuid>/cti-tag", methods=["POST"])
def cti_tag(uuid):
    """Apply a cti-evaluation taxonomy tag to a MISP event.

    POST JSON: {"source": "...", "predicate": "relevance", "value": "high"}
    The tag is pushed as a non-local tag so it syncs to the source MISP server.
    """
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    predicate = (data.get("predicate") or "").strip().lower()
    value = (data.get("value") or "").strip().lower()
    if predicate not in _CTI_EVAL_PREDICATES:
        return jsonify({"ok": False, "error": f"Unknown predicate: {predicate!r}"}), 400
    if value not in _CTI_EVAL_VALUES:
        return jsonify({"ok": False, "error": f"Unknown value: {value!r}"}), 400

    misp, err_msg = _misp_for_source(source_id)
    if misp is None:
        return jsonify({"ok": False, "error": err_msg}), 502

    tag_name = f'{_CTI_EVAL_NAMESPACE}:{predicate}="{value}"'
    try:
        r = misp.tag(uuid, tag_name, local=False)
        if isinstance(r, dict) and "errors" in r:
            return jsonify({"ok": False, "error": str(r["errors"])}), 400
    except Exception as exc:
        logger.warning("cti_tag failed for %s (%s): %s", uuid, tag_name, exc)
        return jsonify({"ok": False, "error": "Could not apply tag."}), 502

    # Refresh this event in local cache so the new CTI-evaluation tag appears immediately.
    _refresh_cached_event(uuid, source_id, misp, context="cti_tag")

    audit.record("tag", "misp-event", entity_id=uuid, details=tag_name)
    return jsonify({"ok": True, "tag": tag_name})


_SCOPE_TAG_ALLOWED_PREFIXES = (
    'misp-galaxy:country=',
    'misp-galaxy:target-information=',
    'misp-galaxy:sector=',
    'misp-galaxy:threat-actor=',
    'misp-galaxy:mitre-attack-pattern=',
)


@bp.route("/<string:uuid>/scope-tag", methods=["POST"])
def scope_tag(uuid):
    """Add or remove a galaxy scope tag on a collection event.

    POST JSON: {"source": "...", "tag": "misp-galaxy:country=...", "action": "add"|"remove"}
    """
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    tag_name = (data.get("tag") or "").strip()
    action = data.get("action", "add")

    if not tag_name:
        return jsonify({"ok": False, "error": "tag is required"}), 400
    if not any(tag_name.startswith(p) for p in _SCOPE_TAG_ALLOWED_PREFIXES):
        return jsonify({"ok": False, "error": "Only galaxy scope tags may be applied"}), 400
    if action not in ("add", "remove"):
        return jsonify({"ok": False, "error": "action must be add or remove"}), 400

    misp, err_msg = _misp_for_source(source_id)
    if misp is None:
        return jsonify({"ok": False, "error": err_msg}), 502

    try:
        if action == "remove":
            r = misp.untag(uuid, tag_name)
            err_text = _misp_response_errors(r)
            if err_text:
                return jsonify({"ok": False, "error": err_text}), 400
        else:
            r = misp.tag(uuid, tag_name)
            err_text = _misp_response_errors(r)
            if err_text:
                misp_store._ensure_tag(misp, tag_name)
                r = misp.tag(uuid, tag_name)
                err_text = _misp_response_errors(r)
                if err_text:
                    return jsonify({"ok": False, "error": err_text}), 400
    except Exception as exc:
        logger.warning("scope_tag failed for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not apply tag"}), 502

    _refresh_cached_event(uuid, source_id, misp, context="scope_tag")

    audit.record("tag", "collection-scope", entity_id=uuid, details=f"{action}: {tag_name}")
    return jsonify({"ok": True, "tag": tag_name, "action": action})


_WORKFLOW_STATE_PREFIX = "workflow:state="
_WORKFLOW_REJECTED_TAG = 'workflow:state="rejected"'


def _dismissed_tag() -> str:
    """Local tag marking an event an analyst set aside.

    Used for events from another MISP server, whose workflow state belongs to
    that server. Configurable under Configuration > Context elements.
    """
    return getattr(config, "TAG_COLLECTION_DISMISSED", 'zsazsa:event="dismiss"')


def _is_set_aside(tags) -> bool:
    """True when an analyst already rejected or dismissed the event."""
    return _WORKFLOW_REJECTED_TAG in tags or _dismissed_tag() in tags


def _force_workflow_tag(row: dict, tag_name: str) -> None:
    """Overwrite the cached row's workflow:state tag with the one we just applied.

    MISP can take a moment to reflect a tag change in get_event responses, so a
    refetch right after tagging may still return the old workflow:state tag.
    Forcing it here keeps the cache consistent with what we just wrote, without
    waiting for a full cache refresh.
    """
    tags = [t for t in row.get("tags", []) if not t.startswith(_WORKFLOW_STATE_PREFIX)]
    tags.append(tag_name)
    row["tags"] = tags


def _force_dismissed_tag(row: dict, tag_name: str) -> None:
    """Make sure the cached row carries the dismiss tag we just applied.

    Same reason as _force_workflow_tag: MISP may still return the old tag list
    when the row is refetched right after the write.
    """
    tags = row.get("tags", [])
    if tag_name not in tags:
        row["tags"] = tags + [tag_name]


def _apply_dismiss_tag(misp, event, source_id: str) -> tuple[bool, str]:
    """Tag a single event as dismissed.

    Returns (changed, error). A False without an error means the event already
    carried the tag.
    """
    uuid = event.uuid
    tag_name = _dismissed_tag()
    if any(getattr(t, "name", "") == tag_name for t in (getattr(event, "tags", []) or [])):
        return False, ""

    try:
        resp = misp.tag(uuid, tag_name, local=True)
        err_text = _misp_response_errors(resp)
        if err_text:
            logger.warning("dismiss: MISP refused the tag on %s: %s", uuid, err_text)
            return False, "Could not apply the dismiss tag."
    except Exception as exc:
        logger.warning("dismiss: could not tag %s: %s", uuid, exc)
        return False, "Could not apply the dismiss tag."

    audit.record(
        "dismiss", "misp-event", entity_id=uuid, entity_label=event.info or uuid,
        details=f"applied {tag_name}",
    )
    _refresh_cached_event(
        uuid, source_id, misp, context="dismiss",
        row_mutator=lambda row: _force_dismissed_tag(row, tag_name),
    )
    return True, ""


@bp.route("/queue-for-tlr", methods=["POST"])
def queue_for_tlr():
    """Tag one or more collection events as candidates for the threat landscape report.

    Applies zsazsa:product="threat-landscape-report" and advances workflow state
    from 'incomplete' to 'ongoing'. Events already at 'complete' are not regressed.

    POST JSON: {"events": [{"uuid": "...", "sourceId": "..."}]}
    """
    data, err = _json_object()
    if err:
        return err
    events = data.get("events") or []
    if not events:
        return jsonify({"ok": False, "error": "No events provided"}), 400

    tagged = 0
    for ev in events:
        uuid = (ev.get("uuid") or "").strip()
        source_id = (ev.get("sourceId") or _SCRAPER_SOURCE_ID).strip()
        if not uuid:
            continue

        misp_client, err_msg = _misp_for_source(source_id)
        if misp_client is None:
            logger.warning("queue_for_tlr: no MISP client for source %s: %s", source_id, err_msg)
            continue

        misp_store._tag_scraper_event_as_product_source(
            uuid, "threat-landscape-report", misp_client=misp_client
        )

        # Refresh cache so the product badge is visible immediately
        _refresh_cached_event(uuid, source_id, misp_client, context="queue_for_tlr")
        tagged += 1

    audit.record("tag", "collection-tlr-queue",
                 details=f"queued {tagged} event(s) for threat landscape")
    return jsonify({"ok": True, "tagged": tagged})


@bp.route("/bulk-reject-excluded", methods=["POST"])
def bulk_reject_excluded():
    """Set aside every cached event whose title matches DAILY_BRIEFING_TITLE_EXCLUSIONS.

    Events on our own MISP get workflow:state="rejected", events from another
    MISP server get the dismiss tag, the same split as the reject button on a
    single event. Events already set aside are skipped.

    Returns JSON: {ok, rejected, dismissed, already_rejected, already_dismissed,
                   errors, message}
    """
    excl_raw = getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", []) or []
    if isinstance(excl_raw, str):
        excl_raw = excl_raw.splitlines()
    excl_patterns = [str(p).strip().lower() for p in excl_raw if str(p).strip()]

    if not excl_patterns:
        return jsonify({"ok": True, "rejected": 0, "dismissed": 0, "already_rejected": 0,
                        "already_dismissed": 0, "errors": 0,
                        "message": "No exclusion patterns configured."})

    data, err = _json_object()
    if err:
        return err
    requested_uuids = {
        (u or "").strip()
        for u in (data.get("uuids") or [])
        if (u or "").strip()
    }

    all_source_ids = [s["id"] for s in _sources()]
    events = collection_cache.get_events(all_source_ids, [], 2000)
    if requested_uuids:
        events = [ev for ev in events if (ev.get("uuid") or "") in requested_uuids]

    def _title_matches(ev):
        return any(p in (ev.get("info") or "").lower() for p in excl_patterns)

    dismissed_tag = _dismissed_tag()
    to_set_aside = []
    already_rejected = already_dismissed = 0
    for ev in events:
        if not _title_matches(ev):
            continue
        tags = ev.get("tags", [])
        if _WORKFLOW_REJECTED_TAG in tags:
            already_rejected += 1
        elif dismissed_tag in tags:
            already_dismissed += 1
        else:
            to_set_aside.append(ev)

    source_cache: dict[str, tuple] = {}
    rejected = dismissed = errors = 0

    for ev in to_set_aside:
        src_id = ev.get("source_id") or _SCRAPER_SOURCE_ID
        if src_id not in source_cache:
            m, err_msg = _misp_for_source(src_id)
            if m is None:
                logger.warning("bulk_reject_excluded: cannot connect to %s: %s", src_id, err_msg)
            source_cache[src_id] = (m, _is_remote_source(src_id))
        misp, remote = source_cache[src_id]
        if misp is None:
            errors += 1
            continue
        uuid = ev.get("uuid")
        try:
            event = misp.get_event(uuid, pythonify=True)
            if event is None or isinstance(event, dict):
                logger.warning("bulk_reject_excluded: cannot load event %s", uuid)
                errors += 1
                continue
            if remote:
                changed, error = _apply_dismiss_tag(misp, event, src_id)
                if error:
                    errors += 1
                elif changed:
                    dismissed += 1
                continue
            from analyser import tagger
            tagger.set_workflow_state(misp, event, "rejected")
            rejected += 1
            audit.record("tag", "misp-event", entity_id=uuid, details=_WORKFLOW_REJECTED_TAG)
            _refresh_cached_event(uuid, src_id, misp, context="bulk_reject_excluded")
        except Exception as exc:
            logger.warning("bulk_reject_excluded: failed to tag %s: %s", uuid, exc)
            errors += 1

    parts = []
    if rejected:
        parts.append(f"{rejected} event(s) set to rejected")
    if dismissed:
        parts.append(f"{dismissed} event(s) dismissed")
    if already_rejected:
        parts.append(f"{already_rejected} already rejected")
    if already_dismissed:
        parts.append(f"{already_dismissed} already dismissed")
    if errors:
        parts.append(f"{errors} error(s)")
    return jsonify({"ok": True, "rejected": rejected, "dismissed": dismissed,
                    "already_rejected": already_rejected, "already_dismissed": already_dismissed,
                    "errors": errors, "message": ", ".join(parts) or "No events changed"})


_BULK_SUMMARISE_LIMIT = 10


@bp.route("/bulk-flag", methods=["POST"])
def bulk_flag():
    """Flag one or more selected collection events for follow-up review.

    POST JSON: {"events": [{"uuid": "...", "sourceId": "..."}]}
    Events already flagged are left untouched.
    Returns JSON: {ok, flagged, already_flagged, errors, message}
    """
    data, err = _json_object()
    if err:
        return err
    events = data.get("events") or []
    if not events:
        return jsonify({"ok": False, "error": "No events provided"}), 400

    tag = getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"')
    misp_cache: dict[str, object] = {}
    flagged = already_flagged = errors = 0

    for ev in events:
        uuid = (ev.get("uuid") or "").strip()
        source_id = (ev.get("sourceId") or _SCRAPER_SOURCE_ID).strip()
        if not uuid:
            continue
        if collection_cache.is_flagged(uuid):
            already_flagged += 1
            continue

        if source_id not in misp_cache:
            m, err_msg = _misp_for_source(source_id)
            if m is None:
                logger.warning("bulk_flag: no MISP client for %s: %s", source_id, err_msg)
            misp_cache[source_id] = m
        misp = misp_cache[source_id]
        if misp is None:
            errors += 1
            continue

        try:
            r = misp.tag(uuid, tag, local=True)
            if isinstance(r, dict) and "errors" in r:
                logger.warning("bulk_flag: MISP error for %s: %s", uuid, r["errors"])
                errors += 1
                continue
            collection_cache.flag_event(uuid)
            _refresh_cached_event(uuid, source_id, misp, context="bulk_flag")
            audit.record("flag", "misp-event", entity_id=uuid)
            flagged += 1
        except Exception as exc:
            logger.warning("bulk_flag: failed to flag %s: %s", uuid, exc)
            errors += 1

    parts = [f"{flagged} event(s) flagged"]
    if already_flagged:
        parts.append(f"{already_flagged} already flagged")
    if errors:
        parts.append(f"{errors} error(s)")
    return jsonify({"ok": True, "flagged": flagged, "already_flagged": already_flagged,
                    "errors": errors, "message": ", ".join(parts)})


@bp.route("/bulk-reject", methods=["POST"])
def bulk_reject():
    """Set aside one or more selected collection events.

    Events on our own MISP get workflow:state="rejected"; events from another
    MISP server get the local dismiss tag instead, since their workflow state
    belongs to that server.

    POST JSON: {"events": [{"uuid": "...", "sourceId": "..."}]}
    Events already rejected or dismissed are left untouched.
    Returns JSON: {ok, rejected, already_rejected, dismissed, already_dismissed,
                   errors, message}
    """
    data, err = _json_object()
    if err:
        return err
    events = data.get("events") or []
    if not events:
        return jsonify({"ok": False, "error": "No events provided"}), 400

    # Client and kind per source, so listing the sources (a MISP call) happens
    # once per source rather than once per event.
    source_cache: dict[str, tuple] = {}
    rejected = already_rejected = dismissed = already_dismissed = errors = 0

    for ev in events:
        uuid = (ev.get("uuid") or "").strip()
        source_id = (ev.get("sourceId") or _SCRAPER_SOURCE_ID).strip()
        if not uuid:
            continue

        if source_id not in source_cache:
            m, err_msg = _misp_for_source(source_id)
            if m is None:
                logger.warning("bulk_reject: no MISP client for %s: %s", source_id, err_msg)
            source_cache[source_id] = (m, _is_remote_source(source_id))
        misp, remote = source_cache[source_id]
        if misp is None:
            errors += 1
            continue

        try:
            event = misp.get_event(uuid, pythonify=True)
        except Exception as exc:
            logger.warning("bulk_reject: cannot load %s: %s", uuid, exc)
            errors += 1
            continue
        if not event or isinstance(event, dict):
            errors += 1
            continue

        if remote:
            changed, error = _apply_dismiss_tag(misp, event, source_id)
            if error:
                errors += 1
            elif changed:
                dismissed += 1
            else:
                already_dismissed += 1
            continue

        currently_rejected = any(
            getattr(t, "name", "") == _WORKFLOW_REJECTED_TAG
            for t in (getattr(event, "tags", []) or [])
        )
        if currently_rejected:
            already_rejected += 1
            continue

        try:
            from analyser import tagger
            tagger.set_workflow_state(misp, event, "rejected")
            audit.record(
                "reject", "misp-event", entity_id=uuid, entity_label=event.info or uuid,
                details=f"applied {_WORKFLOW_REJECTED_TAG}",
            )
            _refresh_cached_event(
                uuid, source_id, misp, context="bulk_reject",
                row_mutator=lambda row: _force_workflow_tag(row, _WORKFLOW_REJECTED_TAG),
            )
            rejected += 1
        except Exception as exc:
            logger.warning("bulk_reject: failed to reject %s: %s", uuid, exc)
            errors += 1

    parts = []
    if rejected:
        parts.append(f"{rejected} event(s) rejected")
    if dismissed:
        parts.append(f"{dismissed} event(s) dismissed")
    if already_rejected:
        parts.append(f"{already_rejected} already rejected")
    if already_dismissed:
        parts.append(f"{already_dismissed} already dismissed")
    if errors:
        parts.append(f"{errors} error(s)")
    return jsonify({"ok": True, "rejected": rejected, "already_rejected": already_rejected,
                    "dismissed": dismissed, "already_dismissed": already_dismissed,
                    "errors": errors, "message": ", ".join(parts) or "No events changed"})


@bp.route("/bulk-summarise", methods=["POST"])
@rate_limited("collection_summarise", limit=15, window_s=60)
def bulk_summarise():
    """Generate LLM summaries for a batch of selected scraper-sourced collection events.

    POST JSON: {"events": [{"uuid": "...", "sourceId": "..."}]}
    Non-scraper events and events that already have a summary are skipped. To
    keep the request bounded, only the first _BULK_SUMMARISE_LIMIT events are processed.
    Returns JSON: {ok, summarised, skipped, errors, message}
    """
    data, err = _json_object()
    if err:
        return err
    events = data.get("events") or []
    if not events:
        return jsonify({"ok": False, "error": "No events provided"}), 400

    uuids = [(ev.get("uuid") or "").strip() for ev in events if (ev.get("uuid") or "").strip()]
    cached_by_uuid = {row["uuid"]: row for row in collection_cache.get_events_by_uuids(uuids)}

    misp = misp_store._scraper_misp()
    summarised = skipped = errors = 0

    for ev in events[:_BULK_SUMMARISE_LIMIT]:
        uuid = (ev.get("uuid") or "").strip()
        source_id = (ev.get("sourceId") or _SCRAPER_SOURCE_ID).strip()
        if not uuid or source_id != _SCRAPER_SOURCE_ID:
            skipped += 1
            continue
        if cached_by_uuid.get(uuid, {}).get("has_ai_summary"):
            skipped += 1
            continue

        try:
            event = misp.get_event(uuid, pythonify=True)
        except Exception as exc:
            logger.warning("bulk_summarise: cannot load %s: %s", uuid, exc)
            errors += 1
            continue
        if not event or isinstance(event, dict):
            errors += 1
            continue

        ok, message, _status = _generate_ai_summary(misp, event, source_id)
        if ok:
            summarised += 1
        else:
            logger.warning("bulk_summarise: failed for %s: %s", uuid, message)
            errors += 1

    skipped_extra = max(0, len(events) - _BULK_SUMMARISE_LIMIT)
    skipped += skipped_extra

    parts = [f"{summarised} summary/summaries created"]
    if skipped:
        parts.append(f"{skipped} skipped")
    if errors:
        parts.append(f"{errors} error(s)")
    return jsonify({"ok": True, "summarised": summarised, "skipped": skipped,
                    "errors": errors, "message": ", ".join(parts)})


@bp.route("/<string:uuid>/flag", methods=["POST"])
def flag_for_review(uuid):
    data, err = _json_object()
    if err:
        return err
    source_id = data.get("source") or _SCRAPER_SOURCE_ID
    src = _find_source(source_id)
    tag = getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"')

    currently_flagged = collection_cache.is_flagged(uuid)

    if src and src["kind"] == "misp":
        if not src.get("api_key"):
            return jsonify({"ok": False, "error": "Source not configured"}), 502
        try:
            misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
        except Exception as exc:
            logger.warning("flag_for_review: source connection failed: %s", exc)
            return jsonify({"ok": False, "error": "Source not available"}), 502
    else:
        misp = misp_store._scraper_misp()

    try:
        if currently_flagged:
            misp.untag(uuid, tag)
            collection_cache.unflag_event(uuid)
            _refresh_cached_event(uuid, source_id, misp, context="unflag")
            audit.record("unflag", "misp-event", entity_id=uuid)
            return jsonify({"ok": True, "flagged": False})
        else:
            r = misp.tag(uuid, tag, local=True)
            if isinstance(r, dict) and "errors" in r:
                return jsonify({"ok": False, "error": str(r["errors"])}), 400
            collection_cache.flag_event(uuid)
            _refresh_cached_event(uuid, source_id, misp, context="flag")
            audit.record("flag", "misp-event", entity_id=uuid)
            return jsonify({"ok": True, "flagged": True})
    except Exception as exc:
        logger.warning("flag_for_review failed for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not update flag."}), 502


@bp.route("/<string:uuid>/reject", methods=["POST"])
def reject_event(uuid):
    """Set workflow:state="rejected" on a single MISP event.

    POST JSON: {"source": "<source_id>"}
    Returns JSON: {ok, rejected: bool, message: str, event_title: str}
    """
    data, err = _json_object()
    if err:
        return err
    source_id = (data.get("source") or _SCRAPER_SOURCE_ID).strip()

    misp, err_msg = _misp_for_source(source_id)
    if misp is None:
        return jsonify({"ok": False, "error": err_msg or "Source not available"}), 502

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("reject_event: cannot load %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not load event from source"}), 502
    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    event_title = (getattr(event, "info", "") or "").strip() or uuid
    currently_rejected = any(
        getattr(t, "name", "") == _WORKFLOW_REJECTED_TAG
        for t in (getattr(event, "tags", []) or [])
    )

    if currently_rejected:
        return jsonify({
            "ok": True,
            "rejected": True,
            "event_title": event_title,
            "message": f"Event '{event_title[:80]}' is already marked as rejected.",
        })

    try:
        from analyser import tagger
        tagger.set_workflow_state(misp, event, "rejected")
        logger.info("reject_event: marked %s rejected (%s)", uuid, event_title)
        audit.record(
            "reject", "misp-event", entity_id=uuid, entity_label=event_title,
            details=f"applied {_WORKFLOW_REJECTED_TAG}",
        )
        message = f"Event '{event_title[:80]}' marked as rejected."
    except Exception as exc:
        logger.warning("reject_event failed for %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not update workflow state."}), 502

    # Refresh cache row so badge/state is immediately visible without a manual refresh
    _refresh_cached_event(
        uuid, source_id, misp, context="reject_event",
        row_mutator=lambda row: _force_workflow_tag(row, _WORKFLOW_REJECTED_TAG),
    )

    return jsonify({
        "ok": True,
        "rejected": True,
        "event_title": event_title,
        "message": message,
    })


@bp.route("/<string:uuid>/dismiss", methods=["POST"])
def dismiss_event(uuid):
    """Mark a single event as dismissed with the configured local tag.

    Events pulled from another MISP server carry that server's workflow state,
    which is not ours to change, so an analyst sets them aside with this tag
    instead of rejecting them.

    POST JSON: {"source": "<source_id>"}
    Returns JSON: {ok, dismissed: bool, message: str, event_title: str}
    """
    data, err = _json_object()
    if err:
        return err
    source_id = (data.get("source") or _SCRAPER_SOURCE_ID).strip()

    misp, err_msg = _misp_for_source(source_id)
    if misp is None:
        return jsonify({"ok": False, "error": err_msg or "Source not available"}), 502

    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("dismiss_event: cannot load %s: %s", uuid, exc)
        return jsonify({"ok": False, "error": "Could not load event from source"}), 502
    if not event or isinstance(event, dict):
        return jsonify({"ok": False, "error": "Event not found"}), 404

    event_title = (getattr(event, "info", "") or "").strip() or uuid
    changed, error = _apply_dismiss_tag(misp, event, source_id)
    if error:
        return jsonify({"ok": False, "error": error}), 502

    if changed:
        message = f"Event '{event_title[:80]}' dismissed."
    else:
        message = f"Event '{event_title[:80]}' was already dismissed."
    return jsonify({
        "ok": True,
        "dismissed": True,
        "event_title": event_title,
        "message": message,
    })
