"""Dashboard-triggered collection analyser actions.

This module provides three manual analyser actions used from the dashboard:
- daily briefing draft generation
- flash intel draft generation (for PIR/GIR matched events)
- vulnerability advisory draft generation (for CVE-matched events)
"""

import logging
import re
import time
from datetime import datetime, timedelta, timezone

import config
from analyser import llm, tagger
from analyser.reader import save_last_action
from core import asset_inventory
from core.db import log_event, log_pipeline_run_end, log_pipeline_run_start
from core.vuln_lookup import CVE_RE, fetch_cve_info
from pymisp import MISPEventReport
from webapp import audit, collection_cache, job_store, matching as req_matching, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX
from webapp.utils import scraper_enabled

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
_BRIEFING_REJECTION_PREFIX = "zsazsa:daily-briefing-rejection"
# How alike two briefing stories have to be, on the 0..1 score
# detect_story_overlaps gives, before the later one is dropped as duplicate.
_OVERLAP_DROP_SCORE = 0.65

_SECTOR_LINE_RE = re.compile(r'\*\*Targeted sector:\*\*\s*(.+)', re.IGNORECASE)
_GEO_LINE_RE = re.compile(r'\*\*Geographic scope:\*\*\s*(.+)', re.IGNORECASE)
_ATTACK_LINE_RE = re.compile(r'\*\*MITRE ATT&CK techniques:\*\*\s*(.+)', re.IGNORECASE)
_ATTACK_ID_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_THREAT_ACTOR_LINE_RE = re.compile(r'\*\*Threat actor:\*\*\s*(.+)', re.IGNORECASE)
_ALSO_KNOWN_AS_RE = re.compile(r'\(\s*(?:also known as|aka)\s+([^)]+)\)', re.IGNORECASE)
_VENDOR_LINE_RE = re.compile(r'\*\*Vendor/Technology:\*\*\s*(.+)', re.IGNORECASE)


def _parse_threat_actors(val: str) -> list:
    """Split a threat actor line, extracting aliases from '(also known as ...)' parentheticals."""
    if "none identified" in val.lower():
        return []
    names = []
    cleaned = re.sub(r'\([^)]*\)', '', val)
    for part in cleaned.split(','):
        part = part.strip()
        if part:
            names.append(part)
    for m in _ALSO_KNOWN_AS_RE.finditer(val):
        for alias in m.group(1).split(','):
            alias = alias.strip()
            if alias:
                names.append(alias)
    return names


def _deduplicate_vendors(vendors: list) -> list:
    """Drop vendor entries that are a more-specific sub-string of a shorter entry already kept."""
    sorted_v = sorted(vendors, key=lambda v: len(v))
    kept = []
    kept_lower = []
    for v in sorted_v:
        vl = v.lower()
        if any(vl == k or vl.startswith(k + ' ') or vl.startswith(k + '-') for k in kept_lower):
            continue
        kept.append(v)
        kept_lower.append(vl)
    return kept


def galaxy_names_with_commas() -> frozenset:
    """The sector and country names, lower-cased, that have a comma in them.

    parse_misp_context needs them to read a line like "Finance, Government,
    Administration" as two sectors rather than three.
    """
    return frozenset(
        name.strip().lower()
        for galaxy in (misp_store.GALAXY_SECTOR, misp_store.GALAXY_COUNTRY, misp_store.GALAXY_TARGET_INFORMATION)
        for name in misp_store._galaxy_tag_map(galaxy)
        if "," in name
    )


def parse_misp_context(text: str, names_with_commas=frozenset()) -> dict:
    """The scope an AI summary names, read from its "MISP context" lines.

    Shared with the data collection page, which writes summaries of its own and
    has to tag them with the same scope this run would. The names on a line are
    separated by commas, so two neighbours that together make a name in
    `names_with_commas` (from galaxy_names_with_commas) stay one name.
    """
    result = {"sectors": [], "geographies": [], "attack_techniques": [], "threat_actors": [], "vendor": []}

    def _csv(regex):
        m = regex.search(text)
        if not m:
            return []
        val = m.group(1).strip()
        if "none identified" in val.lower():
            return []
        names = []
        for part in val.split(","):
            part = part.strip()
            if not part:
                continue
            if names and f"{names[-1]}, {part}".lower() in names_with_commas:
                names[-1] += f", {part}"
            else:
                names.append(part)
        return names

    result["sectors"] = _csv(_SECTOR_LINE_RE)
    result["geographies"] = _csv(_GEO_LINE_RE)
    m = _THREAT_ACTOR_LINE_RE.search(text)
    if m:
        result["threat_actors"] = _parse_threat_actors(m.group(1).strip())
    raw_vendors = _csv(_VENDOR_LINE_RE)
    result["vendor"] = _deduplicate_vendors(raw_vendors)
    m = _ATTACK_LINE_RE.search(text)
    if m:
        val = m.group(1).strip()
        if "none identified" not in val.lower():
            result["attack_techniques"] = _ATTACK_ID_RE.findall(val)
    return result


def _log(event, outcome, detail=None):
    log_event(
        event_uuid=event.uuid,
        event_info=getattr(event, "info", ""),
        source_feed=tagger.get_source_feed(event),
        outcome=outcome,
        detail=detail,
    )


def daily_briefing_title_exclusions() -> list[str]:
    """The configured exclusion patterns, lower-cased for matching.

    Shared with the data collection page, which marks the events this run would
    drop and offers to set them aside, so both work off one reading of the
    setting rather than two that can drift apart.
    """
    raw = getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", [])
    if isinstance(raw, str):
        raw = raw.splitlines()
    return [str(p).strip().lower() for p in (raw or []) if str(p).strip()]


def title_excluded(title: str, patterns: list[str]) -> bool:
    haystack = (title or "").strip().lower()
    if not haystack:
        return False
    return any(p in haystack for p in patterns)


def _event_or_report_title_excluded(event, reports, patterns: list[str]) -> bool:
    if not patterns:
        return False
    if title_excluded(getattr(event, "info", "") or "", patterns):
        return True
    for report in reports or []:
        if title_excluded(getattr(report, "name", "") or "", patterns):
            return True
    return False


def _emit(progress, step: str, state: str, message: str = "") -> None:
    if progress is None:
        return
    try:
        progress(step=step, state=state, message=message)
    except Exception:
        # Progress reporting should never break pipeline execution.
        pass


def _refresh_scraper_cache() -> None:
    if not scraper_enabled():
        return
    # Run a blocking refresh so the action always works from current scraper state.
    collection_cache.refresh_source({"id": "scraper", "kind": "scraper"})


def _incomplete_scraper_events(days=1, since=None):
    """The scraper's events of the last ``days`` days, today included, that are
    still incomplete or ongoing, and with ``since`` only those changed since
    that Unix time."""
    # These candidates come from the scraper only. Without one the pipeline runs
    # and reports no candidates, rather than failing the whole action.
    if not scraper_enabled():
        return None, []
    misp = misp_store._scraper_misp()
    return misp, _incomplete_events(misp, config.SCRAPER_MARKER_TAG, days, since)


def _incomplete_manual_entries(days=1, since=None):
    """The manual collection entries of the same window that have a report.

    They are kept on the webapp MISP. One without a report has nothing for the
    model to read, so it is left for the analyst rather than rejected.
    """
    misp = misp_store._misp()
    entries = _incomplete_events(misp, misp_store.TAG_MANUAL_ENTRY, days, since)
    return misp, [e for e in entries if getattr(e, "event_reports", None)]


def _incomplete_events(misp, marker_tag, days, since):
    first_day = datetime.now(timezone.utc).date() - timedelta(days=days - 1)
    changed = {"timestamp": since} if since else {}
    events = misp.search(
        tags=[marker_tag],
        date_from=first_day.isoformat(),
        limit=getattr(config, "MISP_SCRAPER_LIMIT", 500),
        page=1,
        pythonify=True,
        order=misp_store.NEWEST_FIRST,
        **changed,
    )
    if isinstance(events, dict):
        # Raised rather than read as no events, as the analyser's reader does:
        # the schedule reads from where its last completed run started, so a
        # run that completed on an error answer would skip these events for good.
        raise RuntimeError(f"MISP search failed: {events.get('errors') or events}")
    if not events:
        return []

    eligible = {'workflow:state="incomplete"', 'workflow:state="ongoing"'}
    filtered = []
    for event in events:
        tags = {getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])}
        if tags & eligible:
            filtered.append(event)
    return filtered


def _event_has_product_tag(event, product_label: str) -> bool:
    tag_name = f'zsazsa:product="{product_label}"'
    return any(getattr(t, "name", "") == tag_name for t in (getattr(event, "tags", []) or []))


def _event_http_error(event) -> bool:
    for tag in getattr(event, "tags", []) or []:
        if (getattr(tag, "name", "") or "").startswith(_HTTP_ERROR_PREFIX):
            return True
    return False



def _event_reports(misp, event):
    try:
        return misp.get_event_reports(event.id, pythonify=True) or []
    except Exception:
        return []


def _first_non_empty_report_content(reports) -> str:
    for report in reports:
        content = (getattr(report, "content", "") or "").strip()
        if content:
            return content
    return ""


def _extract_ai_summary(reports) -> str:
    for report in reports:
        name = (getattr(report, "name", "") or "")
        if name.startswith(AI_SUMMARY_PREFIX):
            return (getattr(report, "content", "") or "").strip()
    return ""


def _add_briefing_rejection_note(misp, event, reason: str, report_title: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    note = MISPEventReport()
    note.name = f"{_BRIEFING_REJECTION_PREFIX} {ts}"
    lines = [
        "Decision: rejected for daily briefing relevance",
        f"Time (UTC): {ts}",
        f"Event: {(event.info or '').strip()}",
    ]
    if report_title:
        lines.append(f"Report title: {report_title}")
    if reason:
        lines.append(f"Reason: {reason}")
    note.content = "\n".join(lines)
    note.distribution = 5
    try:
        misp.add_event_report(event.id, note)
    except Exception as exc:
        logger.warning("Could not add daily briefing rejection note for %s: %s", event.uuid, exc)


def _build_galaxy_lookup() -> dict:
    attack_map = misp_store._galaxy_tag_map(misp_store.GALAXY_MITRE_ATTACK)
    attack_by_id = {}
    for value, tag_name in attack_map.items():
        m = _ATTACK_ID_RE.search(value)
        if m:
            attack_by_id[m.group(0)] = tag_name
    sector_map = misp_store._galaxy_tag_map(misp_store.GALAXY_SECTOR)
    country_map = misp_store._galaxy_tag_map(misp_store.GALAXY_COUNTRY)
    ti_map = misp_store._galaxy_tag_map(misp_store.GALAXY_TARGET_INFORMATION)
    ta_map = misp_store._galaxy_tag_map(misp_store.GALAXY_THREAT_ACTOR)
    country_by_name = {k.strip().lower(): v for k, v in country_map.items()}
    country_by_name.update({k.strip().lower(): v for k, v in ti_map.items()})
    logger.info(
        "Galaxy lookup built: %d ATT&CK techniques, %d sectors, %d countries, %d threat actors",
        len(attack_by_id), len(sector_map), len(country_by_name), len(ta_map),
    )
    return {
        "attack_by_id": attack_by_id,
        "sector_by_name": {k.strip().lower(): v for k, v in sector_map.items()},
        "country_by_name": country_by_name,
        "threat_actor_by_name": {k.lower(): v for k, v in ta_map.items()},
    }


# Which context line feeds which galaxy lookup. ATT&CK is keyed on the technique
# ID exactly as parsed, the rest on the lower-cased name.
_CONTEXT_GALAXIES = (
    ("attack_techniques", "attack_by_id", str, "ATT&CK"),
    ("sectors", "sector_by_name", str.lower, "sector"),
    ("geographies", "country_by_name", str.lower, "country"),
    ("threat_actors", "threat_actor_by_name", str.lower, "threat actor"),
)


def _apply_misp_context_tags(misp, event, context: dict, lookup: dict) -> int:
    """Tag an event with the galaxy clusters its summary's context lines name."""
    applied = 0
    for context_key, lookup_key, key_for, label in _CONTEXT_GALAXIES:
        by_name = lookup.get(lookup_key, {})
        for value in context.get(context_key, []):
            tag_name = by_name.get(key_for(value))
            if not tag_name:
                continue
            try:
                r = misp.tag(event.uuid, tag_name)
            except Exception as exc:
                logger.warning("Could not apply %s tag %s to %s: %s", label, value, event.uuid, exc)
                continue
            if isinstance(r, dict) and "errors" in r:
                logger.warning("Could not apply %s tag %s to %s: %s", label, value, event.uuid, r["errors"])
            else:
                applied += 1
    return applied


def _ensure_ai_summary(misp, event, reports, galaxy_lookup: dict) -> tuple[str, bool]:
    existing = _extract_ai_summary(reports)
    if existing:
        return existing, False

    content = _first_non_empty_report_content(reports)
    if not content:
        return "", False

    event_tags = [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])]
    summary = llm.summarise_report(content, event_info=event.info or "", tags=event_tags)
    if not summary or summary.upper().startswith("QUALITY:"):
        return "", False

    report = MISPEventReport()
    report.name = f"{AI_SUMMARY_PREFIX} {(event.info or event.uuid)[:80]}"
    report.content = summary
    report.distribution = 5
    misp.add_event_report(event.id, report)
    try:
        collection_cache.mark_ai_summary(event.uuid, "scraper")
    except Exception as exc:
        logger.warning("mark_ai_summary failed for %s: %s", event.uuid, exc)

    if galaxy_lookup:
        context = parse_misp_context(summary, galaxy_names_with_commas())
        applied = _apply_misp_context_tags(misp, event, context, galaxy_lookup)
        if applied:
            logger.info("Applied %d galaxy tag(s) to %s from MISP context", applied, event.uuid)

    return summary, True


def _extract_admiralty(event, prefix: str) -> str:
    for tag in getattr(event, "tags", []) or []:
        name = (getattr(tag, "name", "") or "")
        if name.startswith(prefix):
            return name.split("=", 1)[1].strip('"')
    return ""


def _common_candidate_events(progress=None, title_exclusions=None, days=1, since=None) -> tuple:
    _emit(progress, "refresh-cache", "in_progress", "Refreshing scraper cache...")
    _refresh_scraper_cache()
    _emit(progress, "refresh-cache", "completed", "Scraper cache refreshed.")

    period = "today" if days == 1 else f"the last {days} days"
    _emit(progress, "collect-events", "in_progress",
          f"Collecting the incomplete scraper events and manual entries of {period}...")
    misp, events = _incomplete_scraper_events(days, since)
    # The MISP each event is on, which is where its reports are read and its
    # summary and workflow state written.
    clients = dict.fromkeys((e.uuid for e in events), misp)
    # Read with the scraper's: without one the analyser does not run at all.
    if misp is not None:
        webapp_misp, entries = _incomplete_manual_entries(days, since)
        clients.update(dict.fromkeys((e.uuid for e in entries), webapp_misp))
        events = events + entries
    _emit(progress, "collect-events", "completed", f"Loaded {len(events)} incomplete event(s) of {period}.")

    hard_rejected = 0
    excluded_by_title = 0
    kept = []
    reports_cache: dict[str, list] = {}
    event_decisions: list[dict] = []

    filter_msg = "Filtering hard negatives (HTTP errors / empty reports)"
    if title_exclusions:
        filter_msg += " and applying title exclusions"
    _emit(progress, "filter-events", "in_progress", filter_msg + "...")

    for event in events:
        reports = _event_reports(clients[event.uuid], event)
        reports_cache[event.uuid] = reports
        first_report = _first_non_empty_report_content(reports)

        is_http_error = _event_http_error(event)
        if is_http_error or not first_report:
            hard_rejected += 1
            reason = "HTTP error fetching article" if is_http_error else "No report content"
            event_decisions.append({"uuid": event.uuid, "title": (event.info or "").strip(), "outcome": "rejected", "reason": reason})
            try:
                tagger.set_workflow_state(clients[event.uuid], event, "rejected")
            except Exception as exc:
                logger.warning("Could not mark %s as rejected: %s", event.uuid, exc)
            _log(event, "http_error" if is_http_error else "no_content")
            continue

        if title_exclusions and _event_or_report_title_excluded(event, reports, title_exclusions):
            excluded_by_title += 1
            event_decisions.append({"uuid": event.uuid, "title": (event.info or "").strip(), "outcome": "excluded", "reason": "Title exclusion filter"})
            _log(event, "not_relevant", "excluded by title filter")
            continue

        kept.append(event)

    filter_detail = f"kept {len(kept)}, rejected {hard_rejected}"
    if title_exclusions:
        filter_detail += f", excluded by title {excluded_by_title}"
    _emit(progress, "filter-events", "completed", f"Filtering complete: {filter_detail}.")

    summaries = {}
    summary_created = summary_failed = 0
    # Reading the galaxies costs several MISP calls, and a run with nothing left
    # to summarise has no use for them.
    galaxy_lookup = _build_galaxy_lookup() if kept else {}

    # Each missing summary is a model call, which on a local model can take
    # minutes, so the job says which one it is on. A slow run then looks alive,
    # and one that died shows how far it got.
    missing = sum(not _extract_ai_summary(reports_cache[e.uuid]) for e in kept)
    _emit(progress, "generate-summaries", "in_progress",
          f"{missing} of {len(kept)} event(s) need an AI summary.")

    written = 0
    for event in kept:
        reports = reports_cache[event.uuid]
        if not _extract_ai_summary(reports):
            written += 1
            _emit(progress, "generate-summaries", "in_progress",
                  f"AI summary {written} of {missing}: {(event.info or event.uuid)[:80]}")
        try:
            summary, created = _ensure_ai_summary(clients[event.uuid], event, reports, galaxy_lookup)
        except Exception as exc:
            # One event the model or MISP fails on should not end the run for
            # the others. It goes on with its article, and the next scheduled
            # run reads it again for the summary.
            logger.warning("AI summary failed for %s: %s", event.uuid, exc)
            summary, created = "", False
            summary_failed += 1
        if created:
            summary_created += 1
        summaries[event.uuid] = summary

    _emit(progress, "generate-summaries", "completed", f"AI summary pass complete: created {summary_created} new summary report(s).")

    return clients, kept, summaries, {
        "total_incomplete_today": len(events),
        "hard_rejected": hard_rejected,
        "excluded_by_title": excluded_by_title,
        "summary_created": summary_created,
        "summary_failed": summary_failed,
        "since": since,
        "event_decisions": event_decisions,
    }, reports_cache


def _duplicate_story_indexes(overlaps) -> set:
    """1-based indexes of the stories to drop as duplicate coverage.

    `overlaps` is (a, b, score) for pairs that scored at or above the drop
    threshold. Of a pair the later story goes, closest pairs are settled first,
    and a story already dropped does not take another with it: two write-ups of
    one incident should cost the briefing one story, not both.
    """
    to_drop = set()
    for a, b, _score in sorted(overlaps, key=lambda pair: pair[2], reverse=True):
        if a in to_drop or b in to_drop:
            continue
        to_drop.add(max(a, b))
    return to_drop


def requirement_matches(events) -> dict:
    """{uuid: matches, best first} for the events that match an active PIR or GIR."""
    match_events = []
    for event in events:
        galaxies = []
        for galaxy in getattr(event, "galaxies", []) or []:
            for cluster in getattr(galaxy, "clusters", []) or []:
                value = getattr(cluster, "value", "") or ""
                if value:
                    galaxies.append(value)
        match_events.append({
            "uuid": event.uuid,
            "info": event.info or "",
            "tags": [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])],
            "galaxy_names": galaxies,
        })
    pirs, girs = req_matching.get_requirements()
    return req_matching.match_events(match_events, pirs, girs)


def run_daily_briefing_action(progress=None, days=1, since=None) -> dict:
    exclusions = daily_briefing_title_exclusions()
    clients, events, summaries, stats, reports_cache = _common_candidate_events(
        progress=progress, title_exclusions=exclusions or None, days=days, since=since,
    )
    decisions = list(stats.get("event_decisions", []))

    already_briefed = [e for e in events if _event_has_product_tag(e, "daily-briefing")]
    for e in already_briefed:
        decisions.append({"uuid": e.uuid, "title": (e.info or "").strip(), "outcome": "excluded", "reason": "Already included in a previous briefing"})
    events = [e for e in events if not _event_has_product_tag(e, "daily-briefing")]

    rejected_by_relevance = 0
    _emit(progress, "review-relevance", "in_progress", "Reviewing daily briefing relevance of candidate stories...")
    # An event that matches an active PIR or GIR is in the briefing whatever the
    # review would say: the requirement already says it matters, and a rejection
    # would take it out of the alert run as well.
    matches = requirement_matches(events) if events else {}
    matched_requirement = {uuid: found[0].get("id", "") for uuid, found in matches.items()}
    kept = []
    for position, event in enumerate(events, start=1):
        title = (event.info or event.uuid)[:80]
        if event.uuid in matched_requirement:
            _emit(progress, "review-relevance", "in_progress",
                  f"Relevance {position} of {len(events)}: {title} matches {matched_requirement[event.uuid]}")
            kept.append(event)
            continue
        # One model call per event, as for the summaries.
        _emit(progress, "review-relevance", "in_progress", f"Relevance {position} of {len(events)}: {title}")
        reports = reports_cache.get(event.uuid, [])
        first_report = _first_non_empty_report_content(reports)
        report_title = (getattr(reports[0], "name", "") or "") if reports else ""
        try:
            decision = llm.review_briefing_relevance(
                event_title=event.info or "",
                report_title=report_title,
                content=first_report,
            )
        except Exception as exc:
            # Kept, as an answer that cannot be read is: the analyst judges it in the draft.
            logger.warning("Briefing relevance check failed for %s: %s", event.uuid, exc)
            decision = {"include": True}
        if not decision.get("include", True):
            rejected_by_relevance += 1
            reason = (decision.get("reason") or "").strip()
            decisions.append({"uuid": event.uuid, "title": (event.info or "").strip(), "outcome": "rejected", "reason": reason or "Failed relevance check"})
            marked = False
            try:
                marked = tagger.set_workflow_state(clients[event.uuid], event, "rejected")
            except Exception as exc:
                logger.warning("Could not mark %s as rejected after relevance review: %s", event.uuid, exc)
            # An event that keeps its incomplete state comes back on the next
            # run, is reviewed again and collects a second rejection note, so
            # only write one once the event has actually been moved on.
            if marked:
                _add_briefing_rejection_note(clients[event.uuid], event, reason=reason, report_title=report_title)
            _log(event, "not_relevant", reason or "rejected by briefing relevance check")
            continue
        kept.append(event)
    events = kept
    _emit(progress, "review-relevance", "completed", f"Relevance review complete: kept {len(events)}, rejected {rejected_by_relevance}.")

    _emit(progress, "build-briefing", "in_progress", "Building daily briefing stories from eligible events...")
    stories = []
    feed_by_uuid = {}
    threat_actor_types_cfg = getattr(config, "THREAT_ACTOR_TYPES", []) or []
    focus_points = {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }
    names_with_commas = galaxy_names_with_commas() if events else frozenset()
    for position, event in enumerate(events, start=1):
        _emit(progress, "build-briefing", "in_progress",
              f"Story {position} of {len(events)}: {(event.info or event.uuid)[:80]}")
        summary = (summaries.get(event.uuid) or "").strip()
        article = _first_non_empty_report_content(reports_cache.get(event.uuid, []))
        source_text = summary or article
        context = parse_misp_context(summary, names_with_commas) if summary else {}

        story_text = source_text
        actor_type = ""
        # Empty unless the model wrote this story, so a story that fell back to
        # the summary or the article text is not shown as an AI draft.
        drafted_by = ""
        if source_text:
            try:
                drafted, actor_type = llm.draft_briefing_story(
                    source_text, focus_points=focus_points, threat_actor_types=threat_actor_types_cfg,
                )
                if drafted:
                    story_text = drafted
                    drafted_by = "ai"
            except Exception as exc:
                logger.warning("draft_briefing_story failed for %s: %s", event.uuid, exc)

        stories.append({
            "title": event.info or "",
            "content": story_text,
            "drafted_by": drafted_by,
            "source_url": misp_store.extract_source_url(event),
            "source_event_uuid": event.uuid,
            "correlation": "",
            "threat_actor_types": [actor_type] if actor_type else [],
            "sectors": context.get("sectors", []),
            "geographic_scope": context.get("geographies", []),
            "techniques": context.get("attack_techniques", []),
            "threat_actors": context.get("threat_actors", []),
            "vendor": context.get("vendor", []),
        })
        feed_by_uuid[event.uuid] = tagger.get_source_feed(event)
    _emit(progress, "build-briefing", "completed", f"Prepared {len(stories)} story candidate(s).")

    overlap_pairs = 0
    dropped = 0
    if len(stories) >= 2:
        _emit(progress, "check-overlap", "in_progress", "Checking overlap between stories and removing duplicates...")
        try:
            overlap = llm.detect_story_overlaps(stories)
            # detect_story_overlaps has already dropped whatever it could not
            # read; all that is left to decide here is how close is too close.
            candidates = [(o["a"], o["b"], o["score"]) for o in overlap.get("overlaps", [])
                          if o["score"] >= _OVERLAP_DROP_SCORE]
            overlap_pairs = len(candidates)
            to_drop = _duplicate_story_indexes(candidates)
            if to_drop:
                for i, s in enumerate(stories, start=1):
                    if i in to_drop:
                        decisions.append({"uuid": s.get("source_event_uuid", ""), "title": s.get("title", ""), "outcome": "dropped", "reason": "Duplicate coverage of another story"})
                stories = [s for i, s in enumerate(stories, start=1) if i not in to_drop]
                dropped = len(to_drop)
        except Exception as exc:
            logger.warning("Daily briefing overlap check failed: %s", exc)
        _emit(progress, "check-overlap", "completed", f"Overlap check complete: {overlap_pairs} pair(s), dropped {dropped} duplicate story(s).")
    else:
        _emit(progress, "check-overlap", "completed", "Not enough stories for overlap checking.")

    for s in stories:
        matched = matched_requirement.get(s.get("source_event_uuid", ""))
        decisions.append({"uuid": s.get("source_event_uuid", ""), "title": s.get("title", ""), "outcome": "included",
                          "reason": f"Matches {matched}" if matched else ""})

    if not stories:
        _emit(progress, "write-summary", "completed", "No stories to summarise.")
        _emit(progress, "create-drafts", "completed", "No daily briefing draft created (no eligible stories).")
        return {
            "ok": True,
            "action": "daily-briefing",
            "created": 0,
            "message": "No eligible events to include in a daily briefing draft.",
            **stats,
            "rejected_by_relevance": rejected_by_relevance,
            "overlap_pairs": overlap_pairs,
            "overlap_dropped": dropped,
            "event_decisions": decisions,
        }

    raw_vendors = [v.strip() for s in stories for v in s.get("vendor", []) if v.strip()]
    vendor_values = _deduplicate_vendors(raw_vendors)

    now = datetime.now(timezone.utc)

    # Written from the stories that survived the overlap check, so the summary
    # describes the draft as it will actually be created. A draft is worth more
    # without a summary than not at all, so a failure here only costs the
    # paragraph and the analyst can write or redraft it on the form.
    _emit(progress, "write-summary", "in_progress", "Writing the briefing summary across the stories...")
    briefing_summary = ""
    try:
        briefing_summary = llm.draft_briefing_summary(
            stories, misp_store.briefing_scope_summary(stories), now.date().isoformat(),
        )
    except Exception as exc:
        logger.warning("draft_briefing_summary failed: %s", exc)
    _emit(progress, "write-summary", "completed",
          "Briefing summary written." if briefing_summary
          else "No briefing summary written; the draft opens without one.")

    data = {
        "date": now.date().isoformat(),
        "title": f"Daily threat briefing for {now.day} {now.strftime('%B %Y')}",
        "author": "analyser",
        "tlp": "clear",
        "escalations": "",
        "notes": "",
        "summary": briefing_summary,
        "review_state": misp_store.BRIEFING_REVIEW_DRAFT,
        "vendor": vendor_values,
        "stories": stories,
    }
    _emit(progress, "create-drafts", "in_progress", "Creating daily briefing draft...")
    briefing_uuid = misp_store.create_briefing(data)
    _emit(progress, "create-drafts", "completed", f"Daily briefing draft created ({briefing_uuid}).")

    for s in stories:
        uuid = s["source_event_uuid"]
        log_event(
            event_uuid=uuid,
            event_info=s.get("title", ""),
            source_feed=feed_by_uuid.get(uuid, "unknown"),
            outcome="product_created",
            detail="daily-briefing",
        )

    return {
        "ok": True,
        "action": "daily-briefing",
        "created": 1,
        "briefing_uuid": briefing_uuid,
        "stories_included": len(stories),
        "message": f"Daily briefing draft created with {len(stories)} stories.",
        **stats,
        "rejected_by_relevance": rejected_by_relevance,
        "overlap_pairs": overlap_pairs,
        "overlap_dropped": dropped,
        "event_decisions": decisions,
    }


def run_flash_intel_action(progress=None, days=1, since=None) -> dict:
    _clients, events, summaries, stats, _ = _common_candidate_events(progress=progress, days=days, since=since)
    # One alert per event, whichever run made it and whatever became of it.
    alerted = misp_store.flash_intel_source_uuids()
    events = [e for e in events if e.uuid not in alerted]

    _emit(progress, "match-requirements", "in_progress", "Matching eligible events against active PIR/GIR scope...")
    match_map = requirement_matches(events)
    matched_count = sum(1 for event in events if match_map.get(event.uuid))
    _emit(progress, "match-requirements", "completed", f"Requirement matching complete: {matched_count} event(s) matched.")

    # The audience is the requirement's: its owner and the stakeholders it is
    # distributed to. One whose stakeholders have no role takes everyone the
    # alert can reach, as an alert from the focus points does.
    pirs, girs = req_matching.get_requirements()
    requirements = {r.uuid: r for r in pirs + girs}
    stakeholders = misp_store.list_stakeholders() if matched_count else []
    reachable = misp_store.subscriber_audience("Flash intel alert", "amber") if matched_count else ""

    created = 0
    _emit(progress, "create-drafts", "in_progress", "Creating flash intel draft(s) for matched events...")
    for event in events:
        matches = match_map.get(event.uuid, [])
        if not matches:
            _log(event, "not_relevant", "no PIR/GIR match")
            continue
        top = matches[0]
        linked_pir_uuid = top.get("uuid", "") if top.get("type") == "pir" else ""
        requirement = requirements.get(top.get("uuid"))
        audience = misp_store.requirement_audience(requirement, stakeholders) if requirement else ""

        data = {
            "title": event.info or "Untitled",
            "audience": audience or reachable,
            "tlp": "amber",
            "summary": (summaries.get(event.uuid) or "").strip(),
            "action_required": "Review and decide whether publication is required.",
            "what_happened": [],
            "source_description": f"Auto-created from source event {event.uuid}; top match: {top.get('id', 'n/a')}",
            "source_reliability": _extract_admiralty(event, "admiralty-scale:source-reliability="),
            "information_credibility": _extract_admiralty(event, "admiralty-scale:information-credibility="),
            "likely_impact": "",
            "affected_assets": "",
            "actor_context": "",
            "geographic_scope": [],
            "sectors": [],
            "threat_actors": [],
            "threat_types": [],
            "technology": [],
            "vendor": [],
            "incident": [],
            "campaign": [],
            "actions_immediate": [],
            "actions_near_term": [],
            "mitre_techniques": [],
            "hunting_hypotheses": [],
            # Rules come from a Rulezet search an analyst runs, not from the model.
            "detection_rules": [],
            "external_references": [],
            "feedback_deadline": "",
            "author": "analyser",
            "source_event_uuids": [event.uuid],
            "context_tags": [f"match:{m.get('id', '')}" for m in matches[:3] if m.get("id")],
            "linked_pir_uuid": linked_pir_uuid,
            "analyser_reason": "Matches " + "; ".join(
                f"{m.get('id', '')} on {', '.join(m.get('matched_terms') or [])}" for m in matches[:3]),
            "review_state": misp_store.FIA_REVIEW_DRAFT,
        }
        misp_store.create_fia(data)
        created += 1
        _log(event, "product_created", f"flash-intel; matched: {top.get('id', 'n/a')}")
    _emit(progress, "create-drafts", "completed", f"Created {created} flash intel draft(s).")

    return {
        "ok": True,
        "action": "flash-intel",
        "created": created,
        "message": f"Created {created} flash intel draft(s) from PIR/GIR matched events.",
        **stats,
    }


_NOT_CHECKED = "Not checked against the asset inventory: the CVE record names no product."


def _cve_in_inventory(cves, progress):
    """The CVE an event's advisory is about with the asset inventory on, as
    (cve, its record, what "Our exposure" says), or None for no advisory.

    The first CVE in a product of the inventory. Failing that, the first whose
    record names no product, as one still reserved does or one whose lookup
    failed: that cannot be checked, so the draft says so and the analyst
    decides. An event listing a month of patches stops after ten, to spare the
    lookups.
    """
    not_checked = None
    for cve in cves[:10]:
        _emit(progress, "create-drafts", "in_progress", f"Checking {cve} against the asset inventory...")
        enrichment = fetch_cve_info(cve)
        affected = enrichment.get("affected") or []
        for vendor, product in affected:
            asset = asset_inventory.find(vendor, product)
            if asset:
                return cve, enrichment, f"In the asset inventory: {asset.supplier} {asset.product} {asset.version}".strip()
        if not affected and not_checked is None:
            not_checked = (cve, enrichment, _NOT_CHECKED)
    return not_checked


def _open_advisory_cves() -> dict:
    """{CVE: the id of the draft or advisory in review that covers it}."""
    covered = {}
    for vea in misp_store.list_veas():
        if vea.review_state in (misp_store.VEA_REVIEW_DRAFT, misp_store.VEA_REVIEW_PENDING):
            for cve in CVE_RE.findall(vea.cve_id or ""):
                covered.setdefault(cve.upper(), vea.vea_id)
    return covered


def run_vea_action(progress=None, days=1, since=None) -> dict:
    # With the asset inventory on, a CVE only makes an advisory when it is in a
    # product we run. Reading it first fails the run on a bad file before the
    # summaries take their model calls.
    checking_assets = asset_inventory.enabled()
    if checking_assets:
        asset_inventory.assets()
    _clients, events, summaries, stats, reports_cache = _common_candidate_events(
        progress=progress, days=days, since=since)
    events = [e for e in events if not _event_has_product_tag(e, "vea")]

    _emit(progress, "detect-cves", "in_progress", "Detecting CVE matches in eligible events...")
    cve_match_count = 0
    cve_map = {}
    for event in events:
        cves = collection_cache.event_cves(event)
        cve_map[event.uuid] = cves
        if cves:
            cve_match_count += 1
    _emit(progress, "detect-cves", "completed", f"CVE detection complete: {cve_match_count} event(s) with CVE match.")
    # Everyone an advisory can reach, for the analyst to narrow down.
    audience = misp_store.subscriber_audience("Vulnerability advisory", "amber") if cve_match_count else ""
    # A CVE that a draft or an advisory in review already covers gets no second
    # one. The scraper reads an article again as a new event when its title
    # changes, as an "(Updated October 25)" does.
    covered = _open_advisory_cves() if cve_match_count else {}

    advised = []
    _emit(progress, "create-drafts", "in_progress", "Creating vulnerability advisory draft(s) for CVE-matched events...")
    for event in events:
        cves = cve_map.get(event.uuid, [])
        if not cves:
            _log(event, "not_relevant", "no CVE found")
            continue
        if all(cve in covered for cve in cves):
            _log(event, "not_relevant", "already in an open advisory: "
                 + ", ".join(f"{cve} in {covered[cve]}" for cve in cves))
            continue
        cves = [cve for cve in cves if cve not in covered]

        exposure = ""
        if checking_assets:
            found = _cve_in_inventory(cves, progress)
            if found is None:
                _log(event, "not_relevant", f"not in the asset inventory: {', '.join(cves[:10])}")
                continue
            primary_cve, enrichment, exposure = found
        else:
            primary_cve = cves[0]
            _emit(progress, "create-drafts", "in_progress", f"Enriching {primary_cve} from vulnerability database...")
            enrichment = fetch_cve_info(primary_cve)

        product_lines = []
        if enrichment.get("products"):
            product_lines.append("Products: " + ", ".join(enrichment["products"]))
        if enrichment.get("versions"):
            product_lines.append("Versions: " + ", ".join(enrichment["versions"]))
        if enrichment.get("description"):
            product_lines.append("Description: " + enrichment["description"])
        product_info = "\n".join(product_lines)

        article = _first_non_empty_report_content(reports_cache.get(event.uuid, []))
        drafted = {}
        try:
            drafted = llm.draft_vea_sections(
                cve_id=primary_cve,
                product_info=product_info,
                article_content=article or (summaries.get(event.uuid) or ""),
            )
        except Exception as exc:
            logger.warning("draft_vea_sections failed for %s: %s", event.uuid, exc)

        cvss = ""
        if enrichment.get("cvss_score"):
            cvss = enrichment["cvss_score"]
            if enrichment.get("cvss_severity"):
                cvss += f" {enrichment['cvss_severity']}"

        data = {
            "cve_id": "\n".join(cves),
            "summary": (drafted.get("summary") or summaries.get(event.uuid) or "").strip(),
            "cvss": cvss or drafted.get("cvss", ""),
            "cwe": enrichment.get("cwes", [""])[0] if enrichment.get("cwes") else drafted.get("cwe", ""),
            "title": event.info or "",
            "tlp": "amber",
            "author": "analyser",
            "audience": audience,
            "affected_product": ", ".join(enrichment.get("products") or []) or drafted.get("affected_product", ""),
            "affected_versions": ", ".join(enrichment.get("versions") or []) or drafted.get("affected_versions", ""),
            "fixed_version": "",
            "exposure": exposure,
            "observed_exploitation": drafted.get("observed_exploitation", ""),
            "exploit_availability": enrichment.get("exploit_availability") or drafted.get("exploit_availability", ""),
            "exploitation_complexity": drafted.get("exploitation_complexity", ""),
            "threat_actor_interest": drafted.get("threat_actor_interest", ""),
            "cisa_kev": enrichment.get("cisa_kev") or drafted.get("cisa_kev", ""),
            "source_description": f"Auto-created from source event {event.uuid}",
            "source_reliability": _extract_admiralty(event, "admiralty-scale:source-reliability="),
            "information_credibility": _extract_admiralty(event, "admiralty-scale:information-credibility="),
            "worst_case": drafted.get("worst_case", ""),
            "most_likely": drafted.get("most_likely", ""),
            "immediate_actions": drafted.get("immediate_actions") or [],
            "patch_sla_internet": "",
            "patch_sla_internal": "",
            "target_patch_version": "",
            "exploitation_indicators": drafted.get("exploitation_indicators") or [],
            "detection_rules": [],
            "references": enrichment.get("references") or [],
            "context_tags": [f"cve:{c}" for c in cves],
            "review_state": misp_store.VEA_REVIEW_DRAFT,
            "source_event_uuid": event.uuid,
            "linked_pir_uuid": "",
            "analyser_reason": f"The event names {', '.join(cves)}. {exposure}".strip(),
        }
        _uuid, vea_id = misp_store.create_vea(data)
        covered.update(dict.fromkeys(cves, vea_id))
        advised.append(event.uuid)
        _log(event, "product_created", f"vea; CVEs: {', '.join(cves)}")
    created = len(advised)
    _emit(progress, "create-drafts", "completed", f"Created {created} vulnerability advisory draft(s).")

    return {
        "ok": True,
        "action": "vea",
        "created": created,
        "source_event_uuids": advised,
        "message": f"Created {created} vulnerability advisory draft(s) from CVE-matched events.",
        **stats,
    }


ACTION_LABELS = {
    "daily-briefing": "Daily briefing",
    "flash-intel": "Flash intel alert",
    "vea": "Vulnerability advisory",
}


def action_steps(action: str) -> list[dict]:
    common = [
        {"id": "refresh-cache", "label": "Refresh scraper cache", "state": "pending"},
        {"id": "collect-events", "label": "Load the incomplete events", "state": "pending"},
        {"id": "filter-events", "label": "Filter hard negatives", "state": "pending"},
        {"id": "generate-summaries", "label": "Generate missing LLM summaries", "state": "pending"},
    ]
    if action == "daily-briefing":
        common.extend([
            {"id": "review-relevance", "label": "Review relevance and usefulness", "state": "pending"},
            {"id": "build-briefing", "label": "Build briefing story set", "state": "pending"},
            {"id": "check-overlap", "label": "Check overlap and remove duplicates", "state": "pending"},
            {"id": "write-summary", "label": "Write the briefing summary", "state": "pending"},
            {"id": "create-drafts", "label": "Create daily briefing draft", "state": "pending"},
        ])
    elif action == "flash-intel":
        common.extend([
            {"id": "match-requirements", "label": "Match events to PIR/GIR", "state": "pending"},
            {"id": "create-drafts", "label": "Create flash intel draft(s)", "state": "pending"},
        ])
    elif action == "vea":
        common.extend([
            {"id": "detect-cves", "label": "Detect CVE matches", "state": "pending"},
            {"id": "create-drafts", "label": "Create vulnerability advisory draft(s)", "state": "pending"},
        ])
    return common


def run_action(job_id: str, user: str, triggered_by: str = "dashboard", days: int = 1,
               since: int | None = None) -> dict | None:
    """Run the analyser action of a job made with action_steps(), and return its
    result, or None when it did not complete. ``user`` goes on the audit
    entries: the analyst, read from the request before this thread began, or
    "analyser" for the schedule. ``days`` is how many days of scraper events it
    reads, today included, and ``since`` keeps those changed since then."""
    job = job_store.get_job(job_id)
    if not job:
        return None
    action = job["action"]
    handlers = {
        "daily-briefing": run_daily_briefing_action,
        "flash-intel": run_flash_intel_action,
        "vea": run_vea_action,
    }
    handler = handlers.get(action)
    if handler is None:
        job_store.update_job(job_id, status="failed", error="Unknown pipeline action.",
                             message="Unknown pipeline action.")
        return None

    run_id = log_pipeline_run_start(action, triggered_by=triggered_by)
    audit.record("run-start", "pipeline", entity_label=action, details=f"triggered by {triggered_by}", user=user)
    job_store.update_job(job_id, status="running", message="Running...")
    job_store.append_log(job_id, f"Started action '{action}'.")

    def _progress(*, step: str, state: str, message: str = ""):
        job_store.set_step(job_id, step=step, state=state, message=message)

    try:
        result = handler(progress=_progress, days=days, since=since)
        # Freshness only. Not save_last_run: that is the analyser's watermark
        # for which scraper events it has already seen, and these actions read a
        # different set (the day's incomplete events), so moving it forward here
        # would make the next analyser run skip everything published in between.
        save_last_action(int(time.time()))
        log_pipeline_run_end(run_id, "completed", result)
        audit.record("run-complete", "pipeline", entity_label=action,
                     details=(result or {}).get("message") or "", user=user)
        job_store.complete_open_steps(job_id)
        job_store.update_job(
            job_id,
            status="completed",
            result=result,
            message=(result or {}).get("message") or "Completed.",
            error=None,
        )
        job_store.append_log(job_id, "Action completed.")
        return result
    except Exception as exc:
        log_pipeline_run_end(run_id, "failed")
        audit.record("run-failed", "pipeline", entity_label=action, details=str(exc), user=user)
        job_store.update_job(job_id, status="failed", error=str(exc), message=f"Failed: {exc}")
        job_store.append_log(job_id, f"Action failed: {exc}")
        logger.exception("Pipeline job %s failed", job_id)
        return None
