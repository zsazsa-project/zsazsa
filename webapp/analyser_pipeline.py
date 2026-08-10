"""Dashboard-triggered collection analyser actions.

This module provides three manual analyser actions used from the dashboard:
- daily briefing draft generation
- flash intel draft generation (for PIR/GIR matched events)
- vulnerability advisory draft generation (for CVE-matched events)
"""

import logging
import re
from datetime import datetime, timezone

import config
from analyser import llm, tagger
from core.db import log_event
from core.vuln_lookup import fetch_cve_info
from pymisp import MISPEventReport
from webapp import collection_cache, matching as req_matching, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_BRIEFING_REJECTION_PREFIX = "zsazsa:daily-briefing-rejection"

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


def _parse_misp_context(text: str) -> dict:
    result = {"sectors": [], "geographies": [], "attack_techniques": [], "threat_actors": [], "vendor": []}

    def _csv(regex):
        m = regex.search(text)
        if not m:
            return []
        val = m.group(1).strip()
        if "none identified" in val.lower():
            return []
        return [s.strip() for s in val.split(",") if s.strip()]

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


def _daily_briefing_title_exclusions() -> list[str]:
    raw = getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", [])
    if isinstance(raw, str):
        raw = raw.splitlines()
    return [str(p).strip().lower() for p in (raw or []) if str(p).strip()]


def _matches_title_exclusion(title: str, patterns: list[str]) -> bool:
    haystack = (title or "").strip().lower()
    if not haystack:
        return False
    return any(p in haystack for p in patterns)


def _event_or_report_title_excluded(event, reports, patterns: list[str]) -> bool:
    if not patterns:
        return False
    if _matches_title_exclusion(getattr(event, "info", "") or "", patterns):
        return True
    for report in reports or []:
        if _matches_title_exclusion(getattr(report, "name", "") or "", patterns):
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
    # Run a blocking refresh so the action always works from current scraper state.
    collection_cache.refresh_source({"id": "scraper", "kind": "scraper"})


def _today_incomplete_scraper_events():
    misp = misp_store._scraper_misp()
    today = datetime.now(timezone.utc).date().isoformat()
    events = misp.search(
        tags=[config.SCRAPER_MARKER_TAG],
        date_from=today,
        limit=getattr(config, "MISP_SCRAPER_LIMIT", 500),
        page=1,
        pythonify=True,
    )
    if isinstance(events, dict):
        # An error answer and an empty one both end the run reporting no
        # eligible events, so the reason has to reach the log at least.
        logger.warning("scraper search for today's incomplete events failed: %s",
                       events.get("errors") or events)
        return misp, []
    if not events:
        return misp, []

    eligible = {'workflow:state="incomplete"', 'workflow:state="ongoing"'}
    filtered = []
    for event in events:
        tags = {getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])}
        if tags & eligible:
            filtered.append(event)
    return misp, filtered


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
    country_by_name = {k.lower(): v for k, v in country_map.items()}
    country_by_name.update({k.lower(): v for k, v in ti_map.items()})
    logger.info(
        "Galaxy lookup built: %d ATT&CK techniques, %d sectors, %d countries, %d threat actors",
        len(attack_by_id), len(sector_map), len(country_by_name), len(ta_map),
    )
    return {
        "attack_by_id": attack_by_id,
        "sector_by_name": {k.lower(): v for k, v in sector_map.items()},
        "country_by_name": country_by_name,
        "threat_actor_by_name": {k.lower(): v for k, v in ta_map.items()},
    }


def _apply_misp_context_tags(misp, event, context: dict, lookup: dict) -> int:
    applied = 0
    for tech_id in context.get("attack_techniques", []):
        tag_name = lookup.get("attack_by_id", {}).get(tech_id)
        if tag_name:
            try:
                r = misp.tag(event.uuid, tag_name)
                if isinstance(r, dict) and "errors" in r:
                    logger.warning("Could not apply ATT&CK tag %s to %s: %s", tech_id, event.uuid, r["errors"])
                else:
                    applied += 1
            except Exception as exc:
                logger.warning("Could not apply ATT&CK tag %s to %s: %s", tech_id, event.uuid, exc)
    for sector in context.get("sectors", []):
        tag_name = lookup.get("sector_by_name", {}).get(sector.lower())
        if tag_name:
            try:
                r = misp.tag(event.uuid, tag_name)
                if isinstance(r, dict) and "errors" in r:
                    logger.warning("Could not apply sector tag %s to %s: %s", sector, event.uuid, r["errors"])
                else:
                    applied += 1
            except Exception as exc:
                logger.warning("Could not apply sector tag %s to %s: %s", sector, event.uuid, exc)
    for geo in context.get("geographies", []):
        tag_name = lookup.get("country_by_name", {}).get(geo.lower())
        if tag_name:
            try:
                r = misp.tag(event.uuid, tag_name)
                if isinstance(r, dict) and "errors" in r:
                    logger.warning("Could not apply country tag %s to %s: %s", geo, event.uuid, r["errors"])
                else:
                    applied += 1
            except Exception as exc:
                logger.warning("Could not apply country tag %s to %s: %s", geo, event.uuid, exc)
    for actor in context.get("threat_actors", []):
        tag_name = lookup.get("threat_actor_by_name", {}).get(actor.lower())
        if tag_name:
            try:
                r = misp.tag(event.uuid, tag_name)
                if isinstance(r, dict) and "errors" in r:
                    logger.warning("Could not apply threat actor tag %s to %s: %s", actor, event.uuid, r["errors"])
                else:
                    applied += 1
            except Exception as exc:
                logger.warning("Could not apply threat actor tag %s to %s: %s", actor, event.uuid, exc)
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
        context = _parse_misp_context(summary)
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


def _extract_cves(event) -> list[str]:
    values = []
    for attr in getattr(event, "attributes", []) or []:
        if getattr(attr, "type", "") == "vulnerability":
            v = (getattr(attr, "value", "") or "").strip().upper()
            if v:
                values.append(v)
    for obj in getattr(event, "objects", []) or []:
        for attr in getattr(obj, "attributes", []) or []:
            if getattr(attr, "type", "") == "vulnerability":
                v = (getattr(attr, "value", "") or "").strip().upper()
                if v:
                    values.append(v)
    if not values:
        values.extend(m.upper() for m in _CVE_RE.findall(getattr(event, "info", "") or ""))
    return list(dict.fromkeys(values))


def _common_candidate_events(progress=None, title_exclusions=None) -> tuple:
    _emit(progress, "refresh-cache", "in_progress", "Refreshing scraper cache...")
    _refresh_scraper_cache()
    _emit(progress, "refresh-cache", "completed", "Scraper cache refreshed.")

    _emit(progress, "collect-events", "in_progress", "Collecting today's incomplete scraper events...")
    misp, events = _today_incomplete_scraper_events()
    _emit(progress, "collect-events", "completed", f"Loaded {len(events)} incomplete event(s) for today.")

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
        reports = _event_reports(misp, event)
        reports_cache[event.uuid] = reports
        first_report = _first_non_empty_report_content(reports)

        is_http_error = _event_http_error(event)
        if is_http_error or not first_report:
            hard_rejected += 1
            reason = "HTTP error fetching article" if is_http_error else "No report content"
            event_decisions.append({"uuid": event.uuid, "title": (event.info or "").strip(), "outcome": "rejected", "reason": reason})
            try:
                tagger.set_workflow_state(misp, event, "rejected")
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
    summary_created = 0
    galaxy_lookup = _build_galaxy_lookup()

    _emit(progress, "generate-summaries", "in_progress", "Ensuring AI summaries exist for eligible events...")

    for event in kept:
        reports = reports_cache[event.uuid]
        summary, created = _ensure_ai_summary(misp, event, reports, galaxy_lookup)
        if created:
            summary_created += 1
        summaries[event.uuid] = summary

    _emit(progress, "generate-summaries", "completed", f"AI summary pass complete: created {summary_created} new summary report(s).")

    return misp, kept, summaries, {
        "total_incomplete_today": len(events),
        "hard_rejected": hard_rejected,
        "excluded_by_title": excluded_by_title,
        "summary_created": summary_created,
        "event_decisions": event_decisions,
    }, reports_cache


def run_daily_briefing_action(progress=None) -> dict:
    exclusions = _daily_briefing_title_exclusions()
    misp, events, summaries, stats, reports_cache = _common_candidate_events(
        progress=progress, title_exclusions=exclusions or None,
    )
    decisions = list(stats.get("event_decisions", []))

    already_briefed = [e for e in events if _event_has_product_tag(e, "daily-briefing")]
    for e in already_briefed:
        decisions.append({"uuid": e.uuid, "title": (e.info or "").strip(), "outcome": "excluded", "reason": "Already included in a previous briefing"})
    events = [e for e in events if not _event_has_product_tag(e, "daily-briefing")]

    rejected_by_relevance = 0
    _emit(progress, "review-relevance", "in_progress", "Reviewing daily briefing relevance of candidate stories...")
    kept = []
    for event in events:
        reports = reports_cache.get(event.uuid, [])
        first_report = _first_non_empty_report_content(reports)
        report_title = (getattr(reports[0], "name", "") or "") if reports else ""
        decision = llm.review_briefing_relevance(
            event_title=event.info or "",
            report_title=report_title,
            content=first_report,
        )
        if not decision.get("include", True):
            rejected_by_relevance += 1
            reason = (decision.get("reason") or "").strip()
            decisions.append({"uuid": event.uuid, "title": (event.info or "").strip(), "outcome": "rejected", "reason": reason or "Failed relevance check"})
            marked = False
            try:
                marked = tagger.set_workflow_state(misp, event, "rejected")
            except Exception as exc:
                logger.warning("Could not mark %s as rejected after relevance review: %s", event.uuid, exc)
            # An event that keeps its incomplete state comes back on the next
            # run, is reviewed again and collects a second rejection note, so
            # only write one once the event has actually been moved on.
            if marked:
                _add_briefing_rejection_note(misp, event, reason=reason, report_title=report_title)
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
    for event in events:
        summary = (summaries.get(event.uuid) or "").strip()
        article = _first_non_empty_report_content(reports_cache.get(event.uuid, []))
        source_text = summary or article
        context = _parse_misp_context(summary) if summary else {}

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
            raw = overlap.get("overlaps", []) if isinstance(overlap, dict) else []
            candidates = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                try:
                    a = int(item.get("a", 0))
                    b = int(item.get("b", 0))
                    score = float(item.get("score", 0))
                except (TypeError, ValueError):
                    continue
                if a > 0 and b > 0 and a != b and score >= 0.65:
                    candidates.append((a, b, score))
            overlap_pairs = len(candidates)
            to_drop = set()
            for a, b, _score in sorted(candidates, key=lambda x: x[2], reverse=True):
                if a in to_drop or b in to_drop:
                    continue
                to_drop.add(max(a, b))
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
        decisions.append({"uuid": s.get("source_event_uuid", ""), "title": s.get("title", ""), "outcome": "included", "reason": ""})

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


def run_flash_intel_action(progress=None) -> dict:
    _misp, events, summaries, stats, _ = _common_candidate_events(progress=progress)
    events = [e for e in events if not _event_has_product_tag(e, "flash-intel")]

    _emit(progress, "match-requirements", "in_progress", "Matching eligible events against active PIR/GIR scope...")
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
    match_map = req_matching.match_events(match_events, pirs, girs)
    matched_count = sum(1 for event in events if match_map.get(event.uuid))
    _emit(progress, "match-requirements", "completed", f"Requirement matching complete: {matched_count} event(s) matched.")

    created = 0
    _emit(progress, "create-drafts", "in_progress", "Creating flash intel draft(s) for matched events...")
    for event in events:
        matches = match_map.get(event.uuid, [])
        if not matches:
            _log(event, "not_relevant", "no PIR/GIR match")
            continue
        top = matches[0]
        linked_pir_uuid = top.get("uuid", "") if top.get("type") == "pir" else ""

        data = {
            "title": event.info or "Untitled",
            "audience": "",
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
            "external_references": [],
            "feedback_deadline": "",
            "author": "analyser",
            "source_event_uuids": [event.uuid],
            "context_tags": [f"match:{m.get('id', '')}" for m in matches[:3] if m.get("id")],
            "linked_pir_uuid": linked_pir_uuid,
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


def run_vea_action(progress=None) -> dict:
    _misp, events, summaries, stats, reports_cache = _common_candidate_events(progress=progress)
    events = [e for e in events if not _event_has_product_tag(e, "vea")]

    _emit(progress, "detect-cves", "in_progress", "Detecting CVE matches in eligible events...")
    cve_match_count = 0
    cve_map = {}
    for event in events:
        cves = _extract_cves(event)
        cve_map[event.uuid] = cves
        if cves:
            cve_match_count += 1
    _emit(progress, "detect-cves", "completed", f"CVE detection complete: {cve_match_count} event(s) with CVE match.")

    created = 0
    _emit(progress, "create-drafts", "in_progress", "Creating vulnerability advisory draft(s) for CVE-matched events...")
    for event in events:
        cves = cve_map.get(event.uuid, [])
        if not cves:
            _log(event, "not_relevant", "no CVE found")
            continue

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
            "audience": "",
            "affected_product": ", ".join(enrichment.get("products") or []) or drafted.get("affected_product", ""),
            "affected_versions": ", ".join(enrichment.get("versions") or []) or drafted.get("affected_versions", ""),
            "fixed_version": "",
            "exposure": "",
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
        }
        misp_store.create_vea(data)
        created += 1
        _log(event, "product_created", f"vea; CVEs: {', '.join(cves)}")
    _emit(progress, "create-drafts", "completed", f"Created {created} vulnerability advisory draft(s).")

    return {
        "ok": True,
        "action": "vea",
        "created": created,
        "message": f"Created {created} vulnerability advisory draft(s) from CVE-matched events.",
        **stats,
    }
