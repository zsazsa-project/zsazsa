"""The analyser actions, started from the dashboard and by the schedule.

This module provides three analyser actions:
- daily briefing draft generation, for the events the relevance verdict wants
  for the briefing, which then closes the events no product wants;
- flash intel draft generation, for the events it wants for an alert;
- vulnerability advisory draft generation, for the CVEs of an event in scope.

Each reads its events through analyser.sources: what changed on every source
since the action's previous completed run. The verdict is analyser.relevance,
the comparison with earlier products analyser.similarity.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import config
from analyser import event_state, llm, relevance, run_lock, settings, similarity, tagger
from analyser.products import flash_intel
from analyser.reader import read_event_reports
from analyser.relevance import Judge
from analyser.sources import Reading
from core import asset_inventory
from core.db import log_event, log_pipeline_run_end, log_pipeline_run_start
from core.vuln_lookup import CVE_RE, lookup_cve
from pymisp import MISPEventReport
from webapp import audit, collection_cache, job_store, matching as req_matching, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX, is_ai_summary_report

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
_REJECTION_PREFIX = "zsazsa:analyser-rejection"

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


def _log(event, source, outcome, detail=None):
    log_event(
        event_uuid=event.uuid,
        event_info=getattr(event, "info", ""),
        source_feed=tagger.get_source_feed(event),
        outcome=outcome,
        detail=detail,
        source_id=source.hint,
    )


def daily_briefing_title_exclusions() -> list[str]:
    """The configured exclusion patterns, lower-cased for matching. They keep
    an event out of the briefing and the alerts.

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


def event_or_report_title_excluded(event, reports, patterns: list[str]) -> bool:
    """Whether the title of an event, or of one of its reports, matches a
    title exclusion pattern."""
    if not patterns:
        return False
    if title_excluded(getattr(event, "info", "") or "", patterns):
        return True
    for report in reports or []:
        if title_excluded(getattr(report, "name", "") or "", patterns):
            return True
    return False


def _emit(progress, step: str, state: str, message: str = "") -> None:
    """Report a step to the job. It is also where a run finds that it lost the
    analyser lock, which a long model call can make it do, so a write that
    follows one comes after a report of its own."""
    if progress is None:
        return
    try:
        progress(step=step, state=state, message=message)
    except run_lock.Lost:
        raise
    except Exception:
        # Progress reporting should never break pipeline execution.
        pass


def _event_http_error(event) -> bool:
    return any(tag.name.startswith(_HTTP_ERROR_PREFIX) for tag in event.tags)


def _content(report) -> str:
    return (report.content or "").strip()


def _changed_at(report) -> float:
    stamp = getattr(report, "timestamp", None)
    return stamp.timestamp() if isinstance(stamp, datetime) else 0


def _article_report(reports):
    """The report with the article: the first with content that zsazsa did
    not write itself, as it writes an AI summary or a rejection note."""
    for report in reports:
        if _content(report) and not is_ai_summary_report(report.name) and not report.name.startswith(_REJECTION_PREFIX):
            return report
    return None


def _article_text(reports) -> str:
    report = _article_report(reports)
    return _content(report) if report else ""


def _summary_report(reports):
    """The newest AI summary of the event, or None when there is none or the
    article changed after it was written: it would tell the old story."""
    summary = max((r for r in reports if r.name.startswith(AI_SUMMARY_PREFIX)),
                  key=_changed_at, default=None)
    article = _article_report(reports)
    if summary is None or (article is not None and _changed_at(article) > _changed_at(summary)):
        return None
    return summary


def _extract_ai_summary(reports) -> str:
    summary = _summary_report(reports)
    return _content(summary) if summary else ""


def _add_rejection_note(misp, event, reasons: list[str]) -> None:
    """A report on the event saying why the analyser rejected it."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    note = MISPEventReport()
    note.name = f"{_REJECTION_PREFIX} {ts}"
    note.content = "\n".join([
        "Decision: rejected by the analyser, as no product wants it",
        f"Time (UTC): {ts}",
        f"Event: {(event.info or '').strip()}",
        *(f"- {reason}" for reason in reasons),
    ])
    note.distribution = 5
    try:
        misp_store._check(misp.add_event_report(event.id, note), "add the rejection note")
    except Exception as exc:
        # The event is rejected all the same; only the note saying why is missing.
        logger.warning("Could not add the rejection note to %s: %s", event.uuid, exc)


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


def _ensure_ai_summary(source, event, reports, galaxy_lookup: dict, progress=None) -> tuple[str, bool]:
    """The event's AI summary, written now when it has none and its source
    takes reports. Returns (summary, whether it was written now). One written
    before the article changed is written again, and the old one deleted.

    On another MISP server it is written as the data collection page writes
    one: for our organisation alone, with the event published again so that it
    stays in that server's search, and without galaxy tags, as the event's tags
    are that server's.
    """
    existing = _extract_ai_summary(reports)
    if existing or not source.may_add_reports:
        return existing, False
    misp = source.client

    content = _article_text(reports)
    if not content:
        return "", False

    summary = llm.summarise_report(content, event_info=event.info or "", tags=[t.name for t in event.tags])
    if not summary:
        # A model out of tokens answers with nothing; the next run asks again.
        raise RuntimeError("The model returned an empty summary")
    if summary.upper().startswith("QUALITY:"):
        return "", False

    _emit(progress, "generate-summaries", "in_progress", f"Writing the AI summary of {(event.info or event.uuid)[:80]}")
    misp_store.add_ai_summary_report(misp, event.id, event.info or event.uuid, summary,
                                     distribution=5 if source.own else 0)
    _delete_outdated_summaries(misp, event, reports)
    if not source.own and not misp_store.publish_event(misp, event, f"{event.uuid} again after its summary"):
        # Unpublished, it drops out of the server's search: neither the
        # analyser nor the collection page reads it again until it is published.
        _log(event, source, "error", "Its summary was written, but MISP did not publish the event again; publish it in MISP")
    collection_cache.mark_ai_summary(event.uuid, _cached_under(source, event))
    if not source.own:
        return summary, True

    if galaxy_lookup:
        context = parse_misp_context(summary, galaxy_names_with_commas())
        applied = _apply_misp_context_tags(misp, event, context, galaxy_lookup)
        if applied:
            logger.info("Applied %d galaxy tag(s) to %s from MISP context", applied, event.uuid)

    return summary, True


def _delete_outdated_summaries(misp, event, reports) -> None:
    """Delete the summaries written before the article changed, now that a
    new one is there. Deleted softly, as MISP keeps them that way."""
    for report in reports:
        if report.name.startswith(AI_SUMMARY_PREFIX):
            try:
                misp_store._check(misp.delete_event_report(report.id), "delete the outdated summary")
            except Exception as exc:
                logger.warning("Could not delete the outdated summary of %s: %s", event.uuid, exc)


def _cached_under(source, event) -> str:
    """The source id the collection cache keeps an event under. A manual entry
    is kept under its collection source, which its zsazsa:source tag names."""
    slug = tagger.tag_value(event, "zsazsa:source=") if source.kind == "manual" else ""
    return collection_cache.manual_source_id(slug) if slug else source.id


def _write_summaries(kept: list, sources: dict, reports: dict, reading: Reading,
                     progress=None) -> tuple[dict, int, int]:
    """The AI summary of each event, {uuid: summary}, written now where its
    source takes one and it has none, and how many were written and failed."""
    summaries = {}
    summary_created = summary_failed = 0
    # Reading the galaxies costs several MISP calls, and a run with nothing left
    # to summarise has no use for them.
    galaxy_lookup = _build_galaxy_lookup() if kept else {}

    # Each missing summary is a model call, which on a local model can take
    # minutes, so the job says which one it is on. A slow run then looks alive,
    # and one that died shows how far it got.
    to_write = {e.uuid for e in kept
                if sources[e.uuid].may_add_reports and not _extract_ai_summary(reports[e.uuid])}
    missing = len(to_write)
    _emit(progress, "generate-summaries", "in_progress",
          f"{missing} of {len(kept)} event(s) need an AI summary.")

    written = 0
    for event in kept:
        if event.uuid in to_write:
            written += 1
            _emit(progress, "generate-summaries", "in_progress",
                  f"AI summary {written} of {missing}: {(event.info or event.uuid)[:80]}")
        try:
            summary, created = _ensure_ai_summary(sources[event.uuid], event, reports[event.uuid], galaxy_lookup, progress)
            if created:
                reading.wrote(event.uuid)
        except run_lock.Lost:
            raise
        except Exception as exc:
            # One event the model or MISP fails on should not end the run for
            # the others. It goes on with its article, and the next run reads it
            # again for the summary.
            logger.warning("AI summary failed for %s: %s", event.uuid, exc)
            summary, created = "", False
            summary_failed += 1
            reading.retry(event.uuid)
            reading.wrote(event.uuid)
        if created:
            summary_created += 1
        summaries[event.uuid] = summary

    _emit(progress, "generate-summaries", "completed",
          f"AI summary pass complete: created {summary_created} new summary report(s).")
    return summaries, summary_created, summary_failed


def _common_candidate_events(reading: Reading, progress=None, title_exclusions=None) -> SimpleNamespace:
    """The events an action works on, read from every source, with the hard
    negatives rejected, the title exclusions set apart when given, and an AI
    summary for each where its source takes one.

    Returns a namespace of ``sources`` (each event's uuid to the source it was
    read from, which is where its reports are read and its summary and
    workflow state written), ``events`` (the ones to work on), ``excluded``
    (those the title exclusions set apart), and the ``summaries``, ``reports``
    and ``stats`` of the run, whose ``event_decisions`` the action adds to.
    """
    _emit(progress, "collect-events", "in_progress", "Reading the new and changed events of every source...")
    pairs = reading.read()
    sources = {event.uuid: source for event, source in pairs}
    events = [event for event, _source in pairs]
    per_source = (", ".join(f"{label} {n}" for label, n in reading.counts.items())
                  or ("no source could be read" if reading.errors else "no source is switched on"))
    _emit(progress, "collect-events", "completed", f"Read {len(events)} event(s): {per_source}.")

    hard_rejected = 0
    kept, excluded = [], []
    reports_cache: dict[str, list] = {}
    event_decisions: list[dict] = []
    # An analyst follows these up: the analyser leaves them open, whatever it finds.
    followed = collection_cache.get_flagged_uuids() if events else set()

    filter_msg = "Filtering hard negatives (HTTP errors / empty reports)"
    if title_exclusions:
        filter_msg += " and applying title exclusions"
    _emit(progress, "filter-events", "in_progress", filter_msg + "...")

    for event in events:
        source = sources[event.uuid]
        try:
            reports = read_event_reports(source.client, event)
        except Exception as exc:
            # Not rejected as empty, and not the end of the run: the other
            # sources are read, as they are when a source cannot be searched.
            logger.warning("Could not read the reports of %s: %s", event.uuid, exc)
            reading.retry(event.uuid)
            event_decisions.append(_decision(event, source, "left open",
                                             "Its reports could not be read; the next run tries again"))
            _log(event, source, "error", "Its reports could not be read; left for the next run")
            continue
        reports_cache[event.uuid] = reports
        first_report = _article_text(reports)

        is_http_error = _event_http_error(event)
        if is_http_error or not first_report:
            reason = "HTTP error fetching article" if is_http_error else "No report content"
            if event.uuid in followed:
                event_decisions.append(_decision(event, source, "left open", f"{reason}; an analyst follows it up"))
                continue
            try:
                rejected = event_state.reject(event, source, reason)
            except Exception as exc:
                logger.warning("Could not mark %s as rejected: %s", event.uuid, exc)
                rejected = False
            reading.wrote(event.uuid)
            if rejected:
                hard_rejected += 1
                event_decisions.append(_decision(event, source, "rejected", reason))
            else:
                # Still open in MISP: the next run tries again.
                reading.retry(event.uuid)
                event_decisions.append(_decision(event, source, "left open", f"{reason}; MISP refused the rejection"))
            _log(event, source, "http_error" if is_http_error else "no_content")
            continue

        if title_exclusions and event_or_report_title_excluded(event, reports, title_exclusions):
            excluded.append(event)
            event_decisions.append(_decision(event, source, "excluded", "Title exclusion filter"))
            _log(event, source, "not_relevant", "excluded by title filter")
            continue

        kept.append(event)

    filter_detail = f"kept {len(kept)}, rejected {hard_rejected}"
    if title_exclusions:
        filter_detail += f", excluded by title {len(excluded)}"
    _emit(progress, "filter-events", "completed", f"Filtering complete: {filter_detail}.")

    summaries, summary_created, summary_failed = _write_summaries(kept, sources, reports_cache, reading, progress)

    stats = {
        "events_read": len(events),
        "events_read_by_source": dict(reading.counts),
        "hard_rejected": hard_rejected,
        "excluded_by_title": len(excluded),
        "summary_created": summary_created,
        "summary_failed": summary_failed,
        "event_decisions": event_decisions,
    }
    if reading.errors:
        # Shown on the job: a source that could not be read is read again by
        # the next run, but someone should know it is down.
        stats["errors"] = list(reading.errors)
    return SimpleNamespace(sources=sources, events=kept, excluded=excluded, summaries=summaries,
                           reports=reports_cache, stats=stats)


def _decision(event, source, outcome: str, reason: str) -> dict:
    """An entry of a run's event_decisions, which the Pipeline page lists."""
    return {"uuid": event.uuid, "title": (event.info or "").strip(), "source": source.label, "outcome": outcome,
            "reason": reason}


def _decide(found, event, outcome: str, reason: str) -> None:
    found.stats["event_decisions"].append(_decision(event, found.sources[event.uuid], outcome, reason))


def _article(found, event) -> str:
    return _article_text(found.reports.get(event.uuid, []))


def _evidence(found, event) -> str:
    return relevance.evidence(event, _article(found, event), found.summaries.get(event.uuid, ""))


def _earlier_outcome(found, event, product: str, reading: Reading) -> str:
    """What became of an event for "flash-intel" or "daily-briefing" in an
    earlier run, such as the product it repeats, while the event is as it was
    then. One whose article changed is compared again: it may report more now.
    So is every event of a rescan, which is for deciding again under the
    settings of now, or after the product it repeated was deleted."""
    if reading.rescan_hours:
        return ""
    state = event_state.load(found.sources[event.uuid].id, event.uuid)
    return event_state.outcome(state, product, _evidence(found, event))


def _judged(found, events, judge: Judge, product: str, progress=None) -> list[tuple]:
    """The events a product wants, as (event, verdict, why), judging those
    whose verdict is missing or out of date. ``product`` is "alert" or
    "briefing". One an analyst pushed is wanted even before the model answered."""
    label = "alerts" if product == "alert" else "the briefing"
    wanted = []
    for position, event in enumerate(events, start=1):
        # One model call for each event not judged yet, as for the summaries.
        _emit(progress, "judge-relevance", "in_progress",
              f"Relevance {position} of {len(events)}: {(event.info or event.uuid)[:80]}")
        verdict = judge.verdict(event, found.sources[event.uuid], _article(found, event),
                                found.summaries.get(event.uuid, ""))
        if verdict is None and not relevance.pushed(event, product):
            _decide(found, event, "left open", "The model's answer could not be read")
            _log(event, found.sources[event.uuid], "error", "The model's relevance answer could not be read; left open")
            continue
        verdict = verdict or relevance.unjudged()
        ok, reason = judge.wants(verdict, product, event)
        if not ok:
            _decide(found, event, "declined", reason)
            _log(event, found.sources[event.uuid], "not_relevant", reason)
            continue
        wanted.append((event, verdict, reason))
    _emit(progress, "judge-relevance", "completed", f"{len(wanted)} of {len(events)} event(s) are for {label}.")
    return wanted


def _grounds_text(grounds: list) -> str:
    return ", ".join(g.get("focus_point") or g["id"] for g in grounds)


def _duplicate_story_indexes(overlaps, keep=frozenset()) -> set:
    """1-based indexes of the stories to drop as duplicate coverage.

    `overlaps` is (a, b, score) for pairs that scored at or above the drop
    threshold. Of a pair the later story goes, closest pairs are settled first,
    and a story already dropped does not take another with it: two write-ups of
    one incident should cost the briefing one story, not both. A story in
    ``keep`` stays: of a pair the other one goes, and of two such, neither.
    """
    to_drop = set()
    for a, b, _score in sorted(overlaps, key=lambda pair: pair[2], reverse=True):
        if a in to_drop or b in to_drop:
            continue
        droppable = [index for index in (a, b) if index not in keep]
        if droppable:
            to_drop.add(max(droppable))
    return to_drop


def _declined_by_alerts_and_briefing(event, excluded: bool, verdict, judge: Judge, running: str,
                                     repeats: dict) -> list[str] | None:
    """Why the alerts and the briefing declined an event, or None when one of
    them wants it or has no current verdict to go by. ``running`` is the
    product of this run, which is not switched off whatever the schedule says:
    it can be started from the dashboard alone. ``repeats`` is the story each
    found the event tells again, which declines it unless an analyst pushed it."""
    reasons = []
    for product, switch, default in (("alert", "ANALYSER_FLASH_INTEL", True),
                                     ("briefing", "ANALYSER_DAILY_BRIEFING", False)):
        if product != running and not getattr(config, switch, default):
            reasons.append(f"{product}: switched off")
        elif excluded:
            reasons.append(f"{product}: excluded by title")
        elif verdict is None or verdict.get("version") != judge.version:
            return None
        else:
            wanted, why = judge.wants(verdict, product, event)
            if wanted and repeats.get(product) and not relevance.pushed(event, product):
                wanted, why = False, repeats[product]
            if wanted:
                return None
            reasons.append(f"{product}: {why}")
    return reasons


def _declined_by_advisories(found, event, state: dict, check) -> tuple[str, str]:
    """Whether the advisories decline an event, as ("declined", why), ("unseen",
    "") for one with a CVE their steps have not seen yet or that could not be
    looked up, or ("open", why) for one with a CVE that would get an advisory.

    Their outcome names every CVE they looked at, so one added to the event
    since keeps it open. It is not taken as it is: the CVE records, the
    advisories that cover them and the settings can have changed since, so
    the CVEs are decided again as an advisory would decide them (``check``,
    from _advisory_check).
    """
    if not getattr(config, "ANALYSER_VULNERABILITY_ADVISORIES", False):
        return "declined", "advisory: switched off"
    cves = collection_cache.event_cves(event)[:settings.get("ANALYSER_ADVISORY_MAX_CVES")]
    if not cves:
        return "declined", "advisory: no CVE"
    outcome = (state["outcomes"].get("vea") or {}).get("outcome", "")
    if not outcome or not set(cves) <= {cve.upper() for cve in CVE_RE.findall(outcome)}:
        return "unseen", ""
    if check is None:
        return "open", "The asset inventory could not be read to check its CVEs again"
    advise, declined, unknown = _cves_to_advise(event, cves, found.summaries.get(event.uuid, ""), check)
    if unknown:
        return "unseen", ""
    if advise:
        return "open", (f"{', '.join(cve for cve, *_rest in advise)} would get an advisory now; run the "
                        "advisories again over the hours it was read in")
    return "declined", f"advisory: {_no_advisory(declined, cves, collection_cache.event_cves(event))}"


def _close_declined(found, judge: Judge | None, reading: Reading, running: str, progress=None) -> int:
    """Reject the events this run read that no product wants, and return how many.

    An event is closed when the alerts, the briefing and the advisories have
    each declined it: switched off, excluded by title, a verdict that does not
    want it or a story it tells again, or for the advisories no CVE or one
    their steps turned down. One that a product was made from, whose verdict
    is still to come or that an analyst flagged for follow-up stays open. So
    does one with a CVE the advisory steps have not seen yet, which the next
    run of this action reads again, to close it then, and one with a CVE that
    the advisory settings of now would give an advisory.
    """
    candidates = found.events + found.excluded
    if not candidates:
        return 0
    _emit(progress, "close-events", "in_progress", "Closing the events no product wants...")
    in_products = (misp_store.flash_intel_source_uuids() | misp_store.briefing_source_uuids()
                   | misp_store.vea_source_uuids())
    followed = collection_cache.get_flagged_uuids()
    check = None
    if getattr(config, "ANALYSER_VULNERABILITY_ADVISORIES", False):
        try:
            check = _advisory_check()
        except asset_inventory.InventoryError as exc:
            logger.warning("The advisory outcomes are not checked again: %s", exc)
    excluded = {event.uuid for event in found.excluded}
    closed = 0
    for event in candidates:
        if event.uuid in in_products:
            continue
        if event.uuid in followed:
            _decide(found, event, "left open", "An analyst follows it up")
            continue
        source = found.sources[event.uuid]
        state = event_state.load(source.id, event.uuid)
        evidence = _evidence(found, event)
        repeats = {"alert": event_state.outcome(state, "flash-intel", evidence),
                   "briefing": event_state.outcome(state, "daily-briefing", evidence)}
        reasons = _declined_by_alerts_and_briefing(event, event.uuid in excluded, state["verdict"], judge, running,
                                                   repeats)
        if reasons is None:
            continue
        advisory, why = _declined_by_advisories(found, event, state, check)
        if advisory == "unseen":
            reading.retry(event.uuid)
            continue
        if advisory == "open":
            _decide(found, event, "left open", why)
            continue
        reasons.append(why)
        rejected = event_state.reject(event, source, "; ".join(reasons))
        reading.wrote(event.uuid)
        if rejected:
            closed += 1
            if source.own:
                _add_rejection_note(source.client, event, reasons)
            _decide(found, event, "closed", "; ".join(reasons))
        else:
            # Still open in MISP: the next run closes it.
            reading.retry(event.uuid)
            _decide(found, event, "left open", f"{'; '.join(reasons)}; MISP refused the rejection")
    _emit(progress, "close-events", "completed", f"Closed {closed} event(s) no product wants.")
    return closed


def _story(found, event, focus: dict, names_with_commas, correlation: str = "") -> dict:
    """A briefing story drafted from an event. ``correlation`` names the
    earlier story it is an update of."""
    summary = (found.summaries.get(event.uuid) or "").strip()
    source_text = summary or _article(found, event)
    context = parse_misp_context(summary, names_with_commas) if summary else {}
    story_text = source_text
    actor_type = ""
    # Empty unless the model wrote this story, so a story that fell back to
    # the summary or the article text is not shown as an AI draft.
    drafted_by = ""
    if source_text:
        try:
            drafted, actor_type = llm.draft_briefing_story(
                source_text, focus_points=focus, threat_actor_types=getattr(config, "THREAT_ACTOR_TYPES", []) or [],
            )
            if drafted:
                story_text = drafted
                drafted_by = "ai"
        except Exception as exc:
            logger.warning("draft_briefing_story failed for %s: %s", event.uuid, exc)
    return {
        "title": event.info or "",
        "content": story_text,
        "drafted_by": drafted_by,
        "source_url": misp_store.extract_source_url(event),
        "source_event_uuid": event.uuid,
        "source_id": found.sources[event.uuid].hint,
        "correlation": correlation,
        "threat_actor_types": [actor_type] if actor_type else [],
        "sectors": context.get("sectors", []),
        "geographic_scope": context.get("geographies", []),
        "techniques": context.get("attack_techniques", []),
        "threat_actors": context.get("threat_actors", []),
        "vendor": context.get("vendor", []),
    }


def _overlapping(stories: list[dict], first_new: int, pushed=frozenset()) -> tuple[set, set]:
    """The 1-based indexes of the stories from ``first_new`` on that tell the
    story of another, as (to drop, to mark). The ones before ``first_new`` are
    in the draft already, and those in ``pushed`` an analyst asked for: neither
    is dropped, and one of those that tells the story of a story that stays is
    marked instead."""
    if len(stories) < 2 or first_new > len(stories):
        return set(), set()
    overlap = llm.detect_story_overlaps(stories)
    # detect_story_overlaps has already dropped whatever it could not read;
    # all that is left to decide here is how close is too close.
    pairs = [(o["a"], o["b"], o["score"]) for o in overlap.get("overlaps", [])
             if o["score"] >= settings.get("ANALYSER_OVERLAP_SCORE") and max(o["a"], o["b"]) >= first_new]
    to_drop = _duplicate_story_indexes(pairs, keep=set(range(1, first_new)) | set(pushed))
    marked = {max(a, b) for a, b, _score in pairs if a not in to_drop and b not in to_drop}
    return to_drop, marked


def _ranked(wanted: list[tuple], judge: Judge) -> list[tuple]:
    """The events for the briefing, best first: those an analyst pushed, then
    alert-worthy ones, then by the highest priority of the PIRs they answer,
    then by their overall score, and those in only as a major development last."""
    def key(found):
        event, verdict, _why = found
        return (not relevance.pushed(event, "briefing"), verdict["briefing"]["major_development"],
                not judge.wants(verdict, "alert", event)[0], judge.pir_priority(verdict),
                -(relevance.overall(verdict, event) or 0))
    return sorted(wanted, key=key)


def _also_seen(found, events: list) -> list[dict]:
    """The events over the cap, as the briefing lists them under Also seen."""
    return [{"title": event.info or "", "source_url": misp_store.extract_source_url(event),
             "source_event_uuid": event.uuid, "source_id": found.sources[event.uuid].hint} for event in events]


def todays_briefings() -> list:
    """The briefings dated today, in any state."""
    today = datetime.now(timezone.utc).date().isoformat()
    return [b for b in misp_store.list_briefings(strict=True) if b.date == today]


def todays_draft():
    """Today's briefing while it is a draft, which a run adds its stories to."""
    return next((b for b in todays_briefings() if b.review_state == misp_store.BRIEFING_REVIEW_DRAFT), None)


def _without_overlaps(found, ranked: list[tuple], existing: list[dict], progress=None) -> tuple[list, int, dict]:
    """The ranked events that do not tell the story of another or of one in the
    draft (``existing``), how many were dropped, and {event uuid: the overlap}
    for those an analyst pushed, which stay with the overlap marked."""
    updates = {}
    if not ranked:
        return ranked, 0, updates
    _emit(progress, "check-overlap", "in_progress", "Checking overlap between stories and removing duplicates...")
    candidates = [{"title": event.info or "", "content": found.summaries.get(event.uuid) or _article(found, event),
                   "source_url": misp_store.extract_source_url(event)} for event, _verdict, _why in ranked]
    first_new = len(existing) + 1
    pushed = {i for i, (event, _verdict, _why) in enumerate(ranked, start=first_new)
              if relevance.pushed(event, "briefing")}
    try:
        to_drop, marked = _overlapping(existing + candidates, first_new, pushed)
    except Exception as exc:
        logger.warning("Daily briefing overlap check failed: %s", exc)
        to_drop, marked = set(), set()
    for index in sorted(to_drop):
        event = ranked[index - first_new][0]
        # Kept, so that the next runs do not propose it again, and the
        # closing step counts it as declined.
        event_state.save_outcome(found.sources[event.uuid].id, event.uuid, "daily-briefing",
                                 "Duplicate coverage of another story", _evidence(found, event))
        _decide(found, event, "dropped", "Duplicate coverage of another story")
        _log(event, found.sources[event.uuid], "not_relevant", "Duplicate coverage of another story")
    for index in marked & pushed:
        updates[ranked[index - first_new][0].uuid] = "Overlaps with another story of this briefing"
    kept = [pair for i, pair in enumerate(ranked, start=first_new) if i not in to_drop]
    _emit(progress, "check-overlap", "completed", f"Overlap check complete: dropped {len(to_drop)} duplicate story(s).")
    return kept, len(to_drop), updates


def _write_briefing(draft, existing: list[dict], stories: list[dict], story_events: list, also_seen: list[dict],
                    progress=None) -> tuple[str, str]:
    """Add the new stories to today's ``draft``, or make one of them, with the
    briefing summary. Returns its uuid and the message of the run."""
    all_stories = existing + stories
    now = datetime.now(timezone.utc)
    # Written from the stories that survived the overlap check, so the summary
    # describes the draft as it will actually be. A draft is worth more without
    # a summary than not at all, so a failure here only costs the paragraph and
    # the analyst can write or redraft it on the form.
    _emit(progress, "write-summary", "in_progress", "Writing the briefing summary across the stories...")
    briefing_summary = ""
    try:
        briefing_summary = llm.draft_briefing_summary(
            all_stories, misp_store.briefing_scope_summary(all_stories), now.date().isoformat(),
        )
    except Exception as exc:
        logger.warning("draft_briefing_summary failed: %s", exc)
    _emit(progress, "write-summary", "completed",
          "Briefing summary written." if briefing_summary
          else "No briefing summary written; the draft opens without one.")

    # Never below what the draft already is.
    tlp = misp_store.source_events_tlp(story_events, draft.tlp if draft else "clear")
    _emit(progress, "create-drafts", "in_progress", "Writing the daily briefing draft...")
    if draft:
        data = {field: getattr(draft, field) for field in misp_store.BRIEFING_FIELDS}
        data.update(
            stories=all_stories, story_count=len(all_stories),
            tlp=tlp,
            vendor=_deduplicate_vendors(list(draft.vendor) + [v.strip() for s in stories
                                                             for v in s.get("vendor", []) if v.strip()]),
            also_seen=draft.also_seen + also_seen,
            summary=briefing_summary or draft.summary,
            # A summary kept from before the new stories no longer covers them.
            summary_stale=bool(draft.summary) and not briefing_summary,
        )
        misp_store.update_briefing(draft.uuid, data, expected_state=misp_store.BRIEFING_REVIEW_DRAFT)
        briefing_uuid = draft.uuid
        message = f"Added {len(stories)} stories to today's daily briefing draft."
    else:
        briefing_uuid = misp_store.create_briefing({
            "date": now.date().isoformat(),
            "title": f"Daily threat briefing for {now.day} {now.strftime('%B %Y')}",
            "author": "analyser",
            "tlp": tlp,
            "escalations": "",
            "notes": "",
            "also_seen": also_seen,
            "summary": briefing_summary,
            "review_state": misp_store.BRIEFING_REVIEW_DRAFT,
            "vendor": _deduplicate_vendors([v.strip() for s in stories for v in s.get("vendor", []) if v.strip()]),
            "stories": stories,
        })
        message = f"Daily briefing draft created with {len(stories)} stories."
    return briefing_uuid, message


def run_daily_briefing_action(reading: Reading, progress=None) -> dict:
    found = _common_candidate_events(reading, progress, title_exclusions=daily_briefing_title_exclusions() or None)

    # Read from the products rather than from a tag on the event: an event on
    # another MISP server has no product tag. One left out over the cap is
    # under Also seen until its briefing is deleted to be made again.
    briefed = misp_store.briefing_source_uuids() if found.events else set()
    listed = misp_store.briefing_also_seen_uuids() if found.events else set()
    alerted = (misp_store.flash_intel_source_uuids()
               if found.events and not settings.get("ANALYSER_BRIEFING_WITH_ALERTS") else set())
    events = []
    for event in found.events:
        outcome = _earlier_outcome(found, event, "daily-briefing", reading)
        is_pushed = relevance.pushed(event, "briefing")
        if event.uuid in briefed:
            _decide(found, event, "excluded", "Already included in a previous briefing")
        elif event.uuid in alerted:
            _decide(found, event, "excluded", "Has a flash intel alert")
        elif event.uuid in listed and not is_pushed:
            _decide(found, event, "excluded", "Listed under Also seen in a briefing")
        elif outcome and not is_pushed:
            _decide(found, event, "excluded", outcome)
        else:
            events.append(event)

    judge = Judge(reading) if found.events else None
    _emit(progress, "judge-relevance", "in_progress", f"Judging {len(events)} event(s) for the briefing...")
    wanted = _judged(found, events, judge, "briefing", progress)
    declined_by_relevance = len(events) - len(wanted)

    draft = todays_draft() if wanted else None
    existing = [{k: v for k, v in vars(s).items() if k != "_report_id"} for s in draft.stories] if draft else []
    ranked = _ranked(wanted, judge)
    events_by_uuid = {event.uuid: event for event, _verdict, _why in ranked}

    # Duplicates and the cap are settled on the summaries, before the stories
    # are drafted, so that no model call goes on a story that is left out.
    ranked, dropped, updates = _without_overlaps(found, ranked, existing, progress)

    # Compared with the briefings of the last weeks only as long as there is
    # room: each comparison is a model call.
    room = max(0, settings.get("ANALYSER_BRIEFING_MAX_STORIES") - len(existing))
    earlier = similarity.recent_stories(but=draft) if ranked else []
    kept, over_cap = [], []
    for event, verdict, why in ranked:
        # One an analyst pushed goes past the cap, and an earlier story only
        # marks it: the analyst asked for it.
        is_pushed = relevance.pushed(event, "briefing")
        if len(kept) >= room and not is_pushed:
            over_cap.append(event)
            continue
        _emit(progress, "check-overlap", "in_progress",
              f"Comparing with earlier briefings: {(event.info or event.uuid)[:80]}")
        try:
            same = similarity.same_story(
                similarity.event_story(event, found.summaries.get(event.uuid, ""), _article(found, event)), earlier)
        except Exception as exc:
            logger.warning("Comparing %s with the earlier briefings failed: %s", event.uuid, exc)
            same = None
            updates[event.uuid] = "Not compared with the earlier briefings, as the comparison failed"
        if similarity.repeats(same) and not is_pushed:
            told = f"The same story as one in {same['story']['id']}"
            event_state.save_outcome(found.sources[event.uuid].id, event.uuid, "daily-briefing", told,
                                     _evidence(found, event))
            _decide(found, event, "dropped", told)
            _log(event, found.sources[event.uuid], "not_relevant", f"{told}.")
            continue
        if same:
            told = "Update of" if same["new_facts"] else "The same story as"
            updates[event.uuid] = f"{told} \"{same['story']['title']}\" in {same['story']['id']}: {same['reason']}"
        kept.append((event, verdict, why))
    ranked = kept
    cap = settings.get("ANALYSER_BRIEFING_MAX_STORIES")
    for event in over_cap:
        _decide(found, event, "over the cap", f"Listed under Also seen: the briefing has {cap} stories")

    _emit(progress, "build-briefing", "in_progress", "Building daily briefing stories from eligible events...")
    focus = llm.configured_focus_points()
    names_with_commas = galaxy_names_with_commas() if ranked else frozenset()
    stories = []
    for position, (event, verdict, why) in enumerate(ranked, start=1):
        _emit(progress, "build-briefing", "in_progress",
              f"Story {position} of {len(ranked)}: {(event.info or event.uuid)[:80]}")
        stories.append(_story(found, event, focus, names_with_commas, updates.get(event.uuid, "")))
        grounds = _grounds_text(verdict["briefing"]["grounds"])
        if verdict["briefing"]["major_development"]:
            grounds = "a major development"
        _decide(found, event, "included", f"{why} Grounds: {grounds}." if grounds else why)
    _emit(progress, "build-briefing", "completed", f"Prepared {len(stories)} story candidate(s).")

    result = {"ok": True, "action": "daily-briefing", **found.stats, "declined_by_relevance": declined_by_relevance,
              "overlap_dropped": dropped, "over_the_cap": len(over_cap)}
    if not stories and not over_cap:
        _emit(progress, "write-summary", "completed", "No stories to summarise.")
        _emit(progress, "create-drafts", "completed", "No daily briefing draft created (no eligible stories).")
        result.update(created=0, message="No eligible events to include in a daily briefing draft.")
        result["closed"] = _close_declined(found, judge, reading, "briefing", progress)
        return result

    if not stories:
        # Today's draft is full: only its Also seen list changes.
        data = {field: getattr(draft, field) for field in misp_store.BRIEFING_FIELDS}
        data.update(stories=existing, also_seen=draft.also_seen + _also_seen(found, over_cap))
        misp_store.update_briefing(draft.uuid, data, expected_state=misp_store.BRIEFING_REVIEW_DRAFT)
        result.update(created=0, briefing_uuid=draft.uuid, message="Today's daily briefing draft is full.")
        result["closed"] = _close_declined(found, judge, reading, "briefing", progress)
        return result

    story_events = [events_by_uuid[s["source_event_uuid"]] for s in stories]
    briefing_uuid, message = _write_briefing(draft, existing, stories, story_events, _also_seen(found, over_cap),
                                             progress)
    _emit(progress, "create-drafts", "completed", f"Daily briefing draft written ({briefing_uuid}).")

    for s in stories:
        uuid = s["source_event_uuid"]
        # Tagged as a source of the briefing.
        reading.wrote(uuid)
        _log(events_by_uuid[uuid], found.sources[uuid], "product_created", "daily-briefing")

    result.update(created=0 if draft else 1, briefing_uuid=briefing_uuid, stories_included=len(stories),
                  message=message)
    result["closed"] = _close_declined(found, judge, reading, "briefing", progress)
    return result


def run_flash_intel_action(reading: Reading, progress=None) -> dict:
    # The title exclusions keep an event out of the alerts as they keep it out
    # of the briefing; only the advisories go by its CVEs alone.
    found = _common_candidate_events(reading, progress, title_exclusions=daily_briefing_title_exclusions() or None)
    # One alert per event, whichever run made it and whatever became of it.
    alerted = misp_store.flash_intel_source_uuids() if found.events else set()
    # One linked to an alert it repeats is left out, unless an analyst pushed it.
    events = [e for e in found.events if e.uuid not in alerted
              and (not _earlier_outcome(found, e, "flash-intel", reading) or relevance.pushed(e, "alert"))]
    judge = Judge(reading) if found.events else None

    _emit(progress, "judge-relevance", "in_progress", f"Judging {len(events)} event(s) for alerts...")
    wanted = _judged(found, events, judge, "alert", progress)

    _emit(progress, "create-drafts", "in_progress", "Drafting flash intel alerts...")
    earlier = similarity.recent_alerts() if wanted else []
    created = []
    for event, verdict, why in wanted:
        source = found.sources[event.uuid]
        article, summary = _article(found, event), found.summaries.get(event.uuid, "")
        update_of = ""
        try:
            same = similarity.same_story(similarity.event_story(event, summary, article), earlier)
        except Exception as exc:
            # Drafted rather than lost, with a word for the analyst.
            logger.warning("Comparing %s with the earlier alerts failed: %s", event.uuid, exc)
            same, update_of = None, "Not compared with the earlier alerts, as the comparison failed"
        if similarity.repeats(same) and not relevance.pushed(event, "alert"):
            told = f"The same story as {same['story']['id']}" + (", rejected" if same["story"]["rejected"] else "")
            # Linked to the alert it repeats, so the next runs do not propose it again.
            event_state.save_outcome(source.id, event.uuid, "flash-intel", told, _evidence(found, event))
            _decide(found, event, "dropped", told)
            _log(event, source, "not_relevant", f"{told}.")
            continue
        if same:
            update_of = (f"{'Update of' if same['new_facts'] else 'The same story as'} {same['story']['id']}: "
                         f"{same['reason']}")
        title = (event.info or event.uuid)[:80]
        _emit(progress, "create-drafts", "in_progress", f"Drafting an alert on {title}...")
        fia_id = problem = ""
        try:
            data = flash_intel.draft_alert(event, source, verdict, judge, article, summary, why, update_of=update_of)
            if data:
                _emit(progress, "create-drafts", "in_progress", f"Filing the alert on {title}...")
                fia_id, problem = flash_intel.file_alert(data, event, source, verdict)
        except run_lock.Lost:
            raise
        except Exception as exc:
            # One event the model or MISP fails on should not end the run for
            # the others, nor keep them waiting every hour after.
            logger.warning("Flash intel draft failed for %s: %s", event.uuid, exc)
        if not fia_id:
            reading.retry(event.uuid)
            _decide(found, event, "left open", "No alert could be drafted; the next run tries again")
            _log(event, source, "error", "No flash intel alert could be drafted; left open for the next run")
            continue
        # Tagged as the alert's source.
        reading.wrote(event.uuid)
        if problem:
            _log(event, source, "error", f"{fia_id} was made, but {problem}")
        earlier.append(similarity.event_story(event, summary, article) | {"id": fia_id})
        created.append(event.uuid)
        _decide(found, event, "included", why)
        _log(event, source, "product_created", f"flash-intel {fia_id}; grounds: {_grounds_text(verdict['alert']['grounds'])}")
    _emit(progress, "create-drafts", "completed", f"Created {len(created)} flash intel draft(s).")

    result = {
        "ok": True,
        "action": "flash-intel",
        "created": len(created),
        "source_event_uuids": created,
        "message": f"Created {len(created)} flash intel draft(s).",
        **found.stats,
    }
    # With the daily briefing on, it closes the events of the day, as the last
    # product to deal with them; without it, nothing else would.
    if not getattr(config, "ANALYSER_DAILY_BRIEFING", False):
        result["closed"] = _close_declined(found, judge, reading, "alert", progress)
    return result


_NOT_CHECKED = "Not checked: the CVE record names no product, and neither does the article."


def _cvss(value) -> float | None:
    """A CVSS score from a record or an advisory, "9.8 CRITICAL" included."""
    found = re.match(r"\s*(\d+(?:\.\d+)?)", str(value or ""))
    return float(found.group(1)) if found else None


def _covered(vea, cvss, cisa_kev) -> SimpleNamespace:
    """A CVE as an advisory covers it, with what it was then. None for a
    value not known."""
    return SimpleNamespace(vea_id=vea.vea_id, review_state=vea.review_state, cvss=cvss, cisa_kev=cisa_kev)


def _advisory_coverage() -> dict:
    """{CVE: the newest advisory of the lookback naming it, with its CVSS
    score and KEV status then}, in any state.

    An advisory has the score and KEV status of its main CVE, and from the
    analyser, of each of its CVEs. Another CVE of one an analyst wrote is
    covered without them, so its change is not measured."""
    oldest = datetime.now(timezone.utc).date() - timedelta(days=settings.get("ANALYSER_ADVISORY_DAYS"))
    covered = {}
    for vea in sorted(misp_store.list_veas(strict=True), key=lambda v: v.created_at or datetime.min, reverse=True):
        if vea.created_at and vea.created_at.date() < oldest:
            continue
        cves = [cve.upper() for cve in CVE_RE.findall(vea.cve_id or "")]
        baselines = vea.cve_baselines
        for position, cve in enumerate(cves):
            if cve in covered:
                continue
            if cve in baselines:
                then = baselines[cve]
                covered[cve] = _covered(vea, then.get("cvss"), then.get("cisa_kev"))
            elif position == 0:
                covered[cve] = _covered(vea, vea.cvss, vea.cisa_kev)
            else:
                covered[cve] = _covered(vea, None, None)
    return covered


def _material_change(earlier, record: dict) -> str:
    """How a CVE changed since an advisory covered it, or "" for not enough
    to be worth a new one."""
    if record.get("cisa_kev") == "Yes" and earlier.cisa_kev is not None and earlier.cisa_kev != "Yes":
        return "it is on the CISA KEV list now"
    now, then = _cvss(record.get("cvss_score")), _cvss(earlier.cvss)
    if now is not None and then is not None and now - then >= settings.get("ANALYSER_ADVISORY_CVSS_RISE"):
        return f"its CVSS score rose from {then} to {now}"
    return ""


def _scope_terms() -> list[tuple[str, str]]:
    """The vendor and technology names an advisory's CVE has to concern, as
    (name, where it is from): the focus points, and the vendor and technology
    scope of every active PIR, except a "Won't have", and GIR."""
    terms = [(name, f"the focus point {name}") for key in ("FOCUS_POINTS_VENDORS", "FOCUS_POINTS_TECHNOLOGIES")
             for name in relevance.focus_names(key)]
    pirs, girs = req_matching.get_requirements(strict=True)
    for requirement in [r for r in pirs if r.priority != "Won't have"] + list(girs):
        rid = req_matching.requirement_id(requirement)
        for name in [*requirement.vendor, *requirement.technology]:
            terms.append((name, f"{rid} ({name})"))
    return terms


def _advisory_check() -> SimpleNamespace:
    """What the advisory steps decide on now: whether the asset inventory is
    on, the scope terms and the advisories that cover a CVE. ``records`` keeps
    the CVEs looked up, each once a run."""
    checking_assets = asset_inventory.enabled()
    if checking_assets:
        # Read now, so that a file that cannot be read fails here rather than
        # half-way through the events.
        asset_inventory.assets()
    return SimpleNamespace(checking_assets=checking_assets, terms=_scope_terms(), coverage=_advisory_coverage(),
                           records={})


def _in_scope(record: dict, text: str, terms: list, checking_assets: bool) -> str | None:
    """What "Our exposure" says of a CVE that concerns the organisation, or
    None when it does not.

    Its record's vendors and products are matched against the asset
    inventory, when it is on, and the scope terms. A record that names no
    product yet, as a new one often does, is matched on the event's title and
    summary instead, and failing that passes, flagged as not checked. With no
    scope to match against at all, every CVE passes, as nothing says otherwise.
    """
    if not checking_assets and not terms:
        return ""
    affected = record.get("affected") or []
    for vendor, product in affected:
        if checking_assets:
            asset = asset_inventory.find(vendor, product)
            if asset:
                return f"In the asset inventory: {asset.supplier} {asset.product} {asset.version}".strip()
        for name, where in terms:
            if asset_inventory.names(name, vendor, product):
                return f"{vendor} {product} is in the scope of {where}.".strip()
    if affected:
        return None
    for name, where in terms:
        if req_matching.term_in_text(name, text):
            return f"The article names {name}, in the scope of {where}."
    return _NOT_CHECKED


def _severe_enough(record: dict) -> bool:
    if settings.get("ANALYSER_ADVISORY_KEV_ONLY") and record.get("cisa_kev") != "Yes":
        return False
    score = _cvss(record.get("cvss_score"))
    return score is None or score >= settings.get("ANALYSER_ADVISORY_CVSS_FLOOR")


def _cves_to_advise(event, cves, summary, check, progress=None):
    """The CVEs of an event an advisory is for, as (cve, record, exposure,
    update of an earlier advisory or ""), why the others are not, and those
    whose record could not be looked up, which are still to be decided.
    ``check`` is what the advisory steps decide on (_advisory_check)."""
    advise, declined, unknown = [], [], []
    text = f"{event.info or ''}\n{summary}"
    for cve in cves:
        if cve not in check.records:
            _emit(progress, "create-drafts", "in_progress", f"Looking up {cve}...")
            check.records[cve] = lookup_cve(cve)
        record = check.records[cve]
        if record is None:
            unknown.append(cve)
            continue
        earlier = check.coverage.get(cve)
        if earlier is not None:
            change = _material_change(earlier, record) if settings.get("ANALYSER_ADVISORY_UPDATES") else ""
            if not change:
                declined.append(f"{cve} in {earlier.vea_id}")
                continue
            if (earlier.review_state == misp_store.VEA_REVIEW_REJECTED
                    and settings.get("ANALYSER_ADVISORY_REJECTED_BLOCKS")):
                declined.append(f"{cve} in {earlier.vea_id}, rejected")
                continue
        exposure = _in_scope(record, text, check.terms, check.checking_assets)
        if exposure is None:
            declined.append(f"{cve} out of scope")
            continue
        if not _severe_enough(record):
            declined.append(f"{cve} below the severity asked for")
            continue
        update = f"Update of {earlier.vea_id}: {change}." if earlier is not None else ""
        advise.append((cve, record, exposure, update))
    # One that could not be checked is never the advisory's main CVE while
    # another is known to concern us.
    advise.sort(key=lambda found: found[2] == _NOT_CHECKED)
    return advise, declined, unknown


def _no_advisory(declined: list, looked_up: list, cves: list) -> str:
    """Why an event gets no advisory, the CVEs past the limit named as not
    looked up: they never keep the event open."""
    skipped = len(cves) - len(looked_up)
    if skipped:
        declined = [*declined, f"{skipped} more not looked up, past the limit of {len(looked_up)}"]
    return f"No CVE to advise on: {', '.join(declined)}"


def _advisory_data(found, event, summary: str, advise: list, audience: str) -> dict:
    """The fields of the advisory on the CVEs in ``advise``, as _cves_to_advise
    gives them, the first its main CVE, with the sections the model drafted.
    ``audience`` is who an amber advisory reaches."""
    primary_cve, enrichment, exposure, update = advise[0]
    cves = [cve for cve, *_rest in advise]
    source = found.sources[event.uuid]

    product_lines = []
    if enrichment.get("products"):
        product_lines.append("Products: " + ", ".join(enrichment["products"]))
    if enrichment.get("versions"):
        product_lines.append("Versions: " + ", ".join(enrichment["versions"]))
    if enrichment.get("description"):
        product_lines.append("Description: " + enrichment["description"])
    product_info = "\n".join(product_lines)

    article = _article(found, event)
    drafted = {}
    try:
        drafted = llm.draft_vea_sections(
            cve_id=primary_cve,
            product_info=product_info,
            article_content=article or summary,
        )
    except Exception as exc:
        logger.warning("draft_vea_sections failed for %s: %s", event.uuid, exc)

    cvss = ""
    if enrichment.get("cvss_score"):
        cvss = enrichment["cvss_score"]
        if enrichment.get("cvss_severity"):
            cvss += f" {enrichment['cvss_severity']}"

    tlp = misp_store.source_events_tlp([event], "amber")
    return {
        "cve_id": "\n".join(cves),
        "summary": (drafted.get("summary") or summary).strip(),
        "cvss": cvss or drafted.get("cvss", ""),
        "cwe": enrichment.get("cwes", [""])[0] if enrichment.get("cwes") else drafted.get("cwe", ""),
        "title": event.info or "",
        "tlp": tlp,
        "author": "analyser",
        "audience": audience if tlp == "amber" else misp_store.subscriber_audience("Vulnerability advisory", tlp),
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
        "source_reliability": tagger.tag_value(event, "admiralty-scale:source-reliability="),
        "information_credibility": tagger.tag_value(event, "admiralty-scale:information-credibility="),
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
        "source_event_hints": {event.uuid: source.hint},
        "linked_pir_uuid": "",
        "analyser_reason": " ".join(part for part in (
            update, f"The event names {', '.join(cves)}.", exposure) if part),
        # What a later change of each CVE is measured against.
        "cve_baselines": {cve: {"cvss": record.get("cvss_score") or "", "cisa_kev": record.get("cisa_kev") or ""}
                          for cve, record, *_rest in advise},
    }


def run_vea_action(reading: Reading, progress=None) -> dict:
    # With the asset inventory on, reading it first fails the run on a bad file
    # before the summaries take their model calls.
    if asset_inventory.enabled():
        asset_inventory.assets()
    found = _common_candidate_events(reading, progress)
    # One advisory per event, read from the advisories: an event on another
    # MISP server has no product tag.
    advised_before = misp_store.vea_source_uuids() if found.events else set()
    events = []
    for event in found.events:
        if event.uuid in advised_before:
            _decide(found, event, "excluded", "Has a vulnerability advisory already")
        else:
            events.append(event)

    _emit(progress, "detect-cves", "in_progress", "Detecting CVE matches in eligible events...")
    cve_map = {e.uuid: collection_cache.event_cves(e) for e in events}
    cve_match_count = sum(1 for cves in cve_map.values() if cves)
    _emit(progress, "detect-cves", "completed", f"CVE detection complete: {cve_match_count} event(s) with CVE match.")
    # Everyone an advisory can reach, for the analyst to narrow down.
    audience = misp_store.subscriber_audience("Vulnerability advisory", "amber") if cve_match_count else ""
    # The scraper reads an article again as a new event when its title
    # changes, as an "(Updated October 25)" does, and several sites write up
    # one CVE: an advisory of the lookback covers it, unless it changed since.
    check = _advisory_check() if cve_match_count else None

    advised = []
    _emit(progress, "create-drafts", "in_progress", "Creating vulnerability advisory draft(s) for CVE-matched events...")
    most = settings.get("ANALYSER_ADVISORY_MAX_CVES")
    for event in events:
        cves = cve_map[event.uuid][:most]
        if not cves:
            _decide(found, event, "declined", "No CVE found")
            _log(event, found.sources[event.uuid], "not_relevant", "no CVE found")
            continue
        source = found.sources[event.uuid]
        summary = found.summaries.get(event.uuid) or ""
        advise, declined, unknown = _cves_to_advise(event, cves, summary, check, progress)
        if unknown:
            # Not decided, also for the CVEs that could be looked up: the
            # event gets one advisory, and the next run makes it with them all.
            reading.retry(event.uuid)
            _decide(found, event, "left open", f"{', '.join(unknown)} could not be looked up; the next run tries again")
            _log(event, source, "error", f"{', '.join(unknown)} could not be looked up; left for the next run")
            continue
        if not advise:
            reason = _no_advisory(declined, cves, cve_map[event.uuid])
            # The closing step waits for this before it closes the event.
            event_state.save_outcome(source.id, event.uuid, "vea", reason)
            _decide(found, event, "declined", reason)
            _log(event, source, "not_relevant", reason)
            continue
        data = _advisory_data(found, event, summary, advise, audience)
        _emit(progress, "create-drafts", "in_progress", f"Writing the advisory on {(event.info or event.uuid)[:80]}...")
        try:
            _uuid, vea_id = misp_store.create_vea(data)
        except Exception as exc:
            # One that MISP refuses should not hold up the others, now or on
            # every run after.
            logger.warning("Vulnerability advisory failed for %s: %s", event.uuid, exc)
            reading.retry(event.uuid)
            _decide(found, event, "left open", "No advisory could be written; the next run tries again")
            _log(event, source, "error", f"No advisory could be written: {exc}; left for the next run")
            continue
        reading.wrote(event.uuid)
        # The next event on these CVEs in this run is covered by this one.
        new = SimpleNamespace(vea_id=vea_id, review_state=misp_store.VEA_REVIEW_DRAFT)
        check.coverage.update({cve: _covered(new, then["cvss"], then["cisa_kev"])
                               for cve, then in data["cve_baselines"].items()})
        advised.append(event.uuid)
        _decide(found, event, "included", f"{vea_id}: {data['analyser_reason']}")
        _log(event, source, "product_created", f"vea; CVEs: {', '.join(data['cve_baselines'])}")
    created = len(advised)
    _emit(progress, "create-drafts", "completed", f"Created {created} vulnerability advisory draft(s).")

    return {
        "ok": True,
        "action": "vea",
        "created": created,
        "source_event_uuids": advised,
        "message": f"Created {created} vulnerability advisory draft(s) from CVE-matched events.",
        **found.stats,
    }


ACTION_LABELS = {
    "daily-briefing": "Daily briefing",
    "flash-intel": "Flash intel alert",
    "vea": "Vulnerability advisory",
}


def action_steps(action: str) -> list[dict]:
    common = [
        {"id": "collect-events", "label": "Read the new and changed events", "state": "pending"},
        {"id": "filter-events", "label": "Filter hard negatives", "state": "pending"},
        {"id": "generate-summaries", "label": "Generate missing LLM summaries", "state": "pending"},
    ]
    if action == "daily-briefing":
        common.extend([
            {"id": "judge-relevance", "label": "Judge relevance for the briefing", "state": "pending"},
            {"id": "check-overlap", "label": "Check overlap and remove duplicates", "state": "pending"},
            {"id": "build-briefing", "label": "Build briefing story set", "state": "pending"},
            {"id": "write-summary", "label": "Write the briefing summary", "state": "pending"},
            {"id": "create-drafts", "label": "Write the daily briefing draft", "state": "pending"},
            {"id": "close-events", "label": "Close the events no product wants", "state": "pending"},
        ])
    elif action == "flash-intel":
        common.extend([
            {"id": "judge-relevance", "label": "Judge relevance for alerts", "state": "pending"},
            {"id": "create-drafts", "label": "Create flash intel draft(s)", "state": "pending"},
        ])
        if not getattr(config, "ANALYSER_DAILY_BRIEFING", False):
            common.append({"id": "close-events", "label": "Close the events no product wants", "state": "pending"})
    elif action == "vea":
        common.extend([
            {"id": "detect-cves", "label": "Detect CVE matches", "state": "pending"},
            {"id": "create-drafts", "label": "Create vulnerability advisory draft(s)", "state": "pending"},
        ])
    return common


def run_action(job_id: str, user: str, triggered_by: str = "dashboard", lock_token: str = "",
               rescan_hours: int | None = None) -> dict | None:
    """Run the analyser action of a job made with action_steps(), and return its
    result, or None when it did not complete. ``user`` goes on the audit
    entries: the analyst, read from the request before this thread began, or
    "analyser" for the schedule.

    The action reads what changed on each source since its previous completed
    run, whoever started that one, or with ``rescan_hours`` that many hours
    back. Its watermarks move only when it completes. ``lock_token`` is the
    analyser lock (analyser.run_lock) the caller holds, refreshed and checked at
    each step it reports.
    """
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
    details = f"triggered by {triggered_by}" + (f", reading the last {rescan_hours} hours again" if rescan_hours else "")
    audit.record("run-start", "pipeline", entity_label=action, details=details, user=user)
    job_store.update_job(job_id, status="running", message="Running...")
    job_store.append_log(job_id, f"Started action '{action}'.")

    def _progress(*, step: str, state: str, message: str = ""):
        job_store.set_step(job_id, step=step, state=state, message=message)
        if not run_lock.refresh(lock_token):
            # Another run took the lock over; this one must not write beside it.
            raise run_lock.Lost("The analyser lock was taken over by another run")

    reading = Reading(action, rescan_hours=rescan_hours)
    try:
        result = handler(reading, progress=_progress)
        # Events left for the next run keep the scheduled briefing's day open.
        result["retried"] = len(reading.retried)
        reading.commit()
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
