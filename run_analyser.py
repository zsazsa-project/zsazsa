import logging
import time
from datetime import datetime, timezone

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.logging_setup import setup_logging
from analyser.products.flash_intel import process as process_flash_intel
from analyser.reader import (get_new_manual_entries, get_new_scraper_events, load_last_briefing,
                             save_last_briefing, save_last_run)
from core.db import get_latest_pipeline_run, init_db, log_event, log_pipeline_run_start, log_pipeline_run_end
from core.misp_client import get_misp, get_misp_webapp
from webapp import analyser_pipeline, audit, feed_cache, job_store, misp_store
from webapp.utils import scraper_enabled


def load_focus_points() -> dict:
    return {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }


def scheduled_actions(now: datetime) -> list[str]:
    """The dashboard's analyser actions this run makes, switched on under
    Settings > System. The daily briefing comes once a day, from its hour on."""
    actions = []
    if getattr(config, "ANALYSER_FLASH_INTEL_REQUIREMENTS", False):
        actions.append("flash-intel")
    if getattr(config, "ANALYSER_VULNERABILITY_ADVISORIES", False):
        actions.append("vea")
    if (getattr(config, "ANALYSER_DAILY_BRIEFING", False)
            and now.hour >= getattr(config, "ANALYSER_DAILY_BRIEFING_HOUR", 21)
            and load_last_briefing() != now.date().isoformat()):
        actions.append("daily-briefing")
    return actions


def _last_scheduled_run(action: str) -> int | None:
    """Where the next scheduled run of an action reads from: when the last one
    that went through started, or where that one read from when a summary
    failed in it, so the event is read and summarised again."""
    run = get_latest_pipeline_run(action, triggered_by="schedule", status="completed")
    if run is None:
        return None
    result = run["result"] or {}
    if result.get("summary_failed"):
        return result.get("since")
    return int(datetime.fromisoformat(run["started_at"]).replace(tzinfo=timezone.utc).timestamp())


def run_scheduled_actions(actions: list[str], now: datetime) -> dict:
    """Run these actions, and return the result of each that went through."""
    logger = logging.getLogger(__name__)
    results = {}
    for action in actions:
        label = analyser_pipeline.ACTION_LABELS[action]
        job = job_store.create_job(action, label=f"Scheduled {label.lower()}",
                                   steps=analyser_pipeline.action_steps(action))
        # Yesterday's events too: one that came in after the last run of the
        # day, or after the day's briefing, would otherwise never be read. The
        # briefing takes the two days whole, once a day. The others run every
        # hour and only read what came in or changed since they last did, or an
        # event would be checked, and logged, some 48 times over.
        since = None if action == "daily-briefing" else _last_scheduled_run(action)
        result = analyser_pipeline.run_action(job["id"], "analyser", triggered_by="schedule", days=2,
                                              since=since)
        if result is None:
            continue
        results[action] = result
        logger.info("Scheduled %s: %s", label.lower(), result.get("message", ""))
        if action == "daily-briefing":
            save_last_briefing(now.date().isoformat())
    return results


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Analyser started")

    init_db()
    # The scheduled actions write to the audit log, and the runs prune it.
    audit.init()
    run_id = log_pipeline_run_start("analyser", triggered_by="cli")
    now = datetime.now(timezone.utc)
    due = scheduled_actions(now) if scraper_enabled() else []

    try:
        # The alerts from requirements and the advisories see the new events
        # first: the check against the focus points below can reject an event
        # that matches no focus point, which would take it out of both. The
        # briefing, which rejects too, goes last.
        results = run_scheduled_actions([a for a in due if a != "daily-briefing"], now)
        advised = set((results.get("vea") or {}).get("source_event_uuids") or [])
        focus_points = load_focus_points()
        # Only the event analysis needs the scraper. An installation that
        # collects from other MISP servers has none, and the run goes ahead with
        # no events so the feed caches below still get their scheduled refresh.
        misp = misp_webapp = None
        events = []
        # The MISP each event is on: manual entries are kept on the webapp's.
        sources = {}
        alerted, matched = set(), set()
        # With the daily briefing on, it judges every event of the day itself,
        # so nothing is rejected here for missing the focus points. Without it,
        # an event a PIR or GIR matches is still left open: a briefing started
        # from the dashboard always includes those.
        for_briefing = getattr(config, "ANALYSER_DAILY_BRIEFING", False)
        if not scraper_enabled():
            logger.info("No MISP scraper configured; refreshing feed caches only")
        elif getattr(config, "ANALYSER_FLASH_INTEL", True):
            misp = get_misp()
            misp_webapp = get_misp_webapp()
            # The watermark is taken as the events are read, after the alerts
            # from requirements and the advisories: the summaries they wrote
            # changed those events, and they would otherwise all be read, and
            # sent to the model, again on the next run.
            read_at = int(time.time())
            events = get_new_scraper_events(misp)
            manual = get_new_manual_entries(misp_webapp)
            sources = dict.fromkeys((e.uuid for e in events), misp) | dict.fromkeys((e.uuid for e in manual), misp_webapp)
            # A manual entry synced to the scraper is there too, under the same
            # uuid. The entry itself is the one kept.
            events = list({e.uuid: e for e in events + manual}.values())
            # One alert per event, whichever run made it and whatever became of it.
            alerted = misp_store.flash_intel_source_uuids()
            # An advisory just made moved its event on to ongoing, which the read
            # above leaves out, but a CVE in a product we run can be worth an
            # alert as well. Fetched again, so its tags are the ones it has now.
            # A manual entry is looked for first, so a copy of it synced to the
            # scraper is not the one changed. A search, because get_event logs
            # an error for an event the other MISP has.
            for uuid in advised - alerted - set(sources):
                for client, filters in ((misp_webapp, {"tags": [misp_store.TAG_MANUAL_ENTRY]}), (misp, {})):
                    found = client.search(uuid=uuid, pythonify=True, **filters)
                    if isinstance(found, dict):
                        raise RuntimeError(f"MISP search for advised event {uuid} failed: {found.get('errors') or found}")
                    if found:
                        events.append(found[0])
                        sources[uuid] = client
                        break
            if events and not for_briefing:
                matched = set(analyser_pipeline.requirement_matches(events))
    except Exception as e:
        logger.error("Startup failed: %s", e)
        log_pipeline_run_end(run_id, "failed")
        raise

    counts = {"product_created": 0, "not_relevant": 0, "http_error": 0, "no_content": 0, "error": 0}

    # A run with work registers a job, so the web app can show it while it is
    # going. Scheduled runs that find nothing stay out of the way: they would
    # otherwise keep the job badge lit with nothing to report.
    job = None
    if events:
        job = job_store.create_job("analyser", label="CLI analyser")
        job_store.update_job(job["id"], status="running", message=f"Processing {len(events)} event(s)")

    try:
        for position, event in enumerate(events, start=1):
            job_store.update_job(job["id"], message=f"Event {position} of {len(events)}: {event.info or event.uuid[:8]}")
            if event.uuid in alerted:
                logger.info("Event %s already has a flash intel alert", event.uuid)
                continue
            if for_briefing:
                keep_open_for = "the daily briefing"
            elif event.uuid in advised:
                keep_open_for = "its advisory"
            elif event.uuid in matched:
                keep_open_for = "its PIR/GIR match"
            else:
                keep_open_for = ""
            try:
                result = process_flash_intel(sources[event.uuid], misp_webapp, event, focus_points,
                                             keep_open_for=keep_open_for)
                outcome = result["outcome"]
                counts[outcome] = counts.get(outcome, 0) + 1

                log_event(
                    event_uuid=event.uuid,
                    event_info=event.info,
                    source_feed=result.get("source_feed", "unknown"),
                    outcome=outcome,
                    detail=result.get("detail"),
                )

                # Drafts now require manual review/approval in the webapp. The
                # Mattermost alert is sent from the approval endpoint, not here.

            except Exception as e:
                logger.error("Failed to process event %s: %s", event.uuid, e)
                counts["error"] = counts.get("error", 0) + 1
                log_event(
                    event_uuid=event.uuid,
                    event_info=getattr(event, "info", ""),
                    source_feed="unknown",
                    outcome="error",
                    detail=f"{type(e).__name__}: {e}",
                )

        # Advance the timestamp so events are not reprocessed on the next run,
        # even if some failed. Errored events are visible in the DB log. Never
        # after a run that read no scraper: the watermark is a queue pointer, so
        # moving it over a window nothing was read from skips it for good.
        if misp is not None:
            save_last_run(read_at)

        run_scheduled_actions([a for a in due if a == "daily-briefing"], now)

        # Cached indicator feeds are re-run here rather than on a timer of their
        # own: this run is already the scheduled MISP work of the application.
        # Missing it only means the next consumer of a stale feed waits for the
        # query, which is what an uncached feed does anyway.
        feeds_refreshed = feed_cache.refresh_due()

        result = {
            "total_events": len(events),
            "product_created": counts.get("product_created", 0),
            "not_relevant": counts.get("not_relevant", 0),
            "http_error": counts.get("http_error", 0),
            "no_content": counts.get("no_content", 0),
            "error": counts.get("error", 0),
            "feed_caches_refreshed": feeds_refreshed,
        }
        log_pipeline_run_end(run_id, "completed", result)
        if job:
            job_store.update_job(
                job["id"], status="completed", result=result,
                message=(f"{len(events)} event(s): {counts.get('product_created', 0)} product(s), "
                         f"{counts.get('not_relevant', 0)} not relevant, {counts.get('error', 0)} error(s)"),
            )
    except Exception as exc:
        # Only this process can close its own run row and job entry. Without
        # this both keep saying "running" long after it is gone, and the web app
        # has no way of telling that from a run that is genuinely still going.
        log_pipeline_run_end(run_id, "failed")
        if job:
            job_store.update_job(job["id"], status="failed", error=str(exc),
                                 message=f"Failed: {exc}")
        raise
    logger.info(
        "Analyser complete: %d events - %d products, %d not relevant, %d HTTP errors, "
        "%d no content, %d errors, %d feed cache(s) refreshed",
        len(events),
        counts.get("product_created", 0),
        counts.get("not_relevant", 0),
        counts.get("http_error", 0),
        counts.get("no_content", 0),
        counts.get("error", 0),
        feeds_refreshed,
    )


if __name__ == "__main__":
    main()
