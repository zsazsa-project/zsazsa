import logging
import time
import warnings

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.logging_setup import setup_logging
from analyser.products.flash_intel import process as process_flash_intel
from analyser.reader import get_new_scraper_events, save_last_run
from core.db import init_db, log_event, log_pipeline_run_start, log_pipeline_run_end
from core.misp_client import get_misp, get_misp_webapp
from webapp import job_store




def load_focus_points() -> dict:
    return {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }


def main() -> None:
    setup_logging()
    logger = logging.getLogger(__name__)
    run_start = int(time.time())
    logger.info("Analyser started")

    init_db()
    run_id = log_pipeline_run_start("analyser", triggered_by="cli")

    try:
        misp = get_misp()
        misp_webapp = get_misp_webapp()
        focus_points = load_focus_points()
        events = get_new_scraper_events(misp)
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

    for position, event in enumerate(events, start=1):
        job_store.update_job(job["id"], message=f"Event {position} of {len(events)}: {event.info or event.uuid[:8]}")
        try:
            result = process_flash_intel(misp, misp_webapp, event, focus_points)
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

    # Advance the timestamp unconditionally so events are not reprocessed on
    # the next run, even if some failed. Errored events are visible in the DB log.
    save_last_run(run_start)
    result = {
        "total_events": len(events),
        "product_created": counts.get("product_created", 0),
        "not_relevant": counts.get("not_relevant", 0),
        "http_error": counts.get("http_error", 0),
        "no_content": counts.get("no_content", 0),
        "error": counts.get("error", 0),
    }
    log_pipeline_run_end(run_id, "completed", result)
    if job:
        job_store.update_job(
            job["id"], status="completed", result=result,
            message=(f"{len(events)} event(s): {counts.get('product_created', 0)} product(s), "
                     f"{counts.get('not_relevant', 0)} not relevant, {counts.get('error', 0)} error(s)"),
        )
    logger.info(
        "Analyser complete: %d events - %d products, %d not relevant, %d HTTP errors, %d no content, %d errors",
        len(events),
        counts.get("product_created", 0),
        counts.get("not_relevant", 0),
        counts.get("http_error", 0),
        counts.get("no_content", 0),
        counts.get("error", 0),
    )


if __name__ == "__main__":
    main()
