import logging
from datetime import datetime, timezone

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.logging_setup import setup_logging
from analyser import run_lock
from analyser.reader import load_last_briefing, save_last_briefing
from core.db import init_db, log_pipeline_run_start, log_pipeline_run_end
from webapp import analyser_pipeline, audit, feed_cache, job_store, misp_store

logger = logging.getLogger(__name__)


def scheduled_actions(now: datetime) -> list[str]:
    """The analyser actions this run makes, switched on under Settings >
    Analyser, in their order: the advisories, then the alerts, then once a day,
    from its hour on, the briefing, which closes the events no product wants.
    A draft made from the dashboard earlier that day gets the events since
    added to it; a day whose briefing is published gets none."""
    actions = []
    if getattr(config, "ANALYSER_VULNERABILITY_ADVISORIES", False):
        actions.append("vea")
    if getattr(config, "ANALYSER_FLASH_INTEL", True):
        actions.append("flash-intel")
    today = now.date().isoformat()
    if (getattr(config, "ANALYSER_DAILY_BRIEFING", False)
            and now.hour >= getattr(config, "ANALYSER_DAILY_BRIEFING_HOUR", 21)
            and load_last_briefing() != today):
        try:
            briefings = analyser_pipeline.todays_briefings()
        except Exception as exc:
            # The other actions still go; the next run tries the briefing again.
            logger.warning("Could not read today's briefings, no briefing this run: %s", exc)
        else:
            if any(b.review_state == misp_store.BRIEFING_REVIEW_PUBLISHED for b in briefings):
                # Sent already: the day's later events wait for tomorrow's.
                save_last_briefing(today)
            else:
                actions.append("daily-briefing")
    return actions


def run_scheduled_actions(actions: list[str], now: datetime, lock_token: str = "") -> dict:
    """Run these actions, and return the result of each that went through.

    Each reads what changed on every source since its previous completed run,
    from the schedule or from the dashboard alike (analyser.sources).
    """
    results = {}
    for action in actions:
        label = analyser_pipeline.ACTION_LABELS[action]
        job = job_store.create_job(action, label=f"Scheduled {label.lower()}",
                                   steps=analyser_pipeline.action_steps(action))
        result = analyser_pipeline.run_action(job["id"], "analyser", triggered_by="schedule", lock_token=lock_token)
        if result is None:
            continue
        results[action] = result
        logger.info("Scheduled %s: %s", label.lower(), result.get("message", ""))
        # A source that could not be read, or an event left for the next run
        # as when the model could not be reached, keeps the day open: the next
        # run adds them to the draft once they are back.
        if action == "daily-briefing" and not result.get("errors") and not result.get("retried"):
            save_last_briefing(now.date().isoformat())
    return results


def main() -> None:
    setup_logging()
    logger.info("Analyser started")

    init_db()
    # The scheduled actions write to the audit log, and the runs prune it.
    audit.init()
    token, busy = run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
    if busy:
        # The run going on is from the dashboard, or a scheduled one that is
        # taking longer than the interval. The watermarks give this hour's
        # events to the next run.
        logger.info("Analyser run skipped: %s is still going", run_lock.describe(busy))
        feed_cache.refresh_due()
        return
    try:
        _run(token)
    finally:
        run_lock.release(token)


def _run(token: str) -> None:
    run_id = log_pipeline_run_start("analyser", triggered_by="cli")
    now = datetime.now(timezone.utc)
    try:
        results = run_scheduled_actions(scheduled_actions(now), now, token)
        # Cached indicator feeds are re-run here rather than on a timer of their
        # own: this run is already the scheduled MISP work of the application.
        # Missing it only means the next consumer of a stale feed waits for the
        # query, which is what an uncached feed does anyway.
        feeds_refreshed = feed_cache.refresh_due()
    except Exception:
        # Only this process can close its own run row. Without this it keeps
        # saying "running" long after the process is gone.
        log_pipeline_run_end(run_id, "failed")
        raise
    # The Pipeline page shows the message of a run.
    message = "; ".join(f"{analyser_pipeline.ACTION_LABELS[action]}: {result.get('message', '')}"
                        for action, result in results.items()) or "No action due"
    log_pipeline_run_end(run_id, "completed", {"message": message, "feed_caches_refreshed": feeds_refreshed})
    logger.info("Analyser complete: %s; %d feed cache(s) refreshed", message, feeds_refreshed)


if __name__ == "__main__":
    main()
