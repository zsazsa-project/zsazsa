import json
import logging
import time
from pathlib import Path

import config
from core.atomic_write import write_atomically
from webapp.misp_store import TAG_MANUAL_ENTRY, live_reports

logger = logging.getLogger(__name__)


def _load_state() -> dict:
    path = Path(config.STATE_FILE)
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("State file unreadable, starting fresh")
        return {}


def _save_state(state: dict) -> None:
    path = Path(config.STATE_FILE)
    path.parent.mkdir(exist_ok=True)
    # The analyser and the web app each keep their own key in here, from
    # separate processes, so a half-written file loses one of them.
    write_atomically(path, json.dumps(state))


def load_last_run() -> int | None:
    return _load_state().get("analyser_last_run")


def save_last_run(timestamp: int) -> None:
    """Advance the analyser's watermark. Only the analyser run may call this.

    get_new_scraper_events() asks MISP for events changed since this timestamp,
    so it is a queue pointer, not a clock: anything published before it and not
    yet processed is skipped for good. Something that merely wants to say "the
    pipeline ran just now" wants save_last_action().
    """
    state = _load_state()
    state["analyser_last_run"] = timestamp
    _save_state(state)


def load_last_briefing() -> str | None:
    """The day (UTC, ISO) the scheduled analyser last made a daily briefing."""
    return _load_state().get("analyser_last_briefing")


def save_last_briefing(day: str) -> None:
    state = _load_state()
    state["analyser_last_briefing"] = day
    _save_state(state)


def load_last_action() -> int | None:
    return _load_state().get("pipeline_last_action")


def save_last_action(timestamp: int) -> None:
    """Record that a dashboard analyser action finished, for display only.

    The dashboard actions read today's incomplete events themselves and cover a
    different set than the analyser run does, so this is kept apart from the
    watermark above.
    """
    state = _load_state()
    state["pipeline_last_action"] = timestamp
    _save_state(state)


def get_new_scraper_events(misp) -> list:
    events = _new_incomplete_events(misp, config.SCRAPER_MARKER_TAG)
    logger.info("Found %d scraper events to process", len(events))
    return events


def get_new_manual_entries(misp) -> list:
    """The manual collection entries of the same window that have a report.

    They are kept on the webapp MISP, so ``misp`` is that one. An entry without
    a report has nothing for the model to read and is left for the analyst.
    """
    entries = [e for e in _new_incomplete_events(misp, TAG_MANUAL_ENTRY) if live_reports(e)]
    logger.info("Found %d manual entries to process", len(entries))
    return entries


def read_event_reports(misp, event) -> list:
    """The reports of an event. A failed request raises: read as an event
    without reports, it would be rejected for having no content."""
    reports = misp.get_event_reports(event.id, pythonify=True)
    if isinstance(reports, dict):
        raise RuntimeError(f"MISP report request failed: {reports.get('errors') or reports}")
    return reports


def _new_incomplete_events(misp, marker_tag) -> list:
    last_run = load_last_run()
    lookback = int(time.time()) - (config.POLL_WINDOW_HOURS * 3600)
    since = max(last_run, lookback) if last_run else lookback

    # MISP REST treats multi-tag filters as OR. Search by the marker only,
    # then keep events that also carry workflow:state="incomplete".
    #
    # Every page, not just the first: the run moves the watermark past
    # everything changed before it started, so an event left on page two is
    # never asked for again. Events already complete still have the marker
    # and fill pages too.
    limit = getattr(config, "MISP_SCRAPER_LIMIT", 500)
    events, page = [], 1
    while True:
        batch = misp.search(
            tags=[marker_tag],
            timestamp=since,
            limit=limit,
            page=page,
            pythonify=True,
        )
        if isinstance(batch, dict) and "errors" in batch:
            # Raised rather than read as "nothing new": an empty result lets
            # the run advance the watermark over a window it never read.
            raise RuntimeError(f"MISP search failed: {batch['errors']}")
        batch = batch or []
        events.extend(batch)
        if not limit or len(batch) < limit:
            break
        page += 1

    needed = 'workflow:state="incomplete"'
    return [
        e for e in events
        if any(getattr(t, "name", "") == needed for t in (getattr(e, "tags", []) or []))
    ]
