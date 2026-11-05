"""The day the scheduled briefing was last made, and an event's reports."""

import json
import logging
from pathlib import Path

import config
from core.atomic_write import write_atomically

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
    # Written from the analyser and read from the web app, separate processes,
    # so a half-written file must never be what the other one reads.
    write_atomically(path, json.dumps(state))


def load_last_briefing() -> str | None:
    """The day (UTC, ISO) the scheduled analyser last made a daily briefing."""
    return _load_state().get("analyser_last_briefing")


def save_last_briefing(day: str) -> None:
    state = _load_state()
    state["analyser_last_briefing"] = day
    _save_state(state)


def read_event_reports(misp, event) -> list:
    """The reports of an event. A failed request raises: read as an event
    without reports, it would be rejected for having no content."""
    reports = misp.get_event_reports(event.id, pythonify=True)
    if isinstance(reports, dict):
        raise RuntimeError(f"MISP report request failed: {reports.get('errors') or reports}")
    return reports
