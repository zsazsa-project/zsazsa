"""What the analyser decided about a source event, kept in zsazsa.

Per event, by its source and uuid, the analysed_events table holds:

- the relevance verdict (analyser.relevance), reused by every run until the
  settings it was judged under change;
- how often the relevance answer could not be read since;
- the outcome per product where the products do not say it themselves, such
  as the CVEs the advisory steps found no advisory for, or a story told
  before, with a fingerprint of the evidence it was decided on, as it holds
  only while that does;
- for an event on another organisation's MISP server, whether the analyser
  closed it. That event is not zsazsa's to change, so this is where its
  rejection goes; on zsazsa's own MISP it is the event's workflow state;
- when an analyst last scored it on the data collection page.

analyser_read_again holds the events an action is to read once more, as those
of a deleted product.

Losing the table loses no intelligence: the products are in MISP. It costs a
model call for every event read again, and the events of other servers that
were closed would be proposed again.
"""

import json
import logging
import time

from analyser import tagger
from core.db import row_connection

logger = logging.getLogger(__name__)


def reject(event, source, reason: str = "") -> bool:
    """Take an event out of the analysis, on whichever MISP it is. False when
    MISP refused the change, so the event is still open there."""
    if source.own:
        return tagger.set_workflow_state(source.client, event, "rejected")
    close(source.id, event.uuid, reason)
    return True


def close(source_id: str, event_uuid: str, reason: str = "") -> None:
    """Record that an event on another MISP server is done with."""
    _write(source_id, event_uuid, closed_at=int(time.time()), reason=reason)
    logger.info("Event %s on %s closed: %s", event_uuid, source_id, reason or "no reason given")


def reopen(source_id: str, event_uuid: str) -> None:
    """Open an event on another MISP server again, for the analyser to read."""
    with row_connection() as conn:
        conn.execute("UPDATE analysed_events SET closed_at = NULL, reason = '' WHERE source_id = ? AND event_uuid = ?",
                     (source_id, event_uuid))


def scored_by_analyst(source_id: str, event_uuid: str) -> None:
    """Record that an analyst changed an event's scores just now. A run that
    read the event before then reads it again, rather than take the change for
    one of its own writes."""
    _write(source_id, event_uuid, analyst_changed_at=int(time.time()))


def scored_by_analyst_since(source_id: str, since: int) -> set[str]:
    """The events of a source an analyst scored from ``since`` on."""
    with row_connection() as conn:
        rows = conn.execute("SELECT event_uuid FROM analysed_events WHERE source_id = ? AND analyst_changed_at >= ?",
                            (source_id, since)).fetchall()
    return {row["event_uuid"] for row in rows}


def closed(source_id: str) -> set[str]:
    """The events of another MISP server the analyser has closed."""
    with row_connection() as conn:
        rows = conn.execute("SELECT event_uuid FROM analysed_events WHERE source_id = ? AND closed_at IS NOT NULL",
                            (source_id,)).fetchall()
    return {row["event_uuid"] for row in rows}


def judged(source_id: str) -> set[str]:
    """The events of a source that have a relevance verdict."""
    with row_connection() as conn:
        rows = conn.execute("SELECT event_uuid FROM analysed_events WHERE source_id = ? AND verdict IS NOT NULL",
                            (source_id,)).fetchall()
    return {row["event_uuid"] for row in rows}


def load(source_id: str, event_uuid: str) -> dict:
    """{"verdict": dict or None, "attempts": int, "outcomes": {product: outcome}}."""
    with row_connection() as conn:
        row = conn.execute("SELECT verdict, attempts, outcomes FROM analysed_events"
                           " WHERE source_id = ? AND event_uuid = ?", (source_id, event_uuid)).fetchone()
    if row is None:
        return {"verdict": None, "attempts": 0, "outcomes": {}}
    return {"verdict": json.loads(row["verdict"]) if row["verdict"] else None,
            "attempts": row["attempts"], "outcomes": json.loads(row["outcomes"])}


def save_verdict(source_id: str, event_uuid: str, verdict: dict) -> None:
    _write(source_id, event_uuid, verdict=json.dumps(verdict), attempts=0)


def count_failed_attempt(source_id: str, event_uuid: str) -> int:
    """Count one more relevance answer that could not be read, and return how
    many there have been since the last verdict."""
    attempts = load(source_id, event_uuid)["attempts"] + 1
    _write(source_id, event_uuid, attempts=attempts)
    return attempts


def save_outcome(source_id: str, event_uuid: str, product: str, outcome: str, decided_on: str = "") -> None:
    """What became of an event for one product ("vea", "flash-intel",
    "daily-briefing"), and ``decided_on``, a fingerprint of what that was
    decided on, such as the event's evidence."""
    outcomes = load(source_id, event_uuid)["outcomes"]
    entry = {"outcome": outcome, "decided_on": decided_on}
    if outcomes.get(product) != entry:
        outcomes[product] = entry
        _write(source_id, event_uuid, outcomes=json.dumps(outcomes))


def outcome(state: dict, product: str, decided_on: str) -> str:
    """The outcome in a loaded state for one product, or "" when there is none
    or it was decided on something other than ``decided_on``."""
    entry = state["outcomes"].get(product) or {}
    return entry.get("outcome", "") if entry.get("decided_on") == decided_on else ""


def source_of(hint: str) -> str:
    """The analyser's id of the source a product or a page names for an event:
    every manual source is one, the manual entries on zsazsa's MISP, and a
    product from before the hint was kept got its events from the scraper."""
    if hint == "webapp" or hint.startswith("manual-"):
        return "manual"
    return hint or "scraper"


def read_again(source_id: str, event_uuid: str, action: str) -> None:
    """Have the next run of an action read this event, as after its product was
    deleted. The tag that comes off is local, which does not change the event in
    MISP, so its watermark alone would pass it by."""
    with row_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO analyser_read_again (action, source_id, event_uuid) VALUES (?, ?, ?)",
                     (action, source_id, event_uuid))


def to_read_again(source_id: str, action: str) -> set[str]:
    with row_connection() as conn:
        rows = conn.execute("SELECT event_uuid FROM analyser_read_again WHERE action = ? AND source_id = ?",
                            (action, source_id)).fetchall()
    return {row["event_uuid"] for row in rows}


def read_again_done(source_id: str, action: str, event_uuids: set[str]) -> None:
    with row_connection() as conn:
        conn.executemany("DELETE FROM analyser_read_again WHERE action = ? AND source_id = ? AND event_uuid = ?",
                         [(action, source_id, uuid) for uuid in event_uuids])


def _write(source_id: str, event_uuid: str, **columns) -> None:
    # The column names are this module's own, never a caller's input.
    names = ", ".join(columns)
    updates = ", ".join(f"{name} = excluded.{name}" for name in columns)
    with row_connection() as conn:
        conn.execute(
            f"INSERT INTO analysed_events (source_id, event_uuid, {names}, updated_at)"
            f" VALUES (?, ?, {', '.join('?' * len(columns))}, ?)"
            f" ON CONFLICT(source_id, event_uuid) DO UPDATE SET {updates}, updated_at = excluded.updated_at",
            (source_id, event_uuid, *columns.values(), int(time.time())),
        )
