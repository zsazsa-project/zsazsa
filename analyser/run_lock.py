"""One analyser run at a time, whichever process starts it.

cron runs the analyser in a process of its own, and the dashboard in a thread of
the web app. Both write workflow states and products for the same events, and
neither sees what the other is about to make, so a run started while another is
going does not start: the dashboard says who has the lock, and a scheduled run
skips that hour, whose events the watermarks then give to the next one.

The lock is a row in the SQLite database both processes share, in Docker too. A
holder refreshes it at every step it reports. One that stops, because its
process died, loses it once it has been quiet for an hour, which is longer than
a model call can take. A run that finds it has lost the lock all the same, as
after its process was suspended for that long, stops at its next step rather
than go on beside the next one.
"""

import time
from uuid import uuid4

from core.db import row_connection

_NAME = "analyser"
QUIET_AFTER_SECONDS = 3600


class Lost(RuntimeError):
    """The run's lock went to another run while it was going."""


def acquire(action: str, label: str, started_by: str, job_id: str = "") -> tuple[str | None, dict | None]:
    """Take the lock for a run. Returns (token, None), or (None, holder) when
    another run has it. The token is what refresh() and release() take."""
    token = uuid4().hex
    now = int(time.time())
    with row_connection() as conn:
        # One statement, so two processes asking at once cannot both get it: a
        # row that is there stays unless its holder has gone quiet.
        conn.execute(
            "INSERT INTO analyser_lock"
            " (name, token, action, label, started_by, job_id, started_at, refreshed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET token = excluded.token, action = excluded.action,"
            " label = excluded.label, started_by = excluded.started_by, job_id = excluded.job_id,"
            " started_at = excluded.started_at, refreshed_at = excluded.refreshed_at"
            " WHERE analyser_lock.refreshed_at < ?",
            (_NAME, token, action, label, started_by, job_id, now, now, now - QUIET_AFTER_SECONDS),
        )
        row = conn.execute("SELECT * FROM analyser_lock WHERE name = ?", (_NAME,)).fetchone()
    if row["token"] == token:
        return token, None
    return None, dict(row)


def refresh(token: str) -> bool:
    """Say the run holding the lock is still going. False when it no longer
    holds it. A run without a token, as in a test, holds nothing to lose."""
    if not token:
        return True
    with row_connection() as conn:
        changed = conn.execute("UPDATE analyser_lock SET refreshed_at = ? WHERE name = ? AND token = ?",
                               (int(time.time()), _NAME, token)).rowcount
    return changed == 1


def release(token: str) -> None:
    """Give the lock up. A token that no longer holds it changes nothing."""
    if not token:
        return
    with row_connection() as conn:
        conn.execute("DELETE FROM analyser_lock WHERE name = ? AND token = ?", (_NAME, token))


def holder() -> dict | None:
    """The run that has the lock, or None when the analyser is free."""
    with row_connection() as conn:
        row = conn.execute("SELECT * FROM analyser_lock WHERE name = ? AND refreshed_at >= ?",
                           (_NAME, int(time.time()) - QUIET_AFTER_SECONDS)).fetchone()
    return dict(row) if row else None


def describe(lock: dict) -> str:
    """A holder as the dashboard and the log say it: what, who, since when."""
    started = time.strftime("%H:%M UTC", time.gmtime(lock.get("started_at") or 0))
    who = lock.get("started_by") or "unknown"
    return f"{lock.get('label') or lock.get('action')}, started at {started} by {who}"
