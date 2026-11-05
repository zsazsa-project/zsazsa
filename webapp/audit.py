import os
from datetime import datetime, timezone

import config
from core.db import row_connection as _conn
from webapp import misp_session


def init():
    os.makedirs(os.path.dirname(config.DB_FILE) or ".", exist_ok=True)
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT,
                entity_label TEXT,
                details TEXT
            )
        """)


def record(action, entity_type, entity_id=None, entity_label=None, details=None, user=None):
    """Write one audit entry.

    ``user`` is for work that runs on a background thread, where there is no
    request to read the signed-in analyst from: the caller reads it while still
    handling the request and passes it in, otherwise the entry would be filed
    under the fallback account.
    """
    with _conn() as db:
        db.execute(
            "INSERT INTO audit_log "
            "(timestamp, user, action, entity_type, entity_id, entity_label, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                # Text column, compared against rows already written, so keep the format.
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                user or misp_session.current_user_email(),
                action,
                entity_type,
                entity_id,
                entity_label,
                details,
            ),
        )


def _where(action=None, entity_type=None, user=None, day=None) -> tuple[str, list]:
    """The WHERE clause of the log page's filters, and its arguments. ``day``
    is a date, YYYY-MM-DD, as the timestamps start with."""
    clauses, args = [], []
    for column, value in (("action", action), ("entity_type", entity_type), ("user", user)):
        if value:
            clauses.append(f"{column} = ?")
            args.append(value)
    if day:
        clauses.append("timestamp LIKE ?")
        args.append(f"{day}%")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def get_logs(limit=200, action=None, entity_type=None, user=None, day=None):
    where, args = _where(action, entity_type, user, day)
    with _conn() as db:
        return db.execute(f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()


def activity(since: str, action=None, entity_type=None, user=None) -> dict:
    """How busy the log has been under these filters: the entries in all, those
    from ``since`` on (a date) per day, and who, what and on what type they
    were, most first."""
    where, args = _where(action, entity_type, user)
    recent = f"{where} {'AND' if where else 'WHERE'} timestamp >= ?"
    with _conn() as db:
        total = db.execute(f"SELECT COUNT(*) FROM audit_log{where}", args).fetchone()[0]
        per_day = {r[0]: r[1] for r in db.execute(
            f"SELECT substr(timestamp, 1, 10) AS day, COUNT(*) FROM audit_log{recent} GROUP BY day", (*args, since))}
        ranked = {column: [tuple(r) for r in db.execute(
            f"SELECT {column}, COUNT(*) AS n FROM audit_log{recent} GROUP BY {column} ORDER BY n DESC",
            (*args, since))] for column in ("user", "action", "entity_type")}
    return {"total": total, "per_day": per_day, **ranked}


def log_filters():
    with _conn() as db:
        return {name: [r[0] for r in db.execute(f"SELECT DISTINCT {column} FROM audit_log ORDER BY {column}")]
                for name, column in (("actions", "action"), ("types", "entity_type"), ("users", "user"))}


def has_event(action, entity_type, entity_id=None, details_contains=None):
    """Return True if at least one matching audit event exists."""
    with _conn() as db:
        query = [
            "SELECT 1 FROM audit_log",
            "WHERE action = ? AND entity_type = ?",
        ]
        args = [action, entity_type]

        if entity_id is not None:
            query.append("AND entity_id = ?")
            args.append(entity_id)
        if details_contains:
            query.append("AND details LIKE ?")
            args.append(f"%{details_contains}%")

        query.append("LIMIT 1")
        row = db.execute(" ".join(query), tuple(args)).fetchone()
        return row is not None


def latest_event(action, entity_type, entity_id=None):
    """Return the latest matching audit row, or None."""
    with _conn() as db:
        query = [
            "SELECT * FROM audit_log",
            "WHERE action = ? AND entity_type = ?",
        ]
        args = [action, entity_type]
        if entity_id is not None:
            query.append("AND entity_id = ?")
            args.append(entity_id)
        query.append("ORDER BY id DESC LIMIT 1")
        return db.execute(" ".join(query), tuple(args)).fetchone()


def latest_notify_status(entity_type, entity_id):
    """Summarise the most recent 'notify' audit event for an entity as a badge.

    Shared by the product detail pages (briefing, flash intel, VEA), which all
    record delivery results in the same `result=ok|failed` / skipped form.
    Returns {"tone", "label", "timestamp", "details"} or None.
    """
    row = latest_event("notify", entity_type, entity_id=entity_id)
    if row is None:
        return None
    details = row["details"] or ""
    lower = details.lower()
    if "result=ok" in lower or lower.startswith("ok"):
        tone, label = "success", "Delivered"
    elif "skip" in lower:
        tone, label = "warning", "Skipped"
    elif "fail" in lower:
        tone, label = "danger", "Failed"
    else:
        tone, label = "secondary", "Unknown"
    return {"tone": tone, "label": label, "timestamp": row["timestamp"], "details": details}
