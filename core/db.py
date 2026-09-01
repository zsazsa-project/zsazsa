import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import config

logger = logging.getLogger(__name__)


@contextmanager
def connection(row_factory=None):
    """Yield a SQLite connection that commits on success and always closes.

    The inner ``with conn`` handles the transaction (commit/rollback); the
    ``finally`` guarantees the connection and its file handle are released.
    """
    conn = sqlite3.connect(config.DB_FILE)
    if row_factory is not None:
        conn.row_factory = row_factory
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def row_connection():
    """connection() with rows returned as sqlite3.Row mappings.

    The webapp's small stores (audit, orgs, SSO users, indicator metadata) all
    read by column name, so they share this rather than each opening their own.
    """
    return connection(sqlite3.Row)


# Kept as the internal name this module already uses throughout.
_connect = connection


def _ensure_columns(conn, table: str, columns: list[tuple[str, str]]) -> None:
    """Add any schema columns missing from an existing table (forward migration only)."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    for col_name, col_def in columns:
        if col_name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
            logger.info("DB migrated: added column %s.%s", table, col_name)


def init_db() -> None:
    Path(config.DB_FILE).parent.mkdir(exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS event_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_uuid   TEXT NOT NULL,
                event_info   TEXT,
                source_feed  TEXT,
                outcome      TEXT,
                detail       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_usage (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                called_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
                feature          TEXT NOT NULL,
                provider         TEXT NOT NULL DEFAULT 'openai',
                model            TEXT NOT NULL,
                input_tokens     INTEGER NOT NULL DEFAULT 0,
                output_tokens    INTEGER NOT NULL DEFAULT 0,
                total_tokens     INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_run_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
                finished_at  TEXT,
                action       TEXT NOT NULL,
                triggered_by TEXT NOT NULL DEFAULT 'dashboard',
                status       TEXT NOT NULL DEFAULT 'running',
                result_json  TEXT
            )
        """)
        # The pipeline page reads this table newest first, page by page.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_log_processed_at"
            " ON event_log (processed_at DESC, id DESC)"
        )
        # Forward migration: add any columns introduced after initial deployment.
        _ensure_columns(conn, "event_log", [
            ("event_uuid", "TEXT NOT NULL DEFAULT ''"),
            ("event_info", "TEXT"),
            ("source_feed", "TEXT"),
            ("outcome", "TEXT"),
            ("detail", "TEXT"),
        ])
        _ensure_columns(conn, "llm_usage", [
            ("feature", "TEXT NOT NULL DEFAULT ''"),
            # Rows written before local LLM support all came from OpenAI.
            ("provider", "TEXT NOT NULL DEFAULT 'openai'"),
            ("model", "TEXT NOT NULL DEFAULT ''"),
            ("input_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("output_tokens", "INTEGER NOT NULL DEFAULT 0"),
            ("total_tokens", "INTEGER NOT NULL DEFAULT 0"),
        ])


def log_llm_usage(feature: str, model: str, input_tokens: int, output_tokens: int, total_tokens: int,
                  provider: str = "openai") -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO llm_usage (feature, provider, model, input_tokens, output_tokens, total_tokens)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (feature, provider, model, input_tokens, output_tokens, total_tokens),
            )
    except sqlite3.Error as e:
        logger.error("DB write failed for llm_usage: %s", e)


def log_event(event_uuid: str, event_info: str, source_feed: str, outcome: str, detail: str | None = None) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO event_log (event_uuid, event_info, source_feed, outcome, detail) VALUES (?, ?, ?, ?, ?)",
                (event_uuid, event_info, source_feed, outcome, detail),
            )
    except sqlite3.Error as e:
        logger.error("DB write failed for %s: %s", event_uuid, e)


def log_pipeline_run_start(action: str, triggered_by: str = "dashboard") -> int:
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO pipeline_run_log (action, triggered_by) VALUES (?, ?)",
                (action, triggered_by),
            )
            return cur.lastrowid
    except sqlite3.Error as e:
        logger.error("DB write failed for pipeline_run_log: %s", e)
        return 0


def log_pipeline_run_end(run_id: int, status: str, result: dict | None = None) -> None:
    if not run_id:
        return
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE pipeline_run_log"
                " SET finished_at = strftime('%Y-%m-%dT%H:%M:%S', 'now'), status = ?, result_json = ?"
                " WHERE id = ?",
                (status, json.dumps(result) if result else None, run_id),
            )
    except sqlite3.Error as e:
        logger.error("DB write failed for pipeline_run_log end: %s", e)
    _prune_logs()


def _prune_logs() -> None:
    event_days = getattr(config, "EVENT_LOG_RETENTION_DAYS", 90)
    run_days = getattr(config, "PIPELINE_RUN_LOG_RETENTION_DAYS", 365)
    try:
        with _connect() as conn:
            conn.execute(
                "DELETE FROM event_log WHERE processed_at < datetime('now', ?)",
                (f"-{event_days} days",),
            )
            conn.execute(
                "DELETE FROM pipeline_run_log WHERE started_at < datetime('now', ?)",
                (f"-{run_days} days",),
            )
    except sqlite3.Error as e:
        logger.warning("Log pruning failed: %s", e)


def _parse_result_json(r: dict) -> None:
    """Pop and parse ``result_json`` into ``r["result"]``, in place.

    A corrupted row should degrade to ``result=None`` rather than crash the
    caller, since one bad row shouldn't take down the whole listing.
    """
    result_json = r.pop("result_json", None)
    try:
        r["result"] = json.loads(result_json) if result_json else None
    except json.JSONDecodeError as e:
        logger.error("Corrupt result_json for pipeline_run_log id=%s: %s", r.get("id"), e)
        r["result"] = None


def get_latest_pipeline_run(action: str) -> dict | None:
    """Return the most recent run of the given action, with its parsed result."""
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, started_at, finished_at, action, triggered_by, status, result_json"
                " FROM pipeline_run_log WHERE action = ? ORDER BY id DESC LIMIT 1",
                (action,),
            ).fetchone()
        if not row:
            return None
        r = dict(row)
        _parse_result_json(r)
        return r
    except sqlite3.Error as e:
        logger.error("DB read failed for pipeline_run_log: %s", e)
        return None


def get_recent_pipeline_runs(limit: int = 20) -> list[dict]:
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, started_at, finished_at, action, triggered_by, status, result_json"
                " FROM pipeline_run_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            _parse_result_json(r)
            if r.get("started_at") and r.get("finished_at"):
                try:
                    start = datetime.fromisoformat(r["started_at"])
                    end = datetime.fromisoformat(r["finished_at"])
                    secs = int((end - start).total_seconds())
                    # Runs do cross the hour, and a few have crossed the day,
                    # where minutes-only reads as noise ("1292m 22s").
                    if secs >= 3600:
                        r["duration"] = f"{secs // 3600}h {secs % 3600 // 60}m"
                    elif secs >= 60:
                        r["duration"] = f"{secs // 60}m {secs % 60}s"
                    else:
                        r["duration"] = f"{secs}s"
                except Exception:
                    r["duration"] = None
            else:
                r["duration"] = None
            result.append(r)
        return result
    except sqlite3.Error as e:
        logger.error("DB read failed for pipeline_run_log: %s", e)
        return []


