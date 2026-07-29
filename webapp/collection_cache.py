"""Background event cache for the data-collection page.

Fetches events from all configured MISP sources on a periodic schedule and
stores them in data/collection_cache.db (SQLite), so /collection/ loads from
the local cache instead of waiting for live MISP queries.

Usage:
    from webapp import collection_cache
    collection_cache.start_worker()   # called once in create_app()
    collection_cache.trigger_refresh()  # wake the worker immediately
    events = collection_cache.get_events(source_ids, tag_filters, limit)
    status = collection_cache.get_source_status()
"""

import datetime as _dt
import json
import logging
import re
import sqlite3
import threading
import time
from contextlib import contextmanager

_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

import urllib3
from pymisp import PyMISP

import config

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DB_FILE = "data/collection_cache.db"
_DEFAULT_INTERVAL_S = 15 * 60  # 15 min, overridden by config.COLLECTION_CACHE_INTERVAL


@contextmanager
def _db():
    conn = sqlite3.connect(_DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


AI_SUMMARY_PREFIX = "[AI-Summary]"


def init_db():
    with _db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS source_status (
                source_id TEXT PRIMARY KEY,
                last_fetch REAL,
                error TEXT,
                event_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                source_id TEXT NOT NULL,
                uuid TEXT NOT NULL,
                event_id TEXT,
                info TEXT,
                date TEXT,
                tags TEXT,
                org TEXT,
                orgc TEXT,
                attribute_count INTEGER DEFAULT 0,
                object_count INTEGER DEFAULT 0,
                galaxy_names TEXT,
                report_count INTEGER DEFAULT 0,
                has_ai_summary INTEGER DEFAULT 0,
                fetched_at REAL,
                PRIMARY KEY (source_id, uuid)
            );
            CREATE INDEX IF NOT EXISTS events_date ON events(date DESC);
        """)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS flagged_events (
                uuid TEXT PRIMARY KEY,
                flagged_at REAL NOT NULL
            );
        """)
        # Migrations: add columns to existing databases that lack them. Only a
        # "duplicate column" error (column already present) is expected and
        # ignored; anything else (locked DB, disk error, bad DDL) is surfaced.
        for _col_ddl in [
            "ALTER TABLE events ADD COLUMN has_ai_summary INTEGER DEFAULT 0",
            "ALTER TABLE events ADD COLUMN vulnerability_ids TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(_col_ddl)
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise


def get_source_status() -> dict:
    """Return {source_id: {last_fetch, error, event_count}} from the status table.

    event_count reflects the actual current row count in the events table,
    not the stale value recorded at the last refresh.
    """
    try:
        with _db() as conn:
            rows = conn.execute("SELECT * FROM source_status").fetchall()
            counts = {r["source_id"]: r["cnt"] for r in conn.execute(
                "SELECT source_id, COUNT(*) AS cnt FROM events GROUP BY source_id"
            ).fetchall()}
        result = {}
        for r in rows:
            d = dict(r)
            d["event_count"] = counts.get(r["source_id"], 0)
            result[r["source_id"]] = d
        return result
    except Exception as exc:
        logger.warning("get_source_status failed: %s", exc)
        return {}


def get_events(source_ids: list, tag_filters: list, limit: int) -> list:
    """Return cached events for the given source IDs, applying tag filters.

    Tags are stored as a JSON array per row, so the tag filter is applied in
    Python. When filtering, all candidate rows are scanned in date order rather
    than a pre-capped slice: capping the SQL result first would silently drop
    matching events that happen to be older than the cap.
    """
    if not source_ids:
        return []
    placeholders = ",".join("?" for _ in source_ids)
    required = set(tag_filters)
    base_sql = (
        f"SELECT * FROM events WHERE source_id IN ({placeholders})"
        f" ORDER BY date DESC, fetched_at DESC"
    )
    try:
        with _db() as conn:
            if required:
                # Filtering in Python: scan everything, stop once `limit` match.
                rows = conn.execute(base_sql, source_ids).fetchall()
            else:
                # No filter: the SQL LIMIT is exact, so cap in the query.
                rows = conn.execute(base_sql + " LIMIT ?", source_ids + [limit]).fetchall()
    except Exception as exc:
        logger.warning("cache read error: %s", exc)
        return []
    result = []
    for r in rows:
        tags = json.loads(r["tags"] or "[]")
        if required and not required.issubset(set(tags)):
            continue
        result.append({
            "uuid": r["uuid"],
            "id": r["event_id"],
            "info": r["info"],
            "date": r["date"],
            "tags": tags,
            "org": r["org"],
            "orgc": r["orgc"],
            "attribute_count": r["attribute_count"],
            "object_count": r["object_count"],
            "galaxy_names": json.loads(r["galaxy_names"] or "[]"),
            "report_count": r["report_count"],
            "has_ai_summary": bool(r["has_ai_summary"]),
            "vulnerability_ids": json.loads(r["vulnerability_ids"] or "[]"),
            "source_id": r["source_id"],
            "fetched_at": r["fetched_at"],
        })
        if len(result) >= limit:
            break
    return result


def _extract_row(e, source_id: str) -> dict:
    tags = [t.name for t in getattr(e, "tags", []) or []]
    galaxies = []
    for g in getattr(e, "galaxies", []) or []:
        for cl in getattr(g, "clusters", []) or []:
            v = getattr(cl, "value", None)
            if v:
                galaxies.append(v)
    org_name = ""
    orgc_name = ""
    org_obj = getattr(e, "Org", None) or getattr(e, "org", None)
    orgc_obj = getattr(e, "Orgc", None) or getattr(e, "orgc", None)
    if org_obj:
        org_name = getattr(org_obj, "name", "") or ""
    if orgc_obj:
        orgc_name = getattr(orgc_obj, "name", "") or ""
    # An event carries its soft-deleted reports too; those are not shown anywhere,
    # so leave them out of the count and the AI-summary marker.
    reports = [r for r in (getattr(e, "event_reports", []) or []) if not getattr(r, "deleted", False)]
    has_ai = any(
        (getattr(r, "name", "") or "").startswith(AI_SUMMARY_PREFIX)
        for r in reports
    )
    vuln_ids = []
    for a in getattr(e, "attributes", []) or []:
        if getattr(a, "type", "") == "vulnerability" and getattr(a, "value", ""):
            vuln_ids.append(a.value.strip())
    for obj in getattr(e, "Object", []) or getattr(e, "objects", []) or []:
        for a in getattr(obj, "attributes", []) or []:
            if getattr(a, "type", "") == "vulnerability" and getattr(a, "value", ""):
                vuln_ids.append(a.value.strip())
    # Fall back to extracting CVE IDs from the event title when none found via attributes
    if not vuln_ids and e.info:
        vuln_ids = [m.upper() for m in _CVE_RE.findall(e.info)]
    return {
        "uuid": e.uuid,
        "event_id": str(e.id),
        "info": e.info or "",
        "date": str(e.date) if e.date else "",
        "tags": tags,
        "org": org_name,
        "orgc": orgc_name,
        "attribute_count": int(getattr(e, "attribute_count", 0) or 0),
        "object_count": len(getattr(e, "Object", []) or []),
        "galaxy_names": galaxies,
        "report_count": len(reports),
        "has_ai_summary": has_ai,
        "vulnerability_ids": list(dict.fromkeys(vuln_ids)),
        "source_id": source_id,
    }


def _split_tags(raw: str) -> list[str]:
    return [t.strip() for t in (raw or "").replace(",", " ").split() if t.strip()]


def _search_payload_error(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("errors"):
        return str(payload.get("errors"))
    if payload.get("error"):
        return str(payload.get("error"))
    if payload.get("message") and payload.get("name") == "Exception":
        return str(payload.get("message"))
    return None


def _source_slug(name: str) -> str:
    return name.lower().replace(" ", "-").replace("/", "-")


def _build_sources() -> list:
    srcs = [{"id": "scraper", "kind": "scraper", "label": "MISP scraper", "url": config.MISP_URL}]
    for s in getattr(config, "MISP_SERVERS", []) or []:
        if not s.get("enabled", True):
            continue
        sid = s.get("id") or s.get("label")
        srcs.append({
            "id": sid,
            "label": s.get("label") or sid,
            "kind": "misp",
            "url": s.get("url"),
            "api_key": s.get("api_key"),
            "verify_tls": s.get("verify_tls", True),
            "tags": _split_tags(s.get("tags", "")),
            "tags_and": _split_tags(s.get("tags_and", "")),
            "tags_not": _split_tags(s.get("tags_not", "")),
            "org_filter_type": s.get("org_filter_type", "") or "",
            "org_filter": _split_tags(s.get("org_filter", "")),
            "since_days": int(s.get("since_days") or 7),
        })
    try:
        from webapp import misp_store
        for src in misp_store.list_collection_sources():
            if not src.enabled or not (src.name or "").strip():
                continue
            slug = _source_slug(src.name)
            srcs.append({
                "id": f"manual-{slug}",
                "label": src.name,
                "kind": "manual",
                "url": config.MISP_WEBAPP_URL,
                "api_key": config.MISP_WEBAPP_KEY,
                "verify_tls": config.MISP_WEBAPP_VERIFYCERT,
                "source_tag": f'zsazsa:source="{slug}"',
            })
    except Exception as exc:
        logger.warning("collection cache: could not load manual sources: %s", exc)
    return srcs


def refresh_source(src: dict):
    source_id = src["id"]
    logger.info("collection cache: refresh start - %s", source_id)
    t0 = time.time()
    error = None
    rows = []

    if src["kind"] == "scraper":
        scraper_limit = getattr(config, "MISP_SCRAPER_LIMIT", 500)
        # Default to a 30-day window when unset; an explicit 0 disables it.
        try:
            since_days = int(getattr(config, "MISP_SCRAPER_SINCE_DAYS", 30))
        except (TypeError, ValueError):
            since_days = 30
        try:
            misp = PyMISP(config.MISP_URL, config.MISP_KEY, config.MISP_VERIFYCERT, False)
            kwargs = dict(
                tags=[config.SCRAPER_MARKER_TAG],
                limit=scraper_limit, page=1, metadata=False, pythonify=True,
            )
            # Restrict to a recent date window so growth past the limit drops the
            # oldest events rather than silently hiding the newest ones.
            if since_days > 0:
                kwargs["date_from"] = (_dt.date.today() - _dt.timedelta(days=since_days)).isoformat()
            events = misp.search(**kwargs)
            payload_err = _search_payload_error(events)
            if payload_err:
                error = payload_err
            elif events and not isinstance(events, dict):
                for e in events:
                    rows.append(_extract_row(e, source_id))
        except Exception as exc:
            error = str(exc)
            logger.warning("collection cache: scraper error - %s", exc)
    elif src["kind"] == "manual":
        if not src.get("url") or not src.get("api_key"):
            error = "No URL or API key configured"
        else:
            try:
                misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
                events = misp.search(
                    tags=['zsazsa:source-type="manual"'],
                    limit=src.get("limit") or 500, page=1, metadata=False, pythonify=True,
                )
                payload_err = _search_payload_error(events)
                if payload_err:
                    error = payload_err
                elif events and not isinstance(events, dict):
                    source_tag = src.get("source_tag", "")
                    for e in events:
                        if source_tag:
                            event_tags = [t.name for t in getattr(e, "tags", []) or []]
                            if source_tag not in event_tags:
                                continue
                        rows.append(_extract_row(e, source_id))
            except Exception as exc:
                error = str(exc)
                logger.warning("collection cache: %s error - %s", source_id, exc)
    else:
        if not src.get("url") or not src.get("api_key"):
            error = "No URL or API key configured"
        else:
            try:
                misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False)
                kwargs = dict(limit=src.get("limit") or 500, page=1, metadata=False, pythonify=True, published=True)
                tags_or = src.get("tags") or []
                tags_and = src.get("tags_and") or []
                tags_not = src.get("tags_not") or []
                if tags_and or tags_not:
                    kwargs["tags"] = misp.build_complex_query(
                        or_parameters=tags_or or None,
                        and_parameters=tags_and or None,
                        not_parameters=tags_not or None,
                    )
                elif tags_or:
                    kwargs["tags"] = tags_or
                if src.get("since_days"):
                    cutoff = (_dt.date.today() - _dt.timedelta(days=int(src["since_days"]))).isoformat()
                    kwargs["date_from"] = cutoff
                events = misp.search(**kwargs)
                payload_err = _search_payload_error(events)
                if payload_err:
                    error = payload_err
                elif events and not isinstance(events, dict):
                    org_filter_type = src.get("org_filter_type", "")
                    org_filter = {o.lower() for o in (src.get("org_filter") or [])}
                    if org_filter_type and org_filter:
                        def _event_org_uuids(e):
                            uuids = set()
                            for attr in ("Org", "org", "Orgc", "orgc"):
                                obj = getattr(e, attr, None)
                                u = (getattr(obj, "uuid", "") or "").lower()
                                if u:
                                    uuids.add(u)
                            return uuids
                        if org_filter_type == "include":
                            events = [e for e in events if _event_org_uuids(e) & org_filter]
                        elif org_filter_type == "exclude":
                            events = [e for e in events if not (_event_org_uuids(e) & org_filter)]
                    for e in events:
                        rows.append(_extract_row(e, source_id))
            except Exception as exc:
                error = str(exc)
                logger.warning("collection cache: %s error - %s", source_id, exc)

    now = time.time()
    with _db() as conn:
        if not error:
            conn.execute("DELETE FROM events WHERE source_id = ?", (source_id,))
            if rows:
                conn.executemany(
                    """INSERT OR REPLACE INTO events
                       (source_id, uuid, event_id, info, date, tags, org, orgc,
                        attribute_count, object_count, galaxy_names, report_count,
                        has_ai_summary, vulnerability_ids, fetched_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [(r["source_id"], r["uuid"], r["event_id"], r["info"], r["date"],
                      json.dumps(r["tags"]), r["org"], r["orgc"],
                      r["attribute_count"], r["object_count"],
                      json.dumps(r["galaxy_names"]), r["report_count"],
                      1 if r.get("has_ai_summary") else 0,
                      json.dumps(r.get("vulnerability_ids") or []), now)
                     for r in rows],
                )
        # event_count is intentionally not written: get_source_status computes
        # it live from the events table, so persisting a copy here would only
        # create a value that can disagree with reality (e.g. on a fetch error
        # the events rows are kept but len(rows) is 0). The column stays in the
        # schema for backwards compatibility and keeps its default.
        conn.execute(
            """INSERT OR REPLACE INTO source_status (source_id, last_fetch, error)
               VALUES (?, ?, ?)""",
            (source_id, now, error),
        )
    logger.info("collection cache: %s done - %d events in %.1fs", source_id, len(rows), time.time() - t0)


_refresh_event = threading.Event()
_worker_thread: threading.Thread | None = None


def _worker_loop(interval: int):
    for src in _build_sources():
        try:
            refresh_source(src)
        except Exception as exc:
            logger.exception("collection cache: worker error for %s: %s", src.get("id"), exc)
    while True:
        _refresh_event.wait(timeout=interval)
        _refresh_event.clear()
        for src in _build_sources():
            try:
                refresh_source(src)
            except Exception as exc:
                logger.exception("collection cache: worker error for %s: %s", src.get("id"), exc)


def start_worker(interval: int = None):
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    if interval is None:
        interval = int(getattr(config, "COLLECTION_CACHE_INTERVAL", 15)) * 60
    init_db()
    _worker_thread = threading.Thread(
        target=_worker_loop, args=(interval,), daemon=True, name="collection-cache",
    )
    _worker_thread.start()
    logger.info("collection cache worker started (interval=%ds)", interval)


def trigger_refresh() -> bool:
    """Wake the worker early to start a fresh fetch immediately.

    Returns True when the refresh signal was queued, False when the worker
    could not be started.
    """
    global _worker_thread
    if not (_worker_thread and _worker_thread.is_alive()):
        try:
            start_worker()
        except Exception as exc:
            logger.warning("collection cache: could not start worker on refresh trigger: %s", exc)
            return False
    if not (_worker_thread and _worker_thread.is_alive()):
        return False
    _refresh_event.set()
    return True


def insert_event(row: dict) -> None:
    """Insert or replace a single event row in the cache (used for manual UUID pulls)."""
    with _db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO events
               (source_id, uuid, event_id, info, date, tags, org, orgc,
                attribute_count, object_count, galaxy_names, report_count,
                has_ai_summary, vulnerability_ids, fetched_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["source_id"], row["uuid"], row.get("event_id", ""),
                row.get("info", ""), row.get("date", ""),
                json.dumps(row.get("tags", [])),
                row.get("org", ""), row.get("orgc", ""),
                row.get("attribute_count", 0), row.get("object_count", 0),
                json.dumps(row.get("galaxy_names", [])),
                row.get("report_count", 0),
                1 if row.get("has_ai_summary") else 0,
                json.dumps(row.get("vulnerability_ids") or []),
                time.time(),
            ),
        )


def get_events_by_uuids(uuids: list) -> list:
    """Return cached event rows for the given UUIDs (any source)."""
    if not uuids:
        return []
    placeholders = ",".join("?" for _ in uuids)
    try:
        with _db() as conn:
            rows = conn.execute(
                f"SELECT * FROM events WHERE uuid IN ({placeholders})",
                uuids,
            ).fetchall()
        return [
            {
                "uuid": r["uuid"],
                "id": r["event_id"],
                "info": r["info"],
                "date": r["date"],
                "tags": json.loads(r["tags"] or "[]"),
                "org": r["org"],
                "orgc": r["orgc"],
                "attribute_count": r["attribute_count"],
                "object_count": r["object_count"],
                "galaxy_names": json.loads(r["galaxy_names"] or "[]"),
                "report_count": r["report_count"],
                "has_ai_summary": bool(r["has_ai_summary"]),
                "vulnerability_ids": json.loads(r["vulnerability_ids"] or "[]"),
                "source_id": r["source_id"],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning("get_events_by_uuids error: %s", exc)
        return []


def patch_event_tags(uuid: str, add_tags: list, remove_tags: list) -> None:
    """Patch the tags column for a cached event without a MISP round-trip.

    Used when the caller knows exactly which tags were added or removed (e.g.
    after tagging a source event as a product source) and wants the queue to
    reflect the change immediately.
    """
    if not add_tags and not remove_tags:
        return
    remove_set = set(remove_tags)
    try:
        with _db() as conn:
            rows = conn.execute(
                "SELECT source_id, tags FROM events WHERE uuid = ?", (uuid,)
            ).fetchall()
            for row in rows:
                tags = json.loads(row["tags"] or "[]")
                tags = [t for t in tags if t not in remove_set]
                for t in add_tags:
                    if t not in tags:
                        tags.append(t)
                conn.execute(
                    "UPDATE events SET tags = ? WHERE uuid = ? AND source_id = ?",
                    (json.dumps(tags), uuid, row["source_id"]),
                )
    except Exception as exc:
        logger.warning("patch_event_tags failed for %s: %s", uuid, exc)


def mark_ai_summary(uuid: str, source_id: str) -> None:
    """Mark a cached event as having an AI-generated summary."""
    try:
        with _db() as conn:
            conn.execute(
                "UPDATE events SET has_ai_summary = 1, report_count = report_count + 1 WHERE uuid = ? AND source_id = ?",
                (uuid, source_id),
            )
    except Exception as exc:
        logger.warning("mark_ai_summary failed for %s: %s", uuid, exc)


def flag_event(uuid: str) -> None:
    try:
        with _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO flagged_events (uuid, flagged_at) VALUES (?, ?)",
                (uuid, time.time()),
            )
    except Exception as exc:
        logger.warning("flag_event failed for %s: %s", uuid, exc)


def unflag_event(uuid: str) -> None:
    try:
        with _db() as conn:
            conn.execute("DELETE FROM flagged_events WHERE uuid = ?", (uuid,))
    except Exception as exc:
        logger.warning("unflag_event failed for %s: %s", uuid, exc)


def is_flagged(uuid: str) -> bool:
    try:
        with _db() as conn:
            row = conn.execute("SELECT 1 FROM flagged_events WHERE uuid = ?", (uuid,)).fetchone()
        return row is not None
    except Exception as exc:
        logger.warning("is_flagged failed for %s: %s", uuid, exc)
        return False


def get_flagged_uuids() -> set:
    try:
        with _db() as conn:
            rows = conn.execute("SELECT uuid FROM flagged_events").fetchall()
        return {r["uuid"] for r in rows}
    except Exception as exc:
        logger.warning("get_flagged_uuids failed: %s", exc)
        return set()
