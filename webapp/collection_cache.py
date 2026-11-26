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
import sqlite3
import threading
import time
from contextlib import contextmanager

import urllib3
from pymisp import PyMISP

import config
from core.vuln_lookup import CVE_RE
from webapp import job_store
from webapp.utils import scraper_enabled

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DB_FILE = "data/collection_cache.db"
_DEFAULT_INTERVAL_MIN = 15


def interval_s() -> int:
    """Seconds between two refresh sweeps."""
    return int(getattr(config, "COLLECTION_CACHE_INTERVAL", _DEFAULT_INTERVAL_MIN)) * 60


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
# A summary of the whole event, written by the AI-connector MISP module.
AI_EVENT_SUMMARY_PREFIX = "[AI-Event-Summary]"
# What an indicator lookup found, added to the event by an analyst.
LOOKUP_REPORT_PREFIX = "[zsazsa-lookup]"
# The note the analyser leaves on an event it turned down.
REJECTION_PREFIX = "zsazsa:analyser-rejection"

WORKFLOW_REJECTED_TAG = 'workflow:state="rejected"'
# Puts an event in the threat landscape queue, which is read from this cache.
TLR_QUEUE_TAG = 'zsazsa:product="threat-landscape-report"'


def dismissed_tag() -> str:
    """Local tag marking an event an analyst set aside.

    Used for events from another MISP server, whose workflow state belongs to
    that server. Configurable under Configuration > Context elements.
    """
    return getattr(config, "TAG_COLLECTION_DISMISSED", 'zsazsa:event="dismiss"')


def followup_tag() -> str:
    """Local tag marking an event an analyst follows up."""
    return getattr(config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"')


def is_set_aside(tags) -> bool:
    """True when an analyst already rejected or dismissed the event."""
    return WORKFLOW_REJECTED_TAG in tags or dismissed_tag() in tags


def is_own_report(name: str) -> bool:
    """True for a report zsazsa wrote itself: an AI summary, of a report or of
    the event, or an indicator lookup. None of them is the article."""
    return (name or "").startswith((AI_SUMMARY_PREFIX, AI_EVENT_SUMMARY_PREFIX, LOOKUP_REPORT_PREFIX))


def _live(reports) -> list:
    """The reports minus the deleted ones, which MISP keeps on the event."""
    return [r for r in reports if not getattr(r, "deleted", False)]


def _text(report) -> str:
    return (report.content or "").strip()


def _changed_at(report) -> float:
    stamp = getattr(report, "timestamp", None)
    return stamp.timestamp() if isinstance(stamp, _dt.datetime) else 0


def article_report(reports):
    """The report with the article: the first with content that zsazsa did
    not write itself, as it writes an AI summary or a rejection note."""
    for report in _live(reports):
        if _text(report) and not is_own_report(report.name) and not report.name.startswith(REJECTION_PREFIX):
            return report
    return None


def ai_summary(reports) -> str:
    """The newest AI summary of an event, or "" when there is none or the
    article changed after it was written: it would tell the old story."""
    summary = max((r for r in _live(reports) if r.name.startswith(AI_SUMMARY_PREFIX)),
                  key=_changed_at, default=None)
    article = article_report(reports)
    if summary is None or (article is not None and _changed_at(article) > _changed_at(summary)):
        return ""
    return _text(summary)


def init_db():
    with _db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS source_status (
                source_id TEXT PRIMARY KEY,
                last_fetch REAL,
                error TEXT,
                event_count INTEGER DEFAULT 0,
                last_duration_s REAL,
                last_event_count INTEGER,
                last_new_count INTEGER
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
            CREATE TABLE IF NOT EXISTS indicator_stats (
                server_id TEXT PRIMARY KEY,
                label TEXT,
                by_type TEXT,
                fetched_at REAL,
                error TEXT
            );
            -- The indicators of the cached events that the pew-pew map shows,
            -- replaced with their events on every refresh of a source.
            CREATE TABLE IF NOT EXISTS indicators (
                source_id TEXT NOT NULL,
                event_uuid TEXT NOT NULL,
                uuid TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                timestamp REAL,
                fetched_at REAL,
                PRIMARY KEY (source_id, uuid)
            );
            CREATE INDEX IF NOT EXISTS indicators_event ON indicators(source_id, event_uuid);
            -- Where ip.circl.lu puts an address. country is '' for one it does
            -- not know, so it is not asked again on every sweep.
            CREATE TABLE IF NOT EXISTS ip_geo (
                ip TEXT PRIMARY KEY,
                country TEXT NOT NULL,
                name TEXT,
                lat REAL,
                lon REAL,
                looked_up_at REAL
            );
        """)
        # Migrations: add columns to existing databases that lack them. Only a
        # "duplicate column" error (column already present) is expected and
        # ignored; anything else (locked DB, disk error, bad DDL) is surfaced.
        for _col_ddl in [
            "ALTER TABLE events ADD COLUMN has_ai_summary INTEGER DEFAULT 0",
            "ALTER TABLE events ADD COLUMN vulnerability_ids TEXT DEFAULT ''",
            "ALTER TABLE source_status ADD COLUMN last_duration_s REAL",
            "ALTER TABLE source_status ADD COLUMN last_event_count INTEGER",
            "ALTER TABLE source_status ADD COLUMN last_new_count INTEGER",
            "ALTER TABLE source_status ADD COLUMN last_limit_reached INTEGER",
            "ALTER TABLE events ADD COLUMN has_ai_event_summary INTEGER DEFAULT 0",
            "ALTER TABLE events ADD COLUMN source_report_count INTEGER",
        ]:
            try:
                conn.execute(_col_ddl)
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        # Rows cached before the column existed had no event summary yet, so
        # their AI summary is the only report a summary is not made from.
        conn.execute("UPDATE events SET source_report_count = report_count - has_ai_summary"
                     " WHERE source_report_count IS NULL")


def get_source_status() -> dict:
    """Return {source_id: {last_fetch, error, event_count, ...}} from the status table.

    event_count reflects the actual current row count in the events table,
    not the stale value recorded at the last refresh, and newest_event is the
    latest event date among those rows. last_event_count, last_new_count and
    last_limit_reached are what the most recent refresh fetched, and are None
    when that refresh failed.
    """
    try:
        with _db() as conn:
            rows = conn.execute("SELECT * FROM source_status").fetchall()
            cached = {r["source_id"]: (r["cnt"], r["newest"] or "") for r in conn.execute(
                "SELECT source_id, COUNT(*) AS cnt, MAX(date) AS newest FROM events GROUP BY source_id"
            ).fetchall()}
        result = {}
        for r in rows:
            d = dict(r)
            d["event_count"], d["newest_event"] = cached.get(r["source_id"], (0, ""))
            result[r["source_id"]] = d
        return result
    except Exception as exc:
        logger.warning("get_source_status failed: %s", exc)
        return {}


def cached_event_counts() -> list[dict]:
    """[{"label", "events"}] per configured source, busiest first.

    The counts come from the local cache, but naming the sources does not: the
    manual ones are registry entries in MISP, so building the list costs one
    search there, around half a second. That is fine for a page rendered once
    and worth knowing before calling this from anything polled.
    """
    status = get_source_status()
    rows = [{"label": src["label"], "events": status.get(src["id"], {}).get("event_count", 0)}
            for src in _build_sources()]
    rows.sort(key=lambda r: r["events"], reverse=True)
    return rows


def get_events(source_ids: list, tag_filters: list, limit: int, exclude=()) -> list:
    """Return cached events for the given source IDs, applying tag filters.

    Tags are stored as a JSON array per row, so the tag filter is applied in
    Python. When filtering, all candidate rows are scanned in date order rather
    than a pre-capped slice: capping the SQL result first would silently drop
    matching events that happen to be older than the cap. Events whose UUID is
    in ``exclude`` are skipped the same way, so they do not count towards
    ``limit``.
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
            if required or exclude:
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
        if (required and not required.issubset(set(tags))) or r["uuid"] in exclude:
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
            "has_ai_event_summary": bool(r["has_ai_event_summary"]),
            "source_report_count": r["source_report_count"],
            "vulnerability_ids": json.loads(r["vulnerability_ids"] or "[]"),
            "source_id": r["source_id"],
            "fetched_at": r["fetched_at"],
        })
        if len(result) >= limit:
            break
    return result


def filter_events_by_org(events, org_filter_type: str, org_filter: set):
    """Keep or drop events by their creator/owner organisation UUID.

    A collection source can include only listed organisations or exclude them.
    Both the cache refresh and the source-preview count in the API apply it, so
    a previewed count matches what the refresh will actually store.
    """
    if not org_filter_type or not org_filter:
        return events

    def org_uuids(event):
        found = set()
        for attr in ("Org", "org", "Orgc", "orgc"):
            uuid = (getattr(getattr(event, attr, None), "uuid", "") or "").lower()
            if uuid:
                found.add(uuid)
        return found

    if org_filter_type == "include":
        return [e for e in events if org_uuids(e) & org_filter]
    if org_filter_type == "exclude":
        return [e for e in events if not (org_uuids(e) & org_filter)]
    return events


def event_cves(event) -> list[str]:
    """CVE IDs carried by an event, in the order found and without duplicates.

    Read from the vulnerability attributes, on the event and on its objects, and
    only failing those from the title, which is where a scraped article often
    names the CVE it is about.
    """
    values = []
    for attr in getattr(event, "attributes", []) or []:
        if getattr(attr, "type", "") == "vulnerability" and getattr(attr, "value", ""):
            values.append(attr.value.strip().upper())
    for obj in getattr(event, "Object", []) or getattr(event, "objects", []) or []:
        for attr in getattr(obj, "attributes", []) or []:
            if getattr(attr, "type", "") == "vulnerability" and getattr(attr, "value", ""):
                values.append(attr.value.strip().upper())
    if not values:
        values = [m.upper() for m in CVE_RE.findall(getattr(event, "info", "") or "")]
    return list(dict.fromkeys(values))


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
    reports = _live(getattr(e, "event_reports", []) or [])
    names = [getattr(r, "name", "") or "" for r in reports]
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
        "has_ai_summary": any(n.startswith(AI_SUMMARY_PREFIX) for n in names),
        "has_ai_event_summary": any(n.startswith(AI_EVENT_SUMMARY_PREFIX) for n in names),
        # The reports a summary can be made from: the ones zsazsa did not write.
        "source_report_count": sum(not is_own_report(n) for n in names),
        "vulnerability_ids": event_cves(e),
        "source_id": source_id,
        "indicators": _extract_indicators(e),
    }


# The attribute types the pew-pew map shows. An address flies to its country, a
# domain, hostname or URL to that of its top-level domain; the rest have no
# place on a map and land in its litter box.
IP_TYPES = {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"}
INDICATOR_TYPES = IP_TYPES | {"domain", "hostname", "url", "md5", "sha1", "sha256", "vulnerability"}
# An event of a few thousand addresses would fill the map on its own.
_INDICATORS_PER_EVENT = 200


def indicator_ip(type_: str, value: str) -> str:
    """The address in an attribute of one of the IP_TYPES."""
    if type_ == "domain|ip":
        return value.rpartition("|")[2]
    return value.partition("|")[0]


def _extract_indicators(e) -> list[dict]:
    """The attributes of an event, its objects' included, that the map shows."""
    attributes = list(getattr(e, "attributes", []) or [])
    for obj in getattr(e, "objects", []) or []:
        attributes.extend(getattr(obj, "attributes", []) or [])
    found, seen = [], set()
    for a in attributes:
        # The type first: PyMISP reads some values as something other than
        # text, a datetime attribute's as a datetime.
        type_ = getattr(a, "type", "")
        if type_ not in INDICATOR_TYPES:
            continue
        value, uuid = str(getattr(a, "value", "") or "").strip(), getattr(a, "uuid", "")
        if not value or not uuid or getattr(a, "deleted", False):
            continue
        if (type_, value) in seen:
            continue
        seen.add((type_, value))
        stamp = getattr(a, "timestamp", None)
        found.append({"uuid": uuid, "type": type_, "value": value,
                      "timestamp": stamp.timestamp() if hasattr(stamp, "timestamp") else None})
        if len(found) >= _INDICATORS_PER_EVENT:
            break
    return found


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


def source_slug(name: str) -> str:
    """Normalise a source name to the kebab-case ID the cache stores it under."""
    return (name or "").lower().replace(" ", "-").replace("/", "-")


def manual_source_id(name: str) -> str:
    """Source id a manual collection source is cached under."""
    return f"manual-{source_slug(name)}"


def source_labels() -> dict:
    """{source id: label} of the sources in the configuration, for source_label()."""
    return {s["id"]: s["label"] for s in _build_sources(with_manual=False)}


def source_label(source_id: str, labels: dict) -> str:
    """A source's name as the pages show it. ``labels`` is what source_labels()
    returned; a manual source is named by its id, which is its own name."""
    if source_id.startswith("manual-"):
        return source_id[len("manual-"):].replace("-", " ")
    return labels.get(source_id, source_id)


def _build_sources(with_manual: bool = True) -> list:
    """Every configured collection source.

    with_manual=False leaves out the manual ones, which are registry entries in
    MISP and cost a search to name. Callers that only need the ids of the
    sources config knows about can skip that round trip.
    """
    srcs = []
    if scraper_enabled():
        srcs.append({"id": "scraper", "kind": "scraper", "label": "MISP scraper",
                     "url": config.MISP_URL})
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
            "limit": int(s.get("limit") or 500),
            "allow_reports": bool(s.get("allow_reports")),
            # Whether the analyser reads this server's events. Their text then
            # goes to the AI features, so it takes an administrator's say-so,
            # also on a server saved before the setting existed.
            "analyse": bool(s.get("analyse", False)),
        })
    if not with_manual:
        return srcs
    try:
        from webapp import misp_store
        for src in misp_store.list_collection_sources():
            if not src.enabled or not (src.name or "").strip():
                continue
            slug = source_slug(src.name)
            srcs.append({
                "id": manual_source_id(src.name),
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


def source_ids() -> list:
    """Ids of every configured collection source, in display order.

    Naming the manual sources means one MISP search, as cached_event_counts()
    notes, so this belongs on a page render rather than in anything polled.
    cached_source_ids() answers the same question off the cache for free.
    """
    return [s["id"] for s in _build_sources()]


def cached_source_ids() -> list:
    """Source ids to search the cache with, without a MISP round trip.

    The scraper and the configured servers come from config, so one that has
    been removed or switched off drops out at once. The manual sources would
    cost a search to name, so they are read off the rows the cache already
    holds; one that has since been disabled lingers until its rows go.
    """
    ids = [s["id"] for s in _build_sources(with_manual=False)]
    try:
        with _db() as conn:
            # The events table, not source_status: a manual entry added through
            # the web app is cached the moment it is created, before any sweep
            # has given its source a status row.
            rows = conn.execute(
                "SELECT DISTINCT source_id FROM events WHERE source_id LIKE 'manual-%'"
            ).fetchall()
        ids.extend(r["source_id"] for r in rows)
    except Exception as exc:
        logger.warning("cached_source_ids: could not read manual sources: %s", exc)
    return ids


def partner_tag_filter(misp, src: dict):
    """The tags a configured MISP server source is searched with, or None: its
    any-of tags, with the all-of and none-of ones when it has them."""
    tags_or = src.get("tags") or []
    tags_and = src.get("tags_and") or []
    tags_not = src.get("tags_not") or []
    if tags_and or tags_not:
        return misp.build_complex_query(or_parameters=tags_or or None, and_parameters=tags_and or None,
                                        not_parameters=tags_not or None)
    return tags_or or None


def _sync_flags(conn, source_id: str, rows: list, since: float) -> None:
    """Bring flagged_events in line with the follow-up tag on a refreshed source.

    The Flag button tags the event in MISP and records it here, where the page
    looks. A rebuilt cache, or the tag added or removed in MISP itself, sets the
    two apart until this runs. A flag set after the search started is kept, and
    so is one on an event that has the tag in another source.
    """
    tag = followup_tag()
    tagged = {r["uuid"] for r in rows if tag in r["tags"]}
    now = time.time()
    conn.executemany("INSERT OR IGNORE INTO flagged_events (uuid, flagged_at) VALUES (?, ?)",
                     [(uuid, now) for uuid in tagged])
    elsewhere = {r["uuid"] for r in conn.execute("SELECT uuid, tags FROM events WHERE source_id != ?", (source_id,))
                 if tag in json.loads(r["tags"] or "[]")}
    keep = tagged | elsewhere
    conn.executemany("DELETE FROM flagged_events WHERE uuid = ? AND flagged_at < ?",
                     [(r["uuid"], since) for r in rows if r["uuid"] not in keep])


def scraper_since_days() -> int:
    """How many days back the scraper is read, 0 for no limit. Unset, 30."""
    try:
        return int(getattr(config, "MISP_SCRAPER_SINCE_DAYS", 30))
    except (TypeError, ValueError):
        return 30


def _queued_beyond_window(misp, search: dict) -> tuple[list, str | None]:
    """The events queued for the threat landscape, whatever their date, so the
    queue keeps an older article an analyst put in it. ``search`` is the
    source's own search, with its tags narrowed to its queued events and no
    date. Returns them and MISP's error, if any.
    """
    queued = misp.search(**search)
    error = _search_payload_error(queued)
    if error or not queued or isinstance(queued, dict):
        return [], error
    return queued, None


def _add_missing_rows(rows: list, events, source_id: str) -> None:
    have = {r["uuid"] for r in rows}
    rows.extend(_extract_row(e, source_id) for e in events if e.uuid not in have)


def refresh_source(src: dict) -> dict:
    """Re-read one source into the cache.

    Returns {"events": n, "new": n, "error": str} for the caller to report on.
    """
    # Imported here rather than at module scope: misp_store imports this module.
    from webapp import misp_store

    source_id = src["id"]
    logger.info("collection cache: refresh start - %s", source_id)
    t0 = time.time()
    error = None
    rows = []
    # MISP sent as many events as the limit allows, so older ones in the window
    # may be missing. Taken from its answer, before the org filter thins it.
    limit_reached = False

    if src["kind"] == "scraper":
        scraper_limit = getattr(config, "MISP_SCRAPER_LIMIT", 500)
        since_days = scraper_since_days()
        try:
            misp = PyMISP(config.MISP_URL, config.MISP_KEY, config.MISP_VERIFYCERT, False,
                          timeout=misp_store.HTTP_TIMEOUT)
            # The follow-up and dismiss tags are local, and MISP leaves local
            # tags out for a key with sync permission unless it is asked for
            # them. Every search below asks.
            kwargs = dict(
                tags=[config.SCRAPER_MARKER_TAG],
                limit=scraper_limit, page=1, metadata=False, pythonify=True,
                order=misp_store.NEWEST_FIRST, excludeLocalTags=False,
            )
            if since_days > 0:
                kwargs["date_from"] = (_dt.date.today() - _dt.timedelta(days=since_days)).isoformat()
            events = misp.search(**kwargs)
            payload_err = _search_payload_error(events)
            if payload_err:
                error = payload_err
            elif events and not isinstance(events, dict):
                limit_reached = len(events) >= scraper_limit
                for e in events:
                    rows.append(_extract_row(e, source_id))
            if not error and since_days > 0:
                del kwargs["date_from"]
                kwargs["tags"] = misp.build_complex_query(
                    and_parameters=[config.SCRAPER_MARKER_TAG, TLR_QUEUE_TAG])
                queued, error = _queued_beyond_window(misp, kwargs)
                _add_missing_rows(rows, queued, source_id)
        except Exception as exc:
            error = str(exc)
            logger.warning("collection cache: scraper error - %s", exc)
    elif src["kind"] == "manual":
        if not src.get("url") or not src.get("api_key"):
            error = "No URL or API key configured"
        else:
            try:
                misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                              timeout=misp_store.HTTP_TIMEOUT)
                # This source's entries only, so the limit is its own and not
                # shared with every other manual source.
                limit = src.get("limit") or 500
                events = misp.search(
                    tags=misp.build_complex_query(
                        and_parameters=[misp_store.TAG_MANUAL_ENTRY, src["source_tag"]]),
                    limit=limit, page=1, metadata=False, pythonify=True, order=misp_store.NEWEST_FIRST,
                    excludeLocalTags=False,
                )
                payload_err = _search_payload_error(events)
                if payload_err:
                    error = payload_err
                elif events and not isinstance(events, dict):
                    limit_reached = len(events) >= limit
                    rows = [_extract_row(e, source_id) for e in events]
            except Exception as exc:
                error = str(exc)
                logger.warning("collection cache: %s error - %s", source_id, exc)
    else:
        if not src.get("url") or not src.get("api_key"):
            error = "No URL or API key configured"
        else:
            try:
                misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                              timeout=misp_store.HTTP_TIMEOUT)
                limit = src.get("limit") or 500
                kwargs = dict(limit=limit, page=1, metadata=False, pythonify=True, published=True,
                              order=misp_store.NEWEST_FIRST, excludeLocalTags=False)
                tags = partner_tag_filter(misp, src)
                if tags:
                    kwargs["tags"] = tags
                if src.get("since_days"):
                    cutoff = (_dt.date.today() - _dt.timedelta(days=int(src["since_days"]))).isoformat()
                    kwargs["date_from"] = cutoff
                org_filter_type = src.get("org_filter_type", "")
                org_filter = {o.lower() for o in (src.get("org_filter") or [])}
                events = misp.search(**kwargs)
                payload_err = _search_payload_error(events)
                if payload_err:
                    error = payload_err
                elif events and not isinstance(events, dict):
                    limit_reached = len(events) >= limit
                    events = filter_events_by_org(events, org_filter_type, org_filter)
                    for e in events:
                        rows.append(_extract_row(e, source_id))
                if not error and src.get("since_days"):
                    del kwargs["date_from"]
                    kwargs["tags"] = [TLR_QUEUE_TAG]
                    queued, error = _queued_beyond_window(misp, kwargs)
                    _add_missing_rows(rows, filter_events_by_org(queued, org_filter_type, org_filter), source_id)
            except Exception as exc:
                error = str(exc)
                logger.warning("collection cache: %s error - %s", source_id, exc)

    now = time.time()
    duration = round(now - t0, 1)
    new_count = None
    with _db() as conn:
        if not error:
            # Count events this refresh brought in that were not cached before.
            # A refresh replaces the whole source, so this is the only moment
            # the previous set is still available to compare against.
            known = {r[0] for r in conn.execute(
                "SELECT uuid FROM events WHERE source_id = ?", (source_id,)
            )}
            new_count = len({r["uuid"] for r in rows} - known)
            # Only what this refresh is replacing. A request thread caching an
            # event while the search was in flight (a new manual entry, a pulled
            # UUID) wrote it after t0, and dropping it here would take it off the
            # collection page until the next sweep.
            conn.execute(
                "DELETE FROM events WHERE source_id = ?"
                " AND (fetched_at IS NULL OR fetched_at < ?)",
                (source_id, t0),
            )
            if rows:
                conn.executemany(
                    """INSERT OR REPLACE INTO events
                       (source_id, uuid, event_id, info, date, tags, org, orgc,
                        attribute_count, object_count, galaxy_names, report_count,
                        has_ai_summary, has_ai_event_summary, source_report_count,
                        vulnerability_ids, fetched_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [(r["source_id"], r["uuid"], r["event_id"], r["info"], r["date"],
                      json.dumps(r["tags"]), r["org"], r["orgc"],
                      r["attribute_count"], r["object_count"],
                      json.dumps(r["galaxy_names"]), r["report_count"],
                      1 if r.get("has_ai_summary") else 0,
                      1 if r.get("has_ai_event_summary") else 0, r.get("source_report_count", 0),
                      json.dumps(r.get("vulnerability_ids") or []), now)
                     for r in rows],
                )
            _replace_indicators(conn, source_id, rows, t0, now)
            _sync_flags(conn, source_id, rows, t0)
        # event_count is intentionally not written: get_source_status computes
        # it live from the events table, so persisting a copy here would only
        # create a value that can disagree with reality (e.g. on a fetch error
        # the events rows are kept but len(rows) is 0). The column stays in the
        # schema for backwards compatibility and keeps its default. The two
        # last_* counts describe this run alone, so a failed run leaves them
        # NULL rather than repeating the previous numbers as if they were fresh.
        conn.execute(
            """INSERT OR REPLACE INTO source_status
               (source_id, last_fetch, error, last_duration_s, last_event_count, last_new_count,
                last_limit_reached)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (source_id, now, error, duration,
             None if error else len(rows), new_count, None if error else int(limit_reached)),
        )
    logger.info("collection cache: %s done - %d events in %.1fs", source_id, len(rows), duration)
    return {"events": len(rows), "new": new_count or 0, "error": error or ""}


def _replace_indicators(conn, source_id: str, rows: list, since: float, now: float) -> None:
    """Swap a source's indicators for the ones this refresh read, as the events
    are swapped: only what was cached before the refresh started goes."""
    conn.execute("DELETE FROM indicators WHERE source_id = ? AND (fetched_at IS NULL OR fetched_at < ?)",
                 (source_id, since))
    _insert_indicators(conn, rows, now)


def _insert_indicators(conn, rows: list, now: float) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO indicators (source_id, event_uuid, uuid, type, value, timestamp, fetched_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(r["source_id"], r["uuid"], i["uuid"], i["type"], i["value"], i["timestamp"], now)
         for r in rows for i in r.get("indicators") or []],
    )


def event_indicators(events: list) -> list[dict]:
    """The cached indicators of these events, each with the source_id and
    event_uuid it belongs to."""
    wanted = {(e["source_id"], e["uuid"]) for e in events}
    if not wanted:
        return []
    sources = sorted({source_id for source_id, _uuid in wanted})
    try:
        with _db() as conn:
            rows = conn.execute(
                f"SELECT * FROM indicators WHERE source_id IN ({','.join('?' * len(sources))})", sources,
            ).fetchall()
    except sqlite3.Error as exc:
        logger.warning("event_indicators failed: %s", exc)
        return []
    return [dict(r) for r in rows if (r["source_id"], r["event_uuid"]) in wanted]


def ip_locations(ips) -> dict:
    """{ip: {"country", "name", "lat", "lon"}} of the addresses already looked
    up, an unknown one with an empty country."""
    ips = sorted(set(ips))
    found = {}
    try:
        with _db() as conn:
            # In slices: SQLite caps the number of placeholders in one query.
            for start in range(0, len(ips), 500):
                part = ips[start:start + 500]
                for r in conn.execute(f"SELECT * FROM ip_geo WHERE ip IN ({','.join('?' * len(part))})", part):
                    found[r["ip"]] = {"country": r["country"], "name": r["name"], "lat": r["lat"], "lon": r["lon"]}
    except sqlite3.Error as exc:
        logger.warning("ip_locations failed: %s", exc)
    return found


# Addresses looked up after one sweep. The rest wait for the next, so a source
# that brings in thousands does not hold the worker for long.
_LOOKUPS_PER_SWEEP = 200


def ips_to_locate(limit: int = _LOOKUPS_PER_SWEEP) -> list[str]:
    """Addresses on cached events not looked up yet, newest first, from events
    marked TLP:CLEAR or TLP:GREEN only: the lookup sends the address to CIRCL,
    which TLP:AMBER and above do not allow."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT i.type, i.value, e.tags FROM indicators i"
            " JOIN events e ON e.source_id = i.source_id AND e.uuid = i.event_uuid"
            f" WHERE i.type IN ({','.join('?' * len(IP_TYPES))})"
            " ORDER BY i.timestamp DESC",
            sorted(IP_TYPES),
        ).fetchall()
        known = {r[0] for r in conn.execute("SELECT ip FROM ip_geo")}
    ips = []
    for r in rows:
        ip = indicator_ip(r["type"], r["value"])
        if ip in known or ip in ips or event_tlp(json.loads(r["tags"] or "[]")) not in ("clear", "green"):
            continue
        ips.append(ip)
        if len(ips) >= limit:
            break
    return ips


def event_tlp(tags) -> str:
    """The strictest TLP tag of an event, amber when it has none, as a product
    without one is read."""
    from webapp import misp_store

    levels = [t for t in tags if t.lower().startswith("tlp:")]
    return misp_store.strictest_tlp(levels) if levels else "amber"


def locate_ips() -> int:
    """Look up the addresses ips_to_locate() names. Returns how many were stored."""
    import requests

    from core import ip_geolocation

    stored = 0
    with requests.Session() as session:
        for ip in ips_to_locate():
            found = ip_geolocation.lookup(ip, session=session)
            if found is None:
                # The service is down or refusing: the rest can wait for the next sweep.
                break
            with _db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO ip_geo (ip, country, name, lat, lon, looked_up_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (ip, found.get("country", ""), found.get("name"), found.get("lat"), found.get("lon"), time.time()))
            stored += 1
    if stored:
        logger.info("collection cache: located %d address(es)", stored)
    return stored


_refresh_event = threading.Event()
_worker_thread: threading.Thread | None = None
# Jobs waiting to be told how the next sweep went. A sweep takes all of them, so
# two clicks while one sweep is running both get an answer from the next one.
_pending_jobs: list[str] = []
_pending_lock = threading.Lock()


def _sweep():
    """Refresh every configured source once, reporting to any job waiting on it."""
    with _pending_lock:
        jobs = list(_pending_jobs)
        _pending_jobs.clear()

    def report(**fields):
        for job_id in jobs:
            job_store.update_job(job_id, **fields)

    def note(message):
        for job_id in jobs:
            job_store.append_log(job_id, message)

    # The only step outside the per-source guard below. A job claimed above and
    # then left without an answer would sit on "queued" until it ages out, which
    # is a worse thing to look at than a failure.
    try:
        sources = _build_sources()
    except Exception as exc:
        report(status="failed", message=f"Could not read the source list: {exc}")
        raise

    # Nothing refreshes a scraper that has been switched off, so its rows would
    # sit here until it came back. Only the scraper is swept this way: manual
    # sources are read from MISP and dropped from the list when that read fails,
    # so pruning every id missing from it could empty the cache over one bad call.
    if not scraper_enabled():
        forget_source("scraper")

    report(status="running", message=f"Refreshing {len(sources)} source(s)...")
    events = new = failures = 0
    for src in sources:
        report(message=f"Refreshing {src['label']}...")
        try:
            outcome = refresh_source(src)
        except Exception as exc:
            logger.exception("collection cache: worker error for %s: %s", src.get("id"), exc)
            note(f"{src['label']}: {exc}")
            failures += 1
            continue
        if outcome["error"]:
            note(f"{src['label']}: {outcome['error']}")
            failures += 1
        else:
            events += outcome["events"]
            new += outcome["new"]

    # After the sources, so a slow statistics call never holds up the cache.
    try:
        refresh_indicator_stats()
    except Exception:
        logger.exception("collection cache: indicator statistics failed")

    message = f"{events} event(s) from {len(sources) - failures} source(s), {new} new"
    if failures:
        message += f", {failures} source(s) failed"
    # Only a sweep that got nothing anywhere counts as failed. One source with a
    # missing API key is a standing condition, and calling every refresh failed
    # over it would leave the top bar permanently red.
    all_failed = failures > 0 and failures == len(sources)
    report(status="failed" if all_failed else "completed", message=message,
           result={"events": events, "new": new, "sources": len(sources), "failures": failures})

    # Last, after the job has its answer: the lookups go to ip.circl.lu one
    # address at a time, and a Refresh click need not wait for them.
    try:
        locate_ips()
    except Exception:
        logger.exception("collection cache: locating addresses failed")


def _worker_loop(interval: int):
    while True:
        # Cleared before the sweep, never after the wait: a trigger arriving in
        # that gap would otherwise be dropped, leaving whoever asked for it
        # waiting a full interval. Clearing here can cost one redundant sweep
        # instead, which is the cheaper mistake.
        _refresh_event.clear()
        try:
            _sweep()
        except Exception as exc:
            # The thread must survive: it is the only thing refreshing the cache.
            logger.exception("collection cache: sweep failed: %s", exc)
        _refresh_event.wait(timeout=interval)


def start_worker(interval: int = None):
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    if interval is None:
        interval = interval_s()
    init_db()
    _worker_thread = threading.Thread(
        target=_worker_loop, args=(interval,), daemon=True, name="collection-cache",
    )
    _worker_thread.start()
    logger.info("collection cache worker started (interval=%ds)", interval)


def trigger_refresh(job_id: str = "") -> bool:
    """Wake the worker early to start a fresh fetch immediately.

    With a job id, that job is moved to running when the sweep starts and told
    what it fetched when it ends. Returns True when the refresh signal was
    queued, False when the worker could not be started; it never raises, so
    callers can fire it from inside a "did the save work" try block.
    """
    if not (_worker_thread and _worker_thread.is_alive()):
        try:
            start_worker()
        except Exception as exc:
            logger.warning("collection cache: could not start worker on refresh trigger: %s", exc)
            return False
    if not (_worker_thread and _worker_thread.is_alive()):
        return False
    if job_id:
        with _pending_lock:
            _pending_jobs.append(job_id)
    _refresh_event.set()
    return True


def insert_event(row: dict) -> None:
    """Insert or replace a single event row in the cache (used for manual UUID pulls)."""
    with _db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO events
               (source_id, uuid, event_id, info, date, tags, org, orgc,
                attribute_count, object_count, galaxy_names, report_count,
                has_ai_summary, has_ai_event_summary, source_report_count,
                vulnerability_ids, fetched_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["source_id"], row["uuid"], row.get("event_id", ""),
                row.get("info", ""), row.get("date", ""),
                json.dumps(row.get("tags", [])),
                row.get("org", ""), row.get("orgc", ""),
                row.get("attribute_count", 0), row.get("object_count", 0),
                json.dumps(row.get("galaxy_names", [])),
                row.get("report_count", 0),
                1 if row.get("has_ai_summary") else 0,
                1 if row.get("has_ai_event_summary") else 0,
                row.get("source_report_count", 0),
                json.dumps(row.get("vulnerability_ids") or []),
                time.time(),
            ),
        )
        if "indicators" in row:
            conn.execute("DELETE FROM indicators WHERE source_id = ? AND event_uuid = ?", (row["source_id"], row["uuid"]))
            _insert_indicators(conn, [row], time.time())


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
                "has_ai_event_summary": bool(r["has_ai_event_summary"]),
                "source_report_count": r["source_report_count"],
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


def forget_source(source_id: str) -> None:
    """Drop a source's cached events and its refresh status.

    The status row goes with them, so a source that is no longer configured
    stops reporting the error and the timestamp of its last refresh.
    """
    try:
        with _db() as conn:
            cur = conn.execute("DELETE FROM events WHERE source_id = ?", (source_id,))
            conn.execute("DELETE FROM indicators WHERE source_id = ?", (source_id,))
            conn.execute("DELETE FROM source_status WHERE source_id = ?", (source_id,))
            if cur.rowcount:
                logger.info("collection cache: dropped %d row(s) for removed source %s",
                            cur.rowcount, source_id)
    except Exception as exc:
        logger.warning("forget_source failed for %s: %s", source_id, exc)


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


def refresh_indicator_stats() -> None:
    """Re-read the attribute counts per type of every server the pipeline shows.

    MISP's attribute statistics take a while on a large instance, so the page
    reads them from here. A server that does not answer keeps the counts it last
    gave, with the error next to them, and one no longer configured drops out.
    """
    from webapp import misp_store

    servers = misp_store.indicator_stat_servers()
    with _db() as conn:
        conn.execute(
            f"DELETE FROM indicator_stats WHERE server_id NOT IN ({','.join('?' * len(servers))})",
            [misp_store._server_id(s) for s in servers],
        )
    for s in servers:
        sid, label = misp_store._server_id(s), s.get("label") or s["url"]
        try:
            misp = PyMISP(s["url"], s["api_key"], s.get("verify_tls", True), False,
                          timeout=misp_store.HTTP_TIMEOUT)
            raw = misp.attributes_statistics("type", percentage=False)
            if isinstance(raw, dict):
                error = str(raw["errors"]) if "errors" in raw else ""
            else:
                error = f"unexpected answer: {raw!r}"[:200]
        except Exception as exc:
            error = str(exc)
        with _db() as conn:
            if error:
                logger.warning("indicator statistics: %s failed: %s", sid, error)
                conn.execute(
                    "INSERT INTO indicator_stats (server_id, label, by_type, error) VALUES (?, ?, '{}', ?)"
                    " ON CONFLICT(server_id) DO UPDATE SET label = excluded.label, error = excluded.error",
                    (sid, label, error))
            else:
                conn.execute(
                    "INSERT INTO indicator_stats (server_id, label, by_type, fetched_at, error) VALUES (?, ?, ?, ?, '')"
                    " ON CONFLICT(server_id) DO UPDATE SET label = excluded.label, by_type = excluded.by_type,"
                    " fetched_at = excluded.fetched_at, error = ''",
                    (sid, label, json.dumps({kind: int(n) for kind, n in raw.items()}), time.time()))


def indicator_stats() -> list[dict]:
    """The cached counts, one {id, label, by_type, fetched_at, error} per server."""
    try:
        with _db() as conn:
            rows = conn.execute("SELECT * FROM indicator_stats ORDER BY rowid").fetchall()
    except sqlite3.Error as exc:
        logger.warning("indicator_stats failed: %s", exc)
        return []
    return [{"id": r["server_id"], "label": r["label"], "by_type": json.loads(r["by_type"] or "{}"),
             "fetched_at": r["fetched_at"], "error": r["error"] or ""} for r in rows]
