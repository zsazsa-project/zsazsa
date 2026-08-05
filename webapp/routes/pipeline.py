import logging
import os
import sqlite3
import time
from datetime import date, datetime, timedelta

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

import config
from core.db import get_recent_pipeline_runs, get_latest_pipeline_run
from webapp import collection_cache, misp_store

logger = logging.getLogger(__name__)
bp = Blueprint("pipeline", __name__)


def _pipeline_stats(source_counts):
    if not os.path.exists(config.DB_FILE):
        return None
    try:
        con = sqlite3.connect(config.DB_FILE)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        total = cur.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]

        # Live per-source counts straight from MISP, so this reflects the actual
        # tagged events rather than the analyser's processing log.
        by_source = source_counts

        by_outcome = [
            dict(r) for r in cur.execute(
                "SELECT outcome, COUNT(*) AS n FROM event_log"
                " GROUP BY outcome ORDER BY n DESC"
            ).fetchall()
        ]

        last_7d = cur.execute(
            "SELECT COUNT(*) FROM event_log"
            " WHERE processed_at >= datetime('now', '-7 days')"
        ).fetchone()[0]

        last_30d = cur.execute(
            "SELECT COUNT(*) FROM event_log"
            " WHERE processed_at >= datetime('now', '-30 days')"
        ).fetchone()[0]

        con.close()
        return {
            "total": total,
            "by_source": by_source,
            "by_outcome": by_outcome,
            "last_7d": last_7d,
            "last_30d": last_30d,
        }
    except Exception:
        return None


# Relative windows offered by the activity filter, as SQLite date modifiers.
_ACTIVITY_PERIODS = {"48h": "-2 days", "7d": "-7 days", "30d": "-30 days"}
_ACTIVITY_PAGE_SIZE = 50


def _activity_filters(args):
    """WHERE clause and parameters for the pipeline activity filters."""
    clauses, params = [], []

    outcome = (args.get("outcome") or "").strip()
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)

    # The failure outcomes the analyser writes: http_error, error, no_content.
    if args.get("problems") == "1":
        clauses.append("(outcome LIKE '%error%' OR outcome = 'no_content')")

    source = (args.get("source") or "").strip()
    if source:
        clauses.append("source_feed = ?")
        params.append(source)

    period = (args.get("period") or "").strip()
    if period == "today":
        clauses.append("processed_at >= date('now')")
    elif period in _ACTIVITY_PERIODS:
        clauses.append("processed_at >= datetime('now', ?)")
        params.append(_ACTIVITY_PERIODS[period])

    q = (args.get("q") or "").strip()
    if q:
        clauses.append("(event_info LIKE ? OR event_uuid LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _activity_page(args, offset, limit):
    """One page of event_log rows, newest first, for the activity browser.

    Paging is by offset, so an analyser run that inserts rows while someone is
    reading can push a row from one page onto the next. That is acceptable for a
    log people scroll; a re-filter or a page reload straightens it out.
    """
    if not os.path.exists(config.DB_FILE):
        return {"rows": [], "total": 0, "has_more": False, "hidden_orphaned": 0}

    where, params = _activity_filters(args)
    con = sqlite3.connect(config.DB_FILE)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        total = cur.execute(f"SELECT COUNT(*) FROM event_log{where}", params).fetchone()[0]
        rows = [
            dict(r) for r in cur.execute(
                "SELECT processed_at, event_uuid, event_info, source_feed, outcome, detail"
                f" FROM event_log{where} ORDER BY processed_at DESC, id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        ]
    finally:
        con.close()

    # Paging counts database rows, so it stays correct whether or not the
    # orphaned ones below are dropped from this page.
    has_more = offset + len(rows) < total

    # Orphaned entries, whose source event no longer exists in the scraper MISP,
    # are hidden unless asked for, as the card did before it was paged.
    hidden_orphaned = 0
    if rows and args.get("include_orphaned") != "1":
        try:
            existing = misp_store.scraper_existing_uuids(
                [r["event_uuid"] for r in rows if r["event_uuid"]]
            )
            kept = [r for r in rows if not r["event_uuid"] or r["event_uuid"] in existing]
            hidden_orphaned = len(rows) - len(kept)
            rows = kept
        except Exception as exc:
            logger.warning("activity MISP existence check failed: %s", exc)

    return {"rows": rows, "total": total, "has_more": has_more, "hidden_orphaned": hidden_orphaned}


_IOC_TYPES = frozenset({
    "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "domain", "hostname", "url", "uri",
    "md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha256",
    "email-src", "email-dst",
    "vulnerability",
    "btc", "xmr",
})


def _indicator_stats():
    try:
        misp = misp_store._misp()
        raw = misp.attributes_statistics("type", percentage=False)
        if not isinstance(raw, dict) or "errors" in raw:
            return {"ok": False, "by_type": {}, "total_ioc": 0, "all_total": 0}
        by_type = {k: int(v) for k, v in raw.items() if k in _IOC_TYPES and int(v) > 0}
        return {
            "ok": True,
            "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
            "total_ioc": sum(by_type.values()),
            "all_total": sum(int(v) for v in raw.values()),
        }
    except Exception as exc:
        logger.warning("indicator stats failed: %s", exc)
        return {"ok": False, "by_type": {}, "total_ioc": 0, "all_total": 0}


def _age_text(seconds: float) -> str:
    """Same wording as the ago() helper the pages use client-side."""
    minutes = round(seconds / 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    if minutes < 1440:
        return f"{round(minutes / 60)}h ago"
    return f"{round(minutes / 1440)}d ago"


def _refresh_status(status: dict | None, interval_s: int) -> dict:
    """Last collection-cache refresh of one source, formatted for display.

    ``status`` is one row of collection_cache.get_source_status(). A refresh
    re-fetches everything the source's filters match and replaces the cached
    copy, so ``matched`` is the size of that set and only ``matched_new`` says
    what this run actually brought in. A run older than twice the refresh
    interval is marked overdue: the worker lives in this process, so a growing
    age is how a dead or stuck worker shows itself.
    """
    if not status or not status.get("last_fetch"):
        return {"last_refresh": "", "refresh_age": "", "matched": None,
                "matched_new": None, "refresh_duration": None,
                "refresh_error": "", "refresh_overdue": False, "cached_events": 0}

    age_s = max(0.0, time.time() - status["last_fetch"])
    return {
        "last_refresh": datetime.fromtimestamp(status["last_fetch"]).strftime("%Y-%m-%d %H:%M"),
        "refresh_age": _age_text(age_s),
        "matched": status.get("last_event_count"),
        "matched_new": status.get("last_new_count"),
        "refresh_duration": status.get("last_duration_s"),
        "refresh_error": status.get("error") or "",
        "refresh_overdue": age_s > 2 * interval_s,
        "cached_events": status.get("event_count", 0),
    }


def _source_health():
    from webapp.routes.data_collection import _sources
    from pymisp import PyMISP
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cache_status = collection_cache.get_source_status()
    interval_s = collection_cache.interval_s()

    results = []
    for src in _sources():
        refresh = _refresh_status(cache_status.get(src["id"]), interval_s)
        if src["kind"] == "manual":
            results.append({
                "label": src["label"], "url": "", "kind": "manual",
                "ok": True, "version": "", "error": "",
                "last_event_date": "", "event_count": None, "manual": True,
                **refresh,
            })
            continue

        row = {"label": src["label"], "url": src.get("url", ""), "kind": src["kind"], **refresh}
        if src["kind"] == "scraper":
            conn = misp_store.test_scraper_misp()
        else:
            conn = misp_store._test_connection(
                src.get("url", ""), src.get("api_key", ""), src.get("verify_tls", True),
            )
        row["ok"] = conn.get("ok", False)
        row["version"] = conn.get("version", "")
        row["error"] = conn.get("error", "")

        if row["ok"]:
            try:
                if src["kind"] == "scraper":
                    misp = misp_store._scraper_misp()
                    search_kwargs = dict(tags=[config.SCRAPER_MARKER_TAG], limit=1, page=1, metadata=True, pythonify=True)
                    count_kwargs = dict(tags=[config.SCRAPER_MARKER_TAG], limit=1, page=1, metadata=True, return_format="count")
                else:
                    misp = PyMISP(src["url"], src["api_key"], src.get("verify_tls", True), False,
                                  timeout=misp_store.HEALTH_CHECK_TIMEOUT)
                    search_kwargs = dict(limit=1, page=1, metadata=True, pythonify=True)
                    count_kwargs = dict(limit=1, page=1, metadata=True, return_format="count")
                    if src.get("tags"):
                        search_kwargs["tags"] = src["tags"]
                        count_kwargs["tags"] = src["tags"]
                    if src.get("since_days"):
                        cutoff = (date.today() - timedelta(days=int(src["since_days"]))).isoformat()
                        search_kwargs["date_from"] = cutoff

                recent = misp.search(**search_kwargs)
                row["last_event_date"] = str(recent[0].date) if recent and not isinstance(recent, dict) and recent[0].date else ""

                count_resp = misp.search(**count_kwargs)
                if isinstance(count_resp, dict) and "count" in count_resp:
                    row["event_count"] = count_resp["count"]
                elif isinstance(count_resp, int):
                    row["event_count"] = count_resp
                else:
                    row["event_count"] = None
            except Exception as exc:
                logger.debug("source health check failed for %s: %s", src["label"], exc)
                row["last_event_date"] = ""
                row["event_count"] = None
        else:
            row["last_event_date"] = ""
            row["event_count"] = None

        results.append(row)
    return results


def _purge_orphaned_rows():
    if not os.path.exists(config.DB_FILE):
        return 0, 0
    con = sqlite3.connect(config.DB_FILE)
    try:
        cur = con.cursor()
        rows = cur.execute(
            "SELECT DISTINCT event_uuid FROM event_log"
            " WHERE event_uuid IS NOT NULL AND event_uuid != ''"
        ).fetchall()
        candidates = [r[0] for r in rows]
        if not candidates:
            return 0, 0
        existing = misp_store.scraper_existing_uuids(candidates)
        orphans = [u for u in candidates if u not in existing]
        if not orphans:
            return 0, len(candidates)
        deleted = 0
        for i in range(0, len(orphans), 500):
            part = orphans[i:i + 500]
            placeholders = ",".join("?" * len(part))
            cur.execute(f"DELETE FROM event_log WHERE event_uuid IN ({placeholders})", part)
            deleted += cur.rowcount or 0
        con.commit()
        return deleted, len(candidates)
    finally:
        con.close()


def _imap_mailbox_status():
    """Per-mailbox last-poll status, from the most recent IMAP collector run."""
    mailboxes = getattr(config, "IMAP_SOURCES", []) or []
    if not mailboxes:
        return []
    latest = get_latest_pipeline_run("imap-collector")
    polled_at = latest.get("started_at") if latest else None
    by_id = {}
    if latest and latest.get("result"):
        for mb in latest["result"].get("mailboxes", []):
            by_id[mb.get("id")] = mb
    rows = []
    for m in mailboxes:
        record = by_id.get(m.get("id"))
        enabled_sources = [s for s in (m.get("sources") or []) if s.get("enabled", True)]
        rows.append({
            "name": m.get("name") or m.get("id"),
            "enabled": m.get("enabled", True),
            "source_count": len(enabled_sources),
            "last_polled": polled_at if record else None,
            "status": record.get("status") if record else None,
            "message": record.get("message") if record else None,
        })
    return rows


def _newsletter_source_health(source_counts):
    """One row per configured newsletter collection source, with how many events
    currently carry its data-collection-source tag (live from MISP)."""
    counts = {row["source_feed"]: row["n"] for row in source_counts}
    rows = []
    for mailbox in getattr(config, "IMAP_SOURCES", []) or []:
        for src in mailbox.get("sources") or []:
            name = src.get("name") or src.get("id")
            rows.append({
                "label": name,
                "mailbox": mailbox.get("name") or mailbox.get("id"),
                "enabled": src.get("enabled", True) and mailbox.get("enabled", True),
                "reliability": src.get("reliability", ""),
                "event_count": counts.get(name, 0),
            })
    return rows


def _configured_source_volume(source_health):
    """Event volume per source configured under Collection sources.

    Reuses the health rows so the panel costs no extra MISP calls. ``cached`` is
    what the local cache holds for the source, capped by its limit and date
    window; ``on_server`` is everything matching its filter, so the two together
    show whether a source is being read in full.
    """
    rows = [{
        "label": src["label"],
        "cached": src.get("cached_events") or 0,
        "on_server": src.get("event_count"),
    } for src in source_health]
    rows.sort(key=lambda r: r["cached"], reverse=True)
    return rows


@bp.route("/pipeline")
def index():
    # One MISP tag-statistics read, shared by the throughput and email-source panels.
    source_counts = misp_store.data_collection_source_counts()
    pipeline = _pipeline_stats(source_counts)
    recent_runs = get_recent_pipeline_runs(20)
    imap_mailboxes = _imap_mailbox_status()
    newsletter_sources = _newsletter_source_health(source_counts)
    scraper_misp = misp_store.test_scraper_misp()
    webapp_misp = misp_store.test_webapp_misp()
    source_health = []
    try:
        source_health = _source_health()
    except Exception as exc:
        logger.warning("source health check failed: %s", exc)
    indicator_stats = _indicator_stats()
    return render_template(
        "pipeline.html",
        configured_source_volume=_configured_source_volume(source_health),
        pipeline=pipeline,
        recent_runs=recent_runs,
        imap_mailboxes=imap_mailboxes,
        newsletter_sources=newsletter_sources,
        scraper_misp=scraper_misp,
        webapp_misp=webapp_misp,
        source_health=source_health,
        cache_interval_min=collection_cache.interval_s() // 60,
        indicator_stats=indicator_stats,
    )


@bp.route("/pipeline/activity")
def activity():
    """One page of pipeline activity, for the filter and load-more controls."""
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(200, max(1, int(request.args.get("limit", _ACTIVITY_PAGE_SIZE))))
    except ValueError:
        offset, limit = 0, _ACTIVITY_PAGE_SIZE

    try:
        page = _activity_page(request.args, offset, limit)
    except sqlite3.Error as exc:
        # The analyser writes to this database from its own process, so a read
        # can time out waiting for a write lock. Say so in JSON rather than
        # letting Flask answer an HTML error page.
        logger.warning("activity query failed: %s", exc)
        return jsonify({"ok": False, "error": "The analyser database is busy. Retry in a moment."}), 503

    return jsonify({"ok": True, "offset": offset, "limit": limit, **page})


@bp.route("/pipeline/purge-orphaned", methods=["POST"])
def purge_orphaned():
    try:
        deleted, scanned = _purge_orphaned_rows()
        if scanned == 0:
            flash("No analyser history to reconcile.", "info")
        elif deleted == 0:
            flash(f"Reconciled {scanned} entries; nothing to purge.", "info")
        else:
            flash(f"Purged {deleted} orphaned entries (scanned {scanned}).", "success")
    except Exception as exc:
        flash(f"Purge failed: {exc}", "warning")
    return redirect(url_for("pipeline.index"))
