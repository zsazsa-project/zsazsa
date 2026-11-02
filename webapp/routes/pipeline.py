import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

import config
from analyser import settings
from core.db import get_latest_pipeline_run, get_recent_pipeline_runs, row_connection
from webapp import analyser_pipeline, collection_cache, job_store, misp_store
from webapp.utils import age_text, scraper_enabled

logger = logging.getLogger(__name__)
bp = Blueprint("pipeline", __name__)


def _pipeline_stats():
    """How many entries the analyser's log holds, in all and of the last 7 and
    30 days, and its problems of the last 7 days, counted as the activity
    filters them. None while there is no analyser database."""
    if not os.path.exists(config.DB_FILE):
        return None
    try:
        with row_connection() as db:
            total = db.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
            last_7d = db.execute(
                "SELECT COUNT(*) FROM event_log"
                " WHERE processed_at >= datetime('now', '-7 days')"
            ).fetchone()[0]
            last_30d = db.execute(
                "SELECT COUNT(*) FROM event_log"
                " WHERE processed_at >= datetime('now', '-30 days')"
            ).fetchone()[0]
            where, params = _activity_filters({"problems": "1", "period": "7d"})
            problems_7d = db.execute(f"SELECT COUNT(*) FROM event_log{where}", params).fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning("could not read the analyser history: %s", exc)
        return None
    return {"total": total, "last_7d": last_7d, "last_30d": last_30d, "problems_7d": problems_7d}


def _outcome_group(outcome: str) -> str:
    """Whether an outcome counts as a product made, declined or a problem.
    "matched", "processed" and "success" are what older versions logged for a
    product; the problems are the failures the analyser writes, http_error,
    error and no_content, as the activity's "Any problem" filter has them."""
    outcome = outcome or ""
    if outcome in ("product_created", "matched", "processed", "success"):
        return "made"
    if "error" in outcome or outcome == "no_content":
        return "problem"
    return "declined"


_OVERVIEW_DAYS = 14


def _overview():
    """What the Overview tab charts: the outcomes per day of the last two
    weeks, and those of the last 30 days by the reason the activity labels
    them with. None while there is no analyser database."""
    if not os.path.exists(config.DB_FILE):
        return None
    try:
        with row_connection() as db:
            daily = db.execute(
                "SELECT date(processed_at) AS day, outcome, COUNT(*) AS n FROM event_log"
                " WHERE processed_at >= date('now', ?) GROUP BY day, outcome",
                (f"-{_OVERVIEW_DAYS - 1} days",),
            ).fetchall()
            # Grouped by detail too, which is the reason a declined event gets.
            month = db.execute(
                "SELECT outcome, detail, COUNT(*) AS n FROM event_log"
                " WHERE processed_at >= datetime('now', '-30 days') GROUP BY outcome, detail"
            ).fetchall()
    except sqlite3.Error as exc:
        logger.warning("could not read the analyser history: %s", exc)
        return None

    today = datetime.now(timezone.utc).date()
    dates = [today - timedelta(days=i) for i in range(_OVERVIEW_DAYS - 1, -1, -1)]
    days = {d.isoformat(): {"made": 0, "declined": 0, "problem": 0} for d in dates}
    for row in daily:
        if row["day"] in days:
            days[row["day"]][_outcome_group(row["outcome"])] += row["n"]

    totals = {"made": 0, "declined": 0, "problem": 0}
    reasons = {group: {} for group in totals}
    for row in month:
        group = _outcome_group(row["outcome"])
        totals[group] += row["n"]
        icon, label = _outcome_icon(row["outcome"] or "", row["detail"])
        # A declined reason is read from the detail, which the activity cannot
        # filter on; any other outcome links to its own entries.
        link = "" if row["outcome"] == "not_relevant" else (row["outcome"] or "")
        reason = reasons[group].setdefault(label, {"icon": icon, "label": label, "n": 0, "outcome": link})
        reason["n"] += row["n"]

    return {
        # The month is named under the first day and under each 1st.
        "days": [{"date": d.isoformat(), "label": f"{d.day} {d.strftime('%b')}" if i == 0 or d.day == 1 else str(d.day),
                  **days[d.isoformat()], "total": sum(days[d.isoformat()].values())} for i, d in enumerate(dates)],
        **totals,
        "reasons": {group: sorted(found.values(), key=lambda r: r["n"], reverse=True)
                    for group, found in reasons.items()},
    }


# What the run history calls each action: the analyser's as the jobs do.
_RUN_ACTIONS = {
    **analyser_pipeline.ACTION_LABELS,
    "analyser": "CLI analyser",
    "imap-collector": "Mailbox poll",
    "bulk-summarise": "AI summaries",
}
# A failed run is worth a look until a later run of the same action, or a week.
_RUN_ATTENTION_DAYS = 7


def _attention(scraper_misp, webapp_misp, source_health, imap_mailboxes, recent_runs, indicator_stats,
               problems_7d):
    """What the Overview lists under "Needs a look": each thing that is down,
    stuck or cut short, most serious first, with the tab that has the rest."""
    found = []

    def add(level, icon, title, text, tab, **link):
        found.append({"level": level, "icon": icon, "title": title, "text": text, "tab": tab, **link})

    # The scraper's own row below says the same of it.
    scraper_listed = any(src["kind"] == "scraper" for src in source_health)
    for label, conn, listed in (("The scraper MISP", scraper_misp, scraper_listed),
                                ("The webapp store MISP", webapp_misp, False)):
        if conn.get("configured", True) and not conn.get("ok") and not listed:
            add("danger", "fa-plug-circle-xmark", f"{label} is unreachable", conn.get("error") or "", "sources")

    for src in source_health:
        if src.get("manual"):
            continue
        if not src["ok"]:
            said = [src["error"].rstrip(".") + "."] if src["error"] else []
            if src["refresh_age"]:
                said.append(f"Its last refresh was {src['refresh_age']}.")
            add("danger", "fa-circle-xmark", f"{src['label']} is unreachable", " ".join(said), "sources")
        elif src["refresh_error"]:
            add("warning", "fa-triangle-exclamation", f"The last refresh of {src['label']} failed",
                src["refresh_error"], "sources")
        elif src["refresh_overdue"]:
            add("warning", "fa-hourglass-half", f"{src['label']} was last refreshed {src['refresh_age']}",
                "Later than twice the refresh interval, so the cache worker may be stuck or stopped.", "sources")
        if src["limit_reached"]:
            add("info", "fa-scissors", f"{src['label']} filled its limit on the last refresh",
                "Older events in its date window may not be cached. Raise the limit or shorten the window "
                "under Collection sources.", "sources")

    for mb in imap_mailboxes:
        if mb["enabled"] and mb["status"] == "failed":
            add("danger", "fa-envelope", f"Mailbox {mb['name']} failed its last poll",
                mb["message"] or "", "sources")

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=_RUN_ATTENTION_DAYS)
    seen = set()
    for run in recent_runs:
        if run["action"] in seen:
            continue
        seen.add(run["action"])
        try:
            started = datetime.fromisoformat(run["started_at"])
        except (TypeError, ValueError):
            continue
        if started < cutoff or not (run["status"] == "failed" or run.get("interrupted")):
            continue
        what = "was interrupted" if run.get("interrupted") else "failed"
        add("warning", "fa-circle-play", f"{run['label']} {what} at {run['started_at'][:16].replace('T', ' ')}",
            (run.get("result") or {}).get("message") or "The log has the reason.", "runs")

    if problems_7d:
        add("warning", "fa-link-slash", f"{problems_7d} problem{'s' if problems_7d != 1 else ''} in the last 7 days",
            "An article that could not be fetched, an event without one, or an error. Review them by hand, "
            "or look at their source.", "activity", outcome="problems", period="7d")

    for server in indicator_stats["servers"]:
        if server["error"]:
            add("info", "fa-fingerprint", f"The indicator counts of {server['label']} could not be read",
                server["error"], "indicators")

    order = {"danger": 0, "warning": 1, "info": 2}
    return sorted(found, key=lambda item: order[item["level"]])


# Relative windows offered by the activity filter, as SQLite date modifiers.
_ACTIVITY_PERIODS = {"48h": "-2 days", "7d": "-7 days", "30d": "-30 days"}
_ACTIVITY_PAGE_SIZE = 50


def _activity_filters(args, skip=()):
    """WHERE clause and parameters for the pipeline activity filters, leaving
    out the dimensions in ``skip`` ("outcome", "source" or "period")."""
    def chosen(name):
        return "" if name in skip else (args.get(name) or "").strip()

    clauses, params = [], []

    outcome = chosen("outcome")
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)

    # The failure outcomes the analyser writes: http_error, error, no_content.
    if "outcome" not in skip and args.get("problems") == "1":
        clauses.append("(outcome LIKE '%error%' OR outcome = 'no_content')")

    source = chosen("source")
    if source:
        clauses.append("source_feed = ?")
        params.append(source)

    period = chosen("period")
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


_FACET_PERIODS = (("", "Any time"), ("today", "Today"), ("48h", "Last 48 hours"),
                  ("7d", "Last 7 days"), ("30d", "Last 30 days"))


def _activity_facets(args):
    """The choices of the activity's outcome, period and feed filters, each with
    how many entries it shows. A dimension is counted under the other filters,
    so a count is what choosing it gives. The choice made is kept, at 0 when
    the other filters leave none of it."""
    with row_connection() as db:
        where, params = _activity_filters(args, skip=("outcome",))
        by_outcome = {r["outcome"] or "": r["n"] for r in db.execute(
            f"SELECT outcome, COUNT(*) AS n FROM event_log{where} GROUP BY outcome ORDER BY n DESC", params)}

        where, params = _activity_filters(args, skip=("period",))
        windows = db.execute(
            "SELECT COUNT(*), COALESCE(SUM(processed_at >= date('now')), 0),"
            " COALESCE(SUM(processed_at >= datetime('now', '-2 days')), 0),"
            " COALESCE(SUM(processed_at >= datetime('now', '-7 days')), 0),"
            " COALESCE(SUM(processed_at >= datetime('now', '-30 days')), 0)"
            f" FROM event_log{where}", params).fetchone()

        where, params = _activity_filters(args, skip=("source",))
        by_feed = [(r["source_feed"], r["n"]) for r in db.execute(
            f"SELECT source_feed, COUNT(*) AS n FROM event_log{where} GROUP BY source_feed ORDER BY n DESC", params)
            if r["source_feed"]]

    chosen = "problems" if args.get("problems") == "1" else (args.get("outcome") or "").strip()
    outcomes = [{"value": "", "label": "All outcomes", "n": sum(by_outcome.values())}]
    for value, label in (("product_created", "Product made"), ("not_relevant", "Declined")):
        if value in by_outcome or chosen == value:
            outcomes.append({"value": value, "label": label, "n": by_outcome.get(value, 0)})
    problems = [(o, n) for o, n in by_outcome.items() if _outcome_group(o) == "problem"]
    if problems or chosen == "problems":
        outcomes.append({"value": "problems", "label": "Any problem", "n": sum(n for _, n in problems)})
        outcomes += [{"value": o, "label": _outcome_icon(o, "")[1], "n": n, "sub": True} for o, n in problems]
    outcomes += [{"value": o, "label": o or "Unknown", "n": n} for o, n in by_outcome.items()
                 if o and o not in ("product_created", "not_relevant") and _outcome_group(o) != "problem"]
    if chosen and chosen not in [o["value"] for o in outcomes]:
        outcomes.append({"value": chosen, "label": _outcome_icon(chosen, "")[1], "n": 0})

    feeds = [{"value": "", "label": "All feeds", "n": sum(n for _, n in by_feed)}]
    feeds += [{"value": feed, "label": feed, "n": n} for feed, n in by_feed]
    source = (args.get("source") or "").strip()
    if source and source not in [f["value"] for f in feeds]:
        feeds.append({"value": source, "label": source, "n": 0})

    periods = [{"value": value, "label": label, "n": n} for (value, label), n in zip(_FACET_PERIODS, windows)]
    return {"outcome": outcomes, "period": periods, "source": feeds}


def _activity_page(args, offset, limit):
    """One page of event_log rows, newest first, for the activity browser.

    Paging is by offset, so an analyser run that inserts rows while someone is
    reading can push a row from one page onto the next. That is acceptable for a
    log people scroll; a re-filter or a page reload straightens it out.
    """
    if not os.path.exists(config.DB_FILE):
        return {"rows": [], "total": 0, "has_more": False, "hidden_orphaned": 0}

    where, params = _activity_filters(args)
    with row_connection() as db:
        total = db.execute(f"SELECT COUNT(*) FROM event_log{where}", params).fetchone()[0]
        rows = [
            dict(r) for r in db.execute(
                "SELECT processed_at, event_uuid, event_info, source_feed, outcome, detail, source_id"
                f" FROM event_log{where} ORDER BY processed_at DESC, id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        ]

    # Paging counts database rows, so it stays correct whether or not the
    # orphaned ones below are dropped from this page.
    has_more = offset + len(rows) < total

    # Orphaned entries, whose source event no longer exists in the scraper MISP,
    # are hidden unless asked for, as the card did before it was paged. Only a
    # scraper event can be checked there; an entry written before the source
    # was recorded is taken for one, as nearly all of them were.
    cached = _cached_sources([r["event_uuid"] for r in rows if r["event_uuid"]])
    hidden_orphaned = 0
    if rows and scraper_enabled() and args.get("include_orphaned") != "1":
        on_scraper = [r["event_uuid"] for r in rows
                      if r["event_uuid"] and _on_scraper(r["source_id"], r["event_uuid"], cached)]
        try:
            existing = misp_store.scraper_existing_uuids(on_scraper)
            kept = [r for r in rows if r["event_uuid"] not in on_scraper or r["event_uuid"] in existing]
            hidden_orphaned = len(rows) - len(kept)
            rows = kept
        except Exception as exc:
            logger.warning("activity MISP existence check failed: %s", exc)

    _add_links_and_icons(rows, cached)
    return {"rows": rows, "total": total, "has_more": has_more, "hidden_orphaned": hidden_orphaned}


# What the analyser wrote as the reason it declined an event, the words that
# tell the kind of reason apart, and the icon and label it gets in the activity.
_DECLINED = (
    ("excluded by title", "fa-filter", "Excluded by title"),
    ("same story", "fa-clone", "Told before"),
    ("analyst scored", "fa-user-pen", "Analyst score"),
    ("under the limit", "fa-gauge", "Under a limit"),
    ("priority gives no alert", "fa-star-half-stroke", "PIR priority"),
    ("no cve", "fa-bug-slash", "No CVE to advise on"),
    ("pir/gir match", "fa-crosshairs", "No requirement match"),
)
_OUTCOMES = {
    "product_created": ("fa-file-circle-check", "Product made"),
    "http_error": ("fa-link-slash", "Article not fetched"),
    "no_content": ("fa-file-circle-xmark", "No article"),
    "error": ("fa-triangle-exclamation", "Error"),
}


def _outcome_icon(outcome: str, detail: str) -> tuple[str, str]:
    """The icon and label of an activity entry."""
    if outcome == "not_relevant":
        reason = (detail or "").lower()
        return next(((icon, label) for words, icon, label in _DECLINED if words in reason),
                    ("fa-circle-minus", "Not relevant"))
    return _OUTCOMES.get(outcome, ("fa-circle-info", outcome or "Unknown"))


def _cached_sources(uuids: list) -> dict:
    """{uuid: the source the collection cache holds the event under}, asked
    in parts, as a purge can ask for thousands."""
    found = {}
    for i in range(0, len(uuids), 500):
        found.update({e["uuid"]: e["source_id"] for e in collection_cache.get_events_by_uuids(uuids[i:i + 500])})
    return found


def _on_scraper(source_id, uuid: str, cached: dict) -> bool:
    """Whether an entry's event is the scraper's, the only MISP the orphan
    check can ask. One logged before the source was kept goes by the cache,
    and is taken for the scraper's once the cache no longer has it: another
    server's event was hidden, and purged, for not being on the scraper."""
    return (source_id or cached.get(uuid)) in (None, "scraper")


def _add_links_and_icons(rows: list[dict], cached: dict) -> None:
    """Give each activity row the link to its event in the MISP it was read
    from, the icon of its outcome, and the source Data collection lists the
    event under, which its Push and Review by hand act on. ``cached`` is
    _cached_sources() of the rows: an entry written before the source was
    recorded goes by it, and has no link once the event has left the cache."""
    for row in rows:
        source_id = row.pop("source_id") or cached.get(row["event_uuid"])
        row["misp_url"] = (misp_store.source_event_urls([row["event_uuid"]], {row["event_uuid"]: source_id})[0]
                           if source_id and row["event_uuid"] else "")
        row["collection_source"] = cached.get(row["event_uuid"], "")
        row["icon"], row["label"] = _outcome_icon(row["outcome"] or "", row["detail"])


_IOC_TYPES = frozenset({
    "ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
    "domain", "hostname", "url", "uri",
    "md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha256",
    "email-src", "email-dst",
    "vulnerability",
    "btc", "xmr",
})


def _indicator_stats():
    """The cached counts per server, indicator types only, for the pane to add up
    over the servers ticked. ``age`` is that of the oldest counts shown."""
    servers = [{
        "id": row["id"],
        "label": row["label"],
        "error": row["error"],
        "by_type": {kind: n for kind, n in row["by_type"].items() if kind in _IOC_TYPES and n > 0},
        "all_total": sum(row["by_type"].values()),
        "fetched_at": row["fetched_at"],
    } for row in collection_cache.indicator_stats()]
    read = [s["fetched_at"] for s in servers if s["fetched_at"]]
    return {"servers": servers, "age": age_text(time.time() - min(read)) if read else ""}


# Matches the stalled threshold the job badge uses, so the two agree on a run.
_RUN_INTERRUPTED_AFTER_S = 1800


# Runs shown at first, and added with each "Show older runs". A scheduled hour
# logs a row for the run and one for each action it made, so twenty covered
# only a few hours.
_RUNS_PAGE = 50
_RUNS_MOST = 1000


def _run_history(shown: int) -> tuple[list, bool]:
    """The newest ``shown`` runs, and whether there are older ones."""
    runs = _mark_interrupted_runs(get_recent_pipeline_runs(shown + 1))
    return runs[:shown], len(runs) > shown


def _logged(uuids: set) -> set:
    """The events among these that the activity has an entry for: a run's
    decision links to them there, and some decisions log none, as an event
    already in a briefing."""
    uuids, found = list(uuids), set()
    if not uuids or not os.path.exists(config.DB_FILE):
        return found
    try:
        with row_connection() as db:
            for i in range(0, len(uuids), 500):
                part = uuids[i:i + 500]
                found.update(r[0] for r in db.execute(
                    f"SELECT DISTINCT event_uuid FROM event_log WHERE event_uuid IN ({','.join('?' * len(part))})",
                    part))
    except sqlite3.Error as exc:
        logger.warning("could not read the analyser history: %s", exc)
    return found


def _mark_interrupted_runs(runs: list) -> list:
    """Flag run-log rows left on "running" by a process that never came back.

    ``started_at`` is written by SQLite's ``now``, which is UTC, so the
    comparison has to be against UTC and not local time.
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=_RUN_INTERRUPTED_AFTER_S)
    for run in runs:
        if run.get("status") != "running" or run.get("finished_at"):
            continue
        try:
            started = datetime.fromisoformat(run["started_at"])
        except (TypeError, ValueError, KeyError):
            continue
        run["interrupted"] = started < cutoff
    return runs


def _refresh_status(status: dict | None, interval_s: int) -> dict:
    """Last collection-cache refresh of one source, formatted for display.

    ``status`` is one row of collection_cache.get_source_status(). A refresh
    re-fetches everything the source's filters match and replaces the cached
    copy, so ``matched`` is the size of that set and only ``matched_new`` says
    what this run actually brought in. ``limit_reached`` means MISP answered
    with as many events as the source's limit allows, so older ones in its
    window may be missing. A run older than twice the refresh interval is
    marked overdue: the worker lives in this process, so a growing age is how a
    dead or stuck worker shows itself.
    """
    if not status or not status.get("last_fetch"):
        return {"last_refresh": "", "refresh_age": "", "matched": None,
                "matched_new": None, "refresh_duration": None,
                "refresh_error": "", "refresh_overdue": False, "cached_events": 0,
                "newest_event": "", "limit_reached": False}

    age_s = max(0.0, time.time() - status["last_fetch"])
    return {
        "last_refresh": datetime.fromtimestamp(status["last_fetch"]).strftime("%Y-%m-%d %H:%M"),
        "refresh_age": age_text(age_s),
        "matched": status.get("last_event_count"),
        "matched_new": status.get("last_new_count"),
        "refresh_duration": status.get("last_duration_s"),
        "refresh_error": status.get("error") or "",
        "refresh_overdue": age_s > 2 * interval_s,
        "cached_events": status.get("event_count", 0),
        "newest_event": status.get("newest_event") or "",
        "limit_reached": bool(status.get("last_limit_reached")),
    }


def _source_health(scraper_conn=None):
    """One row per collection source: whether its server answers, and what the
    cache worker last read from it.

    The events themselves come from the cache, not from the server: this runs
    on every load of the pipeline and statistics pages, and a partner server can
    hold tens of thousands of events. ``scraper_conn`` is the scraper's
    connection check when the page has made it already.
    """
    from webapp.routes.data_collection import _sources

    cache_status = collection_cache.get_source_status()
    interval_s = collection_cache.interval_s()

    results = []
    for src in _sources():
        refresh = _refresh_status(cache_status.get(src["id"]), interval_s)
        if src["kind"] == "manual":
            results.append({
                "label": src["label"], "url": "", "kind": "manual",
                "ok": True, "version": "", "error": "", "manual": True,
                **refresh,
            })
            continue

        if src["kind"] == "scraper":
            conn = scraper_conn or misp_store.test_scraper_misp()
        else:
            conn = misp_store._test_connection(
                src.get("url", ""), src.get("api_key", ""), src.get("verify_tls", True),
            )
        results.append({
            "label": src["label"], "url": src.get("url", ""), "kind": src["kind"],
            "ok": conn.get("ok", False), "version": conn.get("version", ""), "error": conn.get("error", ""),
            **refresh,
        })
    return results


# The entries the scraper may be asked about: its own, and those from before
# the source was kept, which _on_scraper() then sorts out by the cache.
_ON_SCRAPER = "(source_id IS NULL OR source_id = 'scraper')"


def _purge_orphaned_rows():
    """Delete the entries whose event is no longer on the scraper, as the
    activity hides them. Returns (deleted, events checked)."""
    if not os.path.exists(config.DB_FILE):
        return 0, 0
    with row_connection() as db:
        logged = db.execute(
            "SELECT DISTINCT event_uuid, source_id FROM event_log"
            f" WHERE event_uuid IS NOT NULL AND event_uuid != '' AND {_ON_SCRAPER}"
        ).fetchall()
    cached = _cached_sources([r["event_uuid"] for r in logged if r["source_id"] is None])
    candidates = sorted({r["event_uuid"] for r in logged if _on_scraper(r["source_id"], r["event_uuid"], cached)})
    if not candidates:
        return 0, 0
    # Asked before anything is deleted, and outside the transaction: it raises
    # when MISP refuses, and nothing is purged on a partial answer.
    existing = misp_store.scraper_existing_uuids(candidates)
    orphans = [u for u in candidates if u not in existing]
    deleted = 0
    with row_connection() as db:
        for i in range(0, len(orphans), 500):
            part = orphans[i:i + 500]
            placeholders = ",".join("?" * len(part))
            deleted += db.execute(f"DELETE FROM event_log WHERE event_uuid IN ({placeholders}) AND {_ON_SCRAPER}",
                                  part).rowcount
    return deleted, len(candidates)


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


@bp.route("/pipeline")
def index():
    # One MISP tag-statistics read, shared by the scraper's feeds and the email sources.
    source_counts = misp_store.data_collection_source_counts()
    pipeline = _pipeline_stats()
    overview = _overview()
    runs_shown = min(_RUNS_MOST, max(_RUNS_PAGE, request.args.get("runs", _RUNS_PAGE, type=int)))
    recent_runs, older_runs = _run_history(runs_shown)
    decided = {d["uuid"] for run in recent_runs
               for d in ((run.get("result") or {}).get("event_decisions") or []) if d.get("uuid")}
    for run in recent_runs:
        run["label"] = _RUN_ACTIONS.get(run["action"], run["action"])
        run["state"] = "interrupted" if run.get("interrupted") else run["status"]
    imap_mailboxes = _imap_mailbox_status()
    newsletter_sources = _newsletter_source_health(source_counts)
    scraper_misp = misp_store.test_scraper_misp()
    webapp_misp = misp_store.test_webapp_misp()
    source_health = []
    try:
        source_health = _source_health(scraper_misp)
    except Exception as exc:
        logger.warning("source health check failed: %s", exc)
    indicator_stats = _indicator_stats()
    return render_template(
        "pipeline.html",
        pipeline=pipeline,
        log_days=getattr(config, "EVENT_LOG_RETENTION_DAYS", 90),
        feeds=source_counts,
        overview=overview,
        attention=_attention(scraper_misp, webapp_misp, source_health, imap_mailboxes, recent_runs,
                             indicator_stats, pipeline["problems_7d"] if pipeline else 0),
        recent_runs=recent_runs,
        logged_uuids=_logged(decided),
        older_runs_url=(url_for("pipeline.index", runs=runs_shown + _RUNS_PAGE, _anchor="runs")
                        if older_runs and runs_shown < _RUNS_MOST else ""),
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
        # The filter counts change with the filters, not with paging.
        if offset == 0 and os.path.exists(config.DB_FILE):
            page["facets"] = _activity_facets(request.args)
    except sqlite3.Error as exc:
        # The analyser writes to this database from its own process, so a read
        # can time out waiting for a write lock. Say so in JSON rather than
        # letting Flask answer an HTML error page.
        logger.warning("activity query failed: %s", exc)
        return jsonify({"ok": False, "error": "The analyser database is busy. Retry in a moment."}), 503

    # The scores Push sets, as Settings > Analyser has them.
    push = {"briefing": settings.get("ANALYSER_PUSH_BRIEFING"), "alert": settings.get("ANALYSER_PUSH_ALERT")}
    return jsonify({"ok": True, "offset": offset, "limit": limit, "push": push, **page})


@bp.route("/pipeline/indicator-stats/refresh", methods=["POST"])
def refresh_indicator_stats():
    """Read the indicator counts from every server again, as a job the pane follows."""
    job_id = job_store.create_job("indicator-stats", label="Refresh indicator health")["id"]

    def run():
        job_store.update_job(job_id, status="running", message="Reading the attribute statistics...")
        try:
            collection_cache.refresh_indicator_stats()
        except Exception as exc:
            logger.exception("indicator statistics refresh failed")
            job_store.update_job(job_id, status="failed", error=str(exc), message=f"Failed: {exc}")
            return
        job_store.update_job(job_id, status="completed", message="Indicator health refreshed.")

    threading.Thread(target=run, daemon=True, name=job_store.thread_name(job_id)).start()
    return jsonify({"ok": True, "job_id": job_id})


@bp.route("/pipeline/purge-orphaned", methods=["POST"])
def purge_orphaned():
    # Orphans are the rows whose event is gone from the scraper. Without one to
    # ask, every row would read as orphaned and the whole log would go.
    if not scraper_enabled():
        flash("Orphaned entries are found by checking the scraper MISP, and none "
              "is configured.", "info")
        return redirect(url_for("pipeline.index", _anchor="activity"))
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
    return redirect(url_for("pipeline.index", _anchor="activity"))
