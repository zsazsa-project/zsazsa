"""Indicator feed product.

A query builder over MISP attribute search. Analysts build a filter set, run it
to view matching indicators, download them (CSV or a plain value list), save the
query as a named feed (stored as a MISP event), and push a feed's current
results to subscribed stakeholders.
"""

import csv
import io
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlencode

from flask import (
    Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for,
)

from webapp import audit, indicator_meta_store, misp_session, misp_store, notify_jobs
from webapp.rate_limit import rate_limited
from webapp.models import TLP_LEVELS
from notifier import dispatcher

logger = logging.getLogger(__name__)

bp = Blueprint("indicator_feed", __name__, url_prefix="/products/indicator-feed")

PRODUCT_NAME = "Indicator feed"
TO_IDS_CHOICES = ["any", "yes", "no"]
PUBLISHED_CHOICES = ["any", "yes", "no"]
# Attribute timestamp (last change) uses MISP relative shorthand, where the
# units are d/h/m(=minutes); a week/month is expressed in days.
ATTR_RANGES = [("1h", "Last hour"), ("1d", "Last day"), ("7d", "Last week"), ("30d", "Last month")]
# Event date is the event's `date` field (day granularity) and does not accept
# relative shorthand, so these are days-back values converted to an absolute date.
EVENT_RANGES = [("0", "Today"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days")]

# (filter key, CSV/table header). Order defines the table columns and CSV layout.
# Result column order (Server, Event ID, …) — defined once in misp_store and
# reused here and by the threat-actor-profile feed embed.
COLUMNS = misp_store.INDICATOR_FEED_COLUMNS

# `servers` is a list filter too, but it selects targets rather than narrowing
# the indicator query, so it is kept out of _has_query.
_LIST_KEYS = ["servers", "orgs_include", "orgs_exclude", "tags_include", "tags_exclude",
              "events_include", "events_exclude", "types"]
_QUERY_LIST_KEYS = [k for k in _LIST_KEYS if k != "servers"]
_SCALAR_KEYS = ["to_ids", "published", "enforce_warninglist",
                "attr_last", "attr_after", "attr_before",
                "event_last", "event_after", "event_before"]


def _default_filters():
    f = {k: [] for k in _LIST_KEYS}
    f.update({k: "" for k in _SCALAR_KEYS})
    f["to_ids"] = "any"
    f["published"] = "any"
    f["limit"] = 100
    return f


def _filters_from(src):
    """Build the filter dict from a request args/form MultiDict."""
    f = _default_filters()
    for k in _LIST_KEYS:
        f[k] = [v.strip() for v in src.getlist(k) if v.strip()]
    for k in _SCALAR_KEYS:
        f[k] = (src.get(k) or "").strip()
    f["to_ids"] = f["to_ids"] or "any"
    f["published"] = f["published"] or "any"
    try:
        f["limit"] = int(src.get("limit") or 100)
    except (TypeError, ValueError):
        f["limit"] = 100
    return f


def _merge_filters(stored):
    """Overlay a saved feed's stored query onto the defaults so all keys exist."""
    f = _default_filters()
    for k, v in (stored or {}).items():
        if k in f:
            f[k] = v
    return f


def _has_query(f):
    return (
        any(f[k] for k in _QUERY_LIST_KEYS)
        or f["to_ids"] != "any"
        or f["published"] != "any"
        or any(f[k] for k in _SCALAR_KEYS if k not in ("to_ids", "published"))
    )


def _query_string(f):
    params = []
    for k in _LIST_KEYS:
        params += [(k, v) for v in f[k]]
    for k in _SCALAR_KEYS:
        if f[k] and f[k] != "any":
            params.append((k, f[k]))
    params.append(("limit", f["limit"]))
    params.append(("run", "1"))
    return urlencode(params)


def _csv_bytes(rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([header for _, header in COLUMNS])
    for r in rows:
        writer.writerow([r.get(key, "") for key, _ in COLUMNS])
    return buf.getvalue().encode("utf-8")


def _values_text(rows):
    """One line per unique value, in first-seen order.

    The same value can come back on several attributes, events or servers, and
    a plain value list has no context to tell them apart. The CSV export keeps
    every row.
    """
    return "\n".join(dict.fromkeys(str(r.get("value", "")) for r in rows))


# Map a picker field to its cached metadata kind for the autocomplete endpoint.
# (Attribute types are rendered as local checkboxes, so they are not here.)
_SUGGEST_KINDS = {
    "orgs_include": "orgs", "orgs_exclude": "orgs",
    "tags_include": "tags", "tags_exclude": "tags",
}


def _metadata():
    # Only the timestamp is needed for rendering; the lists (tens of thousands of
    # tags) are fetched on demand by the /suggest autocomplete endpoint.
    return {"metadata_refreshed_at": indicator_meta_store.last_refreshed()}


def _run_search(filters):
    try:
        return misp_store.search_indicators(filters, server_ids=filters.get("servers"))
    except Exception as exc:
        logger.exception("Indicator search failed")
        flash(f"Indicator search failed: {exc}", "warning")
        return []


def _render(feed, filters, run, rows):
    recipients = misp_store.recipient_preview(PRODUCT_NAME, feed.tlp, feed.audience) if feed else []
    linked_pir = misp_store.get_pir(feed.linked_pir_uuid) if feed and feed.linked_pir_uuid else None
    return render_template(
        "indicator_feed/index.html",
        feed=feed,
        filters=filters,
        run=run,
        rows=rows,
        recipients=recipients,
        pirs=misp_store.list_pirs(),
        linked_pir=linked_pir,
        audiences=misp_store.FIA_AUDIENCES,
        columns=COLUMNS,
        feeds=misp_store.list_indicator_feeds(),
        servers=misp_store.indicator_feed_servers(),
        attribute_types=misp_store.local_attribute_types(),
        to_ids_choices=TO_IDS_CHOICES,
        published_choices=PUBLISHED_CHOICES,
        attr_ranges=ATTR_RANGES,
        event_ranges=EVENT_RANGES,
        tlp_levels=TLP_LEVELS,
        pymisp_query=misp_store.pymisp_query_string(filters),
        query_string=_query_string(filters),
        **_metadata(),
    )


@bp.route("/")
def index():
    filters = _filters_from(request.args)
    run = bool(request.args.get("run")) or _has_query(filters)
    rows = _run_search(filters) if run else []
    return _render(None, filters, run, rows)


@bp.route("/save", methods=["POST"])
def save():
    filters = _filters_from(request.form)
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("A name is required to save an indicator feed.", "warning")
        return redirect(url_for("indicator_feed.index") + "?" + _query_string(filters))
    data = {
        "name": name,
        "description": (request.form.get("description") or "").strip(),
        "tlp": (request.form.get("tlp") or "clear").strip(),
        "audience": ", ".join(request.form.getlist("audience")),
        "author": (request.form.get("author") or "").strip(),
        "feedback_by": (request.form.get("feedback_by") or "").strip(),
        "linked_pir_uuid": (request.form.get("linked_pir_uuid") or "").strip(),
        "query": filters,
    }
    try:
        uuid = misp_store.create_indicator_feed(data)
        audit.record("create", "indicator-feed", entity_id=uuid, entity_label=data["feed_id"])
        flash(f"{data['feed_id']} created.", "success")
        return redirect(url_for("indicator_feed.detail", id=uuid))
    except Exception as exc:
        flash(f"Could not save indicator feed: {exc}", "warning")
        return redirect(url_for("indicator_feed.index") + "?" + _query_string(filters))


@bp.route("/<string:id>")
def detail(id):
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    filters = _merge_filters(feed.query)
    rows = _run_search(filters)
    return _render(feed, filters, True, rows)


@bp.route("/<string:id>/edit", methods=["POST"])
def edit(id):
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("A name is required.", "warning")
        return redirect(url_for("indicator_feed.detail", id=id))
    data = {
        "feed_id": feed.feed_id,
        "name": name,
        "description": (request.form.get("description") or "").strip(),
        "tlp": (request.form.get("tlp") or "clear").strip(),
        "audience": ", ".join(request.form.getlist("audience")),
        "author": (request.form.get("author") or "").strip(),
        "feedback_by": (request.form.get("feedback_by") or "").strip(),
        "linked_pir_uuid": (request.form.get("linked_pir_uuid") or "").strip(),
        "query": _filters_from(request.form),
    }
    try:
        misp_store.update_indicator_feed(id, data)
        audit.record("update", "indicator-feed", entity_id=id, entity_label=feed.feed_id)
        flash(f"{feed.feed_id} updated.", "success")
    except Exception as exc:
        flash(f"Could not update indicator feed: {exc}", "warning")
    return redirect(url_for("indicator_feed.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    feed = misp_store.get_indicator_feed(id)
    label = feed.feed_id if feed else id
    try:
        misp_store.delete_indicator_feed(id)
        audit.record("delete", "indicator-feed", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete indicator feed: {exc}", "warning")
    return redirect(url_for("indicator_feed.index"))


def _filename_stem(name):
    """A feed name as a download filename: it ends up in a quoted header."""
    stem = re.sub(r"[^a-z0-9._-]+", "-", (name or "").lower()).strip("-.")
    return stem or "indicator-feed"


def _download(rows, fmt, stem):
    if fmt == "txt":
        return Response(
            _values_text(rows),
            mimetype="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{stem}.txt"'},
        )
    return Response(
        _csv_bytes(rows),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{stem}.csv"'},
    )


@bp.route("/download.<string:fmt>")
def download(fmt):
    rows = _run_search(_filters_from(request.args))
    return _download(rows, fmt, "indicator-feed")


@bp.route("/<string:id>/download.<string:fmt>")
def download_feed(id, fmt):
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    rows = _run_search(_merge_filters(feed.query))
    stem = _filename_stem(feed.name or feed.feed_id)
    return _download(rows, fmt, stem)


@bp.route("/<string:id>/notify", methods=["POST"])
def notify(id):
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    rows = _run_search(_merge_filters(feed.query))
    # Deliver to the stakeholders who will actually receive it (subscribed, TLP
    # cleared, audience match) — the green set shown by the Recipients preview.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# {feed.name}", ""]
    if feed.description:
        lines += [feed.description, ""]
    lines += [f"**{len(rows)} indicator(s)** as of {now}.", "", "```", _values_text(rows), "```"]
    markdown = "\n".join(lines)
    csv_bytes = _csv_bytes(rows)

    def deliver(log):
        green = {r["uuid"] for r in misp_store.recipient_preview(
            PRODUCT_NAME, feed.tlp, feed.audience)
            if r["status"] == "green" and r.get("uuid")}
        recipients = [s for s in misp_store.list_stakeholders() if s.uuid in green]
        log(f"{len(recipients)} eligible recipient(s), {len(rows)} indicator(s).")
        summary = dispatcher.send_indicator_feed(feed, markdown, csv_bytes, recipients)
        ok, detail = dispatcher.delivery_outcome(summary)
        log(f"Channels: {detail}.")
        return ok, detail

    notify_jobs.start(
        "notify-feed", f"{feed.feed_id} delivery", deliver,
        entity_type="indicator-feed", entity_id=id, entity_label=feed.feed_id,
        user=misp_session.current_user_email(),
    )
    flash(f"{feed.feed_id} delivery started; the job badge reports the result.", "info")
    return redirect(url_for("indicator_feed.detail", id=id))


@bp.route("/public/<token>")
@rate_limited("indicator_public_feed", limit=30, window_s=60)
def public_feed(token):
    """Unauthenticated capability URL: runs the feed's query and returns the
    attribute values (plain text by default, CSV with ?format=csv). Exempt from
    login in webapp/__init__ via the endpoint name.

    Rate limited because it is the one route that reaches MISP without a session:
    even an unknown token costs a feed listing before the 404."""
    feed = misp_store.get_indicator_feed_by_token(token)
    if feed is None:
        return Response("Feed not found", status=404, mimetype="text/plain")
    try:
        rows = misp_store.search_indicators(feed.query, server_ids=feed.query.get("servers"))
    except Exception:
        logger.exception("Public feed search failed for %s", feed.feed_id)
        rows = []
    if (request.args.get("format") or "").lower() == "csv":
        return Response(_csv_bytes(rows), mimetype="text/csv")
    return Response(_values_text(rows), mimetype="text/plain")


@bp.route("/count")
def count():
    """On-demand total count for the current query (the result table only shows
    the limited, fetched page). Returns {total, capped}."""
    filters = _filters_from(request.args)
    try:
        total, capped = misp_store.count_indicators(filters, server_ids=filters.get("servers"))
        return jsonify({"total": total, "capped": capped})
    except Exception:
        logger.exception("Indicator count failed")
        return jsonify({"error": "count failed"}), 500


@bp.route("/suggest")
def suggest():
    kind = _SUGGEST_KINDS.get((request.args.get("field") or "").strip())
    if not kind:
        return jsonify([])
    return jsonify(indicator_meta_store.suggest(kind, request.args.get("q", "")))


@bp.route("/refresh-metadata", methods=["POST"])
def refresh_metadata():
    try:
        counts = indicator_meta_store.refresh_all()
        summary = ", ".join(f"{n} {kind}" for kind, n in counts.items()) or "nothing"
        flash(f"Refreshed from MISP: {summary}.", "success")
    except Exception as exc:
        flash(f"Could not refresh from MISP: {exc}", "warning")
    return redirect(request.referrer or url_for("indicator_feed.index"))
