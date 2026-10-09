"""Indicator feed product.

The feeds are listed like the other products, each with its own page. Behind
them is a query builder over MISP attribute search: analysts build a filter set,
run it to see the matching indicators, and save it as a named feed (stored as a
MISP event). A feed is then downloaded in any of the formats misp_store renders,
pulled from its own public URL, or pushed to the subscribed stakeholders.
"""

import logging
import re
import time
from types import SimpleNamespace
from datetime import datetime, timezone
from urllib.parse import urlencode

from flask import (
    Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for,
)

from webapp import audit, feed_cache, indicator_meta_store, misp_session, misp_store, notify_jobs
from webapp.rate_limit import rate_limited
from webapp.models import TLP_LEVELS
from webapp.utils import age_text
from notifier import dispatcher

logger = logging.getLogger(__name__)

bp = Blueprint("indicator_feed", __name__, url_prefix="/products/indicator-feed")

PRODUCT_NAME = "Indicator feed"
TO_IDS_CHOICES = ["any", "yes", "no"]
PUBLISHED_CHOICES = ["any", "yes", "no"]
# Attribute timestamp (last change) uses MISP relative shorthand, where the units
# are d/h/m(=minutes). "Today" means since midnight, which the shorthand cannot
# say, so misp_store sends it as today's date instead.
ATTR_RANGES = [("1h", "Last hour"), ("today", "Today"), ("1d", "Last day"),
               ("2d", "Last 2 days"), ("7d", "Last 7 days"),
               ("30d", "Last 30 days"), ("90d", "Last 90 days")]
# Event date is the event's `date` field (day granularity) and does not accept
# relative shorthand, so these are days-back values converted to an absolute
# date. The same offers as the attribute ranges, less the hour a date cannot hold.
EVENT_RANGES = [("0", "Today"), ("1", "Last day"), ("2", "Last 2 days"),
                ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days")]

# Whether the feed is served from disk or queried on every request. It is the
# one thing about a feed that is worth filtering the list by.
FEED_STATES = [("cached", "Cached"), ("not-cached", "Not cached")]

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
    f["limit"] = misp_store.DEFAULT_INDICATOR_LIMIT
    return f


def _resolve_org_uuids(f):
    """Read any organisation UUID in the filters back as the organisation named.

    MISP takes a name or a UUID, so the name is what is kept: it is what the
    chips, the query summary and the PyMISP card then show. Anything that is
    not a UUID, or a UUID no server knows, is left exactly as it was typed.
    """
    for key in ("orgs_include", "orgs_exclude"):
        f[key] = [misp_store.organisation_name(v) or v for v in f[key]]
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
        f["limit"] = int(src.get("limit") or misp_store.DEFAULT_INDICATOR_LIMIT)
    except (TypeError, ValueError):
        f["limit"] = misp_store.DEFAULT_INDICATOR_LIMIT
    return _resolve_org_uuids(f)


def _merge_filters(stored):
    """Overlay a saved feed's stored query onto the defaults so all keys exist."""
    f = _default_filters()
    for k, v in (stored or {}).items():
        if k in f:
            f[k] = v
    # A feed saved before this, or edited straight in MISP, can hold UUIDs.
    return _resolve_org_uuids(f)


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


def _search(filters, limit=None):
    """The matching rows, and what went wrong when the query could not be run.

    A search no MISP server answered is not a query that matches nothing. The
    results card says which of the two it is looking at, and the cache keeps
    the copy it has rather than storing an outage for a week.
    """
    try:
        return misp_store.search_indicators(filters, server_ids=filters.get("servers"), limit=limit), ""
    except Exception as exc:
        logger.exception("Indicator search failed")
        return [], str(exc)


def _cache_fields(form):
    """The caching interval the form asks for and the time it was saved.

    The checkbox and the interval are separate inputs so unticking the box does
    not lose which interval was chosen. The save time is what the schedule hangs
    off, so it moves every time the feed is saved.
    """
    if not form.get("cache_enabled"):
        return {"cache_interval": "", "cache_anchor": ""}
    chosen = form.get("cache_interval")
    return {
        "cache_interval": chosen if chosen in feed_cache.INTERVALS else "daily",
        "cache_anchor": datetime.now().replace(second=0, microsecond=0).isoformat(),
    }


def _export_limit(args):
    """`truncate=off` exports everything that matches instead of the saved limit,
    which sizes the result table rather than the feed."""
    if (args.get("truncate") or "").strip().lower() == "off":
        return misp_store.MAX_SEARCH_LIMIT
    return None


def _with_schedule(feeds):
    """The saved feeds, each carrying when its cache is next due and what went
    wrong the last time it was refreshed."""
    for feed in feeds:
        feed.next_refresh = feed_cache.next_refresh(feed)
        feed.cache_error = feed_cache.failure(feed)
    return feeds


def _cache_age(feed):
    """How long ago the feed was written to disk, or "" when nothing is cached."""
    written = feed_cache.written_at(feed)
    return age_text(time.time() - written) if written else ""


_TIME_FILTERS = (
    ("attributes", ATTR_RANGES, "attr_last", "attr_after", "attr_before"),
    ("events", EVENT_RANGES, "event_last", "event_after", "event_before"),
)


def _query_summary(filters):
    """The query as a handful of readable phrases, for the one-line preview.

    Empty when nothing is filtered, which is what folds the builder away behind
    it: a limit on its own is not a query worth summarising, and a feed being
    built wants the builder open rather than one click away.
    """
    if not _has_query(filters):
        return []
    parts = []
    if filters.get("types"):
        parts.append(", ".join(filters["types"][:3])
                     + (f" +{len(filters['types']) - 3}" if len(filters["types"]) > 3 else ""))
    # Every list an analyst can fill, in the order the query card offers them.
    for key, word in (("tags_include", "tag"), ("tags_exclude", "excluded tag"),
                      ("orgs_include", "org"), ("orgs_exclude", "excluded org"),
                      ("events_include", "event"), ("events_exclude", "excluded event")):
        count = len(filters.get(key) or [])
        if count:
            parts.append(f"{count} {word}{'s' if count != 1 else ''}")
    for noun, ranges, last, after, before in _TIME_FILTERS:
        if filters.get(last):
            parts.append(f"{noun} {dict(ranges).get(filters[last], filters[last]).lower()}")
        elif filters.get(after) or filters.get(before):
            parts.append(f"{noun} {filters.get(after) or '…'} to {filters.get(before) or '…'}")
    if filters.get("to_ids") in ("yes", "no"):
        parts.append(f"to_ids {filters['to_ids']}")
    servers = len(filters.get("servers") or [])
    if servers:
        parts.append(f"{servers} server{'s' if servers != 1 else ''}")
    parts.append(f"limit {misp_store.indicator_limit(filters)}")
    return parts


def _blank_feed():
    """A feed that is not saved yet, so /new can render the page a saved feed
    gets. Same fields, all empty: the form is then one form, not two."""
    return SimpleNamespace(
        id=None, uuid="", feed_id="", name="", description="", query={}, tlp="clear",
        audience="", author="", linked_pir_uuid="", feedback_by=None, created_at=None,
        creator="", token="", public_url_enabled=misp_session.current_user_can_publish(),
        cache_interval="", cache_anchor="")


def _page(feed, filters, run, rows, error=""):
    """The feed page, for a saved feed and for one being built."""
    saved = feed.id is not None
    return render_template(
        "indicator_feed/feed.html",
        feed=feed,
        is_edit=saved,
        page_title_text=(feed.name or feed.feed_id) if saved else "New indicator feed",
        save_label="Save changes" if saved else "Save as feed",
        save_action=url_for("indicator_feed.edit", id=feed.id) if saved
        else url_for("indicator_feed.save"),
        results_url=url_for("indicator_feed.results_fragment", id=feed.id) if saved
        else url_for("indicator_feed.new_results_fragment"),
        filters=filters,
        run=run,
        rows=rows,
        error=error,
        summary=_query_summary(filters),
        query_string=_query_string(filters),
        pymisp_query=misp_store.pymisp_query_string(filters),
        linked_pir=misp_store.get_pir(feed.linked_pir_uuid) if feed.linked_pir_uuid else None,
        pirs=misp_store.list_pirs(),
        audiences=misp_store.FIA_AUDIENCES,
        tlp_levels=TLP_LEVELS,
        servers=misp_store.indicator_feed_servers(),
        attribute_types=misp_store.local_attribute_types(),
        to_ids_choices=TO_IDS_CHOICES,
        published_choices=PUBLISHED_CHOICES,
        attr_ranges=ATTR_RANGES,
        event_ranges=EVENT_RANGES,
        max_limit=misp_store.MAX_SEARCH_LIMIT,
        cache_intervals=list(feed_cache.INTERVALS),
        cache_schedule=feed_cache.schedule_text(feed),
        cache_next=feed_cache.next_refresh(feed),
        cache_age=_cache_age(feed) if saved else "",
        cache_error=feed_cache.failure(feed) if saved else None,
        used_by=misp_store.profiles_using_indicator_feed(feed.uuid) if saved else [],
        can_publish=misp_session.current_user_can_publish(),
        **_metadata(),
    )


@bp.route("/new")
def new():
    """The same page a saved feed gets, for a feed that does not exist yet."""
    filters = _filters_from(request.args)
    run = bool(request.args.get("run")) or _has_query(filters)
    rows, error = _search(filters) if run else ([], "")
    return _page(_blank_feed(), filters, run, rows, error)


@bp.route("/")
def index():
    """The feeds as a product list, in the shape the other CTI products use.

    This used to be the query builder, so a link an analyst kept from before
    carries filters. Those go to the builder, where they still mean something;
    the list's own state filter does not, so it is not one of them.
    """
    if set(request.args) - {"state"}:
        return redirect(url_for("indicator_feed.new") + "?" + request.query_string.decode())
    state = (request.args.get("state") or "").strip()
    feeds = misp_store.list_indicator_feeds()
    if state == "cached":
        feeds = [f for f in feeds if f.cache_interval]
    elif state == "not-cached":
        feeds = [f for f in feeds if not f.cache_interval]
    else:
        # Anything else is not a state, so the list stays whole and says so.
        state = ""
    return render_template("indicator_feed/list.html", feeds=_with_schedule(feeds),
                           states=FEED_STATES, state_filter=state,
                           can_publish=misp_session.current_user_can_publish())


@bp.route("/<string:id>")
def detail(id):
    """One feed as a product page: its fields, what it returns, and who gets it."""
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    # Running the search from this page posts the whole form back, so those
    # filters win and the analyst sees the change before saving it.
    filters = _filters_from(request.args) if request.args else _merge_filters(feed.query)
    rows, error = _search(filters)
    return _page(feed, filters, True, rows, error)


def _results(feed, args):
    """Just the results card, for the Run search button.

    It replaces the table in place, so the analyst keeps the query they were
    working on in front of them instead of the page jumping back to the top.
    """
    filters = _filters_from(args)
    rows, error = _search(filters)
    return render_template("indicator_feed/_results.html", run=True, error=error,
                           feed=feed, rows=rows, query_string=_query_string(filters))


@bp.route("/results")
def new_results_fragment():
    """Run search on a feed that is not saved yet."""
    return _results(_blank_feed(), request.args)


@bp.route("/<string:id>/results")
def results_fragment(id):
    """Run search on a saved feed, with the filters as they stand in the form."""
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    return _results(feed, request.args)


@bp.route("/<string:id>/recipients")
def recipients_fragment(id):
    """Recipients preview for a saved feed, loaded by the button on its page."""
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    return render_template(
        "_recipients_preview.html", product_label=PRODUCT_NAME,
        recipients=misp_store.recipient_preview(PRODUCT_NAME, feed.tlp, feed.audience),
        tlp_label=feed.tlp, audience_label=feed.audience)


def _public_url_choice(current):
    """Whether the feed's public URL answers, from the form.

    The URL hands the feed to anyone who has it, so only a publisher switches
    it on or off. The page sends a hidden "disabled", plus "enabled" while the
    switch is on. For anyone else, and for a form without the switch, it stays
    as it is.
    """
    posted = request.form.getlist("public_url")
    if not posted or not misp_session.current_user_can_publish():
        return current
    return "enabled" in posted


@bp.route("/save", methods=["POST"])
def save():
    filters = _filters_from(request.form)
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("A name is required to save an indicator feed.", "warning")
        return redirect(url_for("indicator_feed.new") + "?" + _query_string(filters))
    data = {
        "name": name,
        "description": (request.form.get("description") or "").strip(),
        "tlp": (request.form.get("tlp") or "clear").strip(),
        "audience": ", ".join(request.form.getlist("audience")),
        "author": (request.form.get("author") or "").strip(),
        "feedback_by": (request.form.get("feedback_by") or "").strip(),
        "linked_pir_uuid": (request.form.get("linked_pir_uuid") or "").strip(),
        "query": filters,
        # A new feed's public URL starts on only when a publisher creates it.
        "public_url_enabled": _public_url_choice(misp_session.current_user_can_publish()),
        **_cache_fields(request.form),
    }
    try:
        uuid = misp_store.create_indicator_feed(data)
        audit.record("create", "indicator-feed", entity_id=uuid, entity_label=data["feed_id"])
        flash(f"{data['feed_id']} created.", "success")
        return redirect(url_for("indicator_feed.detail", id=uuid))
    except Exception as exc:
        flash(f"Could not save indicator feed: {exc}", "warning")
        return redirect(url_for("indicator_feed.new") + "?" + _query_string(filters))


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
        "public_url_enabled": _public_url_choice(feed.public_url_enabled),
        **_cache_fields(request.form),
    }
    try:
        misp_store.update_indicator_feed(id, data)
        feed_cache.clear(id)
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
        # Read the profiles before the delete: they keep the uuid and drop the
        # feed silently, so the analyst has to be told which ones just changed.
        linked = misp_store.profiles_using_indicator_feed(id)
        misp_store.delete_indicator_feed(id)
        feed_cache.clear(id)
        audit.record("delete", "indicator-feed", entity_id=id, entity_label=label)
        if linked:
            names = ", ".join(t.tap_id for t in linked)
            flash(f"{label} deleted. It is no longer part of {names}.", "warning")
        else:
            flash(f"{label} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete indicator feed: {exc}", "warning")
    return redirect(url_for("indicator_feed.index"))


def _filename_stem(name):
    """A feed name as a download filename: it ends up in a quoted header."""
    stem = re.sub(r"[^a-z0-9._-]+", "-", (name or "").lower()).strip("-.")
    return stem or "indicator-feed"


def _format_or_values(fmt):
    """A known format name. Anything else is the plain value list, which is what
    the feed URL has always returned without a format."""
    fmt = (fmt or "").strip().lower()
    return fmt if fmt in misp_store.INDICATOR_FORMATS else "txt"


def _feed_export(feed, fmt, args):
    """A saved feed rendered in `fmt`, from its cache when that is still fresh.

    A cached feed is run once and every format written together, so the next
    pull in any format is a file read. `truncate=off` always runs the query,
    since the cache holds the feed as it is normally served. A query that failed
    is never written, and while it keeps failing the feed hands out the copy it
    already had rather than nothing at all.
    """
    limit = _export_limit(args)
    if limit is None:
        cached = feed_cache.read(feed, fmt)
        if cached is not None:
            return cached
    rows, error = _search(_merge_filters(feed.query), limit)
    if error:
        if not feed_cache.interval(feed):
            return misp_store.indicator_export([], fmt, feed)
        feed_cache.note_failure(feed, error)
        # Stale beats empty: a consumer cannot tell an empty feed from an
        # outage, and would act on it as though everything had been retracted.
        stale = feed_cache.last_copy(feed, fmt)
        return stale if stale is not None else misp_store.indicator_export([], fmt, feed)
    if limit is None and feed_cache.interval(feed):
        bodies = feed_cache.render_all(rows, feed)
        feed_cache.write(feed, bodies)
        feed_cache.clear_failure(feed)
        return bodies[fmt]
    return misp_store.indicator_export(rows, fmt, feed)


def _download(body, fmt, stem):
    return Response(body, mimetype=misp_store.INDICATOR_FORMATS[fmt],
                    headers={"Content-Disposition": f'attachment; filename="{stem}.{fmt}"'})


@bp.route("/download.<string:fmt>")
def download(fmt):
    if fmt not in misp_store.INDICATOR_FORMATS:
        return "Unknown download format", 404
    rows, _ = _search(_filters_from(request.args), _export_limit(request.args))
    return _download(misp_store.indicator_export(rows, fmt), fmt, "indicator-feed")


@bp.route("/<string:id>/download.<string:fmt>")
def download_feed(id, fmt):
    if fmt not in misp_store.INDICATOR_FORMATS:
        return "Unknown download format", 404
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    stem = _filename_stem(feed.name or feed.feed_id)
    return _download(_feed_export(feed, fmt, request.args), fmt, stem)


def _script(body, stem):
    return Response(body, mimetype="text/x-python",
                    headers={"Content-Disposition": f'attachment; filename="{stem}.py"'})


@bp.route("/pymisp.py")
def pymisp_script():
    """The query in the form as a standalone PyMISP script."""
    return _script(misp_store.pymisp_script(_filters_from(request.args)), "indicator-feed")


@bp.route("/<string:id>/pymisp.py")
def pymisp_script_feed(id):
    """A saved feed as a standalone PyMISP script, to run the same search on a
    MISP server that has no zsazsa in front of it. Nothing is searched here."""
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    stem = _filename_stem(feed.name or feed.feed_id)
    return _script(misp_store.pymisp_script(_merge_filters(feed.query), feed), stem)


@bp.route("/<string:id>/notify", methods=["POST"])
def notify(id):
    feed = misp_store.get_indicator_feed(id)
    if feed is None:
        return "Indicator feed not found", 404
    # Delivering reaches the same recipients as publishing a product, so it takes the same right.
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("deliver an indicator feed"), "warning")
        return redirect(url_for("indicator_feed.detail", id=id))
    rows, error = _search(_merge_filters(feed.query))
    if error:
        # Better no delivery than one telling stakeholders the feed is empty.
        flash(f"Could not read {feed.feed_id} from MISP: {error}", "warning")
        return redirect(url_for("indicator_feed.detail", id=id))
    # Deliver to the stakeholders who will actually receive it: subscribed, TLP
    # cleared, audience match, the green set the Recipients preview shows.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# {feed.name}", ""]
    if feed.description:
        lines += [feed.description, ""]
    lines += [f"**{len(rows)} indicator(s)** as of {now}.", "", "```",
              misp_store.indicator_export(rows, "txt"), "```"]
    markdown = "\n".join(lines)
    csv_bytes = misp_store.indicator_export(rows, "csv").encode("utf-8")

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
    attribute values (plain text by default, CSV with ?format=csv, the whole set
    rather than the saved limit with ?truncate=off). Exempt from login in
    webapp/__init__ via the endpoint name.

    Rate limited because it is the one route that reaches MISP without a session:
    even an unknown token costs a feed listing before the 404."""
    feed = misp_store.get_indicator_feed_by_token(token)
    if feed is None:
        return Response("Feed not found", status=404, mimetype="text/plain")
    fmt = _format_or_values(request.args.get("format"))
    return Response(_feed_export(feed, fmt, request.args),
                    mimetype=misp_store.INDICATOR_FORMATS[fmt])


@bp.route("/count")
def count():
    """On-demand total count for the current query (the result table only shows
    the limited, fetched page). Returns {total, capped}."""
    filters = _filters_from(request.args)
    try:
        total, capped = misp_store.count_indicators(filters, server_ids=filters.get("servers"))
        return jsonify({"total": total, "capped": capped})
    except Exception as exc:
        logger.exception("Indicator count failed")
        # The same wording the results card shows when a search cannot be run.
        return jsonify({"error": str(exc)}), 500


@bp.route("/pymisp-query")
def pymisp_query():
    """The PyMISP call for the filters currently in the form.

    The card on the page is server-rendered on load and re-fetched here as the
    analyst edits.
    """
    filters = _filters_from(request.args)
    return jsonify({"query": misp_store.pymisp_query_string(filters),
                    "summary": _query_summary(filters)})


@bp.route("/org-name")
def org_name():
    """The organisation a UUID names, for the chip the browser just added.

    _filters_from does the same thing for what the server renders, but a chip
    is built in the page and never passes through it until the feed is saved.
    """
    return jsonify({"name": misp_store.organisation_name(request.args.get("value", ""))})


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
