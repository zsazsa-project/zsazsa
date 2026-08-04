"""Manual collection source registry routes."""

import logging

from flask import Blueprint, flash, redirect, render_template, request, url_for

import config as _config
from webapp import audit, collection_cache, misp_store, newsletter_parsers

logger = logging.getLogger(__name__)
bp = Blueprint("collection_sources", __name__, url_prefix="/config/sources")

ADMIRALTY_OPTIONS = [
    ("A", "A: Completely reliable"),
    ("B", "B: Usually reliable"),
    ("C", "C: Fairly reliable"),
    ("D", "D: Not usually reliable"),
    ("E", "E: Unreliable"),
    ("F", "F: Reliability cannot be judged"),
]


@bp.route("/")
def index():
    sources = misp_store.list_collection_sources()
    misp_servers = getattr(_config, "MISP_SERVERS", []) or []
    cfg = {
        "MISP_URL": getattr(_config, "MISP_URL", ""),
        "MISP_KEY": getattr(_config, "MISP_KEY", ""),
        "MISP_VERIFYCERT": getattr(_config, "MISP_VERIFYCERT", True),
        "MISP_SCRAPER_LIMIT": getattr(_config, "MISP_SCRAPER_LIMIT", 500),
        "MISP_SCRAPER_SINCE_DAYS": getattr(_config, "MISP_SCRAPER_SINCE_DAYS", 30),
        "MISP_SERVERS": misp_servers,
        "SCRAPER_MARKER_TAG": getattr(_config, "SCRAPER_MARKER_TAG", ""),
        "SCRAPER_REDIS_HOST": getattr(_config, "SCRAPER_REDIS_HOST", "127.0.0.1"),
        "SCRAPER_REDIS_PORT": getattr(_config, "SCRAPER_REDIS_PORT", 6379),
        "SCRAPER_REDIS_PASSWORD": getattr(_config, "SCRAPER_REDIS_PASSWORD", ""),
        "SCRAPER_REDIS_CHANNEL": getattr(_config, "SCRAPER_REDIS_CHANNEL", "urls"),
        "IMAP_SOURCES": getattr(_config, "IMAP_SOURCES", []) or [],
    }
    return render_template("collection_sources/list.html",
                           sources=sources, misp_servers=misp_servers, cfg=cfg,
                           newsletter_sources=newsletter_parsers.available_sources(),
                           admiralty_options=ADMIRALTY_OPTIONS)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        data = _form_data(request.form)
        if not data["name"]:
            flash("Name is required.", "warning")
            return render_template("collection_sources/form.html", source=None, data=data,
                                   admiralty_options=ADMIRALTY_OPTIONS)
        try:
            uuid = misp_store.create_collection_source(data)
            # Give the new source a first import now, so it does not read as
            # "never imported" until the worker's next sweep.
            collection_cache.trigger_refresh()
            audit.record("create", "collection_source", entity_id=uuid, entity_label=data["name"])
            flash(f"Source '{data['name']}' created.", "success")
            return redirect(url_for("collection_sources.index"))
        except Exception as exc:
            flash(f"Could not create source: {exc}", "warning")
    return render_template("collection_sources/form.html", source=None, data={},
                           admiralty_options=ADMIRALTY_OPTIONS)


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    source = misp_store.get_collection_source(id)
    if source is None:
        return "Source not found", 404
    if request.method == "POST":
        data = _form_data(request.form)
        if not data["name"]:
            flash("Name is required.", "warning")
            return render_template("collection_sources/form.html", source=source, data=data,
                                   admiralty_options=ADMIRALTY_OPTIONS)
        if data.get("enabled") is False and source.enabled:
            block = _requirement_block(source, "disable")
            if block:
                flash(f"{block} Other changes were kept.", "warning")
                data["enabled"] = True
        try:
            misp_store.update_collection_source(id, data)
            audit.record("update", "collection_source", entity_id=id, entity_label=data["name"])
            flash(f"Source '{data['name']}' updated.", "success")
            return redirect(url_for("collection_sources.index"))
        except Exception as exc:
            flash(f"Could not update source: {exc}", "warning")
    data = {
        "name": source.name,
        "owner": source.owner,
        "location": source.location,
        "description": source.description,
        "source_reliability": source.source_reliability,
    }
    return render_template("collection_sources/form.html", source=source, data=data,
                           admiralty_options=ADMIRALTY_OPTIONS)


@bp.route("/<string:id>/toggle", methods=["POST"])
def toggle(id):
    source = misp_store.get_collection_source(id)
    if source is None:
        return "Source not found", 404
    new_state = not source.enabled
    if not new_state:
        block = _requirement_block(source, "disable")
        if block:
            flash(block, "warning")
            return redirect(url_for("collection_sources.index"))
    try:
        misp_store.toggle_collection_source(id, new_state)
        if new_state:
            collection_cache.trigger_refresh()
        action = "enabled" if new_state else "disabled"
        audit.record("update", "collection_source", entity_id=id,
                     entity_label=f"{source.name} {action}")
        flash(f"Source '{source.name}' {action}.", "success")
    except Exception as exc:
        flash(f"Could not toggle source: {exc}", "warning")
    return redirect(url_for("collection_sources.index"))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    source = misp_store.get_collection_source(id)
    if source is None:
        flash("Source not found.", "warning")
        return redirect(url_for("collection_sources.index"))
    block = _requirement_block(source, "delete")
    if block:
        flash(block, "warning")
        return redirect(url_for("collection_sources.index"))
    try:
        misp_store.delete_collection_source(id)
        audit.record("delete", "collection_source", entity_id=id, entity_label=source.name)
        flash(f"Source '{source.name}' deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete source: {exc}", "warning")
    return redirect(url_for("collection_sources.index"))


_VALID_RELIABILITY = {code for code, _ in ADMIRALTY_OPTIONS}


def _requirement_block(source, verb):
    """Return a warning message if PIRs or GIRs still reference this source, else
    None. Disabling or deleting a referenced source would leave them dangling."""
    pirs = [p for p in misp_store.list_pirs() if source.name in (p.collection_sources or [])]
    girs = [g for g in misp_store.list_girs() if source.name in (g.collection_sources or [])]
    if not (pirs or girs):
        return None
    refs = ", ".join(([f"{len(pirs)} PIR(s)"] if pirs else []) + ([f"{len(girs)} GIR(s)"] if girs else []))
    return (f"Cannot {verb} '{source.name}': referenced in {refs}. "
            "Remove the source from those requirements first.")


def _form_data(form):
    reliability = form.get("source_reliability", "").strip().upper()
    data = {
        "name": form.get("name", "").strip(),
        "owner": form.get("owner", "").strip(),
        "location": form.get("location", "").strip(),
        "description": form.get("description", "").strip(),
        "source_reliability": reliability if reliability in _VALID_RELIABILITY else "",
    }
    # The inline edit form carries the enabled switch; the new-source form does not.
    if form.get("enabled_field"):
        data["enabled"] = form.get("enabled") == "on"
    return data
