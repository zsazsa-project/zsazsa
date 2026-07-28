"""Threat Landscape Report (TLR) routes."""

import logging

import config as _cfg
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from webapp import audit, collection_cache, misp_store
from webapp.rate_limit import rate_limited

logger = logging.getLogger(__name__)
bp = Blueprint("threat_landscape", __name__, url_prefix="/products/threat-landscape")

_TLR_QUEUE_TAG = 'zsazsa:product="threat-landscape-report"'


def _queued_events():
    """Return collection events tagged for the threat landscape queue."""
    source_ids = ["scraper"]
    for s in getattr(_cfg, "MISP_SERVERS", []) or []:
        sid = s.get("id") or s.get("label") or ""
        if sid and s.get("enabled", True):
            source_ids.append(sid)
    try:
        for src in misp_store.list_collection_sources():
            if src.enabled:
                slug = misp_store.source_slug(src.name)
                source_ids.append(f"manual-{slug}")
    except Exception:
        pass
    return collection_cache.get_events(source_ids, [_TLR_QUEUE_TAG], 500)


def _form_data(form, tlr_id=""):
    return {
        "tlr_id": tlr_id,
        "title": form.get("title", "").strip(),
        "reporting_period": form.get("reporting_period", "").strip(),
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", "").strip(),
        "audience": form.get("audience", "").strip(),
        "top_threats": form.get("top_threats", "").strip(),
        "trending_actors": form.get("trending_actors", "").strip(),
        "key_incidents": form.get("key_incidents", "").strip(),
        "recommendations": form.get("recommendations", "").strip(),
        "outlook": form.get("outlook", "").strip(),
    }


@bp.route("/")
def review():
    tlrs = misp_store.list_tlrs()
    queued = _queued_events()
    return render_template("threat_landscape/list.html", tlrs=tlrs, queued=queued)


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        data = _form_data(request.form)
        data["review_state"] = misp_store.TLR_REVIEW_DRAFT
        try:
            uuid = misp_store.create_tlr(data)
            audit.record("create", "tlr", entity_id=uuid, entity_label=data.get("tlr_id", ""))
            flash(f"{data.get('tlr_id', 'TLR')} created.", "success")
            return redirect(url_for("threat_landscape.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create TLR: {exc}", "warning")
    return render_template(
        "threat_landscape/wizard.html",
        tlr=None,
        tlp_levels=misp_store.TLR_TLP_LEVELS,
        is_edit=False,
        queued=_queued_events(),
    )


@bp.route("/draft-trends", methods=["POST"])
@rate_limited("tlr_draft_trends", limit=20, window_s=60)
def draft_trends():
    """Draft the report sections from the events queued for the landscape report."""
    # A long queue would be cut mid-way by the prompt's own size limit, so keep
    # the most recent events rather than an arbitrary slice of one of them.
    events = [
        {
            "title": ev.get("info") or "",
            "date": ev.get("date") or "",
            "galaxies": ev.get("galaxy_names") or [],
            "cves": ev.get("vulnerability_ids") or [],
            "source": ev.get("source_id") or "",
        }
        for ev in _queued_events()[:150]
    ]
    if not events:
        return jsonify({"sections": {}, "error": "No events are queued for a threat landscape report."})

    try:
        from analyser import llm
        sections = llm.draft_landscape_trends(request.form.get("reporting_period", "").strip(), events)
    except Exception as exc:
        logger.warning("TLR trend draft failed: %s", exc)
        return jsonify({"sections": {}, "error": "Failed to draft the report."}), 502

    if not sections:
        return jsonify({"sections": {}, "error": "The model returned no usable draft. Check the LLM settings and the analyser log."}), 502
    return jsonify({"sections": sections, "event_count": len(events), "error": None})


@bp.route("/<string:id>")
def detail(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    feedback = misp_store.list_product_feedback(tlr.uuid)
    return render_template("threat_landscape/detail.html", tlr=tlr, feedback=feedback)


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(tlr.uuid, author, rating, comment)
        audit.record("create", "tlr_feedback", entity_id=id, entity_label=tlr.tlr_id)
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback TLR %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    if request.method == "POST":
        data = _form_data(request.form, tlr_id=tlr.tlr_id)
        data["review_state"] = tlr.review_state or misp_store.TLR_REVIEW_DRAFT
        try:
            misp_store.update_tlr(id, data)
            audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id)
            flash(f"{tlr.tlr_id} updated.", "success")
            return redirect(url_for("threat_landscape.detail", id=id))
        except Exception as exc:
            flash(f"Could not update TLR: {exc}", "warning")
    return render_template(
        "threat_landscape/wizard.html",
        tlr=tlr,
        tlp_levels=misp_store.TLR_TLP_LEVELS,
        is_edit=True,
        queued=_queued_events(),
    )


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    try:
        misp_store.publish_tlr(id)
        audit.record("publish", "tlr", entity_id=id, entity_label=tlr.tlr_id)
        flash(f"{tlr.tlr_id} published.", "success")
    except Exception as exc:
        flash(f"Could not publish TLR: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    tlr = misp_store.get_tlr(id)
    label = tlr.tlr_id if tlr else id
    try:
        misp_store.delete_tlr(id)
        audit.record("delete", "tlr", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete TLR: {exc}", "warning")
    return redirect(url_for("threat_landscape.review"))
