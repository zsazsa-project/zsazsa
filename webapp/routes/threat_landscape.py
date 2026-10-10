"""Threat Landscape Report (TLR) routes."""

import json
import logging
from collections import Counter

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for

from webapp import audit, branding, collection_cache, matching, misp_session, misp_store, notify_jobs, product_log
from webapp.models import INTEL_LEVELS
from webapp.rate_limit import rate_limited

logger = logging.getLogger(__name__)
bp = Blueprint("threat_landscape", __name__, url_prefix="/products/threat-landscape")

_TLR_QUEUE_TAG = 'zsazsa:product="threat-landscape-report"'
PRODUCT_NAME = "Threat landscape report"


def _queued_events(tlrs):
    """Collection events tagged for the threat landscape queue that no report holds yet.

    An event leaves the queue when it becomes an entry of a report, and comes
    back if that report is deleted. Its tag stays, as the mark that it fed one.
    """
    held = {e.event_uuid for t in tlrs for e in t.entries}
    events = collection_cache.get_events(collection_cache.source_ids(), [_TLR_QUEUE_TAG], 500)
    return [ev for ev in events if ev["uuid"] not in held]


def _source_reliabilities():
    """The Admiralty reliability of each manual collection source, by cache source id."""
    try:
        return {collection_cache.manual_source_id(src.name): src.source_reliability
                for src in misp_store.list_collection_sources() if src.name}
    except Exception as exc:
        logger.warning("TLR: could not read the collection source ratings: %s", exc)
        return {}


def _entry_from_event(ev, reliabilities):
    """A new entry for a queued event, filled in from its tags so triage is mostly confirming."""
    context = misp_store.context_from_tags(ev["tags"])
    return {
        "event_uuid": ev["uuid"],
        "source_id": ev["source_id"],
        "event_info": ev["info"],
        "event_date": ev["date"],
        "source_reliability": context["source_reliability"] or reliabilities.get(ev["source_id"], ""),
        "information_credibility": context["information_credibility"],
        "sectors": context["sectors"],
        "geographic_scope": context["geographic_scope"],
        "threat_actors": context["threat_actors"],
        # The full galaxy names, as the technique picker lists them, rather than
        # the bare IDs the briefing keeps.
        "techniques": [t.split("=", 1)[1].strip('"') for t in ev["tags"]
                       if t.startswith("misp-galaxy:mitre-attack-pattern=")],
    }


def _filter_queue(queued, args):
    """Narrow the queue to what the filters on the list page ask for."""
    since, until = args.get("since", ""), args.get("until", "")
    source, sector, actor = args.get("source", ""), args.get("sector", ""), args.get("actor", "")
    kept = []
    for ev in queued:
        context = ev["context"]
        if (since and ev["date"] < since) or (until and ev["date"] > until):
            continue
        if source and ev["source_id"] != source:
            continue
        if (sector and sector not in context["sectors"]) or (actor and actor not in context["threat_actors"]):
            continue
        kept.append(ev)
    return kept


def _counts(entries):
    """Heading and the values counted under it, over the entries left in the analysis."""
    included = [e for e in entries if not e.excluded]
    return [
        ("Threat type", [e.threat_type or "Not classified" for e in included]),
        ("Relevance", [e.relevance or "Not assessed" for e in included]),
        ("Sector", [v for e in included for v in e.sectors]),
        ("Geography", [v for e in included for v in e.geographic_scope]),
        ("Threat actor", [v for e in included for v in e.threat_actors]),
        ("Technique", [v for e in included for v in e.techniques]),
        ("Admiralty rating", [(e.source_reliability or "?") + (e.information_credibility or "?") for e in included]),
        ("Month", [e.event_date[:7] for e in included if e.event_date]),
    ]


def _statistics(entries, previous=None):
    """The counts the analyst writes against, beside those of the previous report.

    Each is a heading with (value, count, previous count) rows, most frequent
    first, except the months, which run in order. The previous count is None
    when there is no previous report to compare with.
    """
    before = {heading: Counter(values) for heading, values in _counts(previous.entries)} if previous else {}
    stats = []
    for heading, values in _counts(entries):
        if not values:
            continue
        counts = Counter(values)
        order = sorted(counts.items()) if heading == "Month" else counts.most_common()
        old = before.get(heading, Counter())
        stats.append((heading, [(value, count, old[value] if previous else None) for value, count in order]))
    return stats


def _previous_report(tlr, tlrs):
    """The report before this one, by its sequence number, to compare the counts with."""
    earlier = [t for t in tlrs if t.tlr_id < tlr.tlr_id]
    return max(earlier, key=lambda t: t.tlr_id, default=None)


def _outside_scope(tlr, entry):
    """True when the report is limited to sectors or places and the event names
    others only. An event without that classification is not held against it."""
    for scope, values in ((tlr.scope_sectors, entry.sectors), (tlr.scope_geography, entry.geographic_scope)):
        wanted = {v.lower() for v in scope}
        if wanted and values and not wanted & {v.lower() for v in values}:
            return True
    return False


def _linked_pirs(tlr):
    if not tlr.linked_pir_uuids:
        return []
    return [p for p in misp_store.list_pirs() if p.uuid in tlr.linked_pir_uuids]


def _pir_coverage(tlr, pirs):
    """For each linked PIR, how many events in the analysis speak to each of its scope items.

    The entries are matched on their classification as triaged, not on the
    event's tags, so the analyst's corrections count.
    """
    events = [
        {"info": e.event_info,
         "galaxy_names": e.sectors + e.geographic_scope + e.threat_actors + e.techniques + [e.threat_type],
         "tags": []}
        for e in tlr.entries if not e.excluded
    ]
    return [(pir, matching.coverage(events, pir)) for pir in pirs]


def _threat_sections(form):
    """The threat assessments of the wizard, one per set of section fields, dropping empty ones."""
    columns = [form.getlist(f"section_{key}") for key in misp_store.TLR_SECTION_FIELDS]
    sections = []
    for values in zip(*columns):
        section = dict(zip(misp_store.TLR_SECTION_FIELDS, (v.strip() for v in values)))
        if section["title"] or any(section[key] for key, _heading in misp_store.TLR_SECTION_TEXTS):
            sections.append(section)
    return sections


def _report_context():
    """What every rendering of a report needs to label its parts."""
    return {
        "actor_categories": misp_store.TLR_ACTOR_CATEGORIES,
        "confidence_labels": {value: label for value, label, _help in misp_store.ESTIMATIVE_CONFIDENCE},
        "section_texts": misp_store.TLR_SECTION_TEXTS,
    }


def _wizard_context(tlr):
    """What the wizard needs besides the report itself."""
    linked = tlr.linked_pir_uuids if tlr else []
    included = [e for e in tlr.entries if not e.excluded] if tlr else []
    return {
        "tlp_levels": misp_store.TLR_TLP_LEVELS,
        "audiences": misp_store.FIA_AUDIENCES,
        "intel_levels": INTEL_LEVELS,
        "threat_types": misp_store.TLR_THREAT_TYPES,
        "estimative_confidence": misp_store.ESTIMATIVE_CONFIDENCE,
        # An agreed PIR, or one the report is already linked to whatever its
        # status has become, as list_selectable_pirs() does for one PIR.
        "pirs": [p for p in misp_store.list_pirs() if p.status == "Active" or p.uuid in linked],
        "sector_items": misp_store.galaxy_sectors(),
        "geo_items": misp_store.galaxy_geography(),
        "type_counts": Counter(e.threat_type for e in included if e.threat_type),
        **_report_context(),
    }


def _form_data(form, tlr_id=""):
    return {
        "tlr_id": tlr_id,
        "title": form.get("title", "").strip(),
        "reporting_period": form.get("reporting_period", "").strip(),
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", "").strip(),
        "audience": ", ".join(form.getlist("audience")),
        "top_threats": form.get("top_threats", "").strip(),
        "trending_actors": form.get("trending_actors", "").strip(),
        **{key: form.get(key, "").strip() for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES},
        "key_incidents": form.get("key_incidents", "").strip(),
        "recommendations": form.get("recommendations", "").strip(),
        "outlook": form.get("outlook", "").strip(),
        **{key: form.get(key, "").strip() for key in misp_store.TLR_DIRECTION_FIELDS},
        # Checked boxes, or one per line where the galaxy could not be read.
        **{key: [v.strip() for raw in form.getlist(key) for v in raw.splitlines() if v.strip()]
           for key in misp_store.TLR_DIRECTION_LISTS},
        "threat_sections": _threat_sections(form),
    }


def _eligible_recipients(tlr):
    """The stakeholders who receive the report: subscribed, cleared for its TLP and in its audience."""
    green = {r["uuid"] for r in misp_store.recipient_preview(PRODUCT_NAME, tlr.tlp, tlr.audience)
             if r["status"] == "green" and r.get("uuid")}
    return [s for s in misp_store.list_stakeholders() if s.uuid in green]


def _start_delivery(tlr, reason):
    """Send a published report to its channels on a background job.

    The job re-reads the report rather than closing over this one. The link is
    resolved here: only the request knows the app's external address.
    """
    uuid = tlr.uuid
    preview_url = url_for("threat_landscape.detail", id=uuid, _external=True)

    def deliver(log):
        from notifier import dispatcher
        report = misp_store.get_tlr(uuid)
        if report is None:
            return False, "the report could not be loaded"
        stakeholders = _eligible_recipients(report)
        markdown = misp_store.render_tlr_markdown(report, _linked_pirs(report), preview_url)
        log(f"{reason}: {len(stakeholders)} eligible recipient(s).")
        ok, detail = dispatcher.delivery_outcome(
            dispatcher.send_threat_landscape_report(report, markdown, stakeholders))
        log(f"Channels: {detail}.")
        return ok, detail

    notify_jobs.start(
        "notify-tlr", f"{tlr.tlr_id} delivery", deliver,
        entity_type="tlr", entity_id=uuid, entity_label=tlr.tlr_id,
        user=misp_session.current_user_email(),
    )


@bp.route("/")
def review():
    tlrs = misp_store.list_tlrs()
    queued = _queued_events(tlrs)
    for ev in queued:
        ev["context"] = misp_store.context_from_tags(ev["tags"])
    shown = _filter_queue(queued, request.args)
    return render_template(
        "threat_landscape/list.html", tlrs=tlrs, queued=queued, shown=shown,
        filters=request.args,
        sources=sorted({ev["source_id"] for ev in queued}),
        sectors=sorted({v for ev in queued for v in ev["context"]["sectors"]}),
        actors=sorted({v for ev in queued for v in ev["context"]["threat_actors"]}),
        drafts=[t for t in tlrs if t.review_state not in misp_store.TLR_LOCKED_STATES],
        locked_states=misp_store.TLR_LOCKED_STATES,
    )


@bp.route("/build", methods=["POST"])
def build():
    """Put the events picked in the queue into a new or an existing draft report."""
    tlrs = misp_store.list_tlrs()
    queued = {ev["uuid"]: ev for ev in _queued_events(tlrs)}
    events = [queued[u] for u in request.form.getlist("event") if u in queued]
    if not events:
        flash("Select at least one event from the queue.", "warning")
        return redirect(url_for("threat_landscape.review"))

    target = request.form.get("target", "")
    title = request.form.get("title", "").strip()
    if target:
        tlr = next((t for t in tlrs if t.uuid == target), None)
        if tlr is None or tlr.review_state in misp_store.TLR_LOCKED_STATES:
            flash("Events can only be added to a report that is not yet approved.", "warning")
            return redirect(url_for("threat_landscape.review"))
    elif not title:
        flash("Give the new report a title.", "warning")
        return redirect(url_for("threat_landscape.review"))

    reliabilities = _source_reliabilities()
    try:
        if target:
            uuid, label = target, tlr.tlr_id
        else:
            data = {"title": title, "reporting_period": request.form.get("reporting_period", "").strip(),
                    "review_state": misp_store.TLR_REVIEW_DRAFT}
            uuid = misp_store.create_tlr(data)
            label = data["tlr_id"]
            audit.record("create", "tlr", entity_id=uuid, entity_label=label)
        added = misp_store.add_tlr_entries(uuid, [_entry_from_event(ev, reliabilities) for ev in events])
    except Exception as exc:
        logger.warning("TLR build failed: %s", exc)
        flash(f"Could not build the report: {exc}", "warning")
        return redirect(url_for("threat_landscape.review"))
    product_log.log_product_sources([ev["uuid"] for ev in events], "tlr")
    audit.record("update", "tlr", entity_id=uuid, entity_label=label, details=f"added {added} event(s)")
    flash(f"{added} event(s) added to {label}. Triage them below.", "success")
    return redirect(url_for("threat_landscape.entries", id=uuid))


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
    tlrs = misp_store.list_tlrs()
    last = max((t for t in tlrs if t.review_state == misp_store.TLR_REVIEW_PUBLISHED),
               key=lambda t: t.tlr_id, default=None)
    return render_template(
        "threat_landscape/wizard.html", tlr=None, is_edit=False, queued=_queued_events(tlrs),
        last=last, last_feedback=misp_store.list_product_feedback(last.uuid) if last else [],
        **_wizard_context(None),
    )


@bp.route("/draft-trends", methods=["POST"])
@rate_limited("tlr_draft_trends", limit=20, window_s=60)
def draft_trends():
    """Draft the report sections from a report's entries, or from the queue for a new one."""
    tlr_uuid = request.form.get("tlr", "")
    tlr = misp_store.get_tlr(tlr_uuid) if tlr_uuid else None
    if tlr is not None:
        uuids = [e.event_uuid for e in tlr.entries if not e.excluded]
        source = sorted(collection_cache.get_events_by_uuids(uuids), key=lambda ev: ev["date"], reverse=True)
    else:
        source = _queued_events(misp_store.list_tlrs())
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
        for ev in source[:150]
    ]
    if not events:
        return jsonify({"sections": {}, "error": "There are no events to draft from."})

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
    return render_template("threat_landscape/detail.html", tlr=tlr, feedback=feedback,
                           linked_pirs=_linked_pirs(tlr), annex=misp_store.tlr_annex(tlr),
                           next_states=misp_store.TLR_NEXT_STATES.get(tlr.review_state, []),
                           locked=tlr.review_state in misp_store.TLR_LOCKED_STATES,
                           can_publish=misp_session.current_user_can_publish(),
                           **_report_context())


@bp.route("/<string:id>/recipients")
def recipients_fragment(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    return render_template("_recipients_preview.html", product_label=PRODUCT_NAME,
                           recipients=misp_store.recipient_preview(PRODUCT_NAME, tlr.tlp, tlr.audience),
                           tlp_label=tlr.tlp, audience_label=tlr.audience)


@bp.route("/<string:id>/pdf")
def pdf(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    html = render_template("threat_landscape/pdf.html", tlr=tlr, linked_pirs=_linked_pirs(tlr),
                           annex=misp_store.tlr_annex(tlr), css_url=branding.pdf_css_url(),
                           brand=branding.brand(), **_report_context())
    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("pdf: weasyprint failed for TLR %s: %s", id, exc)
        return f"PDF generation failed: {exc}", 500
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{tlr.tlr_id}.pdf"'})


@bp.route("/<string:id>/entries", methods=["GET", "POST"])
def entries(id):
    """The report's dataset: triage of each source event and the counts over them."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    locked = tlr.review_state in misp_store.TLR_LOCKED_STATES
    if request.method == "POST":
        if locked:
            flash("Approved or published reports cannot be edited. Send the report back to draft first.", "warning")
            return redirect(url_for("threat_landscape.entries", id=id))
        # Only the rows that were on the page: an entry added since would
        # otherwise be saved with every field blank.
        changes = {
            e.uuid: {
                "relevance": request.form.get(f"relevance-{e.uuid}", ""),
                "source_reliability": request.form.get(f"reliability-{e.uuid}", ""),
                "information_credibility": request.form.get(f"credibility-{e.uuid}", ""),
                "threat_type": request.form.get(f"threat_type-{e.uuid}", ""),
                "excluded": f"excluded-{e.uuid}" in request.form,
                "note": request.form.get(f"note-{e.uuid}", "").strip(),
                **{key: request.form.getlist(f"{key}-{e.uuid}") for key in misp_store.TLR_ENTRY_LISTS},
                **{key: request.form.get(f"{key}-{e.uuid}", "").strip()
                   for key, _label in misp_store.TLR_ENTRY_QUESTIONS},
            }
            for e in tlr.entries if f"relevance-{e.uuid}" in request.form
        }
        try:
            misp_store.update_tlr_entries(id, changes)
            audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details="entries")
            flash("Triage saved.", "success")
        except Exception as exc:
            logger.warning("TLR %s triage failed: %s", id, exc)
            flash(f"Could not save the triage: {exc}", "warning")
        return redirect(url_for("threat_landscape.entries", id=id))
    previous = _previous_report(tlr, misp_store.list_tlrs())
    return render_template(
        "threat_landscape/entries.html", tlr=tlr, locked=locked, previous=previous,
        stats=_statistics(tlr.entries, previous), entry_questions=misp_store.TLR_ENTRY_QUESTIONS,
        outside_scope={e.uuid for e in tlr.entries if _outside_scope(tlr, e)},
        coverage=_pir_coverage(tlr, _linked_pirs(tlr)),
        threat_types=misp_store.TLR_THREAT_TYPES, relevance_levels=misp_store.TLR_RELEVANCE,
        reliabilities=misp_store.FIA_RELIABILITIES, credibilities=misp_store.FIA_CREDIBILITIES,
        sector_items=misp_store.galaxy_sectors(), geo_items=misp_store.galaxy_geography(),
        threat_actor_items=misp_store.galaxy_threat_actors(),
        mitre_items=misp_store.galaxy_mitre_attack_patterns(),
    )


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
    # As for briefings and alerts: what was signed off stays as it was signed off.
    if tlr.review_state in misp_store.TLR_LOCKED_STATES:
        flash("Approved or published reports cannot be edited. Send the report back to draft first.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
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
    return render_template("threat_landscape/wizard.html", tlr=tlr, is_edit=True, **_wizard_context(tlr))


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message(), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    if tlr.review_state != misp_store.TLR_REVIEW_APPROVED:
        flash("A report is published once it has been reviewed and approved.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.publish_tlr(id)
    except Exception as exc:
        flash(f"Could not publish TLR: {exc}", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    audit.record("publish", "tlr", entity_id=id, entity_label=tlr.tlr_id)
    _start_delivery(tlr, "publish")
    flash(f"{tlr.tlr_id} published. It is being sent to its recipients; the job badge reports the result.", "success")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/state", methods=["POST"])
def move(id):
    """Move a report a step through its review, with an optional comment."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    state = request.form.get("state", "")
    if state not in misp_store.TLR_NEXT_STATES.get(tlr.review_state, []):
        flash("The report cannot move to that state from where it is.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    # The formal validation is the sign-off before publishing, so it takes the same right.
    if state == misp_store.TLR_REVIEW_APPROVED and not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("approve"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.set_tlr_state(id, state, request.form.get("comment", "").strip())
        audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details=f"moved to {state}")
        flash(f"{tlr.tlr_id} moved to {state.replace('-', ' ')}.", "success")
    except Exception as exc:
        flash(f"Could not move the report: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/correction", methods=["POST"])
def correction(id):
    """Record a correction to a published report, dated, without touching its analysis."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    text = request.form.get("text", "").strip()
    if tlr.review_state != misp_store.TLR_REVIEW_PUBLISHED or not text:
        flash("A correction is added to a published report, and needs a text.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("correct a published report"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.add_tlr_correction(id, text)
        audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details="correction")
        flash("Correction added. Resend the report if its recipients should see it.", "success")
    except Exception as exc:
        flash(f"Could not add the correction: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/navigator.json")
def navigator_layer(id):
    """The techniques of the report's events as an ATT&CK Navigator layer, scored by how many events use each.

    The layer leaves zsazsa as a file, so it carries the report's TLP in its
    name, its description and its metadata.
    """
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    counts = Counter(misp_store.technique_id(t) for e in tlr.entries if not e.excluded
                     for t in e.techniques if misp_store.technique_id(t))
    tlp = f"TLP:{tlr.tlp.upper()}"
    layer = {
        "name": f"{tlr.tlr_id} {tlr.title} ({tlp})",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": f"{tlp}. Techniques in the events of threat landscape report {tlr.tlr_id}, "
                       f"scored by the number of events.",
        "metadata": [{"name": "TLP", "value": tlp}, {"name": "Report", "value": tlr.tlr_id}],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "techniques": [{"techniqueID": technique, "score": count, "comment": f"{count} event(s)"}
                       for technique, count in sorted(counts.items())],
    }
    return Response(json.dumps(layer, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{tlr.tlr_id}-navigator.json"'})


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    if tlr.review_state != misp_store.TLR_REVIEW_PUBLISHED:
        flash("Only published reports can be resent.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    # A resend reaches the same stakeholders as publishing did, so it takes the same right.
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("resend"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    _start_delivery(tlr, "resend")
    flash(f"{tlr.tlr_id} resend started; the job badge reports the result.", "info")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    tlr = misp_store.get_tlr(id)
    label = tlr.tlr_id if tlr else id
    if tlr and tlr.review_state == misp_store.TLR_REVIEW_PUBLISHED:
        flash("Published reports cannot be deleted.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.delete_tlr(id)
        audit.record("delete", "tlr", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete TLR: {exc}", "warning")
    return redirect(url_for("threat_landscape.review"))
