"""RFI (Request for Information) workflow routes.

Implements the RFI lifecycle described in the TI program template:
intake → acknowledge → triage → respond → feedback. RFIs are stored as
MISP events tagged 'zsazsa:type="rfi"'.
"""

import logging
from datetime import date, timedelta
from urllib.parse import quote

from flask import (Blueprint, Response, flash, jsonify, redirect, render_template,
                   request, url_for)

from webapp import audit, misp_session, misp_store, notify_jobs
from webapp.models import cti_products, TLP_LEVELS
from webapp.utils import matching, ordered_counts

logger = logging.getLogger(__name__)

bp = Blueprint("rfi", __name__, url_prefix="/rfis")

RFI_PRIORITIES = ["High", "Medium", "Low"]
RFI_STATUSES = ["New", "Acknowledged", "In Progress", "Delivered", "Closed"]
FEEDBACK_REQUIREMENT = ["", "Yes", "Partially", "No"]
FEEDBACK_ON_TIME = ["", "Yes", "No"]
FEEDBACK_USEFULNESS = ["", "Very useful", "Somewhat useful", "Not useful"]


def _sla_status(rfi):
    """Return ('green' | 'amber' | 'red' | 'done', days_remaining_or_None)."""
    if rfi.status in ("Delivered", "Closed"):
        return ("done", None)
    if not rfi.due_date:
        return ("amber", None)
    today = date.today()
    delta = (rfi.due_date - today).days
    if delta < 0:
        return ("red", delta)
    if delta <= 1:
        return ("amber", delta)
    return ("green", delta)


# The SLA states as the bar above the list names them, in its order.
SLA_LABELS = ["Overdue", "Due soon", "No due date", "On track", "Done"]


def _sla_label(state, days):
    if state == "amber" and days is None:
        return "No due date"
    return {"red": "Overdue", "amber": "Due soon", "green": "On track", "done": "Done"}[state]


def _output_formats(form):
    formats = form.getlist("output_format_item")
    tlps = form.getlist("output_format_tlp")
    if len(formats) != len(tlps):
        raise ValueError("Invalid output format payload.")
    return [{"format": f, "tlp": t} for f, t in zip(formats, tlps) if f.strip()]


def _form_data(form, rfi_id):
    fmt_list = _output_formats(form)
    return {
        "rfi_id": rfi_id,
        "question": form["question"],
        "context": form.get("context"),
        "requester_name": form.get("requester_name"),
        "requester_team": form.get("requester_team"),
        "owner_uuid": form.get("owner_uuid") or "",
        "owner_name": form.get("owner_name") or "",
        "priority": form.get("priority", "Medium"),
        "assigned_analyst": form.get("assigned_analyst"),
        "due_date": form.get("due_date") or None,
        "linked_pir_uuid": form.get("linked_pir_uuid") or "",
        "linked_gir_uuid": form.get("linked_gir_uuid") or "",
        "output_format_list": fmt_list,
        "response": form.get("response"),
        "response_confidence": form.get("response_confidence") or "",
        "feedback_requirement_met": form.get("feedback_requirement_met"),
        "feedback_on_time": form.get("feedback_on_time"),
        "feedback_usefulness": form.get("feedback_usefulness"),
        "feedback_suggestions": form.get("feedback_suggestions"),
    }


def _suggested_due_date(priority):
    days = misp_store.RFI_SLA_DAYS.get(priority, 5)
    return (date.today() + timedelta(days=days)).isoformat()


def _rfi_data_from_store(rfi, status: str | None = None) -> dict:
    return {
        "rfi_id": rfi.rfi_id,
        "question": rfi.question,
        "context": rfi.context or "",
        "requester_name": rfi.requester_name or "",
        "requester_team": rfi.requester_team or "",
        "owner_uuid": rfi.owner_uuid or "",
        "owner_name": rfi.owner_name or "",
        "priority": rfi.priority,
        "status": status or rfi.status,
        "assigned_analyst": rfi.assigned_analyst or "",
        "due_date": rfi.due_date.isoformat() if rfi.due_date else None,
        "linked_pir_uuid": rfi.linked_pir_uuid or "",
        "linked_gir_uuid": rfi.linked_gir_uuid or "",
        "output_format_list": list(rfi.output_format_list),
        "response": rfi.response or "",
        "response_confidence": rfi.response_confidence or "",
        "feedback_requirement_met": rfi.feedback_requirement_met or "",
        "feedback_on_time": rfi.feedback_on_time or "",
        "feedback_usefulness": rfi.feedback_usefulness or "",
        "feedback_suggestions": rfi.feedback_suggestions or "",
    }


def _rfi_notify_recipients(rfi):
    stakeholders = misp_store.list_stakeholders()
    if rfi.owner_uuid:
        s = next((x for x in stakeholders if x.id == rfi.owner_uuid), None)
        return [s] if s else []
    if rfi.owner_name:
        s = next((x for x in stakeholders if x.name == rfi.owner_name), None)
        return [s] if s else []
    return []


def _sort_rfis(rfis, sort, direction):
    keys = {
        "id": lambda r: r.rfi_id,
        "question": lambda r: (r.question or "").lower(),
        "status": lambda r: RFI_STATUSES.index(r.status) if r.status in RFI_STATUSES else len(RFI_STATUSES),
        "requester": lambda r: (r.requester_name or "").lower(),
        "sla": lambda r: r.due_date or date.max,
    }
    keyfn = keys.get((sort or "").strip())
    if keyfn:
        rfis = sorted(rfis, key=keyfn, reverse=(direction == "desc"))
    return rfis


@bp.route("/")
def rfi_list():
    all_rfis = misp_store.list_rfis()
    sla_map = {r.id: _sla_status(r) for r in all_rfis}
    sla = {r.id: _sla_label(*sla_map[r.id]) for r in all_rfis}
    status_filter = (request.args.get("status") or "").strip()
    priority_filter = (request.args.get("priority") or "").strip()
    sla_filter = (request.args.get("sla") or "").strip()
    # Closed RFIs are done with, so the list leaves them out until asked for
    # them, or for their status.
    show_closed = request.args.get("closed") == "1"
    hide_closed = not status_filter and not show_closed

    tests = {}
    if status_filter:
        tests["status"] = lambda r: r.status == status_filter
    if priority_filter:
        tests["priority"] = lambda r: r.priority == priority_filter
    if sla_filter:
        tests["sla"] = lambda r: sla[r.id] == sla_filter
    if hide_closed:
        tests["closed"] = lambda r: r.status != "Closed"
    rfis = _sort_rfis(matching(all_rfis, tests), request.args.get("sort"), request.args.get("dir"))
    return render_template(
        "rfi/list.html",
        rfis=rfis,
        sla_map=sla_map,
        statuses=RFI_STATUSES,
        priorities=RFI_PRIORITIES,
        sla_labels=SLA_LABELS,
        status_filter=status_filter,
        priority_filter=priority_filter,
        sla_filter=sla_filter,
        show_closed=show_closed,
        hide_closed=hide_closed,
        closed_count=sum(1 for r in matching(all_rfis, tests, skip="closed") if r.status == "Closed"),
        status_counts=ordered_counts((r.status for r in rfis), RFI_STATUSES),
        priority_counts=ordered_counts((r.priority for r in matching(all_rfis, tests, skip="priority")), RFI_PRIORITIES),
        sla_counts=ordered_counts((sla[r.id] for r in matching(all_rfis, tests, skip="sla")), SLA_LABELS),
        triage_checklist=RFI_TRIAGE_CHECKLIST,
    )


@bp.route("/new", methods=["GET", "POST"])
def rfi_new():
    stakeholders = misp_store.list_stakeholders()
    pirs = misp_store.list_selectable_pirs()
    girs = misp_store.list_girs()
    if request.method == "POST":
        # The id is a placeholder; create_rfi allocates the authoritative
        # rfi_id atomically and writes it back into data.
        data = _form_data(request.form, "")
        data["status"] = "New"
        # Resolve owner_name from selected stakeholder
        if data["owner_uuid"]:
            owner = next((s for s in stakeholders if s.id == data["owner_uuid"]), None)
            if owner:
                data["owner_name"] = owner.name
        if not data.get("due_date"):
            data["due_date"] = _suggested_due_date(data["priority"])
        try:
            uuid = misp_store.create_rfi(data)
            rfi_id = data["rfi_id"]
            audit.record("create", "rfi", entity_id=uuid, entity_label=rfi_id)
            flash(f"{rfi_id} created.", "success")
            return redirect(url_for("rfi.rfi_detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create RFI: {exc}", "warning")

    return render_template(
        "rfi/form.html",
        rfi=None,
        stakeholders=stakeholders,
        pirs=pirs,
        girs=girs,
        priorities=RFI_PRIORITIES,
        statuses=RFI_STATUSES,
        output_formats=cti_products(),
        tlp_levels=TLP_LEVELS,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
        sla_days=misp_store.RFI_SLA_DAYS,
        estimative_confidence=misp_store.ESTIMATIVE_CONFIDENCE,
    )


@bp.route("/<string:id>")
def rfi_detail(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    sla_state, days_remaining = _sla_status(rfi)
    linked_pir = misp_store.get_pir(rfi.linked_pir_uuid) if rfi.linked_pir_uuid else None
    linked_gir = misp_store.get_gir(rfi.linked_gir_uuid) if rfi.linked_gir_uuid else None
    feedback = misp_store.list_product_feedback(rfi.id)
    auto_acknowledged = audit.has_event(
        "acknowledge",
        "rfi",
        entity_id=id,
        details_contains="auto via notify",
    )
    return render_template(
        "rfi/detail.html",
        rfi=rfi,
        triage_checklist=RFI_TRIAGE_CHECKLIST,
        sla_state=sla_state,
        days_remaining=days_remaining,
        linked_pir=linked_pir,
        linked_gir=linked_gir,
        feedback=feedback,
        auto_acknowledged=auto_acknowledged,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
        output_formats=cti_products(),
        tlp_levels=TLP_LEVELS,
        estimative_confidence=misp_store.ESTIMATIVE_CONFIDENCE,
        can_publish=misp_session.current_user_can_publish(),
    )


@bp.route("/<string:id>/response", methods=["POST"])
def rfi_response(id):
    """Save the response card's inline edit: the response, its confidence and
    the preferred output formats, leaving the rest of the RFI as stored."""
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    if rfi.status == "New":
        flash("Triage this RFI before recording a response.", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    data = _rfi_data_from_store(rfi)
    try:
        data["output_format_list"] = _output_formats(request.form)
        data["response"] = request.form.get("response", "")
        data["response_confidence"] = request.form.get("response_confidence") or ""
        misp_store.update_rfi(id, data)
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id, details="response")
        flash(f"{rfi.rfi_id} response saved.", "success")
    except Exception as exc:
        flash(f"Could not save the response: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/feedback", methods=["POST"])
def rfi_feedback(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    data = _rfi_data_from_store(rfi)
    data["feedback_requirement_met"] = request.form.get("feedback_requirement_met", "")
    data["feedback_on_time"] = request.form.get("feedback_on_time", "")
    data["feedback_usefulness"] = request.form.get("feedback_usefulness", "")
    data["feedback_suggestions"] = request.form.get("feedback_suggestions", "").strip()
    try:
        misp_store.update_rfi(id, data)
        audit.record("update", "rfi_feedback", entity_id=id, entity_label=rfi.rfi_id)
        flash("Feedback saved.", "success")
    except Exception as exc:
        logger.warning("rfi_feedback %s failed: %s", id, exc)
        flash(f"Could not save feedback: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def rfi_edit(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    stakeholders = misp_store.list_stakeholders()
    pirs = misp_store.list_selectable_pirs(rfi.linked_pir_uuid)
    girs = misp_store.list_girs()
    if request.method == "POST":
        data = _form_data(request.form, rfi.rfi_id)
        # The status changes through triage and the status board only. The
        # checklist answers given at triage can be corrected here.
        data["status"] = rfi.status
        triage_keys = [key for key, _ in RFI_TRIAGE_CHECKLIST]
        data["triage_checklist"] = [k for k in request.form.getlist("triage_checklist") if k in triage_keys]
        if data["owner_uuid"]:
            owner = next((s for s in stakeholders if s.id == data["owner_uuid"]), None)
            if owner:
                data["owner_name"] = owner.name
        try:
            misp_store.update_rfi(id, data)
            audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
            flash(f"{rfi.rfi_id} updated.", "success")
            return redirect(url_for("rfi.rfi_detail", id=id))
        except Exception as exc:
            flash(f"Could not update RFI: {exc}", "warning")

    return render_template(
        "rfi/form.html",
        rfi=rfi,
        triage_checklist=RFI_TRIAGE_CHECKLIST,
        stakeholders=stakeholders,
        pirs=pirs,
        girs=girs,
        priorities=RFI_PRIORITIES,
        statuses=RFI_STATUSES,
        output_formats=cti_products(),
        tlp_levels=TLP_LEVELS,
        feedback_requirement=FEEDBACK_REQUIREMENT,
        feedback_on_time=FEEDBACK_ON_TIME,
        feedback_usefulness=FEEDBACK_USEFULNESS,
        sla_days=misp_store.RFI_SLA_DAYS,
        estimative_confidence=misp_store.ESTIMATIVE_CONFIDENCE,
    )


@bp.route("/<string:id>/delete", methods=["POST"])
def rfi_delete(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    label = rfi.rfi_id
    try:
        misp_store.delete_rfi(id)
        audit.record("delete", "rfi", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        logger.warning("rfi_delete %s failed: %s", id, exc)
        flash(f"Could not delete {label}: {exc}", "warning")
    return redirect(url_for("rfi.rfi_list"))


RFI_TRIAGE_CHECKLIST = [
    ("clear_question", "The request is a clear, answerable question."),
    ("requester_identified", "The requester and the decision it supports are identified."),
    ("not_duplicate", "It is not a duplicate of an existing RFI or product."),
    ("priority_realistic", "The priority and due date are realistic."),
    ("sources_available", "Sources or data to answer it are plausibly available."),
]


@bp.route("/<string:id>/triage", methods=["POST"])
def rfi_triage(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    if rfi.status != "New":
        flash("This RFI has already been triaged.", "warning")
        return redirect(url_for("rfi.rfi_list"))
    decision = request.form.get("decision", "").strip()
    if decision not in ("acknowledge", "reject"):
        flash("Select a triage decision.", "warning")
        return redirect(url_for("rfi.rfi_list"))
    reason = request.form.get("reason", "").strip()
    if decision == "reject" and not reason:
        flash("A reason is required to reject an RFI.", "warning")
        return redirect(url_for("rfi.rfi_list"))

    data = _rfi_data_from_store(
        rfi, status="Acknowledged" if decision == "acknowledge" else "Closed"
    )
    data["triaged_by"] = misp_session.current_user_email()
    data["triaged_at"] = date.today().isoformat()
    data["triage_checklist"] = request.form.getlist("triage_checklist")
    data["rejection_reason"] = reason if decision == "reject" else ""
    try:
        misp_store.update_rfi(id, data)
        # Record the rejection reason as a note so it is visible on the RFI.
        if decision == "reject":
            misp_store.add_rfi_note(id, "Rejection reason", reason)
        audit.record("triage", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        flash(f"{rfi.rfi_id} {'acknowledged' if decision == 'acknowledge' else 'rejected'}.", "success")
    except Exception as exc:
        flash(f"Could not triage RFI: {exc}", "warning")
    return redirect(url_for("rfi.rfi_list"))


@bp.route("/<string:id>/status", methods=["POST"])
def rfi_status_update(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return jsonify({"error": "RFI not found"}), 404
    new_status = request.form.get("status", "").strip()
    if new_status not in RFI_STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    if rfi.status == "New":
        return jsonify({"error": "Triage this RFI before moving it."}), 400
    if new_status == "New":
        return jsonify({"error": "An RFI cannot be moved back to New."}), 400
    data = _rfi_data_from_store(rfi, status=new_status)
    try:
        misp_store.update_rfi(id, data)
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/<string:id>/notify", methods=["GET", "POST"])
def rfi_notify(id):
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    if rfi.status == "New":
        if request.method == "POST":
            flash("Triage this RFI before notifying stakeholders.", "warning")
            return redirect(url_for("rfi.rfi_detail", id=id))
        return jsonify({"error": "Triage this RFI before notifying stakeholders."}), 400
    preview_url = url_for("rfi.rfi_detail", id=id, _external=True)
    today = date.today().strftime('%d-%m-%Y')
    lines = [
        f"# {rfi.rfi_id}: Request for Information",
        "",
        f"**Date:** {today}",
        f"**Status:** {rfi.status}",
        f"**Priority:** {rfi.priority}",
        f"**TLP:** TLP:{(rfi.deliverable_tlp or 'AMBER').upper()}",
        "",
        "## Question",
        "",
        f"{rfi.question}",
    ]
    if rfi.context:
        lines += ["", f"**Context:** {rfi.context}"]
    if rfi.requester_name:
        lines += ["", f"**Requester:** {rfi.requester_name}" + (f" ({rfi.requester_team})" if rfi.requester_team else "")]
    if rfi.due_date:
        lines += [f"**Due:** {rfi.due_date.strftime('%d-%m-%Y')}"]
    if rfi.response:
        lines += ["", "## Response", ""]
        if rfi.response_confidence:
            lines += [f"*Confidence: {rfi.response_confidence.capitalize()}*", ""]
        lines += [rfi.response]
    lines += ["", "[Open RFI preview](" + preview_url + ")", "", "---", f"*Sent from zsazsa CTI on {today}*"]
    md = "\n".join(lines)
    recipients = _rfi_notify_recipients(rfi)
    # The response is intelligence under the RFI's TLP: like a product, it only
    # reaches a stakeholder cleared for it.
    blocked = [s for s in recipients
               if rfi.response and not misp_store._tlp_cleared(s.tlp_clearance, rfi.deliverable_tlp)]
    recipients = [s for s in recipients if s not in blocked]

    from notifier import dispatcher

    if request.method == "POST":
        # Sending the response takes the same right as delivering a product.
        if rfi.response and not misp_session.current_user_can_publish():
            flash(misp_session.publish_denied_message("send the response to an RFI"), "warning")
            return redirect(url_for("rfi.rfi_detail", id=id))
        try:
            message_md = request.form.get("markdown", "").strip() or md
            notify_jobs.start_preview(
                "notify-rfi",
                f"{rfi.rfi_id} notification",
                lambda: dispatcher.send_rfi_preview(
                    rfi, preview_url=preview_url, markdown=message_md, stakeholders=recipients),
                entity_type="rfi",
                entity_id=id,
                entity_label=rfi.rfi_id,
                user=misp_session.current_user_email(),
            )
            flash("Notification is being sent in the background; the job badge reports the result.", "info")
        except Exception as exc:
            logger.exception("RFI notify failed: rfi=%s", rfi.rfi_id)
            flash(f"Could not start the notification: {exc}", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    diagnostics = dispatcher.describe_delivery(recipients)
    return jsonify({
        "markdown": md,
        "preview_url": preview_url,
        "recipient_count": diagnostics["recipients"],
        "recipient_names": diagnostics["recipient_names"],
        "channel_types": diagnostics["channel_types"],
        "channels_by_type": diagnostics["channels_by_type"],
        "not_cleared": (f"{blocked[0].name} is not cleared for TLP:{(rfi.deliverable_tlp or 'amber').upper()}"
                        if blocked else ""),
    })


def _is_ajax():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


def _an_fragment(id):
    """Render the attachments & notes section (editable) as an HTML fragment,
    used to refresh that section in place after an AJAX add/delete."""
    rfi = misp_store.get_rfi(id)
    return render_template("rfi/_attachments_notes.html", rfi=rfi, editable=True)


@bp.route("/<string:id>/attachments", methods=["POST"])
def rfi_attachment_add(id):
    ajax = _is_ajax()
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    f = request.files.get("attachment")
    if not f or not f.filename:
        if ajax:
            return "No file selected.", 400
        flash("No file selected.", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    try:
        misp_store.add_rfi_attachment(id, f.filename, f.read())
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        if ajax:
            return _an_fragment(id)
        flash(f"Attachment '{f.filename}' added.", "success")
    except Exception as exc:
        if ajax:
            return f"Could not add attachment: {exc}", 500
        flash(f"Could not add attachment: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/attachments/<string:attr_uuid>/delete", methods=["POST"])
def rfi_attachment_delete(id, attr_uuid):
    ajax = _is_ajax()
    rfi = misp_store.get_rfi(id)
    if rfi is None or not any(a.uuid == attr_uuid for a in rfi.attachments):
        return "Attachment not found", 404
    label = rfi.rfi_id
    try:
        misp_store.delete_rfi_attachment(attr_uuid)
        audit.record("update", "rfi", entity_id=id, entity_label=label)
        if ajax:
            return _an_fragment(id)
        flash("Attachment deleted.", "success")
    except Exception as exc:
        if ajax:
            return f"Could not delete attachment: {exc}", 500
        flash(f"Could not delete attachment: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/attachments/<string:attr_uuid>/download")
def rfi_attachment_download(id, attr_uuid):
    rfi = misp_store.get_rfi(id)
    if rfi is None or not any(a.uuid == attr_uuid for a in rfi.attachments):
        return "Attachment not found", 404
    try:
        content, filename = misp_store.get_rfi_attachment_content(attr_uuid)
        return Response(
            content,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
            mimetype="application/octet-stream",
        )
    except Exception as exc:
        flash(f"Download failed: {exc}", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/notes", methods=["POST"])
def rfi_note_add(id):
    ajax = _is_ajax()
    rfi = misp_store.get_rfi(id)
    if rfi is None:
        return "RFI not found", 404
    title = (request.form.get("note_title") or "").strip()
    content = (request.form.get("note_content") or "").strip()
    if not title:
        if ajax:
            return "Note title is required.", 400
        flash("Note title is required.", "warning")
        return redirect(url_for("rfi.rfi_detail", id=id))
    try:
        misp_store.add_rfi_note(id, title, content)
        audit.record("update", "rfi", entity_id=id, entity_label=rfi.rfi_id)
        if ajax:
            return _an_fragment(id)
        flash(f"Note '{title}' added.", "success")
    except Exception as exc:
        if ajax:
            return f"Could not add note: {exc}", 500
        flash(f"Could not add note: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))


@bp.route("/<string:id>/notes/<string:report_id>/delete", methods=["POST"])
def rfi_note_delete(id, report_id):
    ajax = _is_ajax()
    rfi = misp_store.get_rfi(id)
    if rfi is None or not any(str(n.id) == report_id for n in rfi.notes):
        return "Note not found", 404
    label = rfi.rfi_id
    try:
        misp_store.delete_rfi_note(report_id)
        audit.record("update", "rfi", entity_id=id, entity_label=label)
        if ajax:
            return _an_fragment(id)
        flash("Note deleted.", "success")
    except Exception as exc:
        if ajax:
            return f"Could not delete note: {exc}", 500
        flash(f"Could not delete note: {exc}", "warning")
    return redirect(url_for("rfi.rfi_detail", id=id))
