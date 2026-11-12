"""Detection Engineering Request (DER) routes.

A request from CTI to the detection engineering team: "build a detection for
this technique/actor/campaign." Mirrors the VEA product's structure (draft ->
pending-review -> approved/rejected, with notifications and PDF export on
publish), swapping the CVE-specific fields for technique/hypothesis/log
sources/expected output/test cases.
"""

import logging
from types import SimpleNamespace

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for
from webapp.routes.source_event_utils import (
    flattened_references,
    linked_pir_uuid,
    lookup_source_event_meta,
    normalise_source_event_rows,
    parse_source_tokens,
    source_event_cves,
    source_event_references,
    source_tag_values,
)

from core.rulezet_lookup import validate_rule
from core.vuln_lookup import CVE_RE
from webapp import audit, branding, misp_session, misp_store, notify_jobs, product_log
from webapp.models import STAKEHOLDER_ROLES
from webapp.utils import TLP_NAMES, matching, md_to_html, ordered_counts, sort_products, tlp_counts, tlp_of

logger = logging.getLogger(__name__)
bp = Blueprint("detection_eng", __name__, url_prefix="/products/detection-eng")


@bp.route("/source-event-meta")
def source_event_meta():
    return lookup_source_event_meta(request.args)


def _cve_ids(raw):
    """The CVE field split on commas, semicolons and white space, each entry once."""
    return list(dict.fromkeys(raw.replace(",", " ").replace(";", " ").upper().split()))


def _cve_warning(cve_ids):
    not_cves = [c for c in cve_ids if not CVE_RE.fullmatch(c)]
    if not_cves:
        return f"Not a CVE ID: {', '.join(not_cves)}. Write each as CVE-2024-3400."
    return ""


def _seed_from_sources(source_uuids, source_hints):
    """A new request filled in from the events it is made from: they are its
    triggering events, and their ATT&CK techniques and CVEs are filled in."""
    if not source_uuids:
        return None, []
    source_events = misp_store.fetch_source_events(source_uuids, source_hints=source_hints,
                                                   strict_source=bool(source_hints))
    # Only CVE IDs: the field refuses the GHSA and vendor IDs a vulnerability
    # attribute can also hold.
    cve_ids = [c.upper() for c in source_event_cves(source_uuids, source_events) if CVE_RE.fullmatch(c)]
    seed = SimpleNamespace(
        der_id="", title="", hypothesis="", expected_output="", format="", priority="",
        technique=source_tag_values(source_events, "misp-galaxy:mitre-attack-pattern="),
        cve_ids=list(dict.fromkeys(cve_ids)),
        log_sources=[], existing_coverage=[], test_cases=[],
        status=misp_store.DER_STATUS_PENDING, review_state=misp_store.DER_REVIEW_DRAFT,
        tlp="amber", author="", audience="", linked_pir_uuid="",
        source_event_uuids=source_uuids, source_event_hints=source_hints,
        source_event_uuid=source_uuids[0],
    )
    return seed, source_events


def _form_data(form, der_id=""):
    source_event_refs = form.getlist("source_event_url_item") or form.getlist("source_event_uuid_item")
    source_event_servers = form.getlist("source_event_server_item")
    source_event_uuids, source_event_hints = normalise_source_event_rows(source_event_refs, source_event_servers)

    return {
        "der_id": der_id,
        "title": form.get("title", "").strip(),
        "technique": form.getlist("technique"),
        "cve_ids": _cve_ids(form.get("cve_ids", "")),
        "log_sources": misp_store._split_lines(form.get("log_sources")),
        "hypothesis": form.get("hypothesis", "").strip(),
        "expected_output": form.get("expected_output", "").strip(),
        "existing_coverage": misp_store._split_lines(form.get("existing_coverage")),
        "test_cases": misp_store._split_lines(form.get("test_cases")),
        # On edit these two are replaced with the stored values (see
        # wizard_edit): the rule has its own form on the detail page, which
        # knows when it may change.
        "format": form.get("format", ""),
        "draft_rule": form.get("draft_rule", "").strip(),
        "priority": form.get("priority", ""),
        # status is intentionally not read from the form: it only ever changes
        # through set_status/status_update, which enforce the Pending gate and
        # the Rulezet validation required to reach Active. See wizard_edit,
        # which sets it explicitly from the existing request.
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", ""),
        "audience": ", ".join(form.getlist("audience")),
        "review_state": form.get("review_state", misp_store.DER_REVIEW_DRAFT),
        "source_event_uuids": source_event_uuids,
        "source_event_hints": source_event_hints,
        "source_event_uuid": source_event_uuids[0] if source_event_uuids else "",
        "linked_pir_uuid": form.get("linked_pir_uuid", ""),
    }


def _wizard_context(der=None, source_events=None):
    return {
        "der": der,
        "audiences": misp_store.FIA_AUDIENCES,
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "review_states": misp_store.DER_REVIEW_STATES,
        "priorities": misp_store.DER_PRIORITIES,
        "formats": misp_store.DER_FORMATS,
        "statuses": misp_store.DER_STATUSES,
        "pirs": misp_store.list_selectable_pirs(linked_pir_uuid(der)),
        "galaxy_mitre_attack": misp_store.galaxy_mitre_attack_patterns(),
        "source_event_tags": sorted({t for ev in (source_events or []) for t in ev.get("tags", [])}),
        "can_publish": misp_session.current_user_can_publish(),
    }


def _deliver_der(uuid, preview_url, reason):
    """Build the closure that sends a request to its channels.

    Runs on the job thread, so it re-reads the request rather than closing
    over one fetched in the request. `preview_url` is resolved by the caller:
    only the request knows the app's external address.
    """
    def deliver(log):
        from notifier import dispatcher

        der = misp_store.get_der(uuid)
        if der is None:
            return False, "the request could not be loaded"

        stakeholders = misp_store.eligible_recipients("Detection engineering request", der.tlp, der.audience)
        markdown = misp_store.render_der_markdown(der, preview_url=preview_url)
        log(f"{reason}: {len(stakeholders)} eligible recipient(s).")

        ok, detail = notify_jobs.to_channels(
            lambda: dispatcher.send_detection_eng_request(der, markdown, stakeholders), log)
        return ok, detail

    return deliver


def _start_der_delivery(der_id, uuid, reason):
    """Hand a request's delivery to a background job."""
    return notify_jobs.start(
        "notify-der",
        f"{der_id} delivery",
        _deliver_der(uuid, url_for("detection_eng.detail", id=uuid, _external=True), reason),
        entity_type="detection_eng",
        entity_id=uuid,
        entity_label=der_id,
        user=misp_session.current_user_email(),
    )


# The priorities, most urgent first, as the list's filter and bar order them.
PRIORITIES = misp_store.DER_PRIORITIES[::-1]


@bp.route("/")
def review():
    state_filter = (request.args.get("state") or "").strip()
    tlp_filter = (request.args.get("tlp") or "").strip()
    audience_filter = (request.args.get("audience") or "").strip()
    priority_filter = (request.args.get("priority") or "").strip()
    sort = (request.args.get("sort") or "").strip()
    direction = (request.args.get("dir") or "asc").strip()
    all_ders = misp_store.list_ders()
    tests = {}
    if state_filter:
        tests["state"] = lambda d: d.review_state == state_filter
    if tlp_filter:
        tests["tlp"] = lambda d: tlp_of(d) == tlp_filter
    if audience_filter:
        tests["audience"] = lambda d: misp_store.has_audience(d, audience_filter)
    if priority_filter:
        tests["priority"] = lambda d: d.priority == priority_filter
    ders = sort_products(matching(all_ders, tests), sort, direction)
    return render_template(
        "detection_eng/review.html",
        ders=ders,
        state_filter=state_filter,
        review_states=misp_store.DER_REVIEW_STATES,
        priority_filter=priority_filter,
        priorities=PRIORITIES,
        state_counts=ordered_counts((d.review_state for d in matching(all_ders, tests, skip="state")),
                                    misp_store.DER_REVIEW_STATES),
        status_counts=ordered_counts((d.status for d in ders), misp_store.DER_STATUSES),
        priority_counts=ordered_counts((d.priority for d in matching(all_ders, tests, skip="priority")), PRIORITIES),
        tlp_filter=tlp_filter,
        audience_filter=audience_filter,
        tlp_choices=TLP_NAMES,
        audience_choices=STAKEHOLDER_ROLES,
        tlp_counts=tlp_counts(matching(all_ders, tests, skip="tlp")),
        audience_counts=misp_store.audience_counts(matching(all_ders, tests, skip="audience")),
        can_publish=misp_session.current_user_can_publish(),
        sort=sort,
        dir=direction,
    )


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        if request.form.get("prefill_only") == "1":
            source_uuids, source_hints, _source_pairs = parse_source_tokens(request.form.getlist("source"))
            seed, source_events = _seed_from_sources(source_uuids, source_hints)
            return render_template("detection_eng/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(seed, source_events))

        data = _form_data(request.form)
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints=source_hints, strict_source=bool(source_hints)
        )
        if not data["title"]:
            flash("Title is required.", "warning")
            return render_template("detection_eng/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(data, source_events))
        cve_warning = _cve_warning(data["cve_ids"])
        if cve_warning:
            flash(cve_warning, "warning")
            return render_template("detection_eng/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(data, source_events))
        action = request.form.get("action", "save")
        data["review_state"] = (misp_store.DER_REVIEW_PENDING
                                if action == "submit" else misp_store.DER_REVIEW_DRAFT)
        try:
            uuid, der_id = misp_store.create_der(data)
            product_log.log_product_sources(data.get("source_event_uuids") or [], "detection-eng-request",
                                            data.get("source_event_hints"))
            audit.record("create", "detection_eng", entity_id=uuid, entity_label=der_id)
            flash(f"{der_id} {'submitted for review' if action == 'submit' else 'saved as draft'}.", "success")
            return redirect(url_for("detection_eng.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create detection engineering request: {exc}", "warning")
    source_uuids, source_hints, _source_pairs = parse_source_tokens(request.args.getlist("source"))
    seed, source_events = _seed_from_sources(source_uuids, source_hints)
    return render_template("detection_eng/wizard.html", is_edit=False,
                           source_events=source_events, **_wizard_context(seed, source_events))


@bp.route("/<string:id>")
def detail(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    feedback = misp_store.list_product_feedback(der.uuid)
    recipients = misp_store.recipient_preview("Detection engineering request", der.tlp, der.audience)
    notify_status = audit.latest_notify_status("detection_eng", id)
    linked_pir = None
    if getattr(der, "linked_pir_uuid", ""):
        try:
            linked_pir = misp_store.get_pir(der.linked_pir_uuid)
        except Exception:
            linked_pir = None
    source_refs = source_event_references(der)
    return render_template(
        "detection_eng/detail.html",
        der=der,
        reference_items=flattened_references([], source_refs),
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
        linked_pir=linked_pir,
        formats=misp_store.DER_FORMATS,
        format_hints=misp_store.DER_FORMAT_HINTS,
        statuses=misp_store.DER_STATUSES,
        can_publish=misp_session.current_user_can_publish(),
    )


@bp.route("/<string:id>/recipients")
def recipients_fragment(id):
    """Recipients preview for a request, loaded by the review page button."""
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    return render_template(
        "_recipients_preview.html",
        product_label="Detection engineering request",
        recipients=misp_store.recipient_preview("Detection engineering request", der.tlp, der.audience),
        tlp_label=der.tlp,
        audience_label=der.audience,
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    # Approval is final. An approved request has been sent to its stakeholders
    # and is what the engineering status tracks, so editing it here would
    # either change what they were sent without telling them, or (by
    # resubmitting it) drop it back into review while its status is In Dev or
    # further. The detail page only hides the Edit button; this is the check.
    if der.review_state == misp_store.DER_REVIEW_APPROVED:
        flash(f"{der.der_id} is published and can no longer be edited.", "warning")
        return redirect(url_for("detection_eng.detail", id=id))
    if request.method == "POST":
        data = _form_data(request.form, der_id=der.der_id)
        data["status"] = der.status
        data["review_state"] = der.review_state or misp_store.DER_REVIEW_DRAFT
        # The draft rule and its format are only changed through
        # set_draft_rule, which refuses while the request is Active. The
        # wizard has neither as an editable field, so whatever the form
        # posts for them is ignored rather than trusted.
        data["format"] = der.format
        data["draft_rule"] = der.draft_rule
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints=source_hints, strict_source=bool(source_hints)
        )
        cve_warning = _cve_warning(data["cve_ids"])
        if cve_warning:
            flash(cve_warning, "warning")
            return render_template("detection_eng/wizard.html", is_edit=True,
                                   source_events=source_events, **_wizard_context(data, source_events))
        action = request.form.get("action", "save")
        if action == "publish" and not misp_session.current_user_can_publish():
            flash(misp_session.publish_denied_message("approve and publish"), "warning")
            action = "save"
        if action == "publish" and not data["audience"].strip():
            flash("A target audience is required before publishing. Select an audience first.", "warning")
            action = "save"
        if action == "submit":
            data["review_state"] = misp_store.DER_REVIEW_PENDING
        elif action == "publish":
            data["review_state"] = misp_store.DER_REVIEW_APPROVED
        try:
            misp_store.update_der(id, data)
            audit.record("update", "detection_eng", entity_id=id, entity_label=der.der_id)
            if action == "publish":
                in_misp = misp_store.publish_der(id)
                audit.record("publish", "detection_eng", entity_id=id, entity_label=der.der_id)
                _start_der_delivery(der.der_id, id, "publish")
                flash(f"{der.der_id} published.", "success")
                if not in_misp:
                    flash(misp_store.MISP_NOT_PUBLISHED, "warning")
                flash("Notifications are being sent in the background; the job badge reports the result.", "info")
            else:
                flash(f"{der.der_id} saved.", "success")
            return redirect(url_for("detection_eng.detail", id=id))
        except Exception as exc:
            flash(f"Could not update detection engineering request: {exc}", "warning")
            return render_template("detection_eng/wizard.html", is_edit=True,
                                   source_events=source_events, **_wizard_context(data, source_events))
    source_uuids = list(getattr(der, "source_event_uuids", []) or ([der.source_event_uuid] if getattr(der, "source_event_uuid", "") else []))
    source_hints = dict(getattr(der, "source_event_hints", {}) or {})
    source_events = misp_store.fetch_source_events(
        source_uuids, source_hints=source_hints, strict_source=bool(source_hints)
    ) if source_uuids else []
    return render_template("detection_eng/wizard.html", is_edit=True,
                           source_events=source_events, **_wizard_context(der, source_events))


@bp.route("/<string:id>/draft-rule", methods=["POST"])
def set_draft_rule(id):
    """Save the actual rule being built, ahead of Rulezet validation and approval."""
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    # An Active request's rule is the one that passed Rulezet when it was
    # signed off. Saving a new one over it here would skip that check, so the
    # request has to be moved back (to In Test, say) first; setting it Active
    # again then validates the new rule.
    if der.status == misp_store.DER_STATUS_ACTIVE:
        flash(f"{der.der_id} is Active, so its rule cannot be changed. Move it back to In Test first; "
              "marking it Active again validates the new rule.", "warning")
        return redirect(url_for("detection_eng.detail", id=id))
    fmt = request.form.get("format", "").strip()
    draft_rule = request.form.get("draft_rule", "").strip()
    try:
        misp_store.update_der(id, misp_store._der_data(der, format=fmt, draft_rule=draft_rule))
        audit.record("update", "detection_eng", entity_id=id, entity_label=f"{der.der_id} draft rule updated")
        flash(f"{der.der_id} draft rule saved.", "success")
    except Exception as exc:
        flash(f"Could not save draft rule: {exc}", "warning")
    return redirect(url_for("detection_eng.detail", id=id))


@bp.route("/<string:id>/approve", methods=["POST"])
def approve(id):
    return_url = (url_for("detection_eng.review") if request.form.get("return_to") == "review"
                  else url_for("detection_eng.detail", id=id))
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    if der.review_state == misp_store.DER_REVIEW_APPROVED:
        flash(f"{der.der_id} is already published. Resend delivers it again.", "warning")
        return redirect(return_url)
    if not (der.audience or "").strip():
        flash("A target audience is required before publishing. Edit the request and select an audience first.", "warning")
        return redirect(return_url)
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("approve and publish"), "warning")
        return redirect(return_url)
    try:
        in_misp = misp_store.publish_der(id)
        audit.record("publish", "detection_eng", entity_id=id, entity_label=der.der_id)
        _start_der_delivery(der.der_id, id, "publish")
        flash(f"{der.der_id} approved and published.", "success")
        if not in_misp:
            flash(misp_store.MISP_NOT_PUBLISHED, "warning")
        flash("Notifications are being sent in the background; the job badge reports the result.", "info")
    except Exception as exc:
        flash(f"Could not publish detection engineering request: {exc}", "warning")
    return redirect(return_url)


@bp.route("/<string:id>/reject", methods=["POST"])
def reject(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    # Only a request still in review can be rejected. Rejecting an approved one
    # would leave its engineering status (In Dev, Active, ...) on a request
    # that is no longer approved; one that is no longer wanted is Retired.
    if der.review_state == misp_store.DER_REVIEW_APPROVED:
        flash(f"{der.der_id} is already published; retire it from the engineering status instead.", "warning")
        return redirect(url_for("detection_eng.detail", id=id))
    reason = request.form.get("reason", "").strip()
    try:
        misp_store.reject_der(id, reason=reason)
        audit.record("reject", "detection_eng", entity_id=id, entity_label=der.der_id)
        flash(f"{der.der_id} rejected.", "info")
    except Exception as exc:
        flash(f"Could not reject detection engineering request: {exc}", "warning")
    return redirect(url_for("detection_eng.detail", id=id))


def _is_completion(der, status):
    """Whether moving `der` to `status` is the request being delivered.

    Only the first move into Active counts. From Retired it is the same
    detection being switched back on, and stakeholders were told when it
    first went live; Resend is there if they need telling again.
    """
    return (status == misp_store.DER_STATUS_ACTIVE
            and der.status not in (misp_store.DER_STATUS_ACTIVE, misp_store.DER_STATUS_RETIRED))


def _apply_der_status(der, status):
    """Move a request's engineering status, enforcing the same rules
    regardless of caller (detail page dropdown or kanban drag-and-drop).

    Pending is the untriaged state: every other status requires the request
    itself to be approved, mirroring how a PIR only leaves Pending after intake
    triage. Checking this on the target rather than only when leaving Pending
    also covers requests written before approval was made final. Moving into
    Active additionally requires a draft rule that currently passes Rulezet
    validation, so nothing can be signed off as delivered with a rule that
    does not parse, and publish rights, because the first move into Active
    notifies every stakeholder.

    Setting the status a request already has changes nothing and sends
    nothing, so a resubmitted form or a card dropped back on its own column
    does not notify anyone twice.

    Returns None on success, or an error message.
    """
    if status not in misp_store.DER_STATUSES:
        return "Invalid status."
    if status == der.status:
        return None
    if status != misp_store.DER_STATUS_PENDING and der.review_state != misp_store.DER_REVIEW_APPROVED:
        return "Approve this request before tracking its engineering status."
    if status == misp_store.DER_STATUS_PENDING:
        return "A request cannot be moved back to Pending."
    if status == misp_store.DER_STATUS_ACTIVE:
        if not misp_session.current_user_can_publish():
            return misp_session.publish_denied_message("mark a request Active")
        if not (der.format or "").strip() or not (der.draft_rule or "").strip():
            return "A draft rule (with its format) is required, and must pass Rulezet validation, before marking this Active."
        result = validate_rule(der.format, der.draft_rule)
        if result is None:
            return "Could not reach Rulezet to validate the draft rule. This request cannot be marked Active until it can be validated."
        if "error" in result:
            return f"Rulezet could not validate the draft rule: {result['error']}"
        if not result.get("valid"):
            return "Draft rule failed Rulezet validation: " + "; ".join(result.get("errors") or ["no details returned."])

    try:
        misp_store.update_der(der.uuid, misp_store._der_data(der, status=status))
    except Exception as exc:
        logger.warning("DER %s status change to %s failed: %s", der.der_id, status, exc)
        return f"Could not update the status: {exc}"
    audit.record("update", "detection_eng", entity_id=der.uuid, entity_label=f"{der.der_id} status={status}")
    if _is_completion(der, status):
        _start_der_delivery(der.der_id, der.uuid, "completed")
    return None


@bp.route("/<string:id>/status", methods=["POST"])
def set_status(id):
    """Update the engineering team's own progress tracker, independent of the
    publish workflow above (a request stays 'approved' while its status moves
    Pending -> In Dev -> In Test -> Active -> Retired)."""
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    status = request.form.get("status", "").strip()
    if status == der.status:
        flash(f"{der.der_id} is already {status}.", "info")
        return redirect(url_for("detection_eng.detail", id=id))
    error = _apply_der_status(der, status)
    if error:
        flash(error, "warning")
        return redirect(url_for("detection_eng.detail", id=id))
    flash(f"{der.der_id} status set to {status}.", "success")
    if _is_completion(der, status):
        flash("Completion notifications are being sent in the background; the job badge reports the result.", "info")
    return redirect(url_for("detection_eng.detail", id=id))


@bp.route("/<string:id>/status-update", methods=["POST"])
def status_update(id):
    """JSON status update for the kanban board's drag-and-drop."""
    der = misp_store.get_der(id)
    if der is None:
        return jsonify({"error": "Detection engineering request not found"}), 404
    status = request.form.get("status", "").strip()
    error = _apply_der_status(der, status)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True, "status": status})


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    der = misp_store.get_der(id)
    label = der.der_id if der else id
    if der and der.review_state == misp_store.DER_REVIEW_APPROVED:
        flash("Published requests cannot be deleted.", "warning")
        return redirect(url_for("detection_eng.detail", id=id))
    try:
        misp_store.delete_der(id)
        audit.record("delete", "detection_eng", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete detection engineering request: {exc}", "warning")
    return redirect(url_for("detection_eng.review"))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    if request.form.get("next") == "detail":
        redirect_target = url_for("detection_eng.detail", id=id)
    else:
        redirect_target = url_for("detection_eng.review")
    if getattr(der, "review_state", "") != misp_store.DER_REVIEW_APPROVED:
        flash("Only published requests can be resent.", "warning")
        return redirect(redirect_target)
    # A resend reaches the same stakeholders as publishing it did, so it needs
    # the same rights.
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("resend"), "warning")
        return redirect(redirect_target)

    _start_der_delivery(der.der_id, id, "resend")
    flash(f"{der.der_id} resend started; the job badge reports the result.", "info")
    return redirect(redirect_target)


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        in_misp = misp_store.add_product_feedback(der.uuid, author, rating, comment,
                                                    published=der.published)
        audit.record("create", "detection_eng_feedback", entity_id=id, entity_label=der.der_id)
        flash("Feedback recorded.", "success")
        if not in_misp:
            flash(misp_store.MISP_NOT_PUBLISHED, "warning")
    except Exception as exc:
        logger.warning("add_feedback DER %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("detection_eng.detail", id=id))


@bp.route("/<string:id>/pdf")
def pdf(id):
    der = misp_store.get_der(id)
    if der is None:
        return "Detection engineering request not found", 404
    html = render_template(
        "detection_eng/pdf.html",
        der=der,
        css_url=branding.pdf_css_url(),
        brand=branding.brand(),
        hypothesis_html=md_to_html(der.hypothesis or ""),
        expected_output_html=md_to_html(der.expected_output or ""),
    )
    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("pdf: weasyprint failed for DER %s: %s", id, exc)
        return f"PDF generation failed: {exc}", 500
    filename = f"{der.der_id}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
