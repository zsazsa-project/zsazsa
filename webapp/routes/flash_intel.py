"""Flash Intel Alert (FIA) routes.

Manual wizard for creating and reviewing flash intel alerts. Auto-generated
drafts from the analyser pipeline land in the same review queue.
"""

import logging
from types import SimpleNamespace

import config as _cfg

from flask import Blueprint, flash, redirect, render_template, request, url_for, Response

from webapp import audit, branding, misp_store, product_log
from webapp.utils import md_to_html, sort_products
from webapp.routes.source_event_utils import (
    flattened_references,
    lookup_source_event_meta,
    normalise_source_event_rows,
    parse_source_tokens,
    source_event_references,
    source_event_urls_only,
)

logger = logging.getLogger(__name__)

bp = Blueprint("flash_intel", __name__, url_prefix="/products/flash-intel")


@bp.route("/source-event-meta")
def source_event_meta():
    return lookup_source_event_meta(request.args)


def _form_data(form, fia_id=""):
    source_event_refs = form.getlist("source_event_url_item") or form.getlist("source_event_uuid_item")
    source_event_servers = form.getlist("source_event_server_item")
    source_event_uuids, source_event_hints = normalise_source_event_rows(source_event_refs, source_event_servers)

    return {
        "fia_id": fia_id,
        "title": form.get("title", "").strip(),
        "audience": ", ".join(form.getlist("audience")),
        "tlp": form.get("tlp", "amber"),
        "summary": form.get("summary", ""),
        "action_required": form.get("action_required", ""),
        "what_happened": misp_store._split_lines(form.get("what_happened")),
        "source_description": form.get("source_description", ""),
        "source_reliability": form.get("source_reliability", ""),
        "information_credibility": form.get("information_credibility", ""),
        "likely_impact": form.get("likely_impact", ""),
        "affected_assets": form.get("affected_assets", ""),
        "actor_types": form.getlist("actor_types"),
        "actor_context": form.get("actor_context", ""),
        "mitre_attack_techniques": form.getlist("mitre_attack_techniques"),
        "geographic_scope": form.getlist("geographic_scope"),
        "sectors": form.getlist("sectors"),
        "threat_actors": form.getlist("threat_actors"),
        "threat_types": form.getlist("threat_types"),
        "technology": form.getlist("technology"),
        "vendor": form.getlist("vendor"),
        "incident": form.getlist("incident"),
        "campaign": form.getlist("campaign"),
        "actions_immediate": misp_store._split_lines(form.get("actions_immediate")),
        "actions_near_term": misp_store._split_lines(form.get("actions_near_term")),
        "mitre_techniques": misp_store._split_lines(form.get("mitre_techniques")),
        "hunting_hypotheses": misp_store._split_lines(form.get("hunting_hypotheses")),
        "external_references": [r.strip() for r in misp_store._split_lines(form.get("external_references"))
                                 if r.strip() and r.strip().startswith(("http://", "https://"))],
        "feedback_deadline": form.get("feedback_deadline") or "",
        "author": form.get("author", ""),
        "source_event_uuids": source_event_uuids,
        "source_event_hints": source_event_hints,
        "context_tags": form.getlist("context_tags"),
        "linked_pir_uuid": form.get("linked_pir_uuid", ""),
        "review_state": form.get("review_state", misp_store.FIA_REVIEW_DRAFT),
    }


def _wizard_context(fia=None, source_events=None):
    return {
        "fia": fia,
        "audiences": misp_store.FIA_AUDIENCES,
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "reliabilities": misp_store.FIA_RELIABILITIES,
        "credibilities": misp_store.FIA_CREDIBILITIES,
        "review_states": misp_store.FIA_REVIEW_STATES,
        "geo_items": misp_store.galaxy_geography(),
        "sector_items": misp_store.galaxy_sectors(),
        "threat_actor_items": misp_store.galaxy_threat_actors(),
        "threat_actor_types": getattr(_cfg, "THREAT_ACTOR_TYPES", []),
        "mitre_attack_items": misp_store.galaxy_mitre_attack_patterns(),
        "action_presets_immediate": getattr(_cfg, "RECOMMENDED_ACTIONS_IMMEDIATE", []),
        "action_presets_near_term": getattr(_cfg, "RECOMMENDED_ACTIONS_NEAR_TERM", []),
        "pirs": misp_store.list_pirs(),
        "source_event_tags": sorted({t for ev in (source_events or []) for t in ev.get("tags", [])}),
    }


def _extract_scope_from_tags(source_events):
    """Extract geographic, sector, and threat-actor scope from source event galaxy tags."""
    all_tags = [t for ev in source_events for t in ev.get("tags", [])]

    def _vals(prefixes):
        seen, result = set(), []
        for tag in all_tags:
            for prefix in prefixes:
                if tag.startswith(prefix):
                    val = tag[len(prefix):].strip().strip('"')
                    if val and val not in seen:
                        seen.add(val)
                        result.append(val)
                    break
        return result

    return (
        _vals(['misp-galaxy:country=', 'misp-galaxy:target-information=']),
        _vals(['misp-galaxy:sector=']),
        _vals(['misp-galaxy:threat-actor=']),
        _vals(['misp-galaxy:mitre-attack-pattern=']),
    )


def _seed_from_sources(source_uuids, source_hints=None):
    """Build a partial FIA seed from one or more source event UUIDs."""
    if not source_uuids:
        return None, []
    source_hints = source_hints or {}
    source_events = misp_store.fetch_source_events(source_uuids, source_hints, strict_source=bool(source_hints))
    title = source_events[0]["info"] if source_events else ""
    labels = list(dict.fromkeys(ev["source_label"] for ev in source_events if ev.get("source_label")))
    geographic_scope, sectors, threat_actors, mitre_attack_techniques = _extract_scope_from_tags(source_events)
    seed = SimpleNamespace(
        fia_id="",
        title=title,
        audience="", tlp="amber",
        summary="", action_required="",
        what_happened=[], source_description=", ".join(labels),
        source_reliability="", information_credibility="",
        likely_impact="", affected_assets="", actor_types=[], actor_context="",
        mitre_attack_techniques=mitre_attack_techniques,
        geographic_scope=geographic_scope, sectors=sectors, threat_actors=threat_actors,
        threat_types=[], technology=[], vendor=[], incident=[], campaign=[],
        actions_immediate=[], actions_near_term=[],
        mitre_techniques=[], hunting_hypotheses=[],
        external_references=[], feedback_deadline=None,
        author="", source_event_uuids=source_uuids,
        source_event_hints=source_hints,
        source_event_uuid=source_uuids[0] if source_uuids else "",
        review_state=misp_store.FIA_REVIEW_DRAFT,
        rejection_reason="", context_tags=[], linked_pir_uuid="",
    )
    return seed, source_events


def _eligible_flash_recipients(fia):
    allowed = {
        r.get("uuid")
        for r in misp_store.recipient_preview("Flash intel alert", fia.tlp, fia.audience)
        if r.get("status") == "green" and r.get("uuid")
    }
    if not allowed:
        return []
    return [s for s in misp_store.list_stakeholders() if getattr(s, "uuid", None) in allowed]


@bp.route("/")
def review():
    state_filter = (request.args.get("state") or "").strip() or None
    sort = (request.args.get("sort") or "").strip()
    direction = (request.args.get("dir") or "asc").strip()
    fias = misp_store.list_fias(review_state=state_filter)
    sort_products(fias, sort, direction)
    # The queue can hold dozens of alerts, so the preview rows use the reference
    # URLs the FIA already carries rather than resolving each one against MISP.
    reference_items_by_uuid = {
        f.uuid: flattened_references(
            list(getattr(f, "external_references", []) or []),
            source_event_urls_only(f),
        )
        for f in fias
    }
    return render_template(
        "flash_intel/review.html",
        fias=fias,
        reference_items_by_uuid=reference_items_by_uuid,
        state_filter=state_filter or "",
        review_states=misp_store.FIA_REVIEW_STATES,
        sort=sort,
        dir=direction,
    )


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        if request.form.get("prefill_only") == "1":
            source_uuids, source_hints, _ = parse_source_tokens(request.form.getlist("source"))
            seed, source_events = _seed_from_sources(source_uuids, source_hints)
            return render_template("flash_intel/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(seed, source_events))

        data = _form_data(request.form)
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints, strict_source=bool(source_hints)
        )
        if not data["title"]:
            flash("Title is required.", "warning")
            return render_template("flash_intel/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(data, source_events))
        action = request.form.get("action", "save")
        data["review_state"] = (misp_store.FIA_REVIEW_PENDING
                                if action == "submit" else misp_store.FIA_REVIEW_DRAFT)
        try:
            uuid, fia_id = misp_store.create_fia(data)
            product_log.log_product_sources(data.get("source_event_uuids") or [], "flash-intel")
            audit.record("create", "fia", entity_id=uuid, entity_label=fia_id)
            flash(f"{fia_id} {'submitted for review' if action == 'submit' else 'saved as draft'}.",
                  "success")
            return redirect(url_for("flash_intel.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create FIA: {exc}", "warning")
    source_uuids, source_hints, _ = parse_source_tokens(request.args.getlist("source"))
    seed, source_events = _seed_from_sources(source_uuids, source_hints)
    return render_template("flash_intel/wizard.html", is_edit=False,
                           source_events=source_events, **_wizard_context(seed, source_events))


@bp.route("/<string:id>")
def detail(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    feedback = misp_store.list_product_feedback(fia.uuid)
    recipients = misp_store.recipient_preview("Flash intel alert", fia.tlp, fia.audience)
    notify_status = audit.latest_notify_status("fia", id)
    source_refs = source_event_references(fia)
    return render_template(
        "flash_intel/detail.html",
        fia=fia,
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
        reference_items=flattened_references(list(fia.external_references or []), source_refs),
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    if request.method == "POST":
        data = _form_data(request.form, fia_id=fia.fia_id)
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints, strict_source=bool(source_hints)
        )
        action = request.form.get("action", "save")
        if action == "submit":
            data["review_state"] = misp_store.FIA_REVIEW_PENDING
        elif action == "publish":
            data["review_state"] = misp_store.FIA_REVIEW_APPROVED
        else:
            data["review_state"] = fia.review_state or misp_store.FIA_REVIEW_DRAFT
        try:
            misp_store.update_fia(id, data)
            audit.record("update", "fia", entity_id=id, entity_label=fia.fia_id)
            if action == "publish":
                ok, detail = _publish_and_notify(id)
                audit.record(
                    "notify",
                    "fia",
                    entity_id=id,
                    entity_label=fia.fia_id,
                    details=f"publish notification; result={'ok' if ok else 'failed'}; {detail}",
                )
                flash(f"{fia.fia_id} published.", "success")
                flash(f"Notifications: {detail}.", "success" if ok else "warning")
            else:
                flash(f"{fia.fia_id} saved.", "success")
            return redirect(url_for("flash_intel.detail", id=id))
        except Exception as exc:
            flash(f"Could not update FIA: {exc}", "warning")
            return render_template("flash_intel/wizard.html", is_edit=True,
                                   source_events=source_events, **_wizard_context(data, source_events))
    source_uuids = list(getattr(fia, "source_event_uuids", []) or [])
    source_hints = dict(getattr(fia, "source_event_hints", {}) or {})
    source_events = misp_store.fetch_source_events(source_uuids, source_hints, strict_source=bool(source_hints))
    return render_template("flash_intel/wizard.html", is_edit=True,
                           source_events=source_events, **_wizard_context(fia, source_events))


@bp.route("/<string:id>/approve", methods=["POST"])
def approve(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    if not (fia.audience or "").strip():
        flash("A target audience is required before publishing. Edit the alert and select an audience first.", "warning")
        return redirect(url_for("flash_intel.detail", id=id))
    try:
        ok, detail = _publish_and_notify(id)
        audit.record("publish", "fia", entity_id=id, entity_label=fia.fia_id)
        audit.record(
            "notify",
            "fia",
            entity_id=id,
            entity_label=fia.fia_id,
            details=f"publish notification; result={'ok' if ok else 'failed'}; {detail}",
        )
        flash(f"{fia.fia_id} approved and published.", "success")
        flash(f"Notifications: {detail}.", "success" if ok else "warning")
    except Exception as exc:
        flash(f"Could not publish FIA: {exc}", "warning")
    return redirect(url_for("flash_intel.detail", id=id))


@bp.route("/<string:id>/reject", methods=["POST"])
def reject(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    reason = request.form.get("reason", "").strip()
    try:
        misp_store.reject_fia(id, reason=reason)
        audit.record("reject", "fia", entity_id=id, entity_label=fia.fia_id)
        flash(f"{fia.fia_id} rejected.", "info")
    except Exception as exc:
        flash(f"Could not reject FIA: {exc}", "warning")
    return redirect(url_for("flash_intel.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    fia = misp_store.get_fia(id)
    label = fia.fia_id if fia else id
    try:
        misp_store.delete_fia(id)
        audit.record("delete", "fia", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete FIA: {exc}", "warning")
    return redirect(url_for("flash_intel.review"))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    if request.form.get("next") == "detail":
        redirect_target = url_for("flash_intel.detail", id=id)
    else:
        redirect_target = url_for("flash_intel.review")
    if getattr(fia, "review_state", "") != misp_store.FIA_REVIEW_APPROVED:
        flash("Only published alerts can be resent.", "warning")
        return redirect(redirect_target)

    content = misp_store.render_fia_markdown(fia, fia.fia_id, include_source_links=True)
    stakeholders = _eligible_flash_recipients(fia)

    try:
        from notifier import dispatcher

        summary = dispatcher.send_flash_intel(fia, content, stakeholders)
        ok, detail = dispatcher.delivery_outcome(summary)
        audit.record(
            "notify",
            "fia",
            entity_id=id,
            entity_label=fia.fia_id,
            details=(
                f"resend to stakeholders; recipients={len(stakeholders)}; "
                f"result={'ok' if ok else 'failed'}; {detail}"
            ),
        )
        flash(f"{fia.fia_id} resend: {detail}.", "success" if ok else "warning")
    except Exception as exc:
        flash(f"Could not resend {fia.fia_id}: {exc}", "warning")

    try:
        from core import flowintel_client

        preview_url = url_for("flash_intel.detail", id=id, _external=True)

        def send_fn(instance):
            return flowintel_client.send_flash_intel_to_flowintel(instance, fia, content, preview_url=preview_url)

        for instance, result in flowintel_client.send_to_eligible_instances(stakeholders, "Flash intel alert", send_fn):
            instance_name = instance.get("name") or instance.get("id")
            if result["ok"]:
                audit.record(
                    "notify", "fia", entity_id=id, entity_label=fia.fia_id,
                    details=f"Flowintel case {result['case_id']} created on {instance_name}",
                )
                flash(f"{fia.fia_id} sent to Flowintel ({instance_name}): case {result['case_id']} created.", "success")
            else:
                audit.record(
                    "notify", "fia", entity_id=id, entity_label=fia.fia_id,
                    details=f"Flowintel case creation on {instance_name} failed: {result.get('error', 'unknown error')}",
                )
                flash(f"Could not create Flowintel case on {instance_name}: {result.get('error', 'unknown error')}", "warning")
    except Exception as exc:
        flash(f"Could not send {fia.fia_id} to Flowintel: {exc}", "warning")

    return redirect(redirect_target)


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(fia.uuid, author, rating, comment)
        audit.record("create", "fia_feedback", entity_id=id, entity_label=fia.fia_id)
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback FIA %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("flash_intel.detail", id=id))


@bp.route("/<string:id>/pdf")
def pdf(id):
    fia = misp_store.get_fia(id)
    if fia is None:
        return "FIA not found", 404
    html = render_template(
        "flash_intel/pdf.html",
        fia=fia,
        css_url=branding.pdf_css_url(),
        brand=branding.brand(),
        reference_items=flattened_references(list(fia.external_references or []),
                                             source_event_references(fia)),
        summary_html=md_to_html(fia.summary or ""),
        action_required_html=md_to_html(fia.action_required or ""),
        what_happened_html=md_to_html("\n".join(fia.what_happened or [])),
    )
    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("pdf: weasyprint failed for %s: %s", id, exc)
        return f"PDF generation failed: {exc}", 500
    filename = f"{fia.fia_id}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _publish_and_notify(uuid):
    """Publish the FIA, deliver to message channels and create Flowintel cases.

    Returns (ok, detail): the message-channel outcome for the caller to surface.
    Flowintel results are flashed here directly, with their own audit entries.
    """
    from notifier import dispatcher

    misp_store.publish_fia(uuid)
    fia = misp_store.get_fia(uuid)
    if fia is None:
        return False, "the alert could not be reloaded after publishing"

    stakeholders = _eligible_flash_recipients(fia)
    content = misp_store.render_fia_markdown(fia, fia.fia_id, include_source_links=True)

    ok, detail = False, "delivery error (see the application log)"
    try:
        summary = dispatcher.send_flash_intel(fia, content, stakeholders)
        ok, detail = dispatcher.delivery_outcome(summary)
    except Exception as exc:
        logger.warning("notify failed for %s: %s", uuid, exc)

    try:
        from core import flowintel_client

        preview_url = url_for("flash_intel.detail", id=uuid, _external=True)

        def send_fn(instance):
            return flowintel_client.send_flash_intel_to_flowintel(instance, fia, content, preview_url=preview_url)

        for instance, result in flowintel_client.send_to_eligible_instances(stakeholders, "Flash intel alert", send_fn):
            instance_name = instance.get("name") or instance.get("id")
            if result["ok"]:
                audit.record(
                    "notify", "fia", entity_id=uuid, entity_label=fia.fia_id,
                    details=f"Flowintel case {result['case_id']} created on {instance_name}",
                )
                flash(f"{fia.fia_id} sent to Flowintel ({instance_name}): case {result['case_id']} created.", "success")
            else:
                audit.record(
                    "notify", "fia", entity_id=uuid, entity_label=fia.fia_id,
                    details=f"Flowintel case creation on {instance_name} failed: {result.get('error', 'unknown error')}",
                )
                flash(f"Could not create Flowintel case on {instance_name}: {result.get('error', 'unknown error')}", "warning")
    except Exception as exc:
        logger.warning("flowintel notify failed for %s: %s", uuid, exc)

    return ok, detail
