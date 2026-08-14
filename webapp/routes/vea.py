"""Vulnerability Exploitation Advisory (VEA) routes."""

import logging
import re
from types import SimpleNamespace

import config as _cfg
from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from webapp.routes.source_event_utils import (
    flattened_references,
    lookup_source_event_meta,
    normalise_source_event_rows,
    parse_source_tokens,
    source_event_references,
)

_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

from webapp import audit, branding, collection_cache, misp_session, misp_store, notify_jobs, product_log
from webapp.utils import md_to_html, sort_products

logger = logging.getLogger(__name__)
bp = Blueprint("vea", __name__, url_prefix="/products/vea")


@bp.route("/source-event-meta")
def source_event_meta():
    return lookup_source_event_meta(request.args)


def _form_data(form, vea_id=""):
    source_event_refs = form.getlist("source_event_url_item") or form.getlist("source_event_uuid_item")
    source_event_servers = form.getlist("source_event_server_item")
    source_event_uuids, source_event_hints = normalise_source_event_rows(source_event_refs, source_event_servers)

    return {
        "vea_id": vea_id,
        "cve_id": ", ".join(l.strip() for l in form.get("cve_id", "").splitlines() if l.strip()),
        "summary": form.get("summary", "").strip(),
        "cvss": form.get("cvss", "").strip(),
        "cwe": form.get("cwe", "").strip(),
        "title": form.get("title", "").strip(),
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", ""),
        "audience": ", ".join(form.getlist("audience")),
        "affected_product": form.get("affected_product", ""),
        "affected_versions": form.get("affected_versions", ""),
        "fixed_version": form.get("fixed_version", ""),
        "exposure": form.get("exposure", ""),
        "observed_exploitation": form.get("observed_exploitation", ""),
        "exploit_availability": form.get("exploit_availability", ""),
        "exploitation_complexity": form.get("exploitation_complexity", ""),
        "threat_actor_interest": form.get("threat_actor_interest", ""),
        "cisa_kev": form.get("cisa_kev", ""),
        "source_description": form.get("source_description", ""),
        "source_reliability": form.get("source_reliability", ""),
        "information_credibility": form.get("information_credibility", ""),
        "worst_case": form.get("worst_case", ""),
        "most_likely": form.get("most_likely", ""),
        "immediate_actions": misp_store._split_lines(form.get("immediate_actions")),
        "patch_sla_internet": form.get("patch_sla_internet", ""),
        "patch_sla_internal": form.get("patch_sla_internal", ""),
        "target_patch_version": form.get("target_patch_version", ""),
        "exploitation_indicators": misp_store._split_lines(form.get("exploitation_indicators")),
        "detection_rules": misp_store._split_lines(form.get("detection_rules")),
        "references": misp_store._split_lines(form.get("references")),
        "feedback_deadline": form.get("feedback_deadline") or "",
        "context_tags": form.getlist("context_tags"),
        "review_state": form.get("review_state", misp_store.VEA_REVIEW_DRAFT),
        "source_event_uuids": source_event_uuids,
        "source_event_hints": source_event_hints,
        "source_event_uuid": source_event_uuids[0] if source_event_uuids else "",
        "linked_pir_uuid": form.get("linked_pir_uuid", ""),
    }


def _wizard_context(vea=None, source_events=None):
    return {
        "vea": vea,
        "audiences": misp_store.FIA_AUDIENCES,
        "tlp_levels": misp_store.FIA_TLP_LEVELS,
        "reliabilities": misp_store.FIA_RELIABILITIES,
        "credibilities": misp_store.FIA_CREDIBILITIES,
        "review_states": misp_store.VEA_REVIEW_STATES,
        "exploit_availability_options": misp_store.VEA_EXPLOIT_AVAILABILITY,
        "exploit_complexity_options": misp_store.VEA_EXPLOIT_COMPLEXITY,
        "actor_interest_options": misp_store.VEA_ACTOR_INTEREST,
        "cisa_kev_options": misp_store.VEA_CISA_KEV,
        "pirs": misp_store.list_pirs(),
        "action_presets": getattr(_cfg, "RECOMMENDED_ACTIONS_IMMEDIATE", []),
        "source_event_tags": sorted({t for ev in (source_events or []) for t in ev.get("tags", [])}),
    }


def _eligible_vea_recipients(vea):
    allowed = {
        r.get("uuid")
        for r in misp_store.recipient_preview(
            "Vulnerability advisory",
            vea.tlp,
            vea.audience,
        )
        if r.get("status") == "green" and r.get("uuid")
    }
    if not allowed:
        return []
    return [s for s in misp_store.list_stakeholders() if getattr(s, "uuid", None) in allowed]


def _deliver_vea(uuid, preview_url, reason):
    """Build the closure that sends an advisory to its channels and Flowintel.

    Runs on the job thread, so it re-reads the advisory rather than closing over
    one fetched in the request. `preview_url` is resolved by the caller: only the
    request knows the app's external address.
    """
    def deliver(log):
        from notifier import dispatcher
        from core import flowintel_client

        vea = misp_store.get_vea(uuid)
        if vea is None:
            return False, "the advisory could not be loaded"

        stakeholders = _eligible_vea_recipients(vea)
        markdown = misp_store.render_vea_markdown(vea, preview_url=preview_url)
        log(f"{reason}: {len(stakeholders)} eligible recipient(s).")

        ok, detail = notify_jobs.to_channels(
            lambda: dispatcher.send_vea(vea, markdown, stakeholders), log)
        notify_jobs.to_flowintel(
            stakeholders, "Vulnerability advisory",
            lambda instance: flowintel_client.send_vea_to_flowintel(
                instance, vea, markdown, preview_url=preview_url),
            log)
        return ok, detail

    return deliver


def _start_vea_delivery(vea_id, uuid, reason):
    """Hand an advisory's delivery to a background job."""
    return notify_jobs.start(
        "notify-vea",
        f"{vea_id} delivery",
        _deliver_vea(uuid, url_for("vea.detail", id=uuid, _external=True), reason),
        entity_type="vea",
        entity_id=uuid,
        entity_label=vea_id,
        user=misp_session.current_user_email(),
    )


@bp.route("/")
def review():
    state_filter = (request.args.get("state") or "").strip() or None
    sort = (request.args.get("sort") or "").strip()
    direction = (request.args.get("dir") or "asc").strip()
    veas = misp_store.list_veas(review_state=state_filter)
    sort_products(veas, sort, direction)
    return render_template(
        "vea/review.html",
        veas=veas,
        state_filter=state_filter or "",
        review_states=misp_store.VEA_REVIEW_STATES,
        sort=sort,
        dir=direction,
    )


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        if request.form.get("prefill_only") == "1":
            source_uuids, source_hints, source_pairs = parse_source_tokens(request.form.getlist("source"))
            source_events = misp_store.fetch_source_events(
                source_uuids, source_hints=source_hints, strict_source=bool(source_hints)
            ) if source_uuids else []
            seed = _build_seed_from_sources(source_uuids, source_pairs, source_events)
            return render_template("vea/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(seed, source_events))

        data = _form_data(request.form)
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints=source_hints, strict_source=bool(source_hints)
        )
        if not data["cve_id"] and not data["title"]:
            flash("CVE ID or title is required.", "warning")
            return render_template("vea/wizard.html", is_edit=False,
                                   source_events=source_events, **_wizard_context(data, source_events))
        action = request.form.get("action", "save")
        data["review_state"] = (misp_store.VEA_REVIEW_PENDING
                                if action == "submit" else misp_store.VEA_REVIEW_DRAFT)
        try:
            uuid, vea_id = misp_store.create_vea(data)
            product_log.log_product_sources(data.get("source_event_uuids") or [], "vea")
            audit.record("create", "vea", entity_id=uuid, entity_label=vea_id)
            flash(f"{vea_id} {'submitted for review' if action == 'submit' else 'saved as draft'}.", "success")
            return redirect(url_for("vea.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create VEA: {exc}", "warning")
    source_uuids, source_hints, source_pairs = parse_source_tokens(request.args.getlist("source"))
    source_events = misp_store.fetch_source_events(
        source_uuids, source_hints=source_hints, strict_source=bool(source_hints)
    ) if source_uuids else []
    seed = _build_seed_from_sources(source_uuids, source_pairs, source_events)
    return render_template("vea/wizard.html", is_edit=False,
                           source_events=source_events, **_wizard_context(seed, source_events))


@bp.route("/<string:id>")
def detail(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    feedback = misp_store.list_product_feedback(vea.uuid)
    recipients = misp_store.recipient_preview("Vulnerability advisory", vea.tlp, vea.audience)
    notify_status = audit.latest_notify_status("vea", id)
    linked_pir = None
    if getattr(vea, "linked_pir_uuid", ""):
        try:
            linked_pir = misp_store.get_pir(vea.linked_pir_uuid)
        except Exception:
            linked_pir = None
    source_refs = source_event_references(vea)
    return render_template(
        "vea/detail.html",
        vea=vea,
        reference_items=flattened_references(list(vea.references or []), source_refs),
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
        linked_pir=linked_pir,
    )


@bp.route("/<string:id>/recipients")
def recipients_fragment(id):
    """Recipients preview for an advisory, loaded by the review page button."""
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    return render_template(
        "_recipients_preview.html",
        product_label="Vulnerability advisory",
        recipients=misp_store.recipient_preview("Vulnerability advisory", vea.tlp, vea.audience),
        tlp_label=vea.tlp,
        audience_label=vea.audience,
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    if request.method == "POST":
        data = _form_data(request.form, vea_id=vea.vea_id)
        source_hints = data.get("source_event_hints") or {}
        source_events = misp_store.fetch_source_events(
            data.get("source_event_uuids") or [], source_hints=source_hints, strict_source=bool(source_hints)
        )
        action = request.form.get("action", "save")
        if action == "submit":
            data["review_state"] = misp_store.VEA_REVIEW_PENDING
        elif action == "publish":
            data["review_state"] = misp_store.VEA_REVIEW_APPROVED
        else:
            data["review_state"] = vea.review_state or misp_store.VEA_REVIEW_DRAFT
        try:
            misp_store.update_vea(id, data)
            audit.record("update", "vea", entity_id=id, entity_label=vea.vea_id)
            if action == "publish":
                misp_store.publish_vea(id)
                _start_vea_delivery(vea.vea_id, id, "publish")
                flash(f"{vea.vea_id} published.", "success")
                flash("Notifications are being sent in the background; the job badge reports the result.", "info")
            else:
                flash(f"{vea.vea_id} saved.", "success")
            return redirect(url_for("vea.detail", id=id))
        except Exception as exc:
            flash(f"Could not update VEA: {exc}", "warning")
            return render_template("vea/wizard.html", is_edit=True,
                                   source_events=source_events, **_wizard_context(data, source_events))
    source_uuids = list(getattr(vea, "source_event_uuids", []) or ([vea.source_event_uuid] if getattr(vea, "source_event_uuid", "") else []))
    source_hints = dict(getattr(vea, "source_event_hints", {}) or {})
    source_events = misp_store.fetch_source_events(
        source_uuids, source_hints=source_hints, strict_source=bool(source_hints)
    ) if source_uuids else []
    return render_template("vea/wizard.html", is_edit=True,
                           source_events=source_events, **_wizard_context(vea, source_events))


def _build_seed_from_sources(source_uuids, source_pairs, source_events):
    if not source_uuids:
        return None

    def _all_attrs(ev):
        attrs = list(ev.get("attributes", []))
        for obj in ev.get("objects", []):
            attrs.extend(obj.get("attributes", []))
        return attrs

    cve_ids = list(dict.fromkeys(
        a["value"].strip()
        for ev in source_events
        for a in _all_attrs(ev)
        if a.get("type") == "vulnerability" and a.get("value", "").strip()
    ))

    for ev in source_events:
        for m in _CVE_RE.findall(ev.get("info", "")):
            cve = m.upper()
            if cve not in cve_ids:
                cve_ids.append(cve)

    cached_rows = None
    if not cve_ids:
        cached_rows = collection_cache.get_events_by_uuids(source_uuids)
        for row in cached_rows:
            for vid in row.get("vulnerability_ids", []):
                if vid and vid not in cve_ids:
                    cve_ids.append(vid)

    labels = list(dict.fromkeys(ev["source_label"] for ev in source_events if ev.get("source_label")))

    reliability_letters, credibility_numbers = [], []
    tag_sources = source_events or cached_rows or collection_cache.get_events_by_uuids(source_uuids)
    for ev in tag_sources:
        for t in ev.get("tags", []):
            if t.startswith('admiralty-scale:source-reliability='):
                v = t.split('"')[1] if '"' in t else ''
                if v:
                    reliability_letters.append(v.upper())
            elif t.startswith('admiralty-scale:information-credibility='):
                v = t.split('"')[1] if '"' in t else ''
                if v.isdigit():
                    credibility_numbers.append(int(v))
    worst_reliability = max(reliability_letters) if reliability_letters else ""
    worst_credibility = str(max(credibility_numbers)) if credibility_numbers else ""

    first_title = (source_events[0]["info"] if source_events
                   else (collection_cache.get_events_by_uuids([source_uuids[0]]) or [{}])[0].get("info", ""))

    source_hints = {}
    for uuid, sid in source_pairs:
        if sid and not source_hints.get(uuid):
            source_hints[uuid] = sid

    references = []
    for ev in source_events:
        base = (ev.get("source_url") or _cfg.MISP_WEBAPP_URL).rstrip("/")
        references.append(f"{base}/events/view/{ev.get('uuid')}")
    if not references:
        references = misp_store.source_event_urls(source_uuids, source_hints)

    for cve in cve_ids:
        references.append(f"https://vulnerability.circl.lu/vuln/{cve}")
    references = list(dict.fromkeys(references))

    return SimpleNamespace(
        vea_id="",
        cve_id="\n".join(cve_ids),
        title=first_title,
        summary="", cvss="", cwe="",
        tlp="amber", author="", audience="",
        affected_product="", affected_versions="", fixed_version="", exposure="",
        observed_exploitation="", exploit_availability="", exploitation_complexity="",
        threat_actor_interest="", cisa_kev="",
        source_description=", ".join(labels),
        source_reliability=worst_reliability, information_credibility=worst_credibility,
        worst_case="", most_likely="",
        immediate_actions=[], patch_sla_internet="", patch_sla_internal="",
        target_patch_version="", exploitation_indicators=[], detection_rules=[],
        references=references, feedback_deadline=None, review_state=misp_store.VEA_REVIEW_DRAFT,
        rejection_reason="", source_event_uuids=source_uuids,
        source_event_hints=source_hints,
        source_event_uuid=source_uuids[0] if source_uuids else "", linked_pir_uuid="",
        context_tags=[],
    )


@bp.route("/<string:id>/approve", methods=["POST"])
def approve(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    if not (vea.audience or "").strip():
        flash("A target audience is required before publishing. Edit the advisory and select an audience first.", "warning")
        return redirect(url_for("vea.detail", id=id))
    try:
        misp_store.publish_vea(id)
        audit.record("publish", "vea", entity_id=id, entity_label=vea.vea_id)
        _start_vea_delivery(vea.vea_id, id, "publish")
        flash(f"{vea.vea_id} approved and published.", "success")
        flash("Notifications are being sent in the background; the job badge reports the result.", "info")
    except Exception as exc:
        flash(f"Could not publish VEA: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))


@bp.route("/<string:id>/reject", methods=["POST"])
def reject(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    reason = request.form.get("reason", "").strip()
    try:
        misp_store.reject_vea(id, reason=reason)
        audit.record("reject", "vea", entity_id=id, entity_label=vea.vea_id)
        flash(f"{vea.vea_id} rejected.", "info")
    except Exception as exc:
        flash(f"Could not reject VEA: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    vea = misp_store.get_vea(id)
    label = vea.vea_id if vea else id
    try:
        misp_store.delete_vea(id)
        audit.record("delete", "vea", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete VEA: {exc}", "warning")
    return redirect(url_for("vea.review"))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    if request.form.get("next") == "detail":
        redirect_target = url_for("vea.detail", id=id)
    else:
        redirect_target = url_for("vea.review")
    if getattr(vea, "review_state", "") != misp_store.VEA_REVIEW_APPROVED:
        flash("Only published advisories can be resent.", "warning")
        return redirect(redirect_target)

    _start_vea_delivery(vea.vea_id, id, "resend")
    flash(f"{vea.vea_id} resend started; the job badge reports the result.", "info")
    return redirect(redirect_target)


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(vea.uuid, author, rating, comment)
        audit.record("create", "vea_feedback", entity_id=id, entity_label=vea.vea_id)
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback VEA %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("vea.detail", id=id))


@bp.route("/<string:id>/pdf")
def pdf(id):
    vea = misp_store.get_vea(id)
    if vea is None:
        return "VEA not found", 404
    html = render_template(
        "vea/pdf.html",
        vea=vea,
        css_url=branding.pdf_css_url(),
        brand=branding.brand(),
        reference_items=flattened_references(list(vea.references or []),
                                             source_event_references(vea)),
        summary_html=md_to_html(vea.summary or ""),
    )
    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("pdf: weasyprint failed for VEA %s: %s", id, exc)
        return f"PDF generation failed: {exc}", 500
    filename = f"{vea.vea_id}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
