import logging
from datetime import date
from types import SimpleNamespace

import config
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from webapp import audit, matching as _matching, misp_store

logger = logging.getLogger(__name__)


def _sync_focus_points():
    """Legacy no-op: organisation-wide focus points are now managed in Configuration."""
    return
from webapp.models import (
    FOCUS_CATEGORIES,
    INTEL_LEVELS,
    MOSCOW_PRIORITIES,
    cti_products,
    PIR_INTAKE_STATUSES,
    PIR_STATUSES,
    GIR_STATUSES,
    REVIEW_CYCLES,
    TIME_SENSITIVITIES,
)

bp = Blueprint("requirements", __name__)

_SCOPE_PREVIEW_TIMEFRAME_OPTIONS = [
    ("all", "All cache entries"),
    ("24h", "Last 24h"),
    ("48h", "Last 48h"),
    ("7d", "Last 7d"),
]


def _scope_preview_timeframe(raw_value):
    value = (raw_value or "all").strip().lower()
    mapping = {
        "all": None,
        "24h": 24,
        "48h": 48,
        "7d": 24 * 7,
    }
    if value not in mapping:
        value = "all"
    return value, mapping[value]


def _owner_fields(form, stakeholders):
    owner_id = form.get("owner_id", "").strip()
    owner_name_free = form.get("owner_name", "").strip()
    if owner_id:
        owner = next((s for s in stakeholders if s.id == owner_id), None)
        return owner_id, (owner.name if owner else ""), (owner.role if owner else "")
    return "", owner_name_free, ""


def _stakeholder_refs(stakeholders):
    by_uuid = {}
    by_name = {}
    for stakeholder in stakeholders or []:
        if getattr(stakeholder, "uuid", None):
            by_uuid[stakeholder.uuid] = stakeholder
        if getattr(stakeholder, "name", None) and stakeholder.name not in by_name:
            by_name[stakeholder.name] = stakeholder
    return by_uuid, by_name


def _distribution_ids(form, stakeholders):
    by_uuid, _ = _stakeholder_refs(stakeholders)
    selected = []
    seen = set()
    for raw_value in form.getlist("distribution"):
        value = (raw_value or "").strip()
        if not value or value not in by_uuid or value in seen:
            continue
        seen.add(value)
        selected.append(value)
    return selected


def _distribution_labels(values, stakeholders):
    by_uuid, by_name = _stakeholder_refs(stakeholders)
    labels = []
    seen = set()
    for raw_value in values or []:
        value = (raw_value or "").strip()
        if not value:
            continue
        stakeholder = by_uuid.get(value) or by_name.get(value)
        label = stakeholder.name if stakeholder is not None else value
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def _selected_distribution_stakeholders(values, stakeholders):
    by_uuid, by_name = _stakeholder_refs(stakeholders)
    selected = []
    seen = set()
    for raw_value in values or []:
        value = (raw_value or "").strip()
        if not value:
            continue
        stakeholder = by_uuid.get(value) or by_name.get(value)
        if stakeholder is None or stakeholder.uuid in seen:
            continue
        seen.add(stakeholder.uuid)
        selected.append(stakeholder)
    return selected


def _distribution_entries(values, stakeholders):
    by_uuid, by_name = _stakeholder_refs(stakeholders)
    distribution = []
    selected_registered = set()
    selected_legacy = set()

    for raw_value in values or []:
        value = (raw_value or "").strip()
        if not value:
            continue
        stakeholder = by_uuid.get(value) or by_name.get(value)
        if stakeholder is not None:
            if stakeholder.uuid in selected_registered:
                continue
            selected_registered.add(stakeholder.uuid)
            distribution.append(SimpleNamespace(**vars(stakeholder), in_distribution=True))
            continue
        if value in selected_legacy:
            continue
        selected_legacy.add(value)
        distribution.append(SimpleNamespace(
            id=None,
            uuid=None,
            name=value,
            role="",
            organization="",
            email="",
            tlp_clearance="",
            products=[],
            product_modes={},
            notification_channels=[],
            in_distribution=True,
        ))

    for stakeholder in stakeholders:
        if stakeholder.uuid in selected_registered:
            continue
        distribution.append(SimpleNamespace(**vars(stakeholder), in_distribution=False))
    return distribution


def _galaxy_context():
    """Fetch galaxy cluster lists for form dropdowns. Returns empty lists on failure."""
    return {
        "galaxy_countries": misp_store.galaxy_geography(),
        "galaxy_sectors": misp_store.galaxy_sectors(),
        "galaxy_threat_actors": misp_store.galaxy_threat_actors(),
        "galaxy_mitre_attack": misp_store.galaxy_mitre_attack_patterns(),
        "intel_levels": INTEL_LEVELS,
    }


_SCOPE_COUNT_FIELDS = (
    "geographic_scope", "sectors", "threat_actors", "threat_types",
    "technology", "vendor", "incident", "campaign", "mitre_attack_techniques",
)


def _scope_item_count(req):
    """Total number of scope items across every scope dimension of a PIR/GIR."""
    return sum(len(getattr(req, field, None) or []) for field in _SCOPE_COUNT_FIELDS)


def _scope_focus_points(form):
    points = []
    mappings = [
        ("Geography", form.getlist("geographic_scope")),
        ("Sector", form.getlist("sectors")),
        ("Threat Actor", form.getlist("threat_actors")),
        ("Threat Type", form.getlist("threat_types")),
    ]
    seen = set()
    for category, values in mappings:
        for value in values:
            clean = value.strip()
            if not clean:
                continue
            key = (category, clean.lower())
            if key in seen:
                continue
            seen.add(key)
            points.append({"category": category, "value": clean, "notes": ""})
    return points


def _sub_questions(form):
    texts = form.getlist("sub_question_text")
    assigned = form.getlist("sub_question_assigned")
    dues = form.getlist("sub_question_due")
    result = []
    for i, text in enumerate(texts):
        t = text.strip()
        if not t:
            continue
        result.append({
            "text": t,
            "assigned_to": assigned[i].strip() if i < len(assigned) else "",
            "due_date": dues[i].strip() if i < len(dues) else "",
        })
    return result


# ── PIRs ──────────────────────────────────────────────────────────────────────

PIR_TRIAGE_CHECKLIST = [
    ("clear_question", "The intelligence question is clearly stated and answerable within the program's scope."),
    ("requester_identified", "The requester and the decision it supports are identified."),
    ("not_duplicate", "This question is not already answered by an existing active PIR or GIR."),
    ("priority_realistic", "The priority level and time sensitivity are realistic given current team capacity."),
    ("sources_available", "Collection sources are available or can be identified to address the question."),
]


PIR_STATUS_ORDER = ["Pending", "Active", "In Development", "Under Evaluation", "Implemented", "Retired"]
GIR_STATUS_ORDER = ["Pending", "Active", "Retired"]


def _sort_requirements(items, sort, direction, id_attr, text_attr, status_order):
    keys = {
        "id": lambda x: getattr(x, id_attr),
        "text": lambda x: (getattr(x, text_attr) or "").lower(),
        "status": lambda x: status_order.index(x.status) if x.status in status_order else len(status_order),
        "next_review": lambda x: x.next_review or date.max,
    }
    keyfn = keys.get((sort or "").strip())
    if keyfn:
        items = sorted(items, key=keyfn, reverse=(direction == "desc"))
    return items


@bp.route("/pirs")
def pir_list():
    pirs = misp_store.list_pirs()
    intel_filter = (request.args.get("intel_level") or "").strip()
    if intel_filter:
        pirs = [p for p in pirs if intel_filter in (p.intel_level or [])]
    pirs = _sort_requirements(
        pirs, request.args.get("sort"), request.args.get("dir"),
        "pir_id", "question", PIR_STATUS_ORDER,
    )
    scope_counts = {p.uuid: _scope_item_count(p) for p in pirs}
    # Viable merge targets for the inline triage form: any PIR not itself
    # rejected or already merged away.
    not_viable = {"rejected", "merged"}
    merge_targets = [
        p for p in pirs if getattr(p, "intake_status", "submitted") not in not_viable
    ]
    return render_template(
        "requirements/pir_list.html",
        pirs=pirs,
        scope_counts=scope_counts,
        intel_levels=INTEL_LEVELS,
        intel_filter=intel_filter,
        merge_targets=merge_targets,
        triage_checklist=PIR_TRIAGE_CHECKLIST,
    )


@bp.route("/pirs/new", methods=["GET", "POST"])
def pir_new():
    stakeholders = misp_store.list_stakeholders()
    prefill = {}
    from_uuid = (request.args.get("from_stakeholder") or "").strip()
    if from_uuid:
        owner = next((s for s in stakeholders if s.uuid == from_uuid), None)
        if owner:
            prefill = {
                "owner_uuid": owner.uuid,
                "owner_name": owner.name,
                "owner_role": owner.role,
                "distribution": [owner.uuid],
            }
    if request.method == "POST":
        output_format = [v.strip() for v in request.form.getlist("output_format") if v.strip()]
        owner_uuid, owner_name, owner_role = _owner_fields(request.form, stakeholders)
        data = {
            # Placeholder; create_pir allocates the authoritative pir_id atomically.
            "pir_id": "",
            "question": request.form["question"],
            "context": request.form.get("context"),
            "intel_level": [v for v in request.form.getlist("intel_level") if v.strip()],
            "owner_uuid": owner_uuid,
            "owner_name": owner_name,
            "owner_role": owner_role,
            "decision_supported": request.form.get("decision_supported"),
            "decision_maker": [v for v in request.form.getlist("decision_maker") if v.strip()],
            "consequence": [v for v in request.form.getlist("consequence") if v.strip()],
            "deadline": request.form.get("deadline"),
            "priority_justification": request.form.get("priority_justification"),
            "sub_questions": _sub_questions(request.form),
            "priority": request.form.get("priority", "Should have"),
            "time_sensitivity": request.form.get("time_sensitivity", "Standard (<1 month)"),
            "status": "Pending",  # always starts Pending until triage is complete
            "geographic_scope": dedup_lower(request.form.getlist("geographic_scope")),
            "time_frame": request.form.get("time_frame"),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": dedup_lower(request.form.getlist("threat_actors")),
            "sectors": dedup_lower(request.form.getlist("sectors")),
            "out_of_scope": request.form.getlist("out_of_scope"),
            "technology": request.form.getlist("technology"),
            "vendor": request.form.getlist("vendor"),
            "incident": request.form.getlist("incident"),
            "campaign": request.form.getlist("campaign"),
            "collection_sources": request.form.getlist("collection_sources"),
            "output_format": output_format,
            "distribution": _distribution_ids(request.form, stakeholders),
            "focus_points": _scope_focus_points(request.form),
            "next_review": request.form.get("next_review") or None,
            "mitre_attack_techniques": request.form.getlist("mitre_attack_techniques"),
        }
        try:
            uuid = misp_store.create_pir(data)
            pir_id = data["pir_id"]
            audit.record("create", "pir", entity_id=uuid, entity_label=pir_id)
            _matching.invalidate_cache()
            _sync_focus_points()
            flash(f"{pir_id} created.", "success")
            return redirect(url_for("requirements.pir_detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create PIR: {exc}", "warning")

    return render_template(
        "requirements/pir_form.html",
        pir=None,
        prefill=prefill,
        stakeholders=stakeholders,
        priorities=MOSCOW_PRIORITIES,
        statuses=PIR_STATUSES,
        time_sensitivities=TIME_SENSITIVITIES,
        collection_sources=misp_store.get_all_collection_source_labels(),
        output_formats=cti_products(),
        **_galaxy_context(),
    )


@bp.route("/pirs/<string:id>")
def pir_detail(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404
    misp_url = f"{config.MISP_WEBAPP_URL.rstrip('/')}/events/view/{id}"
    fp_by_category = {c: [] for c in FOCUS_CATEGORIES}
    for fp in pir.focus_points:
        fp_by_category.setdefault(fp.category, []).append(fp.value)
    stakeholders = misp_store.list_stakeholders()
    distribution = _distribution_entries(pir.distribution or [], stakeholders)
    coverage = {}
    try:
        coverage = misp_store.pir_collection_gap(pir)
    except Exception as exc:
        logger.warning("collection gap check failed for %s: %s", id, exc)

    return render_template(
        "requirements/pir_detail.html",
        pir=pir,
        focus_points=pir.focus_points,
        categories=FOCUS_CATEGORIES,
        fp_by_category=fp_by_category,
        misp_url=misp_url,
        distribution=distribution,
        selected_count=sum(1 for stakeholder in distribution if stakeholder.in_distribution),
        coverage=coverage,
        **_galaxy_context(),
    )


@bp.route("/pirs/<string:id>/edit", methods=["GET", "POST"])
def pir_edit(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404
    if getattr(pir, "intake_status", "") == "rejected":
        flash(f"{pir.pir_id} has been rejected and cannot be edited.", "warning")
        return redirect(url_for("requirements.pir_detail", id=id))
    stakeholders = misp_store.list_stakeholders()
    if request.method == "POST":
        output_format = [v.strip() for v in request.form.getlist("output_format") if v.strip()]
        owner_uuid, owner_name, owner_role = _owner_fields(request.form, stakeholders)
        data = {
            "pir_id": pir.pir_id,
            "question": request.form["question"],
            "context": request.form.get("context"),
            "intel_level": [v for v in request.form.getlist("intel_level") if v.strip()],
            "owner_uuid": owner_uuid,
            "owner_name": owner_name,
            "owner_role": owner_role,
            "decision_supported": request.form.get("decision_supported"),
            "decision_maker": [v for v in request.form.getlist("decision_maker") if v.strip()],
            "consequence": [v for v in request.form.getlist("consequence") if v.strip()],
            "deadline": request.form.get("deadline"),
            "priority_justification": request.form.get("priority_justification"),
            "sub_questions": _sub_questions(request.form),
            "priority": request.form.get("priority", "Should have"),
            "time_sensitivity": request.form.get("time_sensitivity", "Standard (<1 month)"),
            "status": request.form.get("status", "Pending"),
            "geographic_scope": dedup_lower(request.form.getlist("geographic_scope")),
            "time_frame": request.form.get("time_frame"),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": dedup_lower(request.form.getlist("threat_actors")),
            "sectors": dedup_lower(request.form.getlist("sectors")),
            "out_of_scope": request.form.getlist("out_of_scope"),
            "technology": request.form.getlist("technology"),
            "vendor": request.form.getlist("vendor"),
            "incident": request.form.getlist("incident"),
            "campaign": request.form.getlist("campaign"),
            "collection_sources": request.form.getlist("collection_sources"),
            "output_format": output_format,
            "distribution": _distribution_ids(request.form, stakeholders),
            "focus_points": _scope_focus_points(request.form),
            "resolution_note": request.form.get("resolution_note"),
            "next_review": request.form.get("next_review") or None,
            "mitre_attack_techniques": request.form.getlist("mitre_attack_techniques"),
            # Carry intake fields forward - the edit form does not touch them
            "intake_status": getattr(pir, "intake_status", "submitted") or "submitted",
            "acknowledged_at": getattr(pir, "acknowledged_at", "") or "",
            "acknowledged_by": getattr(pir, "acknowledged_by", "") or "",
            "triaged_at": getattr(pir, "triaged_at", "") or "",
            "triaged_by": getattr(pir, "triaged_by", "") or "",
            "decision_at": getattr(pir, "decision_at", "") or "",
            "decision_by": getattr(pir, "decision_by", "") or "",
            "rejection_reason": getattr(pir, "rejection_reason", "") or "",
            "deferral_reason": getattr(pir, "deferral_reason", "") or "",
            "linked_pir_uuid": getattr(pir, "linked_pir_uuid", "") or "",
            "triage_checklist": list(getattr(pir, "triage_checklist", []) or []),
        }
        try:
            new_id = misp_store.update_pir(id, data)
            audit.record("update", "pir", entity_id=id, entity_label=pir.pir_id)
            _matching.invalidate_cache()
            _sync_focus_points()
            flash(f"{pir.pir_id} updated.", "success")
            return redirect(url_for("requirements.pir_detail", id=new_id))
        except Exception as exc:
            flash(f"Could not update PIR: {exc}", "warning")

    return render_template(
        "requirements/pir_form.html",
        pir=pir,
        stakeholders=stakeholders,
        priorities=MOSCOW_PRIORITIES,
        statuses=PIR_STATUSES,
        time_sensitivities=TIME_SENSITIVITIES,
        collection_sources=misp_store.get_all_collection_source_labels(),
        output_formats=cti_products(),

        **_galaxy_context(),
    )


@bp.route("/pirs/<string:id>/delete", methods=["POST"])
def pir_delete(id):
    pir = misp_store.get_pir(id)
    label = pir.pir_id if pir else id
    try:
        misp_store.delete_pir(id)
        audit.record("delete", "pir", entity_id=id, entity_label=label)
        _matching.invalidate_cache()
        _sync_focus_points()
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete PIR: {exc}", "warning")
    return redirect(url_for("requirements.pir_list"))


@bp.route("/pirs/<string:id>/triage", methods=["POST"])
def pir_triage(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404

    decision = request.form.get("decision", "").strip()
    valid_decisions = [s for s in PIR_INTAKE_STATUSES if s not in ("submitted", "triaged")]
    if decision not in valid_decisions:
        flash("Select a valid decision.", "warning")
        return redirect(url_for("requirements.pir_list"))

    reason = request.form.get("reason", "").strip()
    if decision in ("rejected", "deferred") and not reason:
        flash("A reason is required when rejecting or deferring.", "warning")
        return redirect(url_for("requirements.pir_list"))

    linked_uuid = request.form.get("linked_pir_uuid", "").strip()
    if decision == "merged" and not linked_uuid:
        flash("Select the PIR to merge into.", "warning")
        return redirect(url_for("requirements.pir_list"))

    checklist = request.form.getlist("triage_checklist")
    try:
        misp_store.update_pir_intake(
            id,
            decision,
            reason=reason or None,
            linked_pir_uuid=linked_uuid or None,
            checklist=checklist,
        )
        audit.record("triage", "pir", entity_id=id, entity_label=pir.pir_id)
        try:
            from notifier import mattermost as mm
            mm.send_pir_intake_notification(pir, decision, reason or None)
        except Exception as exc:
            logger.warning("PIR intake notification failed for %s: %s", pir.pir_id, exc)
        flash(f"{pir.pir_id} marked as {decision}.", "success")
    except Exception as exc:
        flash(f"Could not update intake status: {exc}", "warning")
    return redirect(url_for("requirements.pir_list"))


@bp.route("/pirs/<string:id>/focus_points", methods=["POST"])
def pir_add_focus_point(id):
    try:
        misp_store.add_focus_point_with_scope(
            id,
            request.form["category"],
            request.form["value"],
            request.form.get("notes", ""),
        )
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not add scope item: {exc}", "warning")
    return redirect(url_for("requirements.pir_detail", id=id))


@bp.route("/pirs/<string:id>/scope/sync", methods=["POST"])
def pir_sync_scope(id):
    category = request.form.get("category", "").strip()
    if category not in misp_store.GALAXY_FP_CATEGORIES:
        flash("Sync is only supported for galaxy-backed categories.", "warning")
        return redirect(url_for("requirements.pir_detail", id=id))
    values = request.form.getlist("value")
    try:
        misp_store.sync_focus_points_category(id, category, values)
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not sync {category} scope: {exc}", "warning")
    return redirect(url_for("requirements.pir_detail", id=id))


@bp.route("/pirs/<string:id>/scope/preview")
def pir_scope_preview(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404
    timeframe_key, timeframe_hours = _scope_preview_timeframe(request.args.get("timeframe"))
    terms = []
    terms.extend(pir.geographic_scope or [])
    terms.extend(pir.sectors or [])
    terms.extend(pir.threat_actors or [])
    terms.extend(pir.threat_types or [])
    for fp in pir.focus_points:
        if fp.value:
            terms.append(fp.value)
    matches = misp_store.preview_scope_matches(terms, timeframe_hours=timeframe_hours)
    ctx = dict(
        terms=sorted(set(t for t in terms if t)),
        matches=matches,
        timeframe_key=timeframe_key,
        timeframe_options=_SCOPE_PREVIEW_TIMEFRAME_OPTIONS,
    )
    if request.args.get("fragment"):
        return render_template(
            "requirements/_scope_matches.html",
            embedded=True,
            timeframe_action=url_for("requirements.pir_scope_preview", id=pir.uuid, fragment=1),
            **ctx,
        )
    return render_template(
        "requirements/pir_scope_preview.html",
        pir=pir,
        embedded=False,
        timeframe_action=url_for("requirements.pir_scope_preview", id=pir.uuid),
        **ctx,
    )


@bp.route("/pirs/<string:id>/focus_points/<string:fp_id>/delete", methods=["POST"])
def pir_delete_focus_point(id, fp_id):
    try:
        misp_store.remove_focus_point_with_scope(id, fp_id)
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not delete scope item: {exc}", "warning")
    return redirect(url_for("requirements.pir_detail", id=id))


# ── GIRs ──────────────────────────────────────────────────────────────────────

@bp.route("/girs")
def gir_list():
    girs = misp_store.list_girs()
    intel_filter = (request.args.get("intel_level") or "").strip()
    if intel_filter:
        girs = [g for g in girs if intel_filter in (g.intel_level or [])]
    girs = _sort_requirements(
        girs, request.args.get("sort"), request.args.get("dir"),
        "gir_id", "topic", GIR_STATUS_ORDER,
    )
    scope_counts = {g.uuid: _scope_item_count(g) for g in girs}
    return render_template(
        "requirements/gir_list.html",
        girs=girs,
        scope_counts=scope_counts,
        intel_levels=INTEL_LEVELS,
        intel_filter=intel_filter,
    )


@bp.route("/girs/new", methods=["GET", "POST"])
def gir_new():
    stakeholders = misp_store.list_stakeholders()
    if request.method == "POST":
        owner_uuid, owner_name, owner_role = _owner_fields(request.form, stakeholders)
        output_format = [v.strip() for v in request.form.getlist("output_format") if v.strip()]
        data = {
            # Placeholder; create_gir allocates the authoritative gir_id atomically.
            "gir_id": "",
            "topic": request.form["topic"],
            "description": request.form.get("description"),
            "owner_uuid": owner_uuid,
            "owner_name": owner_name,
            "owner_role": owner_role,
            "status": "Pending",
            "review_cycle": request.form.get("review_cycle", "Quarterly"),
            "collection_sources": request.form.getlist("collection_sources"),
            "geographic_scope": dedup_lower(request.form.getlist("geographic_scope")),
            "sectors": dedup_lower(request.form.getlist("sectors")),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": dedup_lower(request.form.getlist("threat_actors")),
            "out_of_scope": request.form.getlist("out_of_scope"),
            "technology": request.form.getlist("technology"),
            "vendor": request.form.getlist("vendor"),
            "incident": request.form.getlist("incident"),
            "campaign": request.form.getlist("campaign"),
            "output_format": output_format,
            "distribution": _distribution_ids(request.form, stakeholders),
            "deadline": request.form.get("deadline"),
            "priority_justification": request.form.get("priority_justification"),
            "sub_questions": _sub_questions(request.form),
            "next_review": request.form.get("next_review") or None,
            "intel_level": request.form.getlist("intel_level"),
            "mitre_attack_techniques": request.form.getlist("mitre_attack_techniques"),
        }
        try:
            uuid = misp_store.create_gir(data)
            gir_id = data["gir_id"]
            audit.record("create", "gir", entity_id=uuid, entity_label=gir_id)
            _matching.invalidate_cache()
            _sync_focus_points()
            flash(f"{gir_id} created.", "success")
            return redirect(url_for("requirements.gir_detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create GIR: {exc}", "warning")

    return render_template(
        "requirements/gir_form.html",
        gir=None,
        stakeholders=stakeholders,
        statuses=GIR_STATUSES,
        review_cycles=REVIEW_CYCLES,
        collection_sources=misp_store.get_all_collection_source_labels(),
        output_formats=cti_products(),
        **_galaxy_context(),
    )


@bp.route("/girs/<string:id>")
def gir_detail(id):
    gir = misp_store.get_gir(id)
    if gir is None:
        return "GIR not found", 404
    misp_url = f"{config.MISP_WEBAPP_URL.rstrip('/')}/events/view/{id}"
    fp_by_category = {c: [] for c in FOCUS_CATEGORIES}
    for fp in gir.focus_points:
        fp_by_category.setdefault(fp.category, []).append(fp.value)
    stakeholders = misp_store.list_stakeholders()
    distribution = _distribution_entries(gir.distribution or [], stakeholders)
    return render_template(
        "requirements/gir_detail.html",
        gir=gir,
        focus_points=gir.focus_points,
        categories=FOCUS_CATEGORIES,
        fp_by_category=fp_by_category,
        distribution=distribution,
        selected_count=sum(1 for stakeholder in distribution if stakeholder.in_distribution),
        misp_url=misp_url,
        **_galaxy_context(),
    )


@bp.route("/girs/<string:id>/edit", methods=["GET", "POST"])
def gir_edit(id):
    gir = misp_store.get_gir(id)
    if gir is None:
        return "GIR not found", 404
    stakeholders = misp_store.list_stakeholders()
    if request.method == "POST":
        owner_uuid, owner_name, owner_role = _owner_fields(request.form, stakeholders)
        output_format = [v.strip() for v in request.form.getlist("output_format") if v.strip()]
        data = {
            "gir_id": gir.gir_id,
            "topic": request.form["topic"],
            "description": request.form.get("description"),
            "owner_uuid": owner_uuid,
            "owner_name": owner_name,
            "owner_role": owner_role,
            "status": request.form.get("status", "Active"),
            "review_cycle": request.form.get("review_cycle", "Quarterly"),
            "collection_sources": request.form.getlist("collection_sources"),
            "geographic_scope": dedup_lower(request.form.getlist("geographic_scope")),
            "sectors": dedup_lower(request.form.getlist("sectors")),
            "threat_types": request.form.getlist("threat_types"),
            "threat_actors": dedup_lower(request.form.getlist("threat_actors")),
            "out_of_scope": request.form.getlist("out_of_scope"),
            "technology": request.form.getlist("technology"),
            "vendor": request.form.getlist("vendor"),
            "incident": request.form.getlist("incident"),
            "campaign": request.form.getlist("campaign"),
            "output_format": output_format,
            "distribution": _distribution_ids(request.form, stakeholders),
            "deadline": request.form.get("deadline"),
            "priority_justification": request.form.get("priority_justification"),
            "sub_questions": _sub_questions(request.form),
            "next_review": request.form.get("next_review") or None,
            "intel_level": request.form.getlist("intel_level"),
            "mitre_attack_techniques": request.form.getlist("mitre_attack_techniques"),
        }
        try:
            new_id = misp_store.update_gir(id, data)
            audit.record("update", "gir", entity_id=id, entity_label=gir.gir_id)
            _matching.invalidate_cache()
            _sync_focus_points()
            flash(f"{gir.gir_id} updated.", "success")
            return redirect(url_for("requirements.gir_detail", id=new_id))
        except Exception as exc:
            flash(f"Could not update GIR: {exc}", "warning")

    return render_template(
        "requirements/gir_form.html",
        gir=gir,
        stakeholders=stakeholders,
        statuses=GIR_STATUSES,
        review_cycles=REVIEW_CYCLES,
        collection_sources=misp_store.get_all_collection_source_labels(),
        output_formats=cti_products(),
        **_galaxy_context(),
    )


@bp.route("/girs/<string:id>/delete", methods=["POST"])
def gir_delete(id):
    gir = misp_store.get_gir(id)
    label = gir.gir_id if gir else id
    try:
        misp_store.delete_gir(id)
        audit.record("delete", "gir", entity_id=id, entity_label=label)
        _matching.invalidate_cache()
        _sync_focus_points()
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete GIR: {exc}", "warning")
    return redirect(url_for("requirements.gir_list"))


@bp.route("/girs/<string:id>/focus_points", methods=["POST"])
def gir_add_focus_point(id):
    try:
        misp_store.add_focus_point_with_scope(
            id,
            request.form["category"],
            request.form["value"],
            request.form.get("notes", ""),
        )
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not add scope item: {exc}", "warning")
    return redirect(url_for("requirements.gir_detail", id=id))


@bp.route("/girs/<string:id>/scope/sync", methods=["POST"])
def gir_sync_scope(id):
    category = request.form.get("category", "").strip()
    if category not in misp_store.GALAXY_FP_CATEGORIES:
        flash("Sync is only supported for galaxy-backed categories.", "warning")
        return redirect(url_for("requirements.gir_detail", id=id))
    values = request.form.getlist("value")
    try:
        misp_store.sync_focus_points_category(id, category, values)
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not sync {category} scope: {exc}", "warning")
    return redirect(url_for("requirements.gir_detail", id=id))


@bp.route("/girs/<string:id>/scope/preview")
def gir_scope_preview(id):
    gir = misp_store.get_gir(id)
    if gir is None:
        return "GIR not found", 404
    timeframe_key, timeframe_hours = _scope_preview_timeframe(request.args.get("timeframe"))
    terms = []
    terms.extend(gir.geographic_scope or [])
    terms.extend(gir.sectors or [])
    terms.extend(gir.threat_actors or [])
    terms.extend(gir.threat_types or [])
    for fp in gir.focus_points:
        if fp.value:
            terms.append(fp.value)
    matches = misp_store.preview_scope_matches(terms, timeframe_hours=timeframe_hours)
    ctx = dict(
        terms=sorted(set(t for t in terms if t)),
        matches=matches,
        timeframe_key=timeframe_key,
        timeframe_options=_SCOPE_PREVIEW_TIMEFRAME_OPTIONS,
    )
    if request.args.get("fragment"):
        return render_template(
            "requirements/_scope_matches.html",
            embedded=True,
            timeframe_action=url_for("requirements.gir_scope_preview", id=gir.uuid, fragment=1),
            **ctx,
        )
    return render_template(
        "requirements/gir_scope_preview.html",
        gir=gir,
        embedded=False,
        timeframe_action=url_for("requirements.gir_scope_preview", id=gir.uuid),
        **ctx,
    )


@bp.route("/girs/<string:id>/focus_points/<string:fp_id>/delete", methods=["POST"])
def gir_delete_focus_point(id, fp_id):
    try:
        misp_store.remove_focus_point_with_scope(id, fp_id)
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not delete scope item: {exc}", "warning")
    return redirect(url_for("requirements.gir_detail", id=id))


# ── Status updates (Kanban) ───────────────────────────────────────────────────

@bp.route("/pirs/<string:id>/status", methods=["POST"])
def pir_status_update(id):
    from flask import jsonify
    pir = misp_store.get_pir(id)
    if pir is None:
        return jsonify({"error": "PIR not found"}), 404
    new_status = request.form.get("status", "").strip()
    if new_status not in PIR_STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    # Pending is the untriaged state; a PIR only leaves it through a terminal
    # triage decision (which itself changes the status). Acknowledge and Defer
    # keep it Pending, so any drag of a Pending card is blocked, and nothing may
    # be dragged back into Pending.
    if pir.status == "Pending":
        return jsonify({"error": "Triage this PIR before moving it."}), 400
    if new_status == "Pending":
        return jsonify({"error": "A PIR cannot be moved back to Pending."}), 400
    data = misp_store.pir_to_data(pir)
    data["status"] = new_status
    try:
        misp_store.update_pir(id, data)
        audit.record("update", "pir", entity_id=id, entity_label=pir.pir_id)
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/girs/<string:id>/status", methods=["POST"])
def gir_status_update(id):
    from flask import jsonify
    gir = misp_store.get_gir(id)
    if gir is None:
        return jsonify({"error": "GIR not found"}), 404
    new_status = request.form.get("status", "").strip()
    if new_status not in GIR_STATUSES:
        return jsonify({"error": "Invalid status"}), 400
    data = misp_store.gir_to_data(gir)
    data["status"] = new_status
    try:
        misp_store.update_gir(id, data)
        audit.record("update", "gir", entity_id=id, entity_label=gir.gir_id)
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Notify stakeholders ───────────────────────────────────────────────────────

def _pir_notify_recipients(pir):
    """Return registered stakeholders selected in PIR distribution."""
    stakeholders = misp_store.list_stakeholders()
    return _selected_distribution_stakeholders(getattr(pir, "distribution", []) or [], stakeholders)


def _gir_notify_recipients(gir):
    """Return registered stakeholders selected in GIR distribution."""
    stakeholders = misp_store.list_stakeholders()
    return _selected_distribution_stakeholders(getattr(gir, "distribution", []) or [], stakeholders)

def _pir_markdown(pir):
    today = date.today().strftime('%d-%m-%Y')
    stakeholders = misp_store.list_stakeholders()
    lines = [
        f"# {pir.pir_id}: Priority Intelligence Requirement",
        f"",
        f"**Date:** {today}",
        f"**Status:** {pir.status}",
        f"**Priority:** {pir.priority}",
        f"",
        f"## Intelligence Question",
        f"",
        f"{pir.question}",
    ]
    if pir.context:
        lines += ["", f"**Context:** {pir.context}"]
    if pir.decision_supported or pir.decision_maker:
        lines += ["", "## Decision Support", ""]
        if pir.decision_supported:
            lines.append(f"**Decision supported:** {pir.decision_supported}")
        if pir.decision_maker:
            if len(pir.decision_maker) == 1:
                lines.append(f"**Decision maker:** {pir.decision_maker[0]}")
            else:
                lines.append("**Decision makers:** " + ", ".join(pir.decision_maker))
        if pir.consequence:
            lines.append(f"**Consequence if unanswered:** {pir.consequence}")
        if getattr(pir, "deadline", ""):
            lines.append(f"**Deadline:** {pir.deadline}")
    if getattr(pir, "priority_justification", ""):
        lines += ["", "## Priority Justification", "", pir.priority_justification]
    scope_parts = []
    if pir.geographic_scope:
        scope_parts.append(f"**Geography:** {', '.join(pir.geographic_scope)}")
    if pir.sectors:
        scope_parts.append(f"**Sectors:** {', '.join(pir.sectors)}")
    if pir.threat_actors:
        scope_parts.append(f"**Threat actors:** {', '.join(pir.threat_actors)}")
    if pir.threat_types:
        scope_parts.append(f"**Threat types:** {', '.join(pir.threat_types)}")
    if getattr(pir, "technology", []):
        scope_parts.append(f"**Technology:** {', '.join(pir.technology)}")
    if getattr(pir, "vendor", []):
        scope_parts.append(f"**Vendor:** {', '.join(pir.vendor)}")
    if getattr(pir, "incident", []):
        scope_parts.append(f"**Incident:** {', '.join(pir.incident)}")
    if getattr(pir, "campaign", []):
        scope_parts.append(f"**Campaign:** {', '.join(pir.campaign)}")
    if scope_parts:
        lines += ["", "## Scope", ""] + scope_parts
    distribution_labels = _distribution_labels(pir.distribution or [], stakeholders)
    if distribution_labels:
        lines += ["", "## Distribution", "", ", ".join(distribution_labels)]
    lines += ["", "---", f"*Sent from zsazsa CTI on {today}*"]
    return "\n".join(lines)


def _gir_markdown(gir):
    today = date.today().strftime('%d-%m-%Y')
    stakeholders = misp_store.list_stakeholders()
    lines = [
        f"# {gir.gir_id}: General Intelligence Requirement",
        f"",
        f"**Date:** {today}",
        f"**Status:** {gir.status}",
        f"**Review cycle:** {gir.review_cycle}",
        f"",
        f"## Topic",
        f"",
        f"{gir.topic}",
    ]
    if gir.description:
        lines += ["", gir.description]
    if getattr(gir, "priority_justification", ""):
        lines += ["", "## Priority Justification", "", gir.priority_justification]
    scope_parts = []
    if gir.geographic_scope:
        scope_parts.append(f"**Geography:** {', '.join(gir.geographic_scope)}")
    if gir.sectors:
        scope_parts.append(f"**Sectors:** {', '.join(gir.sectors)}")
    if gir.threat_actors:
        scope_parts.append(f"**Threat actors:** {', '.join(gir.threat_actors)}")
    if gir.threat_types:
        scope_parts.append(f"**Threat types:** {', '.join(gir.threat_types)}")
    if getattr(gir, "technology", []):
        scope_parts.append(f"**Technology:** {', '.join(gir.technology)}")
    if getattr(gir, "vendor", []):
        scope_parts.append(f"**Vendor:** {', '.join(gir.vendor)}")
    if getattr(gir, "incident", []):
        scope_parts.append(f"**Incident:** {', '.join(gir.incident)}")
    if getattr(gir, "campaign", []):
        scope_parts.append(f"**Campaign:** {', '.join(gir.campaign)}")
    if scope_parts:
        lines += ["", "## Scope", ""] + scope_parts
    distribution_labels = _distribution_labels(getattr(gir, "distribution", []) or [], stakeholders)
    if distribution_labels:
        lines += ["", "## Distribution", "", ", ".join(distribution_labels)]
    lines += ["", "---", f"*Sent from zsazsa CTI on {today}*"]
    return "\n".join(lines)


@bp.route("/pirs/<string:id>/notify", methods=["GET", "POST"])
def pir_notify(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404
    preview_url = url_for("requirements.pir_detail", id=id, _external=True)
    md = _pir_markdown(pir) + f"\n\n[Open PIR preview]({preview_url})"
    recipients = _pir_notify_recipients(pir)

    if request.method == "POST":
        try:
            from notifier import dispatcher

            message_md = request.form.get("markdown", "").strip() or md
            logger.info(
                "PIR notify requested: pir=%s recipients=%d",
                pir.pir_id,
                len(recipients),
            )
            result = dispatcher.send_pir_preview(
                pir,
                preview_url=preview_url,
                markdown=message_md,
                stakeholders=recipients,
            )
            if result["sent_types"]:
                logger.info(
                    "PIR notify sent: pir=%s sent_types=%s recipients=%d",
                    pir.pir_id,
                    ",".join(result["sent_types"]),
                    result["recipients"],
                )
                audit.record(
                    "notify",
                    "pir",
                    entity_id=id,
                    entity_label=pir.pir_id,
                    details=f"ok via {', '.join(result['sent_types'])}; recipients={result['recipients']}",
                )
                flash(
                    f"Notification sent to {result['recipients']} stakeholder(s) via {', '.join(result['sent_types'])}.",
                    "success",
                )
            else:
                logger.warning(
                    "PIR notify skipped: pir=%s recipients=%d no channels",
                    pir.pir_id,
                    result["recipients"],
                )
                audit.record(
                    "notify",
                    "pir",
                    entity_id=id,
                    entity_label=pir.pir_id,
                    details=f"skipped; recipients={result['recipients']}; no eligible channels",
                )
                flash("No notification sent, no eligible stakeholder channels configured.", "warning")
        except Exception as exc:
            logger.exception("PIR notify failed: pir=%s", pir.pir_id)
            audit.record(
                "notify",
                "pir",
                entity_id=id,
                entity_label=pir.pir_id,
                details=f"failed: {exc}",
            )
            flash(f"Notification failed: {exc}", "warning")
        return redirect(url_for("requirements.pir_detail", id=id))
    from notifier import dispatcher
    diagnostics = dispatcher.describe_pir_delivery(recipients)
    return jsonify({
        "markdown": md,
        "preview_url": preview_url,
        "recipient_count": diagnostics["recipients"],
        "recipient_names": diagnostics["recipient_names"],
        "channel_types": diagnostics["channel_types"],
        "channels_by_type": diagnostics["channels_by_type"],
    })


@bp.route("/girs/<string:id>/notify", methods=["GET", "POST"])
def gir_notify(id):
    gir = misp_store.get_gir(id)
    if gir is None:
        return "GIR not found", 404
    preview_url = url_for("requirements.gir_detail", id=id, _external=True)
    md = _gir_markdown(gir) + f"\n\n[Open GIR preview]({preview_url})"
    recipients = _gir_notify_recipients(gir)
    if request.method == "POST":
        try:
            from notifier import dispatcher

            message_md = request.form.get("markdown", "").strip() or md
            logger.info("GIR notify requested: gir=%s recipients=%d", gir.gir_id, len(recipients))
            result = dispatcher.send_gir_preview(
                gir,
                preview_url=preview_url,
                markdown=message_md,
                stakeholders=recipients,
            )
            if result["sent_types"]:
                logger.info(
                    "GIR notify sent: gir=%s sent_types=%s recipients=%d",
                    gir.gir_id,
                    ",".join(result["sent_types"]),
                    result["recipients"],
                )
                audit.record(
                    "notify",
                    "gir",
                    entity_id=id,
                    entity_label=gir.gir_id,
                    details=f"ok via {', '.join(result['sent_types'])}; recipients={result['recipients']}",
                )
                flash(
                    f"Notification sent to {result['recipients']} stakeholder(s) via {', '.join(result['sent_types'])}.",
                    "success",
                )
            else:
                logger.warning("GIR notify skipped: gir=%s recipients=%d no channels", gir.gir_id, result["recipients"])
                audit.record(
                    "notify",
                    "gir",
                    entity_id=id,
                    entity_label=gir.gir_id,
                    details=f"skipped; recipients={result['recipients']}; no eligible channels",
                )
                flash("No notification sent, no eligible stakeholder channels configured.", "warning")
        except Exception as exc:
            logger.exception("GIR notify failed: gir=%s", gir.gir_id)
            audit.record("notify", "gir", entity_id=id, entity_label=gir.gir_id, details=f"failed: {exc}")
            flash(f"Notification failed: {exc}", "warning")
        return redirect(url_for("requirements.gir_detail", id=id))
    from notifier import dispatcher
    diagnostics = dispatcher.describe_delivery(recipients)
    return jsonify({
        "markdown": md,
        "preview_url": preview_url,
        "recipient_count": diagnostics["recipients"],
        "recipient_names": diagnostics["recipient_names"],
        "channel_types": diagnostics["channel_types"],
        "channels_by_type": diagnostics["channels_by_type"],
    })
