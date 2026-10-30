import logging
from datetime import date
from types import SimpleNamespace

import config
from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from webapp import audit, matching as _matching, misp_session, misp_store, notify_jobs, org_store
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
from webapp.utils import dedup_lower, matching, ordered_counts

logger = logging.getLogger(__name__)

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


_SCOPE_FIELDS = (
    "geographic_scope", "sectors", "threat_actors", "threat_types",
    "technology", "vendor", "incident", "campaign", "mitre_attack_techniques",
)


def _level_counts(reqs):
    """Requirements per intelligence level. One can have several levels and
    counts under each; one with none counts as Unspecified."""
    return ordered_counts((level for r in reqs for level in (r.intel_level or ["Unspecified"])), INTEL_LEVELS)


def _scope_item_count(req):
    """Total number of scope items across every scope dimension of a PIR/GIR."""
    return sum(len(getattr(req, field, None) or []) for field in _SCOPE_FIELDS)


def _scope_terms(req):
    """Every scope value on a requirement, as terms for the scope preview.

    All of them, not only the galaxy-backed four: a preview that leaves out the
    vendor or the technique an analyst put in scope reports fewer matches than
    the collection page will flag.
    """
    terms = [value for field in _SCOPE_FIELDS for value in (getattr(req, field, None) or [])]
    terms += [fp.value for fp in (req.focus_points or []) if fp.value]
    return terms


# The scope field each focus point category is posted under, named as the form
# names it. Taken from the store's own mapping so the two agree.
_SCOPE_FP_FIELDS = {
    category: relation.replace("-", "_")
    for category, relation in misp_store._FP_CATEGORY_TO_RELATION.items()
}


def _scope_focus_points(form, existing=()):
    """Focus points for a requirement being saved from its form.

    Saving replaces every focus point, so each category is rebuilt from the
    scope list posted for it. A focus point in a category the form has no field
    for is taken from `existing` instead, which is how a record written before
    a category was added survives a save.
    """
    points = []
    seen = set()
    for category, field in _SCOPE_FP_FIELDS.items():
        for value in form.getlist(field):
            clean = value.strip()
            key = (category, clean.lower())
            if not clean or key in seen:
                continue
            seen.add(key)
            points.append({"category": category, "value": clean})
    for fp in existing or []:
        key = (fp.category, (fp.value or "").lower())
        if fp.category in _SCOPE_FP_FIELDS or key in seen:
            continue
        seen.add(key)
        points.append({"category": fp.category, "value": fp.value})
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


def _pir_form_data(form, stakeholders, focus_points=()):
    """The PIR as its form describes it, for a new PIR and an edit alike.
    ``focus_points`` are the stored ones, kept for categories the form has no field for."""
    owner_uuid, owner_name, owner_role = _owner_fields(form, stakeholders)
    return {
        "question": form["question"],
        "context": form.get("context"),
        "linked_gir_uuids": form.getlist("linked_gir_uuids"),
        "intel_level": [v for v in form.getlist("intel_level") if v in INTEL_LEVELS],
        "owner_uuid": owner_uuid,
        "owner_name": owner_name,
        "owner_role": owner_role,
        "decision_supported": form.get("decision_supported"),
        "decision_maker": [v for v in form.getlist("decision_maker") if v.strip()],
        "consequence": [v for v in form.getlist("consequence") if v.strip()],
        "deadline": form.get("deadline"),
        "priority_justification": form.get("priority_justification"),
        "sub_questions": _sub_questions(form),
        "priority": form.get("priority", "Should have"),
        "time_sensitivity": form.get("time_sensitivity", "Standard (<1 month)"),
        "geographic_scope": dedup_lower(form.getlist("geographic_scope")),
        "time_frame": form.get("time_frame"),
        "threat_types": form.getlist("threat_types"),
        "threat_actors": dedup_lower(form.getlist("threat_actors")),
        "sectors": dedup_lower(form.getlist("sectors")),
        "out_of_scope": form.getlist("out_of_scope"),
        "technology": form.getlist("technology"),
        "vendor": form.getlist("vendor"),
        "incident": form.getlist("incident"),
        "campaign": form.getlist("campaign"),
        "collection_sources": form.getlist("collection_sources"),
        "output_format": [v.strip() for v in form.getlist("output_format") if v.strip()],
        "distribution": _distribution_ids(form, stakeholders),
        "focus_points": _scope_focus_points(form, focus_points),
        "resolution_note": form.get("resolution_note"),
        "next_review": form.get("next_review") or None,
        "mitre_attack_techniques": form.getlist("mitre_attack_techniques"),
    }


def _linkable_girs(linked=()):
    """The GIRs a PIR can be linked to: the active ones, and those it already
    is, so that saving the form keeps a GIR that has since been retired."""
    return [g for g in misp_store.list_girs() if g.status == "Active" or g.uuid in linked]


def _gir_form_data(form, stakeholders, focus_points=()):
    """The GIR as its form describes it, as _pir_form_data does for a PIR."""
    owner_uuid, owner_name, owner_role = _owner_fields(form, stakeholders)
    return {
        "topic": form["topic"],
        "description": form.get("description"),
        "owner_uuid": owner_uuid,
        "owner_name": owner_name,
        "owner_role": owner_role,
        "review_cycle": form.get("review_cycle", "Quarterly"),
        "collection_sources": form.getlist("collection_sources"),
        "geographic_scope": dedup_lower(form.getlist("geographic_scope")),
        "sectors": dedup_lower(form.getlist("sectors")),
        "threat_types": form.getlist("threat_types"),
        "threat_actors": dedup_lower(form.getlist("threat_actors")),
        "out_of_scope": form.getlist("out_of_scope"),
        "technology": form.getlist("technology"),
        "vendor": form.getlist("vendor"),
        "incident": form.getlist("incident"),
        "campaign": form.getlist("campaign"),
        "output_format": [v.strip() for v in form.getlist("output_format") if v.strip()],
        "distribution": _distribution_ids(form, stakeholders),
        "deadline": form.get("deadline"),
        "priority_justification": form.get("priority_justification"),
        "sub_questions": _sub_questions(form),
        "focus_points": _scope_focus_points(form, focus_points),
        "next_review": form.get("next_review") or None,
        "intel_level": [v for v in form.getlist("intel_level") if v in INTEL_LEVELS],
        "mitre_attack_techniques": form.getlist("mitre_attack_techniques"),
    }


INTEL_LEVEL_REQUIRED = "Select at least one intelligence level."


# ── PIRs ──────────────────────────────────────────────────────────────────────

PIR_TRIAGE_CHECKLIST = [
    ("clear_question", "The intelligence question is clearly stated and answerable within the program's scope."),
    ("requester_identified", "The requester and the decision it supports are identified."),
    ("not_duplicate", "This question is not already answered by an existing active PIR or GIR."),
    ("priority_realistic", "The priority level and time sensitivity are realistic given current team capacity."),
    ("sources_available", "Collection sources are available or can be identified to address the question."),
]


# A PIR that was rejected or already merged away cannot take another one in.
_NOT_MERGE_TARGETS = ("rejected", "merged")

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
    all_pirs = misp_store.list_pirs()
    intel_filter = (request.args.get("intel_level") or "").strip()
    priority_filter = (request.args.get("priority") or "").strip()
    # Rejected PIRs are done with, so the list leaves them out until asked for
    # them, as the RFI list does with closed RFIs.
    show_rejected = request.args.get("rejected") == "1"
    tests = {}
    if intel_filter:
        tests["intel_level"] = lambda p: intel_filter in (p.intel_level or [])
    if priority_filter:
        tests["priority"] = lambda p: p.priority == priority_filter
    if not show_rejected:
        tests["rejected"] = lambda p: p.intake_status != "rejected"
    pirs = _sort_requirements(
        matching(all_pirs, tests), request.args.get("sort"), request.args.get("dir"),
        "pir_id", "question", PIR_STATUS_ORDER,
    )
    linked_girs = {}
    if any(p.linked_gir_uuids for p in pirs):
        all_girs = misp_store.list_girs()
        linked_girs = {p.uuid: [g for g in all_girs if g.uuid in p.linked_gir_uuids] for p in pirs}
    return render_template(
        "requirements/pir_list.html",
        pirs=pirs,
        linked_girs=linked_girs,
        scope_counts={p.uuid: _scope_item_count(p) for p in pirs},
        status_counts=ordered_counts(("Rejected" if p.intake_status == "rejected" else p.status for p in pirs),
                                     PIR_STATUS_ORDER),
        priority_counts=ordered_counts((p.priority for p in matching(all_pirs, tests, skip="priority")),
                                       MOSCOW_PRIORITIES),
        level_counts=_level_counts(matching(all_pirs, tests, skip="intel_level")),
        intel_levels=INTEL_LEVELS,
        intel_filter=intel_filter,
        priorities=MOSCOW_PRIORITIES,
        priority_filter=priority_filter,
        show_rejected=show_rejected,
        rejected_count=sum(1 for p in matching(all_pirs, tests, skip="rejected") if p.intake_status == "rejected"),
        merge_targets=[p for p in all_pirs if p.intake_status not in _NOT_MERGE_TARGETS],
        triage_checklist=PIR_TRIAGE_CHECKLIST,
    )


def _prefill_from_stakeholder(stakeholders) -> dict:
    """Owner and distribution for a requirement started from a stakeholder's page."""
    from_uuid = (request.args.get("from_stakeholder") or "").strip()
    owner = next((s for s in stakeholders if s.uuid == from_uuid), None)
    return {"owner_uuid": owner.uuid, "distribution": [owner.uuid]} if owner else {}


@bp.route("/pirs/new", methods=["GET", "POST"])
def pir_new():
    stakeholders = misp_store.list_stakeholders()
    prefill = _prefill_from_stakeholder(stakeholders)
    if request.method == "POST":
        data = _pir_form_data(request.form, stakeholders)
        # Placeholder; create_pir allocates the authoritative pir_id atomically.
        data["pir_id"] = ""
        data["status"] = "Pending"  # always starts Pending until triage is complete
        if not data["intel_level"]:
            flash(INTEL_LEVEL_REQUIRED, "warning")
        else:
            try:
                uuid = misp_store.create_pir(data)
                pir_id = data["pir_id"]
                audit.record("create", "pir", entity_id=uuid, entity_label=pir_id)
                _matching.invalidate_cache()
                flash(f"{pir_id} created.", "success")
                return redirect(url_for("requirements.pir_detail", id=uuid))
            except Exception as exc:
                logger.exception("Could not create PIR")
                flash(f"Could not create PIR: {exc}", "warning")

    return render_template(
        "requirements/pir_form.html",
        pir=None,
        prefill=prefill,
        girs=_linkable_girs(),
        stakeholders=stakeholders,
        org_map=org_store.org_map(),
        priorities=MOSCOW_PRIORITIES,
        statuses=PIR_STATUSES,
        time_sensitivities=TIME_SENSITIVITIES,
        collection_source_groups=misp_store.collection_source_groups(),
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
    scope_terms = _scope_terms(pir)
    coverage = {}
    try:
        coverage = misp_store.pir_collection_gap(scope_terms)
    except Exception as exc:
        logger.warning("collection gap check failed for %s: %s", id, exc)
    linked_girs = []
    if pir.linked_gir_uuids:
        linked_girs = [g for g in misp_store.list_girs() if g.uuid in pir.linked_gir_uuids]

    return render_template(
        "requirements/pir_detail.html",
        pir=pir,
        focus_points=pir.focus_points,
        categories=FOCUS_CATEGORIES,
        fp_by_category=fp_by_category,
        misp_url=misp_url,
        distribution=distribution,
        selected_count=sum(1 for stakeholder in distribution if stakeholder.in_distribution),
        scope_terms=scope_terms,
        coverage=coverage,
        linked_girs=linked_girs,
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
        # The status and the intake decision are kept as stored: they change
        # through triage and the status board, not this form. The checklist
        # answers given at triage can be corrected here.
        data = {**misp_store.pir_to_data(pir),
                **_pir_form_data(request.form, stakeholders, pir.focus_points)}
        triage_keys = [key for key, _ in PIR_TRIAGE_CHECKLIST]
        data["triage_checklist"] = [k for k in request.form.getlist("triage_checklist") if k in triage_keys]
        if not data["intel_level"]:
            flash(INTEL_LEVEL_REQUIRED, "warning")
        else:
            try:
                misp_store.update_pir(id, data)
                audit.record("update", "pir", entity_id=id, entity_label=pir.pir_id)
                _matching.invalidate_cache()
                flash(f"{pir.pir_id} updated.", "success")
                return redirect(url_for("requirements.pir_detail", id=id))
            except Exception as exc:
                logger.exception("Could not update PIR %s", id)
                flash(f"Could not update PIR: {exc}", "warning")

    return render_template(
        "requirements/pir_form.html",
        pir=pir,
        girs=_linkable_girs(pir.linked_gir_uuids),
        triage_checklist=PIR_TRIAGE_CHECKLIST,
        stakeholders=stakeholders,
        org_map=org_store.org_map(),
        priorities=MOSCOW_PRIORITIES,
        statuses=PIR_STATUSES,
        time_sensitivities=TIME_SENSITIVITIES,
        collection_source_groups=misp_store.collection_source_groups(),
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
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        logger.exception("Could not delete PIR %s", id)
        flash(f"Could not delete PIR: {exc}", "warning")
    return redirect(url_for("requirements.pir_list"))


@bp.route("/pirs/<string:id>/triage", methods=["POST"])
def pir_triage(id):
    pir = misp_store.get_pir(id)
    if pir is None:
        return "PIR not found", 404
    # The PIR list offers triage only to these.
    if pir.status != "Pending" or pir.intake_status == "rejected":
        flash(f"{pir.pir_id} has already been triaged.", "warning")
        return redirect(url_for("requirements.pir_list"))

    decision = request.form.get("decision", "").strip()
    valid_decisions = [s for s in PIR_INTAKE_STATUSES if s not in ("submitted", "triaged")]
    if decision not in valid_decisions:
        flash("Select a valid decision.", "warning")
        return redirect(url_for("requirements.pir_list"))

    reason = request.form.get("reason", "").strip()
    if decision in ("rejected", "deferred") and not reason:
        flash("A reason is required when rejecting or deferring.", "warning")
        return redirect(url_for("requirements.pir_list"))

    target = None
    if decision == "merged":
        linked_uuid = request.form.get("linked_pir_uuid", "").strip()
        target = misp_store.get_pir(linked_uuid) if linked_uuid else None
        if target is None or target.uuid == pir.uuid or target.intake_status in _NOT_MERGE_TARGETS:
            flash("Select the PIR to merge into.", "warning")
            return redirect(url_for("requirements.pir_list"))

    checklist = request.form.getlist("triage_checklist")
    try:
        misp_store.update_pir_intake(
            id,
            decision,
            reason=reason or None,
            linked_pir_uuid=target.uuid if target else None,
            checklist=checklist,
        )
        audit.record("triage", "pir", entity_id=id, entity_label=pir.pir_id)
        # Approving or merging changes whether the PIR is matched against events.
        _matching.invalidate_cache()
        try:
            from notifier import dispatcher
            stakeholders = misp_store.list_stakeholders()
            recipients = _selected_distribution_stakeholders([pir.owner_uuid, *pir.distribution], stakeholders)
            dispatcher.send_pir_intake(pir, decision, reason or None, recipients)
        except Exception as exc:
            logger.warning("PIR intake notification failed for %s: %s", pir.pir_id, exc)
        if decision in ("acknowledged", "deferred"):
            flash(f"{pir.pir_id} marked as {decision}. It stays Pending until it is "
                  "approved, rejected or merged.", "success")
        else:
            flash(f"{pir.pir_id} marked as {decision}.", "success")
    except Exception as exc:
        flash(f"Could not update intake status: {exc}", "warning")
    return redirect(url_for("requirements.pir_list"))


@bp.route("/pirs/<string:id>/focus_points", methods=["POST"])
def pir_add_focus_point(id):
    if misp_store.get_pir(id) is None:
        return "PIR not found", 404
    try:
        misp_store.add_focus_point_with_scope(
            id,
            request.form["category"],
            request.form["value"],
        )
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not add scope item: {exc}", "warning")
    return redirect(url_for("requirements.pir_detail", id=id))


@bp.route("/pirs/<string:id>/scope/sync", methods=["POST"])
def pir_sync_scope(id):
    if misp_store.get_pir(id) is None:
        return "PIR not found", 404
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
    terms = _scope_terms(pir)
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
    if misp_store.get_pir(id) is None:
        return "PIR not found", 404
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
    all_girs = misp_store.list_girs()
    intel_filter = (request.args.get("intel_level") or "").strip()
    cycle_filter = (request.args.get("review_cycle") or "").strip()
    # Retired GIRs are done with, so the list leaves them out until asked for them.
    show_retired = request.args.get("retired") == "1"
    tests = {}
    if intel_filter:
        tests["intel_level"] = lambda g: intel_filter in (g.intel_level or [])
    if cycle_filter:
        tests["review_cycle"] = lambda g: g.review_cycle == cycle_filter
    if not show_retired:
        tests["retired"] = lambda g: g.status != "Retired"
    girs = _sort_requirements(
        matching(all_girs, tests), request.args.get("sort"), request.args.get("dir"),
        "gir_id", "topic", GIR_STATUS_ORDER,
    )
    # The link is kept on the PIR, so a GIR's PIRs are those that name it.
    linked_pirs = {}
    if girs:
        for pir in misp_store.list_pirs():
            for gir_uuid in pir.linked_gir_uuids:
                linked_pirs.setdefault(gir_uuid, []).append(pir)
    return render_template(
        "requirements/gir_list.html",
        girs=girs,
        linked_pirs=linked_pirs,
        scope_counts={g.uuid: _scope_item_count(g) for g in girs},
        status_counts=ordered_counts((g.status for g in girs), GIR_STATUS_ORDER),
        level_counts=_level_counts(matching(all_girs, tests, skip="intel_level")),
        cycle_counts=ordered_counts((g.review_cycle for g in matching(all_girs, tests, skip="review_cycle")),
                                    REVIEW_CYCLES),
        intel_levels=INTEL_LEVELS,
        intel_filter=intel_filter,
        review_cycles=REVIEW_CYCLES,
        cycle_filter=cycle_filter,
        show_retired=show_retired,
        retired_count=sum(1 for g in matching(all_girs, tests, skip="retired") if g.status == "Retired"),
    )


@bp.route("/girs/new", methods=["GET", "POST"])
def gir_new():
    stakeholders = misp_store.list_stakeholders()
    prefill = _prefill_from_stakeholder(stakeholders)
    if request.method == "POST":
        data = _gir_form_data(request.form, stakeholders)
        # Placeholder; create_gir allocates the authoritative gir_id atomically.
        data["gir_id"] = ""
        data["status"] = "Pending"
        if not data["intel_level"]:
            flash(INTEL_LEVEL_REQUIRED, "warning")
        else:
            try:
                uuid = misp_store.create_gir(data)
                gir_id = data["gir_id"]
                audit.record("create", "gir", entity_id=uuid, entity_label=gir_id)
                _matching.invalidate_cache()
                flash(f"{gir_id} created.", "success")
                return redirect(url_for("requirements.gir_detail", id=uuid))
            except Exception as exc:
                logger.exception("Could not create GIR")
                flash(f"Could not create GIR: {exc}", "warning")

    return render_template(
        "requirements/gir_form.html",
        gir=None,
        prefill=prefill,
        stakeholders=stakeholders,
        org_map=org_store.org_map(),
        statuses=GIR_STATUSES,
        review_cycles=REVIEW_CYCLES,
        collection_source_groups=misp_store.collection_source_groups(),
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
        linked_pirs=[p for p in misp_store.list_pirs() if gir.uuid in p.linked_gir_uuids],
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
        data = _gir_form_data(request.form, stakeholders, gir.focus_points)
        data["gir_id"] = gir.gir_id
        status = request.form.get("status")
        data["status"] = status if status in GIR_STATUSES else gir.status
        if not data["intel_level"]:
            flash(INTEL_LEVEL_REQUIRED, "warning")
        else:
            try:
                misp_store.update_gir(id, data)
                audit.record("update", "gir", entity_id=id, entity_label=gir.gir_id)
                _matching.invalidate_cache()
                flash(f"{gir.gir_id} updated.", "success")
                return redirect(url_for("requirements.gir_detail", id=id))
            except Exception as exc:
                logger.exception("Could not update GIR %s", id)
                flash(f"Could not update GIR: {exc}", "warning")

    return render_template(
        "requirements/gir_form.html",
        gir=gir,
        stakeholders=stakeholders,
        org_map=org_store.org_map(),
        statuses=GIR_STATUSES,
        review_cycles=REVIEW_CYCLES,
        collection_source_groups=misp_store.collection_source_groups(),
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
        flash(f"{label} deleted.", "info")
    except Exception as exc:
        logger.exception("Could not delete GIR %s", id)
        flash(f"Could not delete GIR: {exc}", "warning")
    return redirect(url_for("requirements.gir_list"))


@bp.route("/girs/<string:id>/focus_points", methods=["POST"])
def gir_add_focus_point(id):
    if misp_store.get_gir(id) is None:
        return "GIR not found", 404
    try:
        misp_store.add_focus_point_with_scope(
            id,
            request.form["category"],
            request.form["value"],
        )
        misp_store.sync_scope_tags_from_store(id)
        _matching.invalidate_cache()
    except Exception as exc:
        flash(f"Could not add scope item: {exc}", "warning")
    return redirect(url_for("requirements.gir_detail", id=id))


@bp.route("/girs/<string:id>/scope/sync", methods=["POST"])
def gir_sync_scope(id):
    if misp_store.get_gir(id) is None:
        return "GIR not found", 404
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
    terms = _scope_terms(gir)
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
    if misp_store.get_gir(id) is None:
        return "GIR not found", 404
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
        _matching.invalidate_cache()
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bp.route("/girs/<string:id>/status", methods=["POST"])
def gir_status_update(id):
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
        _matching.invalidate_cache()
        return jsonify({"ok": True, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Notify stakeholders ───────────────────────────────────────────────────────

def _notify_recipients(req):
    """Registered stakeholders selected in a requirement's distribution."""
    stakeholders = misp_store.list_stakeholders()
    return _selected_distribution_stakeholders(getattr(req, "distribution", []) or [], stakeholders)


_SCOPE_MARKDOWN_LABELS = (
    ("Geography", "geographic_scope"),
    ("Sectors", "sectors"),
    ("Threat actors", "threat_actors"),
    ("Threat types", "threat_types"),
    ("Technology", "technology"),
    ("Vendor", "vendor"),
    ("Incident", "incident"),
    ("Campaign", "campaign"),
    ("ATT&CK techniques", "mitre_attack_techniques"),
)


def _scope_markdown(req):
    """The "## Scope" section, the same for a PIR and a GIR."""
    parts = []
    for label, field in _SCOPE_MARKDOWN_LABELS:
        values = getattr(req, field, None) or []
        if values:
            parts.append(f"**{label}:** {', '.join(values)}")
    return ["", "## Scope", ""] + parts if parts else []


def _pir_markdown(pir):
    today = date.today().strftime('%d-%m-%Y')
    stakeholders = misp_store.list_stakeholders()
    lines = [
        f"# {pir.pir_id}: Priority Intelligence Requirement",
        "",
        f"**Date:** {today}",
        f"**Status:** {pir.status}",
        f"**Priority:** {pir.priority}",
        "",
        "## Intelligence Question",
        "",
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
            label = "Consequence" if len(pir.consequence) == 1 else "Consequences"
            lines.append(f"**{label} if unanswered:** " + ", ".join(pir.consequence))
        if getattr(pir, "deadline", ""):
            lines.append(f"**Deadline:** {pir.deadline}")
    if getattr(pir, "priority_justification", ""):
        lines += ["", "## Priority Justification", "", pir.priority_justification]
    lines += _scope_markdown(pir)
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
        "",
        f"**Date:** {today}",
        f"**Status:** {gir.status}",
        f"**Review cycle:** {gir.review_cycle}",
        "",
        "## Topic",
        "",
        f"{gir.topic}",
    ]
    if gir.description:
        lines += ["", gir.description]
    if getattr(gir, "priority_justification", ""):
        lines += ["", "## Priority Justification", "", gir.priority_justification]
    lines += _scope_markdown(gir)
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
    recipients = _notify_recipients(pir)

    from notifier import dispatcher

    if request.method == "POST":
        try:
            message_md = request.form.get("markdown", "").strip() or md
            notify_jobs.start_preview(
                "notify-pir",
                f"{pir.pir_id} notification",
                lambda: dispatcher.send_pir_preview(
                    pir, preview_url=preview_url, markdown=message_md, stakeholders=recipients),
                entity_type="pir",
                entity_id=id,
                entity_label=pir.pir_id,
                user=misp_session.current_user_email(),
            )
            flash("Notification is being sent in the background; the job badge reports the result.", "info")
        except Exception as exc:
            logger.exception("PIR notify failed: pir=%s", pir.pir_id)
            flash(f"Could not start the notification: {exc}", "warning")
        return redirect(url_for("requirements.pir_detail", id=id))
    diagnostics = dispatcher.describe_delivery(recipients)
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
    recipients = _notify_recipients(gir)
    from notifier import dispatcher

    if request.method == "POST":
        try:
            message_md = request.form.get("markdown", "").strip() or md
            notify_jobs.start_preview(
                "notify-gir",
                f"{gir.gir_id} notification",
                lambda: dispatcher.send_gir_preview(
                    gir, preview_url=preview_url, markdown=message_md, stakeholders=recipients),
                entity_type="gir",
                entity_id=id,
                entity_label=gir.gir_id,
                user=misp_session.current_user_email(),
            )
            flash("Notification is being sent in the background; the job badge reports the result.", "info")
        except Exception as exc:
            logger.exception("GIR notify failed: gir=%s", gir.gir_id)
            flash(f"Could not start the notification: {exc}", "warning")
        return redirect(url_for("requirements.gir_detail", id=id))
    diagnostics = dispatcher.describe_delivery(recipients)
    return jsonify({
        "markdown": md,
        "preview_url": preview_url,
        "recipient_count": diagnostics["recipients"],
        "recipient_names": diagnostics["recipient_names"],
        "channel_types": diagnostics["channel_types"],
        "channels_by_type": diagnostics["channels_by_type"],
    })
