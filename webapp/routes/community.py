from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for

from webapp import audit, misp_store, org_store, sso_users

bp = Blueprint("community", __name__, url_prefix="/community")


def _breakdown(values, missing="not set"):
    """How often each value comes up for a banner's breakdown: the most first,
    then by name, and the empty ones, named ``missing``, last."""
    counts = Counter(v or missing for v in values)
    return sorted(counts.items(), key=lambda item: (item[0] == missing, -item[1], item[0].lower()))


@bp.route("/organisations")
def organisations():
    orgs = org_store.list_organisations()
    stakeholders = misp_store.list_stakeholders()
    stakeholder_counts = Counter(s.organization for s in stakeholders if s.organization)
    user_counts = Counter(u.organisation_uuid for u in sso_users.list_sso_users() if u.organisation_uuid)
    without_organisation = sum(1 for s in stakeholders if not s.organization)
    by_stakeholders = [(o.name, stakeholder_counts[o.uuid]) for o in orgs if stakeholder_counts[o.uuid]]
    if without_organisation:
        by_stakeholders.append(("none", without_organisation))
    return render_template(
        "community/organisations.html", orgs=orgs, stakeholder_counts=stakeholder_counts, user_counts=user_counts,
        stakeholders_in_orgs=sum(stakeholder_counts[o.uuid] for o in orgs),
        users_in_orgs=sum(user_counts[o.uuid] for o in orgs),
        without_organisation=without_organisation, by_stakeholders=by_stakeholders,
        by_sector=_breakdown(o.sector for o in orgs), by_country=_breakdown(o.country for o in orgs),
        countries=len({o.country for o in orgs if o.country}))


@bp.route("/organisations/add", methods=["POST"])
def organisations_add():
    uuid = (request.form.get("uuid") or "").strip()
    try:
        org = org_store.add_organisation(uuid)
        audit.record("create", "organisation", entity_id=org.uuid, entity_label=org.name)
        flash(f'Organisation "{org.name}" added.', "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/<string:uuid>/delete", methods=["POST"])
def organisations_delete(uuid):
    org = org_store.get_organisation(uuid)
    name = org.name if org else uuid
    try:
        org_store.delete_organisation(uuid)
        audit.record("delete", "organisation", entity_id=uuid, entity_label=name)
        flash(f'Organisation "{name}" removed.', "info")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/<string:uuid>/sync", methods=["POST"])
def organisations_sync(uuid):
    org = org_store.get_organisation(uuid)
    name = org.name if org else uuid
    try:
        updated = org_store.sync_organisation(uuid)
        audit.record("update", "organisation", entity_id=updated.uuid, entity_label=updated.name)
        flash(f'Organisation "{name}" synced from MISP.', "success")
    except ValueError as exc:
        flash(str(exc), "warning")
    return redirect(url_for("community.organisations"))


@bp.route("/organisations/sync-all", methods=["POST"])
def organisations_sync_all():
    updated_count, failed_count = org_store.sync_all_organisations()
    audit.record(
        "update",
        "organisation",
        entity_id="all",
        entity_label=f"sync-all updated={updated_count} failed={failed_count}",
    )
    if failed_count:
        flash(
            f"Synced {updated_count} organisations from MISP, {failed_count} failed.",
            "warning",
        )
    else:
        flash(f"Synced {updated_count} organisations from MISP.", "success")
    return redirect(url_for("community.organisations"))


def _seen_at(value):
    """A sighting's time, stored in UTC as 2026-11-15T22:41:37, or None."""
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _ago(when, now):
    days = (now.date() - when.date()).days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 14:
        return f"{days} days ago"
    if days < 60:
        return f"{days // 7} weeks ago"
    return f"{days // 30} months ago"


@bp.route("/users")
def users():
    now = datetime.now(timezone.utc)
    seen_users = sso_users.list_sso_users()
    for u in seen_users:
        u.first_seen_at = _seen_at(u.first_seen)
        u.last_seen_at = _seen_at(u.last_seen)
        u.last_seen_ago = _ago(u.last_seen_at, now) if u.last_seen_at else ""
    seen_users.sort(key=lambda u: u.last_seen or "", reverse=True)
    week_ago = now - timedelta(days=7)
    recent = [u for u in seen_users if u.last_seen_at and u.last_seen_at >= week_ago]
    return render_template("community/users.html", sso_users=seen_users, recent=recent,
                           earlier=[u for u in seen_users if u not in recent],
                           shared_ids=len({u.misp_user_id for u in seen_users if u.same_user_as}),
                           organisations=len({u.organisation_uuid for u in seen_users if u.organisation_uuid}),
                           by_role=_breakdown((u.role for u in seen_users), "unknown"),
                           by_organisation=_breakdown((u.organisation for u in seen_users), "none"))


@bp.route("/roles")
def roles():
    return render_template("community/roles.html")
