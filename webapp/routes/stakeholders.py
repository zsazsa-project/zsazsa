import config as _config

from flask import Blueprint, flash, redirect, render_template, request, url_for

from webapp import audit, misp_store, org_store
from webapp.models import cti_products, STAKEHOLDER_ROLES, TLP_LEVELS
from webapp.utils import normalize_notification_channels, product_detail_url


def _notification_channels() -> list[dict]:
    """Return all configured notification channels (Mattermost + Flowintel)."""
    from core import flowintel_client

    channels = normalize_notification_channels(
        getattr(_config, "NOTIFICATION_CHANNELS", []),
        legacy_url=getattr(_config, "MATTERMOST_WEBHOOK_URL", ""),
        legacy_enabled=getattr(_config, "MATTERMOST_ENABLED", False),
    )
    return channels + flowintel_client.notification_channels()


def _active_notification_channels() -> list[dict]:
    """Return enabled notification channels from config."""
    return [c for c in _notification_channels() if c.get("enabled")]


def _notification_channel_names() -> dict[str, str]:
    """Return a mapping of notification channel id to display name."""
    return {c["id"]: c["name"] for c in _notification_channels() if c.get("id")}

bp = Blueprint("stakeholders", __name__)


def _parse_contacts(form):
    """Build a list of contact dicts from the multi-row contacts form fields."""
    types = form.getlist("contact_type")
    values = form.getlist("contact_value")
    preferred_idx = form.get("contact_preferred", "")
    contacts = []
    for i, (t, v) in enumerate(zip(types, values)):
        v = v.strip()
        if not v:
            continue
        contacts.append({
            "type": t,
            "value": v,
            "preferred": (str(i) == preferred_idx),
        })
    if contacts and not any(c["preferred"] for c in contacts):
        contacts[0]["preferred"] = True
    return contacts


def _parse_subscriptions(form):
    """Return (products_list, product_modes_dict) from form fields.

    For each product type the form sends ``products=<name>`` (when checked)
    and ``mode__<name>`` set to one of SUBSCRIPTION_MODES.
    """
    selected = form.getlist("products")
    modes = {}
    for p in selected:
        m = form.get(f"mode__{p}", misp_store.DEFAULT_SUBSCRIPTION_MODE)
        if m not in misp_store.SUBSCRIPTION_MODES:
            m = misp_store.DEFAULT_SUBSCRIPTION_MODE
        modes[p] = m
    return selected, modes


def _parse_notification_channels(form, subscribed: list | None = None) -> list[str]:
    """Channel subscriptions from the form, keeping the ones it cannot show.

    Only active channels get a checkbox, so a channel that is disabled while it is
    being reconfigured is absent from the submission. Dropping it would silently
    unsubscribe the stakeholder, and re-enabling the channel would not bring the
    subscription back. Channels that were deleted outright do fall away here.
    """
    channels = _notification_channels()
    active = {c["id"] for c in channels if c.get("id") and c.get("enabled")}
    hidden = [c["id"] for c in channels if c.get("id") and not c.get("enabled")]
    selected = [cid for cid in form.getlist("notification_channels") if cid in active]
    return selected + [cid for cid in hidden if cid in (subscribed or [])]


def _parse_scale(form, name, default=5):
    """Parse a 1-10 matrix scale value from the form, falling back to ``default``."""
    try:
        value = int(form.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(1, min(10, value))


QUADRANTS = {
    "manage-closely": "Manage Closely",
    "keep-satisfied": "Keep Satisfied",
    "keep-informed": "Keep Informed",
    "monitor": "Monitor",
}


def _quadrant_for(influence, interest):
    """Return the (key, label) of the power/interest quadrant for the given scores."""
    high_influence = influence > 5
    high_interest = interest > 5
    if high_influence and high_interest:
        return "manage-closely", QUADRANTS["manage-closely"]
    if high_influence:
        return "keep-satisfied", QUADRANTS["keep-satisfied"]
    if high_interest:
        return "keep-informed", QUADRANTS["keep-informed"]
    return "monitor", QUADRANTS["monitor"]


def _place_on_matrix(stakeholder):
    """Annotate a stakeholder namespace with its matrix quadrant and plot position."""
    stakeholder.quadrant_key, stakeholder.quadrant_label = _quadrant_for(stakeholder.influence, stakeholder.interest)
    # Inset from the 0/100 edges so dots for scores of 1 or 10 still sit fully inside the grid.
    stakeholder.interest_pct = 5 + (stakeholder.interest - 1) / 9 * 90
    stakeholder.influence_pct = 5 + (stakeholder.influence - 1) / 9 * 90
    return stakeholder


def _spread_overlapping(stakeholders):
    """Nudge stakeholders that plot to the same spot so all of them stay visible."""
    groups = {}
    for s in stakeholders:
        groups.setdefault((s.interest_pct, s.influence_pct), []).append(s)
    for group in groups.values():
        if len(group) < 2:
            continue
        for i, s in enumerate(group):
            offset = (i - (len(group) - 1) / 2) * 5
            s.interest_pct = min(95, max(5, s.interest_pct + offset))
            s.influence_pct = min(95, max(5, s.influence_pct + offset))


def _sort_stakeholders(items, sort, direction):
    keys = {
        "name": lambda s: (s.name or "").lower(),
        "role": lambda s: (s.role or "").lower(),
    }
    keyfn = keys.get((sort or "").strip())
    if keyfn:
        items = sorted(items, key=keyfn, reverse=(direction == "desc"))
    return items


@bp.route("/", endpoint="list")
def list_stakeholders():
    stakeholders = misp_store.list_stakeholders()
    org_map = org_store.org_map()
    # Organisation options for the filter: distinct organisations actually in use,
    # labelled via org_map and sorted by display name.
    org_values = sorted(
        {s.organization for s in stakeholders if s.organization},
        key=lambda v: (org_map.get(v, v) or "").lower(),
    )
    org_options = [(v, org_map.get(v, v)) for v in org_values]

    type_filter = (request.args.get("type") or "").strip()
    org_filter = (request.args.get("organization") or "").strip()
    if type_filter:
        stakeholders = [s for s in stakeholders if s.stakeholder_type == type_filter]
    if org_filter:
        stakeholders = [s for s in stakeholders if s.organization == org_filter]
    stakeholders = _sort_stakeholders(stakeholders, request.args.get("sort"), request.args.get("dir"))

    return render_template(
        "stakeholders/list.html",
        stakeholders=stakeholders,
        org_map=org_map,
        org_options=org_options,
        type_filter=type_filter,
        org_filter=org_filter,
    )


@bp.route("/matrix")
def matrix():
    stakeholders = [_place_on_matrix(s) for s in misp_store.list_stakeholders()]
    _spread_overlapping(stakeholders)
    by_quadrant = {key: [] for key in QUADRANTS}
    for s in stakeholders:
        by_quadrant[s.quadrant_key].append(s)
    return render_template("stakeholders/matrix.html", stakeholders=stakeholders, by_quadrant=by_quadrant, quadrants=QUADRANTS)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        products, product_modes = _parse_subscriptions(request.form)
        data = {
            "name": request.form["name"],
            "role": request.form.get("role"),
            "organization": request.form.get("organization"),
            "stakeholder_type": request.form.get("stakeholder_type", "External"),
            "contacts": _parse_contacts(request.form),
            "tlp_clearance": request.form.get("tlp_clearance", "amber"),
            "notes": request.form.get("notes"),
            "products": products,
            "product_modes": product_modes,
            "notification_channels": _parse_notification_channels(request.form),
            "influence": _parse_scale(request.form, "influence"),
            "interest": _parse_scale(request.form, "interest"),
            "engagement_strategy": request.form.get("engagement_strategy"),
        }
        try:
            uuid = misp_store.create_stakeholder(data)
            audit.record("create", "stakeholder", entity_id=uuid, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} created.", "success")
            return redirect(url_for("stakeholders.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create stakeholder: {exc}", "warning")

    return render_template(
        "stakeholders/form.html",
        stakeholder=None,
        roles=STAKEHOLDER_ROLES,
        products=cti_products(),
        tlp_levels=TLP_LEVELS,
        subscription_modes=misp_store.SUBSCRIPTION_MODES,
        default_subscription_mode=misp_store.DEFAULT_SUBSCRIPTION_MODE,
        notification_channels=_active_notification_channels(),
        organisations=org_store.list_organisations(),
    )


@bp.route("/<string:id>")
def detail(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    _place_on_matrix(stakeholder)
    owned_pirs = misp_store.pirs_for_stakeholder(id)
    distributed_pirs = misp_store.pirs_distributed_to_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    owned_girs = misp_store.girs_for_stakeholder(id)
    distributed_girs = misp_store.girs_distributed_to_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    recent_products = misp_store.products_for_stakeholder(
        id,
        stakeholder_name=getattr(stakeholder, "name", ""),
        stakeholder_email=getattr(stakeholder, "email", ""),
    )
    for ev in recent_products:
        ev.app_url = product_detail_url(getattr(ev, "product_type", ""), getattr(ev, "uuid", ""), fallback_url=getattr(ev, "misp_url", ""))
    return render_template(
        "stakeholders/detail.html",
        stakeholder=stakeholder,
        owned_pirs=owned_pirs,
        distributed_pirs=distributed_pirs,
        owned_girs=owned_girs,
        distributed_girs=distributed_girs,
        recent_products=recent_products,
        org_map=org_store.org_map(),
        notification_channel_names=_notification_channel_names(),
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    if request.method == "POST":
        products, product_modes = _parse_subscriptions(request.form)
        data = {
            "name": request.form["name"],
            "role": request.form.get("role"),
            "organization": request.form.get("organization"),
            "stakeholder_type": request.form.get("stakeholder_type", "External"),
            "contacts": _parse_contacts(request.form),
            "tlp_clearance": request.form.get("tlp_clearance", "amber"),
            "notes": request.form.get("notes"),
            "products": products,
            "product_modes": product_modes,
            "notification_channels": _parse_notification_channels(
                request.form, getattr(stakeholder, "notification_channels", None)),
            "influence": _parse_scale(request.form, "influence"),
            "interest": _parse_scale(request.form, "interest"),
            "engagement_strategy": request.form.get("engagement_strategy"),
        }
        try:
            new_id = misp_store.update_stakeholder(id, data)
            audit.record("update", "stakeholder", entity_id=id, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} updated.", "success")
            return redirect(url_for("stakeholders.detail", id=new_id))
        except Exception as exc:
            flash(f"Could not update stakeholder: {exc}", "warning")

    return render_template(
        "stakeholders/form.html",
        stakeholder=stakeholder,
        roles=STAKEHOLDER_ROLES,
        products=cti_products(),
        tlp_levels=TLP_LEVELS,
        subscription_modes=misp_store.SUBSCRIPTION_MODES,
        default_subscription_mode=misp_store.DEFAULT_SUBSCRIPTION_MODE,
        notification_channels=_active_notification_channels(),
        organisations=org_store.list_organisations(),
    )


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    stakeholder = misp_store.get_stakeholder(id)
    name = stakeholder.name if stakeholder else id
    try:
        misp_store.delete_stakeholder(id)
        audit.record("delete", "stakeholder", entity_id=id, entity_label=name)
        flash(f"Stakeholder {name} deleted.", "info")
    except Exception as exc:
        flash(f"Could not delete stakeholder: {exc}", "warning")
    return redirect(url_for("stakeholders.list"))
