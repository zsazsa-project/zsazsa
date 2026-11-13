import re
from collections import Counter

from flask import Blueprint, flash, redirect, render_template, request, url_for

from notifier import dispatcher
from webapp import audit, misp_session, misp_store, org_store
from webapp.models import cti_products, STAKEHOLDER_ROLES, TLP_LEVELS, subscribed_products
from webapp.routes.stats import FOCUS_POINT_CATEGORIES, FOCUS_SETTINGS, focus_point_of, focus_points
from webapp.utils import matching, product_detail_url

bp = Blueprint("stakeholders", __name__)

# What zsazsa puts before the title of each record it files in MISP.
_INFO_PREFIX = re.compile(r"^\[zsazsa:[^\]]*\]\s*")


def _scope_and_focus(owned, listed):
    """The scope items of the PIRs and GIRs a stakeholder owns or is listed in,
    per category, and the focus points beside them, each marked where the two
    meet. A scope item names the records it is in, under "owned" and "listed"."""
    points = focus_points()
    scope, shared = [], set()
    for label, attr in misp_store.SCOPE_CATEGORIES:
        items = {}
        for how, records in (("owned", owned), ("listed", listed)):
            for record in records:
                for value in getattr(record, attr, None) or []:
                    value = (value or "").strip()
                    if not value:
                        continue
                    item = items.setdefault(value.casefold(), {"value": value, "owned": [], "listed": []})
                    record_id = getattr(record, "pir_id", "") or getattr(record, "gir_id", "")
                    if record_id not in item[how]:
                        item[how].append(record_id)
        for item in items.values():
            item["focus"] = focus_point_of(attr, item["value"], points)
            if item["focus"]:
                shared.add((FOCUS_SETTINGS[attr], item["focus"].casefold()))
        if items:
            scope.append({"label": label, "attr": attr,
                          "items": sorted(items.values(), key=lambda i: i["value"].casefold())})
    focus = [{"label": label, "attr": attr,
              "names": [{"name": name, "shared": (FOCUS_SETTINGS[attr], key) in shared}
                        for key, name in points[FOCUS_SETTINGS[attr]].items()]}
             for label, attr in FOCUS_POINT_CATEGORIES]
    return scope, focus


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


def _parse_subscriptions(form, previous_modes=None):
    """Return (products_list, product_modes_dict) from form fields.

    For each product type the form sends ``products=<name>`` (when checked)
    and ``mode__<name>`` set to one of SUBSCRIPTION_MODES.

    Switching a product to "automated" takes the publish right: the analyser
    then publishes and delivers that product to this stakeholder with nobody
    reviewing it, which is publishing by another route. A mode that was already
    automated is kept as it is, so editing a stakeholder's contacts does not
    need a publisher.
    """
    previous_modes = previous_modes or {}
    selected = form.getlist("products")
    modes = {}
    refused = False
    for p in selected:
        m = form.get(f"mode__{p}", misp_store.DEFAULT_SUBSCRIPTION_MODE)
        if m not in misp_store.SUBSCRIPTION_MODES:
            m = misp_store.DEFAULT_SUBSCRIPTION_MODE
        if (m == "automated" and previous_modes.get(p) != "automated"
                and not misp_session.current_user_can_publish()):
            m = misp_store.DEFAULT_SUBSCRIPTION_MODE
            refused = True
        modes[p] = m
    if refused:
        flash(misp_session.publish_denied_message("set a product to automated delivery"), "warning")
    return selected, modes


def _parse_notification_channels(form, subscribed: list | None = None) -> list[str]:
    """Channel subscriptions from the form, keeping the ones it cannot show.

    Only active channels get a checkbox, so a channel that is disabled while it is
    being reconfigured is absent from the submission. Dropping it would silently
    unsubscribe the stakeholder, and re-enabling the channel would not bring the
    subscription back. Channels that were deleted outright do fall away here.
    """
    channels = dispatcher.notification_channels()
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


def _form_data(form, stakeholder=None):
    """The stakeholder as the form describes it. ``stakeholder`` is the stored
    one when editing, whose automated modes and hidden channels are kept."""
    products, product_modes = _parse_subscriptions(form, getattr(stakeholder, "product_modes", None))
    return {
        "name": form.get("name", "").strip(),
        "role": form.get("role"),
        "organization": form.get("organization"),
        "stakeholder_type": form.get("stakeholder_type", "External"),
        "contacts": _parse_contacts(form),
        "tlp_clearance": form.get("tlp_clearance", "amber"),
        "notes": form.get("notes"),
        "products": products,
        "product_modes": product_modes,
        "notification_channels": _parse_notification_channels(
            form, getattr(stakeholder, "notification_channels", None)),
        "influence": _parse_scale(form, "influence"),
        "interest": _parse_scale(form, "interest"),
        "engagement_strategy": form.get("engagement_strategy"),
    }


def _render_form(stakeholder=None):
    return render_template(
        "stakeholders/form.html",
        stakeholder=stakeholder,
        roles=STAKEHOLDER_ROLES,
        products=cti_products(),
        tlp_levels=TLP_LEVELS,
        subscription_modes=misp_store.SUBSCRIPTION_MODES,
        default_subscription_mode=misp_store.DEFAULT_SUBSCRIPTION_MODE,
        notification_channels=[c for c in dispatcher.notification_channels() if c.get("enabled")],
        organisations=org_store.list_organisations(),
    )


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
    all_stakeholders = misp_store.list_stakeholders()
    # Counted, filtered and shown without a product type no longer offered,
    # as the edit form does.
    products = {s.uuid: subscribed_products(s) for s in all_stakeholders}
    org_map = org_store.org_map()
    # Organisation options for the filter: distinct organisations actually in use,
    # labelled via org_map and sorted by display name.
    org_values = sorted(
        {s.organization for s in all_stakeholders if s.organization},
        key=lambda v: (org_map.get(v, v) or "").lower(),
    )
    org_options = [(v, org_map.get(v, v)) for v in org_values]
    role_options = sorted({s.role for s in all_stakeholders if s.role}, key=str.lower)
    product_options = sorted({p for s in all_stakeholders for p in products[s.uuid]}, key=str.lower)

    type_filter = (request.args.get("type") or "").strip()
    org_filter = (request.args.get("organization") or "").strip()
    role_filter = (request.args.get("role") or "").strip()
    product_filter = (request.args.get("product") or "").strip()
    tests = {}
    if type_filter:
        tests["type"] = lambda s: s.stakeholder_type == type_filter
    if org_filter:
        tests["organization"] = lambda s: s.organization == org_filter
    if role_filter:
        tests["role"] = lambda s: s.role == role_filter
    if product_filter:
        tests["product"] = lambda s: product_filter in products[s.uuid]
    stakeholders = _sort_stakeholders(matching(all_stakeholders, tests), request.args.get("sort"), request.args.get("dir"))
    by_product = matching(all_stakeholders, tests, skip="product")
    pirs, girs = misp_store.list_pirs(), misp_store.list_girs()

    return render_template(
        "stakeholders/list.html",
        stakeholders=stakeholders,
        type_counts=Counter(s.stakeholder_type for s in matching(all_stakeholders, tests, skip="type")),
        role_counts=Counter(s.role or "Unspecified" for s in matching(all_stakeholders, tests, skip="role")).most_common(),
        subscription_counts=Counter(p for s in by_product for p in products[s.uuid]).most_common(),
        unsubscribed=sum(1 for s in by_product if not products[s.uuid]),
        owned_records=misp_store.records_owned_by_stakeholders(pirs, girs),
        requirement_counts={s.uuid: (misp_store.active_requirement_counts(s, pirs),
                                     misp_store.active_requirement_counts(s, girs)) for s in stakeholders},
        org_map=org_map,
        org_options=org_options,
        role_options=role_options,
        product_options=product_options,
        type_filter=type_filter,
        org_filter=org_filter,
        role_filter=role_filter,
        product_filter=product_filter,
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
        data = _form_data(request.form)
        if not data["name"]:
            flash("Name is required.", "warning")
            return _render_form()
        try:
            uuid = misp_store.create_stakeholder(data)
            audit.record("create", "stakeholder", entity_id=uuid, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} created.", "success")
            return redirect(url_for("stakeholders.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create stakeholder: {exc}", "warning")
    return _render_form()


@bp.route("/<string:id>")
def detail(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    _place_on_matrix(stakeholder)
    # By UUID, which records keep: the id in the URL may be the numeric one.
    uuid = stakeholder.uuid
    owned_pirs = misp_store.pirs_for_stakeholder(uuid)
    distributed_pirs = misp_store.pirs_distributed_to_stakeholder(uuid, stakeholder.name, stakeholder.email)
    owned_girs = misp_store.girs_for_stakeholder(uuid)
    distributed_girs = misp_store.girs_distributed_to_stakeholder(uuid, stakeholder.name, stakeholder.email)
    recent_products = misp_store.products_for_stakeholder(
        stakeholder, owned_pirs + distributed_pirs, owned_girs + distributed_girs)
    for ev in recent_products:
        ev.app_url = product_detail_url(getattr(ev, "product_type", ""), getattr(ev, "uuid", ""), fallback_url=getattr(ev, "misp_url", ""))
        # The product type has its own badge in front of the title.
        ev.title = _INFO_PREFIX.sub("", ev.info or "")
    scope_items, focus_groups = _scope_and_focus(owned_pirs + owned_girs, distributed_pirs + distributed_girs)
    return render_template(
        "stakeholders/detail.html",
        stakeholder=stakeholder,
        owned_pirs=owned_pirs,
        distributed_pirs=distributed_pirs,
        owned_girs=owned_girs,
        distributed_girs=distributed_girs,
        recent_products=recent_products,
        scope_items=scope_items,
        focus_groups=focus_groups,
        owned_records=misp_store.records_owned_by_stakeholders().get(uuid, []),
        org_map=org_store.org_map(),
        notification_channel_names={c["id"]: c["name"] for c in dispatcher.notification_channels() if c.get("id")},
    )


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    stakeholder = misp_store.get_stakeholder(id)
    if stakeholder is None:
        return "Stakeholder not found", 404
    if request.method == "POST":
        data = _form_data(request.form, stakeholder)
        if not data["name"]:
            flash("Name is required.", "warning")
            return _render_form(stakeholder)
        try:
            misp_store.update_stakeholder(id, data)
            audit.record("update", "stakeholder", entity_id=id, entity_label=data['name'])
            flash(f"Stakeholder {data['name']} updated.", "success")
            return redirect(url_for("stakeholders.detail", id=id))
        except Exception as exc:
            flash(f"Could not update stakeholder: {exc}", "warning")
    return _render_form(stakeholder)


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
