"""Browse CTI products produced by the analyser.

A product is any MISP event tagged 'zsazsa:ctiproduct="…"'. The list page
groups events by product type and supports filtering by type and by linked PIR.
"""

import logging
from collections import Counter

from flask import Blueprint, render_template, request

import config
from webapp import misp_store
from webapp.models import cti_products
from webapp.utils import product_detail_url, product_type_label, product_type_tag_value

logger = logging.getLogger(__name__)

bp = Blueprint("products", __name__, url_prefix="/products")

_LIMIT = 500


def _event_tags(ev):
    return [t.name for t in getattr(ev, "tags", []) or []]


def _product_type_from_tags(tags):
    for t in tags:
        if t.startswith('zsazsa:ctiproduct='):
            return product_type_label(t.split('=', 1)[1].strip('"'))
    return ""


def _non_feedback_report_count(misp, event) -> int:
    reports = list(getattr(event, "event_reports", []) or [])
    if not reports:
        try:
            full = misp.get_event(event.uuid, pythonify=True)
            if full and not isinstance(full, dict):
                reports = list(getattr(full, "event_reports", []) or [])
        except Exception as exc:
            logger.debug("Could not fetch full event for report count %s: %s", getattr(event, "uuid", ""), exc)
    return sum(1 for er in reports if not (getattr(er, "name", "") or "").startswith("feedback"))


def _list_product_events(type_filter: str | None, linked_pir: str | None):
    misp = misp_store._misp()
    if type_filter:
        tags = [f'zsazsa:ctiproduct="{product_type_tag_value(type_filter)}"']
    else:
        # Match any zsazsa:ctiproduct value via wildcard
        tags = ['zsazsa:ctiproduct="%"']
    try:
        events = misp.search(tags=tags, limit=_LIMIT, metadata=False, pythonify=True)
    except Exception as exc:
        logger.warning("Analyser MISP search for products failed: %s", exc)
        return []
    if not events or isinstance(events, dict):
        return []

    rows = []
    for e in events:
        ev_tags = _event_tags(e)
        ptype = _product_type_from_tags(ev_tags)
        if linked_pir:
            # Match if event references the PIR id either in info or as a tag value
            if linked_pir not in (e.info or '') and linked_pir not in ev_tags:
                continue
        rows.append({
            "uuid": e.uuid,
            "id": e.id,
            "info": e.info or '',
            "date": str(e.date) if e.date else '',
            "tags": ev_tags,
            "product_type": ptype,
            "report_count": _non_feedback_report_count(misp, e),
            "misp_url": f"{config.MISP_WEBAPP_URL}/events/view/{e.uuid}",
            "app_url": product_detail_url(ptype, e.uuid, fallback_url=f"{config.MISP_WEBAPP_URL}/events/view/{e.uuid}"),
        })
    return rows


@bp.route("/")
def index():
    type_filter = (request.args.get("type") or "").strip()
    linked_pir = (request.args.get("linked_pir") or "").strip()

    events = _list_product_events(type_filter or None, linked_pir or None)

    type_counter = Counter(ev["product_type"] for ev in events if ev["product_type"])
    grouped = {}
    for ev in events:
        grouped.setdefault(ev["product_type"] or "(untyped)", []).append(ev)

    pirs = misp_store.list_pirs()

    return render_template(
        "products/list.html",
        events=events,
        grouped=grouped,
        type_counter=type_counter,
        product_types=cti_products(),
        pirs=pirs,
        type_filter=type_filter,
        linked_pir=linked_pir,
    )
