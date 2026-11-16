"""Browse every CTI product zsazsa holds, whoever made it.

A product is any MISP event tagged 'zsazsa:ctiproduct="…"'. The list page
groups events by product type and supports filtering by type and by linked PIR.
"""

import logging
from collections import Counter
from types import SimpleNamespace

from flask import Blueprint, render_template, request

import config
from webapp import misp_store
from webapp.models import cti_products
from webapp.utils import (
    PRODUCT_TAG_PREFIX, ordered_counts, product_detail_url, product_list_url, product_type_label,
    product_type_tag_value, record_title, TLP_NAMES,
)

logger = logging.getLogger(__name__)

bp = Blueprint("products", __name__, url_prefix="/products")

_LIMIT = 500


def _event_tags(ev):
    return [t.name for t in getattr(ev, "tags", []) or []]


def _product_type_from_tags(tags):
    for t in tags:
        if t.startswith(PRODUCT_TAG_PREFIX):
            return product_type_label(t.split('=', 1)[1].strip('"'))
    return ""


def _tag_columns(tags):
    """The TLP and the workflow state read out of a product's tags, and the
    tags left over once those and the product tag are taken out."""
    tlp = next((t[4:].upper() for t in tags if t.lower().startswith("tlp:")), "")
    state = next((t.split("=", 1)[1].strip('"') for t in tags if t.startswith("workflow:state=")), "")
    rest = [t for t in tags if not t.lower().startswith(("tlp:", "workflow:state=", PRODUCT_TAG_PREFIX))]
    return tlp, state, rest


# An indicator feed keeps a query, not a write-up, so it never carries an event
# report: counting them for one says nothing and costs a fetch per row.
_PRODUCTS_WITHOUT_REPORTS = {"Indicator feed"}


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


def _list_product_events(type_filter: str | None, linked_pir=None):
    misp = misp_store._misp()
    if type_filter:
        tags = [f'{PRODUCT_TAG_PREFIX}"{product_type_tag_value(type_filter)}"']
    else:
        # Match any zsazsa:ctiproduct value via wildcard
        tags = [f'{PRODUCT_TAG_PREFIX}"%"']
    try:
        events = misp.search(tags=tags, limit=_LIMIT, metadata=False, pythonify=True,
                             order=misp_store.NEWEST_FIRST)
    except Exception as exc:
        logger.warning("Analyser MISP search for products failed: %s", exc)
        return []
    if not events or isinstance(events, dict):
        return []

    rows = []
    for e in events:
        ev_tags = _event_tags(e)
        ptype = _product_type_from_tags(ev_tags)
        # A product records the PIR it answers on its object; an older one may
        # only name it in its title.
        if linked_pir and not (linked_pir.uuid in misp_store.linked_pir_uuids(e)
                               or linked_pir.pir_id in (e.info or "")):
            continue
        tlp, state, other_tags = _tag_columns(ev_tags)
        rows.append({
            "uuid": e.uuid,
            "id": e.id,
            "info": e.info or '',
            # The products are listed by type, so the type in front of the title says nothing.
            "title": record_title(e.info),
            "date": str(e.date) if e.date else '',
            "tags": ev_tags,
            "tlp": tlp,
            "workflow": state,
            "other_tags": other_tags,
            "product_type": ptype,
            "report_count": None if ptype in _PRODUCTS_WITHOUT_REPORTS
            else _non_feedback_report_count(misp, e),
            "misp_url": f"{config.MISP_WEBAPP_URL}/events/view/{e.uuid}",
            "app_url": product_detail_url(ptype, e.uuid, fallback_url=f"{config.MISP_WEBAPP_URL}/events/view/{e.uuid}"),
        })
    return rows


@bp.route("/")
def index():
    type_filter = (request.args.get("type") or "").strip()
    linked_pir = (request.args.get("linked_pir") or "").strip()

    pirs = misp_store.list_pirs()
    pir = None
    if linked_pir:
        # An id no PIR has any more can still be matched in a title.
        pir = next((p for p in pirs if p.pir_id == linked_pir), SimpleNamespace(uuid="", pir_id=linked_pir))
    events = _list_product_events(type_filter or None, pir)

    type_counter = Counter(ev["product_type"] for ev in events if ev["product_type"])
    grouped = {}
    for ev in events:
        grouped.setdefault(ev["product_type"] or "(untyped)", []).append(ev)

    return render_template(
        "products/list.html",
        events=events,
        grouped=grouped,
        list_urls={ptype: product_list_url(ptype) for ptype in grouped},
        workflow_counts=ordered_counts((ev["workflow"] or "no tag" for ev in events),
                                       ["draft", "ongoing", "complete", "rejected"]),
        tlp_counts=ordered_counts((ev["tlp"] or "none" for ev in events), TLP_NAMES),
        type_counter=type_counter,
        product_types=cti_products(),
        pirs=pirs,
        type_filter=type_filter,
        linked_pir=linked_pir,
    )
