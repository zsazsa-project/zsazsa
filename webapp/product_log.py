"""Record manually-created products' source events in the analyser log.

When a product (briefing, flash intel, VEA) is composed by hand, each source
event is logged here as a product creation, exactly like the automated analyser
does in analyser_pipeline. This is what makes those sources appear under the
pipeline's "By collection source". Feed names are read from the collection
cache tags, so there is no extra MISP round-trip.
"""

from analyser import tagger
from core.db import log_event
from webapp import collection_cache


def log_product_sources(source_event_uuids, product_label: str, hints=None) -> None:
    """Log each source event of a product. ``hints`` maps an event to the
    source it was picked from, which the Pipeline page links it to. Without a
    hint the collection cache names the source, and for an event that two
    sources hold, either of them."""
    hints = hints or {}
    uuids = []
    for u in source_event_uuids or []:
        u = (u or "").strip()
        if u and u not in uuids:
            uuids.append(u)
    if not uuids:
        return
    rows = {row["uuid"]: row for row in collection_cache.get_events_by_uuids(uuids)}
    for uuid in uuids:
        row = rows.get(uuid, {})
        log_event(
            event_uuid=uuid,
            event_info=row.get("info", ""),
            source_feed=tagger.source_feed_from_tags(row.get("tags", [])),
            outcome="product_created",
            detail=product_label,
            source_id=hints.get(uuid) or row.get("source_id"),
        )
