"""The collection plan as it works out: per active PIR and GIR, the sources it
names and what each of them delivered, the sources that delivered without
being named, its events per month, and the open RFIs it answers.

An event is the requirement's when it matches the requirement's scope, the
same match the Data collection page makes. Only what the collection cache
holds counts, so a month older than a source's collection window has nothing
of that source in it: the page says how far back each source goes.
"""

import logging
from collections import Counter
from datetime import date, timedelta

import config
from webapp import collection_cache, matching, misp_store

logger = logging.getLogger(__name__)

MONTHS = 6
# Far more events than the cache holds over the months shown.
_MAX_EVENTS = 20000
# A requirement with no event this many days is quiet.
_QUIET_DAYS = 30


def _months(today: date) -> list:
    """The last MONTHS months as "YYYY-MM", the oldest first, this one last."""
    months, year, month = [], today.year, today.month
    for _ in range(MONTHS):
        months.append(f"{year:04d}-{month:02d}")
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    return months[::-1]


def _planned_source_id(name: str):
    """The id the cache files a source's events under, for a source as a
    requirement names it, or None for a mailbox, whose articles reach the
    cache through the source they are handed to."""
    if name == "misp-scraper":
        return "scraper"
    for server in getattr(config, "MISP_SERVERS", []) or []:
        if (server.get("label") or "").strip() == name:
            return server.get("id") or name
    if "/" in name:
        return None
    return collection_cache.manual_source_id(name)


def plan(today: date | None = None) -> dict:
    today = today or date.today()
    months = _months(today)
    pirs, girs = matching.get_requirements()
    events = [e for e in collection_cache.get_events(collection_cache.cached_source_ids(), [], _MAX_EVENTS)
              if (e.get("date") or "")[:7] >= months[0]]
    matched = matching.match_events(events, pirs, girs)
    labels = collection_cache.source_labels()
    try:
        rfis = [r for r in misp_store.list_rfis() if r.status in misp_store.RFI_OPEN_STATUSES]
    except Exception as exc:
        logger.warning("collection plan: could not read the RFIs: %s", exc)
        rfis = []

    per_requirement = {}
    for event in events:
        for match in matched.get(event["uuid"], []):
            per_requirement.setdefault(match["uuid"], []).append(event)

    quiet_after = (today - timedelta(days=_QUIET_DAYS)).isoformat()
    rows = []
    for kind, requirements in (("PIR", pirs), ("GIR", girs)):
        for req in requirements:
            mine = per_requirement.get(req.uuid, [])
            by_source = Counter(e["source_id"] for e in mine)
            planned, planned_ids = [], set()
            for name in req.collection_sources:
                source_id = _planned_source_id(name)
                planned_ids.add(source_id)
                planned.append({"name": name, "traced": source_id is not None, "events": by_source.get(source_id, 0)})
            by_month = Counter(e["date"][:7] for e in mine)
            last = max((e["date"] for e in mine), default="")
            rows.append({
                "kind": kind, "uuid": req.uuid,
                "id": req.pir_id if kind == "PIR" else req.gir_id,
                "label": req.question if kind == "PIR" else req.topic,
                "planned": planned,
                "unplanned": [(collection_cache.source_label(source, labels), n) for source, n in by_source.most_common()
                              if source not in planned_ids],
                "months": [(month, by_month.get(month, 0)) for month in months],
                "events": len(mine), "last": last, "quiet": last < quiet_after,
                "rfis": [r for r in rfis if req.uuid in (r.linked_pir_uuid, r.linked_gir_uuid)],
            })
    rows.sort(key=lambda r: (not r["quiet"], r["kind"], r["id"]))
    linked = {r.uuid for row in rows for r in row["rfis"]}
    windows = {}
    for event in events:
        source = collection_cache.source_label(event["source_id"], labels)
        windows[source] = min(windows.get(source, event["date"]), event["date"])
    return {
        "months": months,
        "rows": rows,
        "quiet": sum(1 for r in rows if r["quiet"]),
        "silent_sources": sum(1 for r in rows for p in r["planned"] if p["traced"] and not p["events"]),
        "unlinked_rfis": [r for r in rfis if r.uuid not in linked],
        "windows": sorted(windows.items()),
    }
