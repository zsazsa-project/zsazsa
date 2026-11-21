"""Threat Landscape Report (TLR) routes."""

import json
import logging
from collections import Counter
from datetime import date
from types import SimpleNamespace

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for

from analyser import tagger
from core import asset_inventory
from webapp import (audit, branding, collection_cache, matching, misp_session, misp_store, notify_jobs, product_log,
                    report_stories)
from webapp.models import INTEL_LEVELS
from webapp.rate_limit import rate_limited

logger = logging.getLogger(__name__)
bp = Blueprint("threat_landscape", __name__, url_prefix="/products/threat-landscape")

_TLR_QUEUE_TAG = collection_cache.TLR_QUEUE_TAG
QUEUE_SIZE = 500
PRODUCT_NAME = "Threat landscape report"


def _queued_events(tlrs, limit=QUEUE_SIZE):
    """The newest collection events tagged for the threat landscape queue that no report holds yet.

    An event leaves the queue when it becomes an entry of a report, and comes
    back if that report is deleted. Its tag stays, as the mark that it fed one.
    Removing an unused event from the queue takes that tag off instead.
    """
    held = {e.event_uuid for t in tlrs for e in t.entries}
    return collection_cache.get_events(collection_cache.source_ids(), [_TLR_QUEUE_TAG], limit, exclude=held)


def _source_reliabilities():
    """The Admiralty reliability of each manual collection source, by cache source id."""
    try:
        return {collection_cache.manual_source_id(src.name): src.source_reliability
                for src in misp_store.list_collection_sources() if src.name}
    except Exception as exc:
        logger.warning("TLR: could not read the collection source ratings: %s", exc)
        return {}


def _reports_of(events) -> dict:
    """The imported reports the stories among these events come from, by UUID."""
    if not any(misp_store.report_of(ev["tags"]) for ev in events):
        return {}
    try:
        return {r.uuid: r for r in misp_store.list_report_documents()}
    except Exception as exc:
        logger.warning("TLR: could not read the imported reports: %s", exc)
        return {}


def _story_fields(ev, reports) -> dict:
    """What a story of an imported report adds to its entry: the context the
    review gave it, and in the note where in the report it is."""
    report_uuid = misp_store.report_of(ev["tags"])
    if not report_uuid:
        return {}
    try:
        story = misp_store.report_story_details(ev["uuid"])
    except Exception as exc:
        logger.warning("TLR: could not read the story %s: %s", ev["uuid"], exc)
        return {}
    if not story:
        return {}
    fields = {key: story[key] for key in ("affected_assets", "impact", "motivation", "mitigation") if story[key]}
    if story["threat_type"] in misp_store.tlr_threat_types():
        fields["threat_type"] = story["threat_type"]
    # The context is the story's own; only the note needs its threat report, which may have been deleted.
    report = reports.get(report_uuid)
    if report is not None:
        pages = f"page {story['pages']}" if "-" not in story["pages"] else f"pages {story['pages'].replace('-', ' to ')}"
        fields["note"] = f"From {report.title}, {report.provider}, {pages}."
    return fields


def _entry_from_event(ev, reliabilities, reports=None):
    """A new entry for a queued event, filled in from its tags so triage is
    mostly confirming, and for a report's story from its reviewed context."""
    context = misp_store.context_from_tags(ev["tags"])
    return {
        "event_uuid": ev["uuid"],
        "source_id": ev["source_id"],
        "event_info": ev["info"],
        "event_date": ev["date"],
        "source_reliability": context["source_reliability"] or reliabilities.get(ev["source_id"], ""),
        "information_credibility": context["information_credibility"],
        "sectors": context["sectors"],
        "geographic_scope": context["geographic_scope"],
        "threat_actors": context["threat_actors"],
        # The full galaxy names, as the technique picker lists them, rather than
        # the bare IDs the briefing keeps.
        "techniques": [t.split("=", 1)[1].strip('"') for t in ev["tags"]
                       if t.startswith("misp-galaxy:mitre-attack-pattern=")],
        **_story_fields(ev, reports or {}),
    }


def _queue_rows(events, reports):
    """The queue as it is listed: each event in its place, but the stories of
    one report together under it, where the first of them is.

    Each row is ("event", event) or ("report", report, its stories), and a
    report that is gone has its stories listed as events.
    """
    rows, groups = [], {}
    for ev in events:
        ev["story_kind"] = misp_store.story_kind(ev["tags"])
        report = reports.get(misp_store.report_of(ev["tags"]))
        if report is None:
            rows.append(("event", ev))
        elif report.uuid in groups:
            groups[report.uuid].append(ev)
        else:
            groups[report.uuid] = [ev]
            rows.append(("report", report, groups[report.uuid]))
    return rows


def _filter_queue(queued, args):
    """Narrow the queue to what the filters on the list page ask for."""
    since, until = args.get("since", ""), args.get("until", "")
    source, sector, actor = args.get("source", ""), args.get("sector", ""), args.get("actor", "")
    kept = []
    for ev in queued:
        context = ev["context"]
        if (since and ev["date"] < since) or (until and ev["date"] > until):
            continue
        if source and ev["source_id"] != source:
            continue
        if (sector and sector not in context["sectors"]) or (actor and actor not in context["threat_actors"]):
            continue
        kept.append(ev)
    return kept


def _counts(entries):
    """Heading and the values counted under it, over the incidents of the
    entries left in the analysis: the events that report one count once."""
    included = misp_store.tlr_incidents(entries)
    return [
        ("Threat type", [e.threat_type or "Not classified" for e in included]),
        ("Relevance", [e.relevance or "Not assessed" for e in included]),
        ("Sector", [v for e in included for v in e.sectors]),
        ("Geography", [v for e in included for v in e.geographic_scope]),
        ("Threat actor", [v for e in included for v in e.threat_actors]),
        ("Technique", [v for e in included for v in e.techniques]),
        ("Admiralty rating", [(e.source_reliability or "?") + (e.information_credibility or "?") for e in included]),
        ("Month", [e.event_date[:7] for e in included if e.event_date]),
    ]


def _statistics(entries, previous=None):
    """The counts the analyst writes against, beside those of the previous report.

    Each is a heading with (value, count, previous count) rows, most frequent
    first, except the months, which run in order. The previous count is None
    when there is no previous report to compare with.
    """
    before = {heading: Counter(values) for heading, values in _counts(previous.entries)} if previous else {}
    stats = []
    for heading, values in _counts(entries):
        if not values:
            continue
        counts = Counter(values)
        order = sorted(counts.items()) if heading == "Month" else counts.most_common()
        old = before.get(heading, Counter())
        stats.append((heading, [(value, count, old[value] if previous else None) for value, count in order]))
    return stats


def _previous_report(tlrs, before=None):
    """The last published report, or the last one numbered before ``before``.

    A draft is no baseline: its dataset and its findings can still change.
    """
    published = [t for t in tlrs if t.review_state == misp_store.TLR_REVIEW_PUBLISHED
                 and (before is None or t.tlr_id < before.tlr_id)]
    return max(published, key=lambda t: t.tlr_id, default=None)


def _outside_scope(tlr, entry):
    """True when the report is limited to sectors or places and the event names
    others only. An event without that classification is not held against it."""
    for scope, values in ((tlr.scope_sectors, entry.sectors), (tlr.scope_geography, entry.geographic_scope)):
        wanted = {v.lower() for v in scope}
        if wanted and values and not wanted & {v.lower() for v in values}:
            return True
    return False


# What an event needs to count as triaged, besides a classification.
_TRIAGE_NEEDS = (("relevance", "relevance"), ("source_reliability", "source reliability"),
                 ("information_credibility", "information credibility"), ("threat_type", "threat type"))


def _classified(entry) -> bool:
    """Whether the event's classification is done: a sector, place, actor or
    technique, or its affected assets, impact, motivation or mitigation, is
    set, or the analyst found none of them relevant."""
    return (entry.no_classification
            or any(getattr(entry, key) for key in misp_store.TLR_ENTRY_LISTS)
            or any(getattr(entry, key) for key, _label in misp_store.TLR_ENTRY_QUESTIONS))


def _still_to_do(entries) -> dict:
    """{entry uuid: what the event lacks to count as triaged}: a relevance,
    both halves of its Admiralty rating, a threat type and a classification.
    An event is judged with its duplicates, as the report counts them once and
    takes each field from whichever has it. A left-out event lacks nothing."""
    by_event = {e.event_uuid: e for e in entries}
    lacking = {}
    for incident in misp_store.tlr_incidents(entries):
        lacks = [label for attr, label in _TRIAGE_NEEDS if not getattr(incident, attr)]
        if not any(_classified(by_event[uuid]) for uuid in incident.event_uuids):
            lacks.append("classification")
        lacking.update(dict.fromkeys(incident.event_uuids, lacks))
    return {e.uuid: [] if e.excluded else lacking[e.event_uuid] for e in entries}


def _dataset_summary(tlr, outside_scope, coverage, internal=()):
    """The figures and bars the banner of the dataset page shows."""
    included = [e for e in tlr.entries if not e.excluded]
    incidents = misp_store.tlr_incidents(included)
    left_out = len(tlr.entries) - len(included)
    lacking = _still_to_do(tlr.entries)
    triaged = sum(1 for e in included if not lacking[e.uuid])
    triage = {"done": triaged, "todo": len(included) - triaged, "out": left_out}
    return {
        "used": len(included),
        "left_out": left_out,
        "outside": sum(1 for e in included if e.uuid in outside_scope),
        "unclassified": sum(1 for e in included if not e.threat_type),
        "gaps": sum(1 for _pir, items in coverage for _label, _term, count in items if not count),
        "triage": triage,
        "incidents": len(incidents),
        "own": sum(1 for i in incidents if _own(i, internal)),
        "threat_types": Counter(e.threat_type or "Not classified" for e in incidents).most_common(),
    }


# The threat actors of the dataset the ranking lists, the most frequent first.
_RANKED_ACTORS = 5


def _internal_sources() -> dict:
    """{source id: name} of the manual sources that are the organisation's own:
    its incidents and the detections of its SOC/CSIRT."""
    return {collection_cache.manual_source_id(s.name): s.name
            for s in misp_store.list_collection_sources() if s.internal}


def _own(incident, internal) -> bool:
    return any(source in internal for source in incident.source_ids)


def _own_incidents(tlr, internal) -> list:
    """The incidents of the analysis that hit the organisation itself, the newest first."""
    return sorted((i for i in misp_store.tlr_incidents(tlr.entries) if _own(i, internal)),
                  key=lambda i: i.event_date or "", reverse=True)


def _tally(incidents, kind, internal=frozenset()):
    """{name: (incidents, high-relevance incidents, own incidents)} of the threat types or threat actors."""
    counts, high, ours = Counter(), Counter(), Counter()
    for i in incidents:
        for name in ([i.threat_type] if i.threat_type else []) if kind == "threat type" else i.threat_actors:
            counts[name] += 1
            if i.relevance == "high":
                high[name] += 1
            if _own(i, internal):
                ours[name] += 1
    return {name: (n, high[name], ours[name]) for name, n in counts.items()}


def _movement(now: int, before) -> str:
    if before is None:
        return ""
    if not before:
        return "new"
    return "up" if now > before else "down" if now < before else "stable"


def _threat_ranking(tlr, previous, internal=frozenset()) -> list:
    """The threat types of the dataset and its most frequent threat actors, each
    with its incidents in the period and in the previous report, its movement,
    its incidents of high relevance and of the organisation's own (``internal``
    names its sources) and why the analyst says it matters. A threat type of
    the previous report the period no longer has stays, as gone, and a why
    given for a threat with no events now or before is dropped. The most
    incidents of high relevance come first, then those that hit the
    organisation, those growing and the most incidents."""
    now = misp_store.tlr_incidents(tlr.entries)
    before = misp_store.tlr_incidents(previous.entries) if previous is not None else None
    saved = {(r.get("kind"), r.get("name")): r for r in tlr.threat_ranking}
    rows = []
    for kind in misp_store.TLR_RANKING_KINDS:
        counts = _tally(now, kind, internal)
        old = _tally(before, kind) if before is not None else {}
        if kind == "threat type":
            names = list(dict.fromkeys(list(counts) + list(old)))
        else:
            names = [name for name, _n in sorted(counts.items(), key=lambda item: (-item[1][0], item[0]))[:_RANKED_ACTORS]]
        names += [name for k, name in saved if k == kind and name not in names and (name in counts or name in old)]
        for name in names:
            incidents, high, ours = counts.get(name, (0, 0, 0))
            previous_count = old.get(name, (0, 0, 0))[0] if before is not None else None
            movement = _movement(incidents, previous_count)
            mine = saved.get((kind, name), {})
            rows.append({"name": name, "kind": kind, "incidents": incidents, "previous": previous_count,
                         "movement": movement, "high": high, "ours": ours, "rationale": mine.get("rationale", "")})
    return sorted(rows, key=lambda r: (-r["high"], -r["ours"], r["movement"] not in ("up", "new"),
                                       -r["incidents"], r["name"]))


def _charts(tlr, previous, ranking) -> dict:
    """What the charts of a report draw, from its dataset: the incidents per
    threat type beside the previous report's, the sectors and techniques most
    named, and the incidents per month."""
    stats = dict(_statistics(tlr.entries, previous))
    threat_types = [(r["name"], r["incidents"], r["previous"]) for r in ranking if r["kind"] == "threat type"]
    return {
        "threat_types": sorted(threat_types, key=lambda row: (-row[1], row[0])),
        "sectors": stats.get("Sector", [])[:8],
        "techniques": stats.get("Technique", [])[:8],
        "months": [(value, count) for value, count, _before in stats.get("Month", [])],
    }


_EXPLOITED = ("Active", "KEV listed")
_IN_INVENTORY = "In the asset inventory"


def _in_inventory(vea) -> bool:
    """Whether an advisory's CVE is in a product the organisation runs: as the
    analyser found it when it made the advisory, or as the asset inventory,
    when it is on, has the affected product."""
    if (vea.exposure or "").startswith(_IN_INVENTORY):
        return True
    if not (asset_inventory.enabled() and vea.affected_product):
        return False
    return asset_inventory.find("", vea.affected_product) is not None


def _cvss(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _shared_within(record, tlr) -> bool:
    """Whether a record may be named in the report: shared no more strictly
    than the report itself."""
    levels = misp_store.TLR_TLP_LEVELS
    report = levels.index(tlr.tlp) if tlr.tlp in levels else levels.index("amber")
    return record.tlp in levels and levels.index(record.tlp) <= report


def _vulnerabilities(tlr) -> dict:
    """The vulnerabilities of the report's period: the CVEs its incidents name,
    and those of the vulnerability advisories made in the period, each with how
    far it is exploited and whether it is in a product the organisation runs.

    The period is the report's own, or the dates of its events. An advisory
    shared more strictly than the report is left out, as is a rejected one.
    Empty when there is nothing to say.
    """
    included = [e for e in tlr.entries if not e.excluded]
    dates = sorted(e.event_date[:10] for e in included if e.event_date)
    start, end = tlr.period_start or (dates[0] if dates else ""), tlr.period_end or (dates[-1] if dates else "")
    cached = {ev["uuid"]: ev for ev in collection_cache.get_events_by_uuids([e.event_uuid for e in included])}
    named = Counter()
    for incident in misp_store.tlr_incidents(included):
        cves = {cve.upper() for uuid in incident.event_uuids for cve in cached.get(uuid, {}).get("vulnerability_ids") or []}
        named.update(cves)
    advisories = {}
    if start and end:
        try:
            for vea in misp_store.list_veas():
                made = vea.created_at.date().isoformat() if vea.created_at else ""
                if (vea.cve_id and vea.review_state != misp_store.VEA_REVIEW_REJECTED and start <= made <= end
                        and _shared_within(vea, tlr)):
                    advisories.setdefault(vea.cve_id.upper(), vea)
        except Exception as exc:
            logger.warning("TLR: could not read the vulnerability advisories: %s", exc)
    try:
        ours = {cve for cve, vea in advisories.items() if _in_inventory(vea)}
    except asset_inventory.InventoryError as exc:
        logger.warning("TLR: %s", exc)
        ours = {cve for cve, vea in advisories.items() if (vea.exposure or "").startswith(_IN_INVENTORY)}
    rows = []
    for cve in set(named) | set(advisories):
        vea = advisories.get(cve)
        rows.append({"cve": cve, "incidents": named[cve], "vea": vea, "ours": cve in ours,
                     "product": vea.affected_product if vea else "", "cvss": vea.cvss if vea else "",
                     "cwe": vea.cwe if vea else "", "exploitation": misp_store.vea_exploitation(vea) if vea else ""})
    if not rows:
        return {}
    rows.sort(key=lambda r: (not r["ours"], r["exploitation"] not in _EXPLOITED, -_cvss(r["cvss"]), -r["incidents"],
                             r["cve"]))
    return {
        "rows": rows,
        "cves": len(rows),
        "advisories": len(advisories),
        "exploited": sum(1 for r in rows if r["exploitation"] in _EXPLOITED),
        "ours": sum(1 for r in rows if r["ours"]),
        # As (name, count, none) rows, as the charts take them.
        "products": [(name, n, None) for name, n in Counter(r["product"] for r in rows if r["product"]).most_common(6)],
        "weaknesses": [(name, n, None) for name, n in Counter(r["cwe"] for r in rows if r["cwe"]).most_common(6)],
    }


# The techniques of the dataset the annex weighs against detection.
_COVERAGE_TECHNIQUES = 15
_IN_PROGRESS = (misp_store.DER_STATUS_PENDING, misp_store.DER_STATUS_IN_DEV, misp_store.DER_STATUS_IN_TEST)


def _detection_coverage(tlr) -> list:
    """The most frequent ATT&CK techniques of the report's incidents, each with
    the detection engineering requests for it and what they come to: covered
    by an active detection or one found through Rulezet, in progress, or a gap.
    A rejected or retired request does not count, and one shared more strictly
    than the report is left out. Each technique has the events of its newest
    incidents, as "<uuid>|<source>", to request a detection from.
    """
    incidents = misp_store.tlr_incidents(tlr.entries)
    counts, names, events = Counter(), {}, {}
    for incident in incidents:
        for name in incident.techniques:
            tid = misp_store.technique_id(name)
            # "Phishing - T1566" says more than "T1566".
            if tid and len(name) > len(names.get(tid, "")):
                names[tid] = name
        for tid in {misp_store.technique_id(t) for t in incident.techniques} - {""}:
            counts[tid] += 1
            events.setdefault(tid, []).append(f"{incident.event_uuid}|{incident.source_id}")
    if not counts:
        return []
    try:
        ders = [d for d in misp_store.list_ders() if d.review_state != misp_store.DER_REVIEW_REJECTED
                and d.status != misp_store.DER_STATUS_RETIRED and _shared_within(d, tlr)]
    except Exception as exc:
        logger.warning("TLR: could not read the detection engineering requests: %s", exc)
        ders = []
    rows = []
    for tid, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:_COVERAGE_TECHNIQUES]:
        mine = [d for d in ders if tid in {misp_store.technique_id(t) for t in d.technique}]
        if any(d.status == misp_store.DER_STATUS_ACTIVE or d.existing_coverage for d in mine):
            state = "covered"
        elif any(d.status in _IN_PROGRESS for d in mine):
            state = "in progress"
        else:
            state = "gap"
        rows.append({"technique": tid, "name": names[tid], "incidents": n, "state": state, "requests": mine,
                     "events": events[tid][:5]})
    return rows


def _shown_figures(tlr, charts) -> list:
    """The figures the PDF and the brief draw: those with something to show,
    but the ones the analyst left out. A single month makes no chart."""
    return [key for key, _label in misp_store.TLR_FIGURES if key not in tlr.hidden_figures
            and len(charts.get(key) or []) > (1 if key == "months" else 0)]


def _ranking_form(form) -> list:
    """Why each threat matters, as the analyst wrote it in the wizard. A row
    without a why is left out."""
    rows = zip(*(form.getlist(f"rank_{field}") for field in ("kind", "name", "rationale")))
    return [{"kind": kind, "name": name.strip(), "rationale": rationale.strip()}
            for kind, name, rationale in rows
            if kind in misp_store.TLR_RANKING_KINDS and name.strip() and rationale.strip()]


def _posted_incident(entry, allowed):
    """The incident the triage form gives an entry, or the one it has when the
    form gives none it may have."""
    value = request.form.get(f"incident-{entry.uuid}", entry.incident)
    return value if value in allowed else entry.incident


# Events this many days apart or more are not proposed as one incident.
_INCIDENT_DAYS = 7


def _incident_proposals(tlr) -> list:
    """Groups of events in the analysis that may report the same incident, for
    the analyst to confirm: dated within a week of each other, and sharing a CVE,
    a threat actor or most of the words of their titles, as the analyser
    shortlists the same story. Only events not yet grouped, nor marked as
    standing alone, are proposed, and no story of an imported threat report:
    those of one report share its date, and are parts of it rather than news.
    Each group is a list of entries, oldest first.
    """
    from analyser import similarity

    candidates = [e for e in tlr.entries if not e.excluded and not e.incident]
    cached = {ev["uuid"]: ev for ev in collection_cache.get_events_by_uuids([e.event_uuid for e in candidates])}
    days = {}
    for e in candidates:
        try:
            days[e.uuid] = date.fromisoformat((e.event_date or "")[:10])
        except ValueError:
            continue
    open_ = sorted((e for e in candidates if e.uuid in days
                    and not misp_store.report_of(cached.get(e.event_uuid, {}).get("tags") or [])),
                   key=lambda e: days[e.uuid])
    stories = []
    for e in open_:
        story = similarity.story(e.uuid, e.event_info, "", e.threat_actors)
        story["cves"] |= {cve.upper() for cve in cached.get(e.event_uuid, {}).get("vulnerability_ids") or []}
        stories.append(story)
    group = list(range(len(open_)))

    def root(i):
        while group[i] != i:
            i = group[i]
        return i

    for i, a in enumerate(open_):
        for j in range(i + 1, len(open_)):
            if (days[open_[j].uuid] - days[a.uuid]).days >= _INCIDENT_DAYS:
                break
            if similarity.resembles(stories[i], stories[j]):
                group[root(j)] = root(i)
    groups = {}
    for i, e in enumerate(open_):
        groups.setdefault(root(i), []).append(e)
    return [members for members in groups.values() if len(members) > 1]


def _triage_blocks(entries) -> list:
    """The events as the triage table lists them, as (number, entries): the
    duplicates of an event together where the first of them is, numbered in
    that order, and every other event on its own, numbered 0."""
    groups = {}
    for e in entries:
        if e.incident and e.incident != misp_store.TLR_INCIDENT_ALONE:
            groups.setdefault(e.incident, []).append(e)
    blocks, placed = [], []
    for e in entries:
        members = groups.get(e.incident, [])
        if len(members) < 2:
            blocks.append((0, [e]))
        elif e.incident not in placed:
            placed.append(e.incident)
            blocks.append((len(placed), members))
    return blocks


def _linked_pirs(tlr):
    if not tlr.linked_pir_uuids:
        return []
    return [p for p in misp_store.list_pirs() if p.uuid in tlr.linked_pir_uuids]


def _pir_coverage(tlr, pirs):
    """For each linked PIR, how many incidents in the analysis speak to each of its scope items.

    The entries are matched on their classification as triaged, not on the
    event's tags, so the analyst's corrections count.
    """
    events = [
        {"info": e.event_info,
         "galaxy_names": e.sectors + e.geographic_scope + e.threat_actors + e.techniques + [e.threat_type],
         "tags": []}
        for e in misp_store.tlr_incidents(tlr.entries)
    ]
    return [(pir, matching.coverage(events, pir)) for pir in pirs]


def _threat_sections(form):
    """The threat assessments of the wizard, one per set of section fields, dropping empty ones."""
    columns = [form.getlist(f"section_{key}") for key in misp_store.TLR_SECTION_FIELDS]
    sections = []
    for values in zip(*columns):
        section = dict(zip(misp_store.TLR_SECTION_FIELDS, (v.strip() for v in values)))
        if section["title"] or any(section[key] for key, _heading in misp_store.TLR_SECTION_TEXTS):
            sections.append(section)
    return sections


def _key_judgements(form):
    """The key judgements of the wizard, one per row, dropping rows without a judgement."""
    confidences = {value for value, _label, _help in misp_store.ESTIMATIVE_CONFIDENCE}
    rows = zip(*(form.getlist(f"kj_{field}") for field in misp_store.TLR_JUDGEMENT_FIELDS))
    return [{"judgement": judgement.strip(), "confidence": confidence if confidence in confidences else "",
             "implication": implication.strip()}
            for judgement, confidence, implication in rows if judgement.strip()]


def _report_context():
    """What every rendering of a report needs to label its parts."""
    return {
        "actor_categories": misp_store.TLR_ACTOR_CATEGORIES,
        "confidence_labels": {value: label for value, label, _help in misp_store.ESTIMATIVE_CONFIDENCE},
        "section_texts": misp_store.TLR_SECTION_TEXTS,
        "figures": misp_store.TLR_FIGURES,
    }


def _wizard_context(tlr):
    """What the wizard needs besides the report itself."""
    incidents = misp_store.tlr_incidents(tlr.entries) if tlr else []
    return {
        "tlp_levels": misp_store.TLR_TLP_LEVELS,
        "audiences": misp_store.FIA_AUDIENCES,
        "intel_levels": INTEL_LEVELS,
        "threat_types": misp_store.tlr_threat_types(),
        "estimative_confidence": misp_store.ESTIMATIVE_CONFIDENCE,
        "pirs": misp_store.list_selectable_pirs(*(tlr.linked_pir_uuids if tlr else [])),
        "sector_items": misp_store.galaxy_sectors(),
        "geo_items": misp_store.galaxy_geography(),
        "type_counts": Counter(e.threat_type for e in incidents if e.threat_type),
        **_report_context(),
    }


def _form_data(form, tlr_id=""):
    return {
        "tlr_id": tlr_id,
        "title": form.get("title", "").strip(),
        "reporting_period": form.get("reporting_period", "").strip(),
        "tlp": form.get("tlp", "amber"),
        "author": form.get("author", "").strip(),
        "audience": ", ".join(form.getlist("audience")),
        "top_threats": form.get("top_threats", "").strip(),
        "trending_actors": form.get("trending_actors", "").strip(),
        **{key: form.get(key, "").strip() for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES},
        "key_incidents": form.get("key_incidents", "").strip(),
        "recommendations": form.get("recommendations", "").strip(),
        "outlook": form.get("outlook", "").strip(),
        "executive_summary": form.get("executive_summary", "").strip(),
        "key_judgements": _key_judgements(form),
        "ai_drafted": [s for s in dict.fromkeys(form.getlist("ai_drafted")) if s in misp_store.TLR_AI_SECTIONS],
        "threat_ranking": _ranking_form(form),
        # The figures left unticked under "As it will appear".
        "hidden_figures": [key for key, _label in misp_store.TLR_FIGURES if key not in form.getlist("figure")],
        **{key: form.get(key, "").strip() for key in misp_store.TLR_DIRECTION_FIELDS},
        # Checked boxes, or one per line where the galaxy could not be read.
        **{key: [v.strip() for raw in form.getlist(key) for v in raw.splitlines() if v.strip()]
           for key in misp_store.TLR_DIRECTION_LISTS},
        "threat_sections": _threat_sections(form),
    }


def _start_delivery(tlr, reason):
    """Send a published report to its channels on a background job.

    The job re-reads the report rather than closing over this one. The link is
    resolved here: only the request knows the app's external address.
    """
    uuid = tlr.uuid
    preview_url = url_for("threat_landscape.detail", id=uuid, _external=True)

    def deliver(log):
        from notifier import dispatcher
        report = misp_store.get_tlr(uuid)
        if report is None:
            return False, "the report could not be loaded"
        stakeholders = misp_store.eligible_recipients(PRODUCT_NAME, report.tlp, report.audience)
        internal = _internal_sources()
        previous = _previous_report(misp_store.list_tlrs(), before=report)
        ranking = _threat_ranking(report, previous, internal)
        markdown = misp_store.render_tlr_markdown(report, _linked_pirs(report), preview_url, ranking,
                                                  _vulnerabilities(report), _own_incidents(report, internal),
                                                  _charts(report, previous, ranking), previous)
        log(f"{reason}: {len(stakeholders)} eligible recipient(s).")
        ok, detail = dispatcher.delivery_outcome(
            dispatcher.send_threat_landscape_report(report, markdown, stakeholders))
        log(f"Channels: {detail}.")
        return ok, detail

    notify_jobs.start(
        "notify-tlr", f"{tlr.tlr_id} delivery", deliver,
        entity_type="tlr", entity_id=uuid, entity_label=tlr.tlr_id,
        user=misp_session.current_user_email(),
    )


@bp.route("/")
def review():
    tlrs = misp_store.list_tlrs()
    # One more than is shown, to know whether older events are waiting too.
    queued = _queued_events(tlrs, QUEUE_SIZE + 1)
    more_waiting = len(queued) > QUEUE_SIZE
    queued = queued[:QUEUE_SIZE]
    for ev in queued:
        ev["context"] = misp_store.context_from_tags(ev["tags"])
    shown = _filter_queue(queued, request.args)
    return render_template(
        "threat_landscape/list.html", tlrs=tlrs, queued=queued, shown=shown, more_waiting=more_waiting,
        rows=_queue_rows(shown, _reports_of(shown)), unticked_kinds=report_stories.unticked_kinds(),
        filters=request.args,
        sources=sorted({ev["source_id"] for ev in queued}),
        sectors=sorted({v for ev in queued for v in ev["context"]["sectors"]}),
        actors=sorted({v for ev in queued for v in ev["context"]["threat_actors"]}),
        drafts=[t for t in tlrs if t.review_state not in misp_store.TLR_LOCKED_STATES],
        locked_states=misp_store.TLR_LOCKED_STATES,
        can_publish=misp_session.current_user_can_publish(),
    )


@bp.route("/build", methods=["POST"])
def build():
    """Put the events picked in the queue into a new or an existing draft report."""
    tlrs = misp_store.list_tlrs()
    queued = {ev["uuid"]: ev for ev in _queued_events(tlrs)}
    events = [queued[u] for u in request.form.getlist("event") if u in queued]
    if not events:
        flash("Select at least one event from the queue.", "warning")
        return redirect(url_for("threat_landscape.review"))

    target = request.form.get("target", "")
    title = request.form.get("title", "").strip()
    if target:
        tlr = next((t for t in tlrs if t.uuid == target), None)
        if tlr is None or tlr.review_state in misp_store.TLR_LOCKED_STATES:
            flash("Events can only be added to a report that is not yet approved.", "warning")
            return redirect(url_for("threat_landscape.review"))
    elif not title:
        flash("Give the new report a title.", "warning")
        return redirect(url_for("threat_landscape.review"))

    reliabilities = _source_reliabilities()
    try:
        if target:
            uuid, label = target, tlr.tlr_id
        else:
            data = {"title": title, "reporting_period": request.form.get("reporting_period", "").strip(),
                    "review_state": misp_store.TLR_REVIEW_DRAFT}
            uuid = misp_store.create_tlr(data)
            label = data["tlr_id"]
            audit.record("create", "tlr", entity_id=uuid, entity_label=label)
        reports = _reports_of(events)
        added = misp_store.add_tlr_entries(uuid, [_entry_from_event(ev, reliabilities, reports) for ev in events])
    except Exception as exc:
        logger.warning("TLR build failed: %s", exc)
        flash(f"Could not build the report: {exc}", "warning")
        return redirect(url_for("threat_landscape.review"))
    product_log.log_product_sources([ev["uuid"] for ev in events], "tlr",
                                    {ev["uuid"]: ev["source_id"] for ev in events})
    audit.record("update", "tlr", entity_id=uuid, entity_label=label, details=f"added {added} event(s)")
    flash(f"{added} event(s) added to {label}. Triage them below.", "success")
    return redirect(url_for("threat_landscape.entries", id=uuid))


def _remove_queued_event(ev):
    """Remove the queue tag, returning a warning if its workflow could not reset."""
    from webapp.routes.data_collection import _misp_for_source

    uuid = ev["uuid"]
    misp, error = _misp_for_source(ev["source_id"])
    if misp is None:
        raise RuntimeError(error or "Could not connect to the source")
    event = misp.get_event(uuid, pythonify=True)
    if not event or isinstance(event, dict) or misp_store._is_own_record(t.name for t in event.tags):
        raise RuntimeError("Not a readable collection event")
    names = {t.name for t in event.tags}
    misp_store._check(misp.untag(uuid, _TLR_QUEUE_TAG), "remove threat landscape queue tag")
    collection_cache.patch_event_tags(uuid, [], [_TLR_QUEUE_TAG])
    other_products = {name for name in names if name.startswith("zsazsa:product=")
                      and name != _TLR_QUEUE_TAG}
    if ('workflow:state="ongoing"' in names and 'workflow:state="complete"' not in names
            and not other_products):
        try:
            reset = tagger.set_workflow_state(misp, event, "incomplete")
        except Exception as exc:
            logger.warning("TLR: removed %s from queue but could not reset its workflow: %s", uuid, exc)
            reset = False
        if not reset:
            return "The story was removed, but its workflow could not be reset. The log says why."
        collection_cache.patch_event_tags(
            uuid, ['workflow:state="incomplete"'],
            [name for name in names if name.startswith("workflow:state=")],
        )
    return ""


@bp.route("/remove-from-queue", methods=["POST"])
def remove_from_queue():
    """Return selected, unused queue events to regular data collection."""
    queued = {ev["uuid"]: ev for ev in _queued_events(misp_store.list_tlrs())}
    selected = set(request.form.getlist("event"))
    events = [queued[uuid] for uuid in selected if uuid in queued]
    if not events:
        flash("Select at least one event from the queue.", "warning")
        return redirect(url_for("threat_landscape.review"))

    removed = 0
    failed = len(selected - queued.keys())
    for ev in events:
        try:
            warning = _remove_queued_event(ev)
        except Exception as exc:
            logger.warning("TLR: could not remove %s from the queue: %s", ev["uuid"], exc)
            failed += 1
            continue
        removed += 1
        audit.record("untag", "collection-tlr-queue", entity_id=ev["uuid"],
                     entity_label=ev["info"], details="removed from threat landscape queue")
        if warning:
            flash(warning, "warning")
    if removed:
        flash(f"{removed} stor{'y' if removed == 1 else 'ies'} removed from the queue. "
              "They remain in Data collection.", "success")
    if failed:
        flash(f"{failed} selected event(s) could not be removed. "
              "They may no longer be in the queue, or MISP refused the change.", "warning")
    return redirect(url_for("threat_landscape.review"))


@bp.route("/new", methods=["GET", "POST"])
def wizard_new():
    if request.method == "POST":
        data = _form_data(request.form)
        data["review_state"] = misp_store.TLR_REVIEW_DRAFT
        try:
            uuid = misp_store.create_tlr(data)
            audit.record("create", "tlr", entity_id=uuid, entity_label=data.get("tlr_id", ""))
            flash(f"{data.get('tlr_id', 'TLR')} created.", "success")
            return redirect(url_for("threat_landscape.detail", id=uuid))
        except Exception as exc:
            flash(f"Could not create TLR: {exc}", "warning")
    tlrs = misp_store.list_tlrs()
    last = _previous_report(tlrs)
    return render_template(
        "threat_landscape/wizard.html", tlr=None, is_edit=False, queued=_queued_events(tlrs), ranking=[],
        last=last, last_feedback=misp_store.list_product_feedback(last.uuid) if last else [],
        **_wizard_context(None),
    )


@bp.route("/draft-trends", methods=["POST"])
@rate_limited("tlr_draft_trends", limit=20, window_s=60)
def draft_trends():
    """Draft the report sections from a report's entries, or from the queue for a new one."""
    tlr_uuid = request.form.get("tlr", "")
    tlr = misp_store.get_tlr(tlr_uuid) if tlr_uuid else None
    reported_by = {}
    if tlr is not None:
        # One event per incident, with how many events report it.
        incidents = misp_store.tlr_incidents(tlr.entries)
        reported_by = {i.event_uuid: i.events for i in incidents}
        source = sorted(collection_cache.get_events_by_uuids(list(reported_by)), key=lambda ev: ev["date"], reverse=True)
    else:
        source = _queued_events(misp_store.list_tlrs())
    documents = _documents(source, _reports_of(source))
    events = [
        {
            "title": ev.get("info") or "",
            "date": ev.get("date") or "",
            "galaxies": ev.get("galaxy_names") or [],
            "cves": ev.get("vulnerability_ids") or [],
            "source": ev.get("source_id") or "",
            **({"reported_by": reported_by[ev["uuid"]]} if reported_by.get(ev.get("uuid"), 1) > 1 else {}),
        }
        # A story is read with its threat report, or as an event of its own once
        # the threat report is deleted or its stories cannot be read.
        for ev in source if misp_store.report_of(ev.get("tags") or []) not in documents
    ][:150]
    if not events and not documents:
        return jsonify({"sections": {}, "error": "There are no events to draft from."})

    try:
        from analyser import llm
        sections = llm.draft_landscape_trends(request.form.get("reporting_period", "").strip(), events,
                                              list(documents.values()), report_stories.kind_notes())
    except Exception as exc:
        logger.warning("TLR trend draft failed: %s", exc)
        return jsonify({"sections": {}, "error": "Failed to draft the report."}), 502

    if not sections:
        return jsonify({"sections": {}, "error": "The model returned no usable draft. Check the LLM settings and the analyser log."}), 502
    return jsonify({"sections": sections, "event_count": len(events), "document_count": len(documents),
                    "error": None})


def _documents(events, reports) -> dict:
    """The imported reports among the events, by UUID, each with the stories
    of it the events are, as the trend draft reads them: one source each,
    however many stories it has. A story's summary and period come from the
    report's manifest, read once per report."""
    wanted = {}
    for ev in events:
        report = misp_store.report_of(ev.get("tags") or [])
        if report in reports:
            wanted.setdefault(report, set()).add(ev["uuid"])
    documents = {}
    for uuid, events_of in wanted.items():
        report = reports[uuid]
        try:
            stories = misp_store.report_manifest(report)["stories"]
        except Exception as exc:
            logger.warning("TLR: could not read the stories of %s: %s", report.title, exc)
            continue
        documents[uuid] = {
            "title": report.title, "publisher": report.provider, "published": report.published,
            "stories": [{"title": s["title"], "kind": s["kind"], "period": (s.get("context") or {}).get("period", ""),
                         "summary": (s.get("context") or {}).get("summary", "")}
                        for s in stories if s.get("event") in events_of],
        }
    return documents


def _mix(counter) -> str:
    """Names with their counts, the most frequent first, and by name among equals."""
    return ", ".join(f"{name} ({n})" for name, n in sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _methodology_draft(tlr, previous, ai_drafted, internal=()) -> str:
    """The methodology and limitations of a report, drafted from its dataset
    as ENISA has every landscape state them: what it was built from, how the
    events were selected and rated, what changed in collection since the
    previous report, where AI was used, and what the report cannot say.

    Built from the data, not by a model: the analyst edits it from there.
    """
    included = [e for e in tlr.entries if not e.excluded]
    labels = collection_cache.source_labels()

    def sources(entries):
        return Counter(collection_cache.source_label(e.source_id or "", labels) or "an unknown source" for e in entries)

    now = sources(included)
    dates = sorted(e.event_date for e in included if e.event_date)
    period = (f"{tlr.period_start or '…'} to {tlr.period_end or '…'}" if tlr.period_start or tlr.period_end
              else tlr.reporting_period or "the reporting period")
    built = (f"This report covers {period}. It is built from {len(included)} event{'s' if len(included) != 1 else ''}"
             f" collected by zsazsa from {len(now)} source{'s' if len(now) != 1 else ''}: {_mix(now)}.")
    if dates:
        built += f" The events are dated {dates[0]} to {dates[-1]}."
    left_out = len(tlr.entries) - len(included)
    if left_out:
        built += (f" {left_out} more {'was' if left_out == 1 else 'were'} queued for it and left out at triage,"
                  " as outside its scope or of no use to it.")
    paragraphs = [built]

    events = collection_cache.get_events_by_uuids([e.event_uuid for e in included])
    reports = _reports_of(events)
    stories = Counter(misp_store.report_of(ev["tags"]) for ev in events if misp_store.report_of(ev["tags"]) in reports)
    if stories:
        named = ", ".join(f"{reports[u].title} by {reports[u].provider} ({n} stor{'y' if n == 1 else 'ies'})"
                          for u, n in stories.most_common())
        paragraphs.append(f"Besides the events, it draws on {len(stories)} imported threat report"
                          f"{'s' if len(stories) != 1 else ''}: {named}. Each report counts as one source when "
                          "trends are counted, however many of its stories are used.")

    threat_types = ("the prime threats of the ENISA Threat Landscape and vulnerability exploitation"
                    if misp_store.tlr_threat_types() == misp_store.DEFAULT_THREAT_TYPES else "the organisation's threat types")
    unrated = sum(1 for e in included if not (e.source_reliability and e.information_credibility))
    untyped = sum(1 for e in included if not e.threat_type)
    rating = ("Analysts queued the events from Data collection and triaged each one: its relevance to the "
              "organisation, the Admiralty rating of its source and of the information, its threat type from "
              f"{threat_types}, and the sectors, places, actors and ATT&CK techniques from the MISP galaxies.")
    gaps = [f"{n} {'has' if n == 1 else 'have'} no {what}"
            for n, what in ((unrated, "Admiralty rating"), (untyped, "threat type")) if n]
    if gaps:
        rating += f" Of the events in the analysis, {' and '.join(gaps)}."
    paragraphs.append(rating)

    own = [i for i in misp_store.tlr_incidents(included) if _own(i, internal)]
    if own:
        names = sorted({internal[s] for i in own for s in i.source_ids if s in internal})
        paragraphs.append(f"{len(own)} of the events hit the organisation itself, from its own records: "
                          f"{', '.join(names)}. The others are what was reported elsewhere.")

    if previous is not None:
        before = sources([e for e in previous.entries if not e.excluded])
        compared = (f"Counts are compared with {previous.tlr_id}, which had {sum(before.values())} events "
                    f"against {len(included)} here.")
        added, gone = sorted(set(now) - set(before)), sorted(set(before) - set(now))
        if added or gone:
            changes = []
            if added:
                changes.append(f"{', '.join(added)} added")
            if gone:
                changes.append(f"{', '.join(gone)} no longer used")
            compared += (f" The collection changed in between ({'; '.join(changes)}), so part of a change in the "
                         "counts may come from collection rather than from the threats.")
        paragraphs.append(compared)

    drafted = [misp_store.TLR_AI_SECTIONS[s] for s in ai_drafted if s in misp_store.TLR_AI_SECTIONS]
    if drafted:
        listed = drafted[0] if len(drafted) == 1 else f"{', '.join(drafted[:-1])} and {drafted[-1]}"
        paragraphs.append(f"AI drafted the {listed} from the events in the analysis. The analyst reviewed and "
                          "completed what it drafted, and is responsible for every judgement in the report.")
    else:
        paragraphs.append("The analysis and judgements are the analyst's; no section was drafted with AI.")
    if stories:
        paragraphs[-1] += (" Where an analyst asked for it, AI named the stories of the imported threat reports and "
                           "proposed their context; an analyst made each story into an event before it was queued.")

    incidents = len(misp_store.tlr_incidents(included))
    if incidents < len(included):
        counted = (f"Events that report the same thing count once: analysts marked the duplicates, so the "
                   f"{len(included)} events count as {incidents}.")
    else:
        counted = ("No events are marked as duplicates, so what several sources report counts once for each of "
                   "them.")
    paragraphs.append(f"Limitations: {counted[0].lower()}{counted[1:]} The dataset holds what the collection sources "
                      "published or shared and what analysts queued; what none of them reported is not in it.")
    return "\n\n".join(paragraphs)


@bp.route("/<string:id>/draft-methodology", methods=["POST"])
def draft_methodology(id):
    """The methodology drafted from the report's dataset, for the wizard to fill
    in. The sections the AI drafted come from the form, which may not be saved yet."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return jsonify({"ok": False, "error": "This report no longer exists."}), 404
    if not tlr.entries:
        return jsonify({"ok": False, "error": "The report has no events to describe yet."}), 400
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    ai_drafted = list(dict.fromkeys(tlr.ai_drafted + request.form.getlist("ai_drafted")))
    return jsonify({"ok": True, "text": _methodology_draft(tlr, previous, ai_drafted, _internal_sources())})


@bp.route("/<string:id>")
def detail(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    feedback = misp_store.list_product_feedback(tlr.uuid)
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    internal = _internal_sources()
    ranking = _threat_ranking(tlr, previous, internal)
    charts = _charts(tlr, previous, ranking)
    return render_template("threat_landscape/detail.html", tlr=tlr, feedback=feedback, previous=previous,
                           own=_own_incidents(tlr, internal), internal=internal, detection=_detection_coverage(tlr),
                           ranking=ranking, charts=charts, shown=_shown_figures(tlr, charts),
                           vulnerabilities=_vulnerabilities(tlr),
                           linked_pirs=_linked_pirs(tlr), annex=misp_store.tlr_annex(tlr),
                           next_states=misp_store.TLR_NEXT_STATES.get(tlr.review_state, []),
                           locked=tlr.review_state in misp_store.TLR_LOCKED_STATES,
                           can_publish=misp_session.current_user_can_publish(),
                           **_report_context())


@bp.route("/<string:id>/recipients")
def recipients_fragment(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    return render_template("_recipients_preview.html", product_label=PRODUCT_NAME,
                           recipients=misp_store.recipient_preview(PRODUCT_NAME, tlr.tlp, tlr.audience),
                           tlp_label=tlr.tlp, audience_label=tlr.audience)


def _pdf(id, template, suffix=""):
    """A report, or its brief, as a PDF to download, marked with its TLP as the
    page shows it."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    internal = _internal_sources()
    ranking = _threat_ranking(tlr, previous, internal)
    charts = _charts(tlr, previous, ranking)
    html = render_template(template, tlr=tlr, linked_pirs=_linked_pirs(tlr), previous=previous,
                           own=_own_incidents(tlr, internal), internal=internal, detection=_detection_coverage(tlr),
                           ranking=ranking, charts=charts, shown=_shown_figures(tlr, charts),
                           vulnerabilities=_vulnerabilities(tlr),
                           annex=misp_store.tlr_annex(tlr), css_url=branding.pdf_css_url(),
                           brand=branding.brand(), **_report_context())
    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception as exc:
        logger.warning("pdf: weasyprint failed for TLR %s: %s", id, exc)
        return f"PDF generation failed: {exc}", 500
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{tlr.tlr_id}{suffix}.pdf"'})


@bp.route("/<string:id>/pdf")
def pdf(id):
    return _pdf(id, "threat_landscape/pdf.html")


@bp.route("/<string:id>/brief.pdf")
def brief(id):
    """The report on one page for management: its executive summary, its threat
    ranking and the incidents per threat type."""
    return _pdf(id, "threat_landscape/brief.html", "-brief")


def _posted_triage(tlr) -> dict:
    """{entry uuid: fields} as the triage form posts them. Only the rows that
    were on the page: an entry added since would otherwise be saved with every
    field blank. An incident is named by an event of this report, or marks an
    event as standing alone."""
    incidents = {"", misp_store.TLR_INCIDENT_ALONE} | {e.event_uuid for e in tlr.entries}
    return {
        e.uuid: {
            "relevance": request.form.get(f"relevance-{e.uuid}", ""),
            "source_reliability": request.form.get(f"reliability-{e.uuid}", ""),
            "information_credibility": request.form.get(f"credibility-{e.uuid}", ""),
            "threat_type": request.form.get(f"threat_type-{e.uuid}", ""),
            "excluded": f"excluded-{e.uuid}" in request.form,
            "no_classification": f"no_classification-{e.uuid}" in request.form,
            "note": request.form.get(f"note-{e.uuid}", "").strip(),
            "incident": _posted_incident(e, incidents),
            **{key: request.form.getlist(f"{key}-{e.uuid}") for key in misp_store.TLR_ENTRY_LISTS},
            **{key: request.form.get(f"{key}-{e.uuid}", "").strip()
               for key, _label in misp_store.TLR_ENTRY_QUESTIONS},
        }
        for e in tlr.entries if f"relevance-{e.uuid}" in request.form
    }


@bp.route("/<string:id>/entries/statistics", methods=["POST"])
def entries_statistics(id):
    """The statistics and PIR coverage of the dataset as the triage form
    stands, so the page can redraw them before the triage is saved. Nothing is
    stored."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    changes = _posted_triage(tlr)
    posted = SimpleNamespace(**{**vars(tlr), "entries": [SimpleNamespace(**{**vars(e), **changes.get(e.uuid, {})})
                                                         for e in tlr.entries]})
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    coverage = _pir_coverage(posted, _linked_pirs(tlr))
    return render_template("threat_landscape/_dataset_stats.html", tlr=posted, previous=previous, coverage=coverage,
                           stats=_statistics(posted.entries, previous), summary=_dataset_summary(posted, set(), coverage))


@bp.route("/<string:id>/entries", methods=["GET", "POST"])
def entries(id):
    """The report's dataset: triage of each source event and the counts over them."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    locked = tlr.review_state in misp_store.TLR_LOCKED_STATES
    if request.method == "POST":
        if locked:
            flash("Approved or published reports cannot be edited. Send the report back to draft first.", "warning")
            return redirect(url_for("threat_landscape.entries", id=id))
        changes = _posted_triage(tlr)
        try:
            misp_store.update_tlr_entries(id, changes)
            audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details="entries")
            flash("Triage saved.", "success")
        except Exception as exc:
            logger.warning("TLR %s triage failed: %s", id, exc)
            flash(f"Could not save the triage: {exc}", "warning")
        return redirect(url_for("threat_landscape.entries", id=id))
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    outside_scope = {e.uuid for e in tlr.entries if _outside_scope(tlr, e)}
    coverage = _pir_coverage(tlr, _linked_pirs(tlr))
    internal = _internal_sources()
    return render_template(
        "threat_landscape/entries.html", tlr=tlr, locked=locked, previous=previous,
        stats=_statistics(tlr.entries, previous), entry_questions=misp_store.TLR_ENTRY_QUESTIONS,
        outside_scope=outside_scope, coverage=coverage, internal=internal,
        summary=_dataset_summary(tlr, outside_scope, coverage, internal),
        proposals=[] if locked else _incident_proposals(tlr), blocks=_triage_blocks(tlr.entries),
        lacking=_still_to_do(tlr.entries), incident_alone=misp_store.TLR_INCIDENT_ALONE,
        threat_types=sorted(misp_store.tlr_threat_types(), key=str.casefold), relevance_levels=misp_store.TLR_RELEVANCE,
        reliabilities=misp_store.FIA_RELIABILITIES, credibilities=misp_store.FIA_CREDIBILITIES,
        sector_items=misp_store.galaxy_sectors(), geo_items=misp_store.galaxy_geography(),
        threat_actor_items=misp_store.galaxy_threat_actors(),
        mitre_items=misp_store.galaxy_mitre_attack_patterns(),
    )


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        in_misp = misp_store.add_product_feedback(tlr.uuid, author, rating, comment,
                                                    published=tlr.published)
        audit.record("create", "tlr_feedback", entity_id=id, entity_label=tlr.tlr_id)
        flash("Feedback recorded.", "success")
        if not in_misp:
            flash(misp_store.MISP_NOT_PUBLISHED, "warning")
    except Exception as exc:
        logger.warning("add_feedback TLR %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def wizard_edit(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    # As for briefings and alerts: what was signed off stays as it was signed off.
    if tlr.review_state in misp_store.TLR_LOCKED_STATES:
        flash("Approved or published reports cannot be edited. Send the report back to draft first.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    if request.method == "POST":
        data = _form_data(request.form, tlr_id=tlr.tlr_id)
        data["review_state"] = tlr.review_state or misp_store.TLR_REVIEW_DRAFT
        try:
            misp_store.update_tlr(id, data)
            audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id)
            flash(f"{tlr.tlr_id} updated.", "success")
            return redirect(url_for("threat_landscape.detail", id=id))
        except Exception as exc:
            flash(f"Could not update TLR: {exc}", "warning")
    previous = _previous_report(misp_store.list_tlrs(), before=tlr)
    return render_template("threat_landscape/wizard.html", tlr=tlr, is_edit=True, previous=previous,
                           ranking=_threat_ranking(tlr, previous, _internal_sources()), **_wizard_context(tlr))


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message(), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    if tlr.review_state != misp_store.TLR_REVIEW_APPROVED:
        flash("A report is published once it has been reviewed and approved.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        in_misp = misp_store.publish_tlr(id)
    except Exception as exc:
        flash(f"Could not publish TLR: {exc}", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    audit.record("publish", "tlr", entity_id=id, entity_label=tlr.tlr_id)
    _start_delivery(tlr, "publish")
    flash(f"{tlr.tlr_id} published. It is being sent to its recipients; the job badge reports the result.", "success")
    if not in_misp:
        flash(misp_store.MISP_NOT_PUBLISHED, "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/state", methods=["POST"])
def move(id):
    """Move a report a step through its review, with an optional comment."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    state = request.form.get("state", "")
    if state not in misp_store.TLR_NEXT_STATES.get(tlr.review_state, []):
        flash("The report cannot move to that state from where it is.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    # The formal validation is the sign-off before publishing, so it takes the same right.
    if state == misp_store.TLR_REVIEW_APPROVED and not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("approve"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.set_tlr_state(id, state, request.form.get("comment", "").strip())
        audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details=f"moved to {state}")
        flash(f"{tlr.tlr_id} moved to {state.replace('-', ' ')}.", "success")
    except Exception as exc:
        flash(f"Could not move the report: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/correction", methods=["POST"])
def correction(id):
    """Record a correction to a published report, dated, without touching its analysis."""
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    text = request.form.get("text", "").strip()
    if tlr.review_state != misp_store.TLR_REVIEW_PUBLISHED or not text:
        flash("A correction is added to a published report, and needs a text.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("correct a published report"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        in_misp = misp_store.add_tlr_correction(id, text)
        audit.record("update", "tlr", entity_id=id, entity_label=tlr.tlr_id, details="correction")
        flash("Correction added. Resend the report if its recipients should see it.", "success")
        if not in_misp:
            flash(misp_store.MISP_NOT_PUBLISHED, "warning")
    except Exception as exc:
        flash(f"Could not add the correction: {exc}", "warning")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/navigator.json")
def navigator_layer(id):
    """The techniques of the report's incidents as an ATT&CK Navigator layer, scored by how many use each.

    The layer leaves zsazsa as a file, so its name, description and metadata
    all state the report's TLP.
    """
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    ids = (misp_store.technique_id(t) for e in misp_store.tlr_incidents(tlr.entries) for t in e.techniques)
    counts = Counter(technique for technique in ids if technique)
    tlp = f"TLP:{tlr.tlp.upper()}"
    layer = {
        "name": f"{tlr.tlr_id} {tlr.title} ({tlp})",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": f"{tlp}. Techniques in the events of threat landscape report {tlr.tlr_id}, "
                       f"scored by the number of events, duplicates once.",
        "metadata": [{"name": "TLP", "value": tlp}, {"name": "Report", "value": tlr.tlr_id}],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "techniques": [{"techniqueID": technique, "score": count, "comment": f"{count} event(s)"}
                       for technique, count in sorted(counts.items())],
    }
    return Response(json.dumps(layer, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{tlr.tlr_id}-navigator.json"'})


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    tlr = misp_store.get_tlr(id)
    if tlr is None:
        return "TLR not found", 404
    if tlr.review_state != misp_store.TLR_REVIEW_PUBLISHED:
        flash("Only published reports can be resent.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    # A resend reaches the same stakeholders as publishing did, so it takes the same right.
    if not misp_session.current_user_can_publish():
        flash(misp_session.publish_denied_message("resend"), "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    _start_delivery(tlr, "resend")
    flash(f"{tlr.tlr_id} resend started; the job badge reports the result.", "info")
    return redirect(url_for("threat_landscape.detail", id=id))


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    tlr = misp_store.get_tlr(id)
    label = tlr.tlr_id if tlr else id
    if tlr and tlr.review_state == misp_store.TLR_REVIEW_PUBLISHED:
        flash("Published reports cannot be deleted.", "warning")
        return redirect(url_for("threat_landscape.detail", id=id))
    try:
        misp_store.delete_tlr(id)
        audit.record("delete", "tlr", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete TLR: {exc}", "warning")
    return redirect(url_for("threat_landscape.review"))
