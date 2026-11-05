"""Where the analyser reads its events from, and from when.

It reads three kinds of source:

- the scraper, whose events have SCRAPER_MARKER_TAG;
- the manual entries, kept on the webapp MISP with TAG_MANUAL_ENTRY;
- each additional MISP server in MISP_SERVERS whose "analyse" setting is on,
  with the filters it already has for the collection page.

The first two are zsazsa's own MISP, where the analyser writes workflow states
and tags on the events. Another server's events are not zsazsa's to change, so
what the analyser decides about them is kept in zsazsa (analyser.event_state).

Each run of an action reads what is new for it on every source, with a
watermark kept per action and per source, as every server can be down on its
own. On zsazsa's own MISP that is what changed since the previous completed run
started. Another server is read over its own "events from last (days)" window
instead: an event synced to it from elsewhere keeps the timestamp it had there,
which can be days old by the time it arrives. A source that cannot be read is
reported and skipped, and its watermark stays where it is, so the next run
reads what this one missed.

A run writes to the events it handles. A summary or a global tag moves the
event's timestamp in MISP; a local tag, as the workflow state and the product
tag are, does not. So the events of a deleted product, which did not change,
are asked for by their uuid (event_state.read_again). So that the next run does
not take its own writes for news, the watermark also remembers each event it
handled, and an event that has not changed since is not read again for the same
action. For an event the run wrote to, that is the moment of its last write.
For one it did not, it is the MISP timestamp the event had when it was read, so
any later change counts, whatever the two clocks say and also when an update
reaches another server late with the older timestamp of where it was made. Each
entry also keeps when the run handled the event, which a rescan and the pruning
of old entries go by.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from pymisp import PyMISP

import config
from analyser import event_state, settings, tagger
from core.db import row_connection

logger = logging.getLogger(__name__)

# Each read starts this much before the previous one did. MISP stamps an event
# with its own clock, and the watermark is taken with ours; the margin covers
# the difference between the two. Events the previous run already handled are
# not read twice for it.
WATERMARK_MARGIN_SECONDS = 300

# Events asked for per page. Every page is read, so this only sets the size of
# one answer.
_PAGE_SIZE = 100


@dataclass
class Source:
    """A MISP the analyser reads events from."""
    id: str
    kind: str  # "scraper", "manual" or "misp"
    label: str
    # Made by connect(), when the source is read: PyMISP contacts the server as
    # it is made, and a server that is down should fail only its own read.
    client: object
    # A summary is a report on the event. Always on zsazsa's own MISP, and on
    # another server only when its "Allow adding reports to events" is on.
    may_add_reports: bool
    # The server's entry from collection_cache._build_sources(), for its filters.
    settings: dict = field(default_factory=dict)

    @property
    def own(self) -> bool:
        """zsazsa's own MISP, where workflow states and tags are written on the event."""
        return self.kind != "misp"

    @property
    def hint(self) -> str:
        """The source a product names for its source event (source_event_hints)."""
        return {"scraper": "scraper", "manual": "webapp"}.get(self.kind, self.id)

    def connect(self) -> None:
        if self.client is not None:
            return
        from webapp import misp_store

        if self.kind == "manual":
            self.client = misp_store._misp()
        elif self.kind == "scraper":
            self.client = misp_store._scraper_misp()
        else:
            self.client = PyMISP(self.settings["url"], self.settings["api_key"], self.settings["verify_tls"],
                                 False, timeout=misp_store.HTTP_TIMEOUT)


def configured_sources() -> list[Source]:
    """Every source the analyser reads, as Settings > Analyser switches them
    on: the manual entries first and the other servers last, as an event on
    two of them is kept from the first, which is where its state can be
    written. A source switched off is not read, and its watermark stays, so
    switched on again it reads what came in since: the scraper's events of
    the last days, the manual entries all of them."""
    # Imported here: collection_cache imports the analyser.
    from webapp import collection_cache

    sources = []
    if settings.get("ANALYSER_READ_MANUAL"):
        sources.append(Source("manual", "manual", "Manual entries", None, True))
    for src in collection_cache._build_sources(with_manual=False):
        if src["kind"] == "scraper":
            if settings.get("ANALYSER_READ_SCRAPER"):
                sources.append(Source("scraper", "scraper", src["label"], None, True))
        elif settings.get("ANALYSER_READ_MISP_SERVERS") and src["analyse"] and src["url"] and src["api_key"]:
            sources.append(Source(src["id"], "misp", src["label"], None, src["allow_reports"], src))
    return sources


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _search_filters(source: Source, since: int) -> dict:
    """What a source is searched with. Never an event dated after today, as
    no article is."""
    from webapp import collection_cache, misp_store

    today = _today()
    if source.kind == "scraper":
        oldest = today - timedelta(days=settings.get("ANALYSER_MAX_EVENT_AGE_DAYS"))
        return {"tags": [config.SCRAPER_MARKER_TAG], "date_from": oldest.isoformat(), "date_to": today.isoformat(),
                "timestamp": since}
    if source.kind == "manual":
        return {"tags": [misp_store.TAG_MANUAL_ENTRY], "date_to": today.isoformat(), "timestamp": since}
    # Its whole window, light: only the events not handled yet are fetched
    # whole afterwards (_full_event).
    filters = {"published": True, "metadata": True,
               "date_from": (today - timedelta(days=source.settings["since_days"])).isoformat(),
               "date_to": today.isoformat()}
    tags = collection_cache.partner_tag_filter(source.client, source.settings)
    if tags:
        filters["tags"] = tags
    return filters


def _pushed_filters(source: Source, since: int) -> dict:
    """The scraper's events an analyst pushed by their relevance score, read
    past the oldest date the other events are read from."""
    # Imported here: analyser.relevance reads the webapp's MISP store.
    from analyser import relevance

    tags = source.client.build_complex_query(
        and_parameters=[config.SCRAPER_MARKER_TAG],
        or_parameters=[f'cti-evaluation:relevance="{level}"' for level in settings.LEVELS if relevance.pushes(level)])
    return {"tags": tags, "date_to": _today().isoformat(), "timestamp": since}


def _asked_filters(source: Source, asked: set) -> dict:
    """The events an action is to read again, by their uuid: they did not change,
    and can be older than what the action reads."""
    filters = {"uuid": sorted(asked)}
    if not source.own:
        filters["metadata"] = True
    return filters


def _search(source: Source, filters: dict) -> list:
    """Every event of a search on a source, page by page.

    Every page, not only the first: the watermark moves past everything this
    read covered, so an event left on page two would never be asked for again.
    A failed search raises rather than reading as "nothing new", for the same
    reason, and so does one that stops at the most pages a search reads, as
    with a server that answers every page with the first.

    The workflow states are local tags, which MISP leaves out for a key with
    sync permission unless asked for them, as the collection cache asks. An
    open event would read as a closed one, and be passed over for good.
    """
    from webapp import misp_store

    return misp_store._search_all(source.client, strict=True, limit=_PAGE_SIZE, pythonify=True,
                                  excludeLocalTags=False, **filters)


def _full_event(source: Source, event):
    """Another server's event as a whole, for its reports and attributes: its
    search only asked for what decides whether to read it."""
    from webapp import misp_store

    return misp_store._check(source.client.get_event(event.uuid, pythonify=True), f"read event {event.uuid}")


def _timestamp(event) -> int:
    """When an event last changed, in Unix time."""
    return int(event.timestamp.timestamp())


def _still_open(event, source: Source) -> bool:
    """On zsazsa's own MISP, whether the analyser still has something to decide
    about an event. Another server's workflow states are not zsazsa's, and its
    closed events are left out before this (event_state)."""
    return not source.own or bool({t.name for t in event.tags} & tagger.OPEN_STATES)


def _has_report(event, source: Source) -> bool:
    """A manual entry or another server's event without a report has nothing for
    the model to read, and is left for the analyst. A scraper event is read
    either way: the analyser rejects the ones it could not fetch an article for."""
    from webapp import misp_store

    return source.kind == "scraper" or bool(misp_store.live_reports(event))


class Reading:
    """One run's read of its sources, and the watermarks it moves once the run
    has completed.

    ``rescan_hours`` reads that many hours back, and reads again the events
    already handled there, for a run started again after the settings changed.
    """

    def __init__(self, action: str, rescan_hours: int | None = None):
        self.action = action
        self.rescan_hours = rescan_hours
        # One line per source that could not be read, for the run's result.
        self.errors: list[str] = []
        # Events read per source, by label, for the run's result.
        self.counts: dict[str, int] = {}
        # The events the next run reads again, as when a summary failed.
        self.retried: set[str] = set()
        self._read: dict[str, dict] = {}
        self._wrote: dict[str, int] = {}

    def read(self, sources: list[Source] | None = None) -> list[tuple]:
        """The events to analyse, each as (event, source), each event once."""
        found = {}
        for source in configured_sources() if sources is None else sources:
            try:
                source.connect()
                events = self._read_source(source)
            except Exception as exc:
                logger.warning("Analyser could not read %s: %s", source.label, exc)
                self.errors.append(f"{source.label}: {exc}")
                continue
            self.counts[source.label] = len(events)
            for event in events:
                found.setdefault(event.uuid, (event, source))
        return list(found.values())

    def _read_source(self, source: Source) -> list:
        mark = _load_watermark(self.action, source.id)
        started = int(time.time())
        since = self._since(mark, started)
        handled = mark["handled"] if mark else {}
        if self.rescan_hours:
            # What was handled since then is read again: it was judged under
            # the settings the rescan is for.
            handled = {uuid: entry for uuid, entry in handled.items() if entry[0] < since}
        asked = event_state.to_read_again(source.id, self.action)
        found = _search(source, _search_filters(source, since))
        if source.kind == "scraper":
            found += _search(source, _pushed_filters(source, since))
        if asked:
            found += _search(source, _asked_filters(source, asked))
        events = [e for e in {e.uuid: e for e in found}.values()
                  if e.uuid in asked or e.uuid not in handled or _timestamp(e) > handled[e.uuid][1]]
        if not source.own:
            from webapp import collection_cache

            closed = event_state.closed(source.id)
            events = collection_cache.filter_events_by_org(
                [e for e in events if e.uuid not in closed], source.settings["org_filter_type"],
                {o.lower() for o in source.settings["org_filter"]})
            # The server's limit, the newest first: each event read can cost a
            # model call, and the rest are read by the next runs.
            events = sorted(events, key=lambda e: (e.uuid in asked, _timestamp(e)),
                            reverse=True)[:source.settings["limit"]]
            events = [_full_event(source, e) for e in events]
        # Every event looked at is handled, also one without a report: on
        # another server most are, and each would be fetched whole every run.
        self._read[source.id] = {"source": source, "mark": mark, "started": started, "asked": asked,
                                 "seen": {e.uuid: _timestamp(e) for e in events}}
        return [e for e in events if _still_open(e, source) and _has_report(e, source)]

    def _since(self, mark: dict | None, started: int) -> int:
        if self.rescan_hours:
            return started - int(self.rescan_hours) * 3600
        if mark:
            return mark["read_from"] - WATERMARK_MARGIN_SECONDS
        # The advisories as far back as the briefing, which closes an event only
        # once they have seen its CVEs.
        hours = settings.get("ANALYSER_BRIEFING_LOOKBACK_HOURS" if self.action in ("daily-briefing", "vea")
                             else "ANALYSER_LOOKBACK_HOURS")
        return started - hours * 3600

    def retry(self, event_uuid: str) -> None:
        """Have the next run read this event again, as when its summary failed."""
        self.retried.add(event_uuid)

    def wrote(self, event_uuid: str) -> None:
        """Say the run has just written to this event, a summary, a state or a
        product tag, so the next run does not read the change as news."""
        self._wrote[event_uuid] = int(time.time())

    def commit(self) -> None:
        """Move the watermarks of the sources this run read. Only for a run that
        completed: one that failed leaves them, and the next run reads it all again."""
        now = int(time.time())
        for source_id, read in self._read.items():
            mark, seen = read["mark"], read["seen"]
            # One asked for by its uuid stays asked for: an old event would
            # otherwise send the next read back to its timestamp.
            again = (self.retried & set(seen)) - read["asked"]
            # The next run reads from when this one started, or from the oldest
            # event to read again, which a rescan can have read from long before.
            read_from = min([seen[uuid] for uuid in again], default=read["started"])
            # An event handled before this cannot come back unchanged: on our
            # own MISP the next read asks for what changed since it, and another
            # server's window has moved past it.
            if read["source"].own:
                keep_from = read_from - WATERMARK_MARGIN_SECONDS
            else:
                keep_from = now - (read["source"].settings["since_days"] + 1) * 86400
            handled = {uuid: entry for uuid, entry in (mark["handled"] if mark else {}).items()
                       if entry[0] >= keep_from}
            # [when it was handled, what its timestamp is taken to be then]
            handled.update({uuid: [self._wrote.get(uuid, read["started"]), self._wrote.get(uuid, seen[uuid])]
                            for uuid in seen})
            # One an analyst scored after this run read it changed after that
            # read, and the change is not this run's own write.
            for uuid in again | (event_state.scored_by_analyst_since(source_id, read["started"]) & set(seen)):
                del handled[uuid]
            _save_watermark(self.action, source_id, read_from, handled, now)
            event_state.read_again_done(source_id, self.action, read["asked"] - self.retried)
        self._read.clear()


def _load_watermark(action: str, source_id: str) -> dict | None:
    with row_connection() as conn:
        row = conn.execute("SELECT read_from, handled FROM analyser_watermark WHERE action = ? AND source_id = ?",
                           (action, source_id)).fetchone()
    if not row:
        return None
    try:
        handled = json.loads(row["handled"] or "{}")
    except ValueError:
        logger.warning("Watermark of %s on %s lists unreadable events; reading them all again", action, source_id)
        handled = {}
    return {"read_from": int(row["read_from"]), "handled": handled}


def _save_watermark(action: str, source_id: str, read_from: int, handled: dict, now: int) -> None:
    with row_connection() as conn:
        conn.execute(
            "INSERT INTO analyser_watermark (action, source_id, read_from, handled, updated_at) VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(action, source_id) DO UPDATE SET read_from = excluded.read_from,"
            " handled = excluded.handled, updated_at = excluded.updated_at",
            (action, source_id, read_from, json.dumps(handled), now),
        )


def last_completed_at() -> int | None:
    """When an analyser run last completed, of any action and on any source."""
    with row_connection() as conn:
        row = conn.execute("SELECT MAX(updated_at) AS at FROM analyser_watermark").fetchone()
    return row["at"] if row and row["at"] else None
