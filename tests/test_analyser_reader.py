"""Which events an analyser run reads, from which sources, and from when.

Every source with MISP events is read: the scraper, the manual entries, and each
additional MISP server whose "analyse" setting is on, with that server's own
filters, unless Settings > Analyser switches that kind of source off for every
product. From the manual entries and the other servers only events with a
report are read; from the scraper every event, as the run rejects those it
could not fetch an article for. On zsazsa's own MISP an event is read while its
workflow state is open; another server's event until the analyser has closed it
in zsazsa, since its workflow state is not zsazsa's to change. An event on two
sources is read once, from zsazsa's own MISP when it is there.

Each action reads each source from its own watermark. On zsazsa's own MISP
that is what changed since its previous completed run started, or on a first
run the last hour, or day for the briefing. Another server is read over its own
"events from last (days)" window, lightly, and only the events not handled yet
are fetched whole: an event synced to it from elsewhere keeps the timestamp it
had there, which a "changed since" search would have passed by. Only a
completed run moves the watermarks, so a run that failed is read again whole.
The events a run handled are remembered with the moment it last wrote to them,
or when it wrote nothing with the MISP timestamp they had when it read them,
and are not read again for that action unless they changed since: the run's own
summaries and tags change them in MISP, and would otherwise bring them all
back, while a change someone else made after the read is news, also when MISP's
clock is behind zsazsa's or the change reaches another server late. An event without a report is remembered too, which
another server would otherwise send whole every run. One an analyst scored on
the data collection page after the run read it is read again all the same, as
is one whose summary failed, also when a rescan read it from before the
watermark, and a rescan, started after the settings changed, reads the handled
ones again too. At most a server's limit of events is read in one run, the
newest first.

Every page of a search is read, as the watermark moves past whatever the read
covered, up to the most pages any search of zsazsa reads. Every search asks for
the local tags, which hold the workflow state, as MISP leaves them out for a
key with sync permission otherwise. A source that cannot be read is reported
and skipped, keeps its watermark, and does not stop the others.

The database is temporary, MISP is an autospec of PyMISP.

    python -m unittest tests.test_analyser_reader
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

import config
from analyser import event_state, sources
from analyser.sources import Reading, Source
from core import db
from webapp import misp_store

NOW = 1_800_000_000
OPEN = 'workflow:state="incomplete"'
ONGOING = 'workflow:state="ongoing"'
REJECTED = 'workflow:state="rejected"'
REPORT = SimpleNamespace(name="Article", content="An article")


def _at(unix_time):
    """A timestamp as PyMISP gives it."""
    return datetime.fromtimestamp(unix_time, timezone.utc)


def _event(uuid, state=OPEN, changed=NOW - 60, reports=(REPORT,), org=""):
    tags = [SimpleNamespace(name=state)] if state else []
    return SimpleNamespace(uuid=uuid, info=uuid, tags=tags, timestamp=_at(changed), event_reports=list(reports),
                           Orgc=SimpleNamespace(uuid=org))


def _misp(events=(), error=None, pushed=(), sync_key=False):
    """A MISP that answers its searches from `events`, a page at a time, and
    gives each of them whole when asked; the search for the scraper's events
    an analyst pushed from `pushed`. With `sync_key`, as for a key with sync
    permission, the workflow states, which are local tags, are left out
    unless the search asks for local tags."""
    misp = mock.create_autospec(PyMISP, instance=True)

    def search(limit=None, page=None, **filters):
        if error is not None:
            return error
        found = pushed if filters.get("tags") is misp.build_complex_query.return_value else events
        found = list(found)[(page - 1) * limit:page * limit]
        if sync_key and filters.get("excludeLocalTags") is not False:
            found = [SimpleNamespace(**dict(vars(e), tags=[t for t in e.tags if not t.name.startswith("workflow:")]))
                     for e in found]
        return found
    misp.search.side_effect = search
    misp.get_event.side_effect = lambda uuid, pythonify: next(e for e in events if e.uuid == uuid)
    return misp


class ReaderTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")),
                        mock.patch.object(sources.time, "time", side_effect=lambda: self.now)):
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        self.now = NOW

    def read(self, *source_list, action="vea", rescan_hours=None, commit=True, retry=()):
        reading = Reading(action, rescan_hours=rescan_hours)
        pairs = reading.read(list(source_list))
        for uuid in retry:
            reading.retry(uuid)
        if commit:
            reading.commit()
        self.reading = reading
        return [event.uuid for event, _source in pairs]

    @staticmethod
    def scraper(misp):
        return Source("scraper", "scraper", "MISP scraper", misp, True)

    @staticmethod
    def manual(misp):
        return Source("manual", "manual", "Manual entries", misp, True)

    @staticmethod
    def partner(misp, **settings):
        """As collection_cache._build_sources() gives a server."""
        return Source("partner", "misp", "Partner", misp, False,
                      {"url": "https://partner.example.org", "api_key": "k", "verify_tls": True, "tags": [],
                       "tags_and": [], "tags_not": [], "org_filter_type": "", "org_filter": [], "since_days": 7,
                       "limit": 500, **settings})


class EveryPageIsRead(ReaderTest):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(sources, "_PAGE_SIZE", 2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_event_past_the_first_page_is_read(self):
        misp = _misp([_event(f"e{n}") for n in range(3)])
        self.assertEqual(self.read(self.scraper(misp)), ["e0", "e1", "e2"])

    def test_closed_events_filling_a_page_do_not_hide_an_open_one(self):
        misp = _misp([_event("done", REJECTED), _event("done too", "workflow:state=\"complete\""), _event("open")])
        self.assertEqual(self.read(self.scraper(misp)), ["open"])

    def test_a_full_last_page_costs_one_empty_request(self):
        misp = _misp([_event("e1"), _event("e2")])
        self.read(self.scraper(misp))
        # Then one search for the events an analyst pushed, which has none.
        self.assertEqual([c.kwargs["page"] for c in misp.search.call_args_list], [1, 2, 1])

    def test_a_server_that_answers_every_page_with_the_first_is_not_read_for_ever(self):
        """It is reported as not read, and keeps its watermark."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [_event("e1"), _event("e2")]
        with mock.patch.object(misp_store, "_SEARCH_MAX_PAGES", 5), \
             self.assertLogs("analyser.sources", level="WARNING"):
            self.assertEqual(self.read(self.scraper(misp)), [])
        self.assertEqual(misp.search.call_count, 5)
        self.assertIn("stopped at 5 pages", self.reading.errors[0])


class WhatIsRead(ReaderTest):
    def test_an_open_or_ongoing_event_is_read_on_zsazsa_s_own_misp(self):
        misp = _misp([_event("new"), _event("in a product", ONGOING), _event("turned down", REJECTED),
                      _event("no state", None)])
        self.assertEqual(self.read(self.scraper(misp)), ["new", "in a product"])

    def test_the_workflow_states_are_read_with_a_key_that_has_sync_permission(self):
        """MISP leaves local tags out for such a key unless asked. An open
        event would read as closed, and be passed over for good."""
        misp = _misp([_event("new")], sync_key=True)
        self.assertEqual(self.read(self.scraper(misp)), ["new"])

    def test_a_manual_entry_without_a_report_is_left_for_the_analyst(self):
        deleted = SimpleNamespace(name="Article", content="An article", deleted=True)
        misp = _misp([_event("with"), _event("without", reports=()), _event("deleted", reports=(deleted,))])
        self.assertEqual(self.read(self.manual(misp)), ["with"])
        self.assertEqual(misp.search.call_args.kwargs["tags"], [misp_store.TAG_MANUAL_ENTRY])

    def test_a_scraper_event_without_a_report_is_read_to_be_rejected(self):
        misp = _misp([_event("unfetched", reports=())])
        self.assertEqual(self.read(self.scraper(misp)), ["unfetched"])

    def test_scraper_events_are_read_for_a_week_by_their_date(self):
        """Their date is the day they were scraped. Without a limit, an analyst
        tagging an old one would bring it back in."""
        misp = _misp([])
        self.read(self.scraper(misp))
        filters = misp.search.call_args_list[0].kwargs
        self.assertEqual(filters["tags"], [config.SCRAPER_MARKER_TAG])
        self.assertEqual(filters["date_from"], (sources._today() - timedelta(days=7)).isoformat())

    def test_no_search_reads_an_event_dated_after_today(self):
        """As the analyser did before its watermarks."""
        misp = _misp([])
        self.read(self.scraper(misp), self.manual(misp), self.partner(misp))
        for call in misp.search.call_args_list:
            self.assertEqual(call.kwargs["date_to"], sources._today().isoformat())
        self.assertEqual(misp.search.call_count, 4)

    def test_one_an_analyst_pushed_is_read_whatever_its_age(self):
        """Their relevance score pushes it into the alerts or the briefing."""
        misp = _misp([_event("new")], pushed=[_event("old but pushed"), _event("new")])
        self.assertEqual(self.read(self.scraper(misp)), ["new", "old but pushed"])
        pushed = misp.search.call_args_list[-1].kwargs
        self.assertNotIn("date_from", pushed)
        misp.build_complex_query.assert_called_once_with(
            and_parameters=[config.SCRAPER_MARKER_TAG],
            or_parameters=['cti-evaluation:relevance="high"', 'cti-evaluation:relevance="very-high"'])

    def test_an_event_on_two_sources_is_read_once_from_the_first(self):
        """A manual entry synced to the scraper is read as the entry."""
        entry = _event("same")
        read = Reading("vea").read([self.manual(_misp([entry])), self.scraper(_misp([_event("same")]))])
        self.assertEqual([(e, s.kind) for e, s in read], [(entry, "manual")])


class AnotherServer(ReaderTest):
    def test_its_own_filters_are_used(self):
        misp = _misp([])
        self.read(self.partner(misp, tags=["tlp:clear"], tags_and=[], tags_not=["tlp:red"], since_days=3))
        filters = misp.search.call_args.kwargs
        self.assertTrue(filters["published"])
        self.assertTrue(filters["metadata"])
        self.assertNotIn("timestamp", filters)
        self.assertEqual(filters["tags"], misp.build_complex_query.return_value)
        misp.build_complex_query.assert_called_once_with(
            or_parameters=["tlp:clear"], and_parameters=None, not_parameters=["tlp:red"])
        self.assertEqual(filters["date_from"], (sources._today() - timedelta(days=3)).isoformat())

    def test_its_organisation_filter_is_used(self):
        misp = _misp([_event("ours", None, org="aaaa"), _event("theirs", None, org="bbbb")])
        self.assertEqual(self.read(self.partner(misp, org_filter_type="include", org_filter=["AAAA"])), ["ours"])

    def test_its_events_are_read_whatever_their_workflow_state(self):
        """It is not zsazsa's: another organisation's state says nothing about our analysis."""
        misp = _misp([_event("closed there", REJECTED), _event("no state", None)])
        self.assertEqual(self.read(self.partner(misp)), ["closed there", "no state"])

    def test_only_its_events_with_a_report_are_read(self):
        """An event that is a set of indicators has nothing for the model to read."""
        misp = _misp([_event("article"), _event("indicators", reports=())])
        self.assertEqual(self.read(self.partner(misp)), ["article"])

    def test_an_event_the_analyser_closed_is_not_read_again(self):
        event_state.close("partner", "turned down", "Not relevant")
        event_state.close("other server", "elsewhere", "Not relevant")
        misp = _misp([_event("turned down"), _event("elsewhere"), _event("new")])
        self.assertEqual(self.read(self.partner(misp)), ["elsewhere", "new"])

    def test_an_event_synced_to_it_late_is_read_though_its_timestamp_is_old(self):
        """It keeps the timestamp it had on the server it came from."""
        misp = _misp([_event("first")])
        self.read(self.partner(misp))
        self.now = NOW + 3600
        misp = _misp([_event("first"), _event("arrived late", changed=NOW - 3 * 86400)])
        self.assertEqual(self.read(self.partner(misp)), ["arrived late"])

    def test_an_update_that_reaches_it_late_is_read_though_its_timestamp_is_old(self):
        """Made where the event came from before the run read the old version
        here, it arrived after, with the timestamp it was made at."""
        event = _event("first", changed=NOW - 86400)
        misp = _misp([event])
        self.read(self.partner(misp))
        event.timestamp = _at(NOW - 600)
        self.now = NOW + 3600
        self.assertEqual(self.read(self.partner(misp)), ["first"])

    def test_only_the_events_not_handled_yet_are_fetched_whole(self):
        misp = _misp([_event("first")])
        self.read(self.partner(misp))
        self.now = NOW + 3600
        misp = _misp([_event("first"), _event("new")])
        self.read(self.partner(misp))
        misp.get_event.assert_called_once_with("new", pythonify=True)

    def test_one_without_a_report_is_not_fetched_whole_again(self):
        """Most events of a community server are sets of indicators."""
        misp = _misp([_event("indicators", reports=())])
        self.read(self.partner(misp))
        self.now = NOW + 3600
        misp = _misp([_event("indicators", reports=())])
        self.read(self.partner(misp))
        misp.get_event.assert_not_called()

    def test_a_run_reads_at_most_its_limit_the_newest_first_and_the_next_one_the_rest(self):
        """Each event read can cost a model call."""
        events = [_event("older", changed=NOW - 7200), _event("newest", changed=NOW - 60),
                  _event("newer", changed=NOW - 3600)]
        self.assertEqual(self.read(self.partner(_misp(events), limit=2)), ["newest", "newer"])
        self.now = NOW + 3600
        self.assertEqual(self.read(self.partner(_misp(events), limit=2)), ["older"])

    def test_one_that_cannot_be_reached_does_not_stop_the_others(self):
        down = self.partner(_misp(error={"errors": (500, "Internal error")}))
        with self.assertLogs("analyser.sources", level="WARNING"):
            read = self.read(down, self.scraper(_misp([_event("scraped")])))
        self.assertEqual(read, ["scraped"])
        self.assertEqual(len(self.reading.errors), 1)
        self.assertIn("Partner", self.reading.errors[0])
        # Nothing read, so nothing to move: the next run reads what it missed.
        self.assertIsNone(sources._load_watermark("vea", "partner"))
        self.assertIsNotNone(sources._load_watermark("vea", "scraper"))


class Watermarks(ReaderTest):
    def since(self, misp):
        return misp.search.call_args.kwargs["timestamp"]

    def test_a_first_run_reads_the_last_hour_and_the_briefing_the_last_day(self):
        misp = _misp([])
        self.read(self.scraper(misp), action="vea")
        self.assertEqual(self.since(misp), NOW - 3600)
        self.read(self.scraper(misp), action="daily-briefing")
        self.assertEqual(self.since(misp), NOW - 24 * 3600)

    def test_the_next_run_reads_from_where_the_last_one_started(self):
        misp = _misp([])
        self.read(self.scraper(misp))
        self.now = NOW + 3600
        self.read(self.scraper(misp))
        self.assertEqual(self.since(misp), NOW - sources.WATERMARK_MARGIN_SECONDS)

    def test_each_action_and_each_source_has_its_own(self):
        misp = _misp([])
        self.read(self.scraper(misp), action="vea")
        self.now = NOW + 3600
        self.read(self.scraper(misp), action="flash-intel")
        self.assertEqual(self.since(misp), NOW + 3600 - 3600)
        self.read(self.manual(misp), action="vea")
        self.assertEqual(self.since(misp), NOW + 3600 - 3600)

    def test_a_run_that_did_not_complete_moves_nothing(self):
        misp = _misp([_event("e1")])
        self.read(self.scraper(misp), commit=False)
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["e1"])
        self.assertEqual(self.since(misp), NOW + 3600 - 3600)

    def test_an_event_the_run_handled_is_not_read_again_for_its_own_changes(self):
        """The summary and tags the run wrote changed the event after it was read."""
        event = _event("e1", changed=NOW - 60)
        misp = _misp([event])
        reading = Reading("vea")
        reading.read([self.scraper(misp)])
        event.timestamp, self.now = _at(NOW + 30), NOW + 30
        reading.wrote("e1")
        self.now = NOW + 40
        reading.commit()
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), [])

    def test_but_a_change_someone_else_made_while_it_went_on_is_read(self):
        """The run wrote nothing to the event: an analyst added the article to a
        manual entry the run had read without one."""
        event = _event("e1", changed=NOW - 60, reports=())
        misp = _misp([event])
        reading = Reading("vea")
        self.assertEqual(reading.read([self.manual(misp)]), [])
        event.timestamp, event.event_reports, self.now = _at(NOW + 30), [REPORT], NOW + 40
        reading.commit()
        self.now = NOW + 3600
        self.assertEqual(self.read(self.manual(misp)), ["e1"])

    def test_nor_one_an_analyst_scored_while_the_run_went_on(self):
        """The score came after the run read the event, and before it
        completed, so it looked like one of the run's own writes: a push was lost."""
        event = _event("e1", changed=NOW - 60)
        misp = _misp([event])
        reading = Reading("vea")
        reading.read([self.scraper(misp)])
        event.timestamp, self.now = _at(NOW + 30), NOW + 30
        event_state.scored_by_analyst("scraper", "e1")
        self.now = NOW + 40
        reading.commit()
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["e1"])

    def test_but_it_is_when_it_changed_after(self):
        event = _event("e1", changed=NOW - 60)
        misp = _misp([event])
        self.read(self.scraper(misp))
        event.timestamp = _at(NOW + 1800)
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["e1"])

    def test_an_edit_misp_stamped_before_the_run_read_by_its_own_clock_is_read(self):
        """MISP's clock is three minutes behind: an edit two minutes after
        the run read the event was stamped before the moment the run had
        recorded as handled, and passed over."""
        event = _event("e1", changed=NOW - 300)
        misp = _misp([event])
        self.read(self.scraper(misp))
        event.timestamp = _at(NOW + 120 - 180)
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["e1"])

    def test_another_action_reads_it_all_the_same(self):
        misp = _misp([_event("e1")])
        self.read(self.scraper(misp), action="vea")
        self.assertEqual(self.read(self.scraper(misp), action="flash-intel"), ["e1"])

    def test_an_event_to_retry_is_read_again_and_the_others_are_not(self):
        """A summary that failed: nothing else changes the event, so a run
        reading from when the last one started would never read it again."""
        misp = _misp([_event("failed"), _event("done")])
        self.read(self.scraper(misp), retry=["failed"])
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["failed"])
        # From when it last changed.
        self.assertEqual(self.since(misp), NOW - 60 - sources.WATERMARK_MARGIN_SECONDS)
        self.now = NOW + 7200
        self.read(self.scraper(misp))
        self.assertEqual(self.since(misp), NOW + 3600 - sources.WATERMARK_MARGIN_SECONDS)

    def test_a_rescan_reads_back_as_far_as_it_is_asked_and_reads_the_handled_ones_too(self):
        """It is for after the settings changed: what was handled was handled
        under the old ones."""
        misp = _misp([_event("e1")])
        self.read(self.scraper(misp))
        self.now = NOW + 600
        self.assertEqual(self.read(self.scraper(misp), rescan_hours=24), ["e1"])
        self.assertEqual(self.since(misp), NOW + 600 - 24 * 3600)

    def test_one_a_rescan_read_from_before_the_watermark_is_read_again(self):
        """The next run read from where the last normal one had, after the
        event's last change, and so never asked for it. It reads from that
        change instead, not from the start of the rescan's window."""
        misp = _misp([_event("failed", changed=NOW - 30 * 3600), _event("done", changed=NOW - 40 * 3600)])
        self.read(self.scraper(misp))
        self.now = NOW + 600
        self.read(self.scraper(misp), rescan_hours=48, retry=["failed"])
        self.now = NOW + 3600
        self.assertEqual(self.read(self.scraper(misp)), ["failed"])
        self.assertEqual(self.since(misp), NOW - 30 * 3600 - sources.WATERMARK_MARGIN_SECONDS)

    def test_a_rescan_of_another_server_reads_again_what_it_handled_in_those_hours(self):
        """Its events are not read by when they changed, so neither is a rescan."""
        misp = _misp([_event("handled lately", changed=NOW - 5 * 86400), _event("handled before", changed=NOW - 5 * 86400)])
        self.read(self.partner(misp), retry=["handled lately"])
        self.now = NOW + 2 * 86400
        self.read(self.partner(misp))
        self.now = NOW + 2 * 86400 + 600
        self.assertEqual(self.read(self.partner(misp), rescan_hours=24), ["handled lately"])

    def test_the_last_completed_run_is_the_latest_of_any(self):
        self.read(self.scraper(_misp([])), action="vea")
        self.now = NOW + 60
        self.read(self.partner(_misp([])), action="daily-briefing")
        self.assertEqual(sources.last_completed_at(), NOW + 60)


class ConfiguredSources(unittest.TestCase):
    def configured(self, servers, scraper=True, **switches):
        """``switches`` the source switches of Settings > Analyser."""
        with mock.patch("webapp.collection_cache.scraper_enabled", return_value=scraper), \
             mock.patch.object(config, "MISP_SERVERS", servers, create=True), \
             mock.patch.multiple(config, create=True, **{"ANALYSER_READ_SCRAPER": True, "ANALYSER_READ_MANUAL": True,
                                                         "ANALYSER_READ_MISP_SERVERS": True, **switches}), \
             mock.patch("webapp.misp_store._misp", return_value="webapp MISP"), \
             mock.patch("webapp.misp_store._scraper_misp", return_value="scraper MISP"):
            return [(s.id, s.kind, s.may_add_reports) for s in sources.configured_sources()]

    def server(self, sid, **settings):
        return {"id": sid, "label": sid, "url": f"https://{sid}.example.org", "api_key": "k", **settings}

    def test_the_manual_entries_first_then_the_scraper_then_the_other_servers(self):
        self.assertEqual(self.configured([self.server("partner")]),
                         [("manual", "manual", True), ("scraper", "scraper", True), ("partner", "misp", False)])

    def test_a_server_is_analysed_unless_switched_off(self):
        """A server saved before the setting existed is analysed."""
        servers = [self.server("on"), self.server("off", analyse=False), self.server("disabled", enabled=False),
                   self.server("unset", url="")]
        self.assertEqual([sid for sid, *_ in self.configured(servers)], ["manual", "scraper", "on"])

    def test_a_summary_goes_on_a_server_s_event_only_when_it_allows_reports(self):
        self.assertEqual(self.configured([self.server("partner", allow_reports=True)])[-1], ("partner", "misp", True))

    def test_each_kind_of_source_can_be_switched_off_for_every_product(self):
        servers = [self.server("partner")]
        for switch, left in (("ANALYSER_READ_SCRAPER", ["manual", "partner"]),
                             ("ANALYSER_READ_MANUAL", ["scraper", "partner"]),
                             ("ANALYSER_READ_MISP_SERVERS", ["manual", "scraper"])):
            with self.subTest(switch):
                self.assertEqual([sid for sid, *_ in self.configured(servers, **{switch: False})], left)

    def test_without_a_scraper_the_others_are_still_read(self):
        self.assertEqual([sid for sid, *_ in self.configured([self.server("partner")], scraper=False)],
                         ["manual", "partner"])


if __name__ == "__main__":
    unittest.main()
