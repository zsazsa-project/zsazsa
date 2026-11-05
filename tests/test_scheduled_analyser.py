"""What the scheduled analyser makes, as Settings > Analyser switches it on.

The flash intel alerts are what it always made, and stay on by default; the
advisories and the daily briefing run only when switched on. They go in that
order: the advisories, then the alerts, and the briefing last, which closes the
events no product wants and so needs the others' outcomes first. The briefing
comes once a day, from its hour on; a day only counts as briefed when the run
went through, read every source and left no event for the next run. A draft
made from the dashboard earlier that day gets the events since added to it, and
the day's events are closed; a day whose briefing is published gets no more.

Every action reads what changed on each source since its own previous completed
run, from the schedule or from the dashboard alike (tests.test_analyser_reader
pins how), and only a completed run moves those watermarks. One analyser run
goes at a time: a scheduled run that finds another one holding the lock skips
its hour, and the next run reads what it would have. The feed caches are
refreshed either way.

Each event is checked, summarised and tagged on the MISP it was read from, and
a run that lost its lock while the model wrote a summary does not write it. The
title exclusions keep an event out of the alerts as they keep it out of the
briefing, but not out of the advisories.

The database and the log are temporary; every MISP and model call is stubbed.

    python -m unittest tests.test_scheduled_analyser
"""

import contextlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

import config
import run_analyser
from analyser import reader
from analyser.sources import Reading, Source
from core import db
from webapp import misp_store

SWITCHES = {"ANALYSER_FLASH_INTEL": True, "ANALYSER_VULNERABILITY_ADVISORIES": False, "ANALYSER_DAILY_BRIEFING": False,
            "ANALYSER_DAILY_BRIEFING_HOUR": 21}
EVENING = datetime(2026, 10, 24, 21, 15, tzinfo=timezone.utc)


def _switches(**on):
    return mock.patch.multiple(config, create=True, **{**SWITCHES, **on})


class Due(unittest.TestCase):
    def due(self, now=EVENING, briefed=None, today=(), **on):
        """``today`` the states of the briefings dated today, or the error reading them."""
        listed = today if isinstance(today, Exception) else [SimpleNamespace(review_state=s) for s in today]
        with _switches(**on), mock.patch.object(run_analyser, "load_last_briefing", return_value=briefed), \
             mock.patch.object(run_analyser.analyser_pipeline, "todays_briefings",
                               **({"side_effect": listed} if isinstance(listed, Exception) else {"return_value": listed})), \
             mock.patch.object(run_analyser, "save_last_briefing") as self.briefed:
            return run_analyser.scheduled_actions(now)

    def test_out_of_the_box_only_the_alerts_run(self):
        self.assertEqual(self.due(), ["flash-intel"])

    def test_everything_switched_on_runs_with_the_briefing_last(self):
        self.assertEqual(self.due(ANALYSER_VULNERABILITY_ADVISORIES=True, ANALYSER_DAILY_BRIEFING=True),
                         ["vea", "flash-intel", "daily-briefing"])

    def test_the_briefing_waits_for_its_hour_and_comes_once_a_day(self):
        self.assertEqual(self.due(EVENING.replace(hour=20), ANALYSER_DAILY_BRIEFING=True), ["flash-intel"])
        self.assertEqual(self.due(briefed="2026-10-24", ANALYSER_DAILY_BRIEFING=True), ["flash-intel"])
        self.assertEqual(self.due(briefed="2026-10-23", ANALYSER_DAILY_BRIEFING=True),
                         ["flash-intel", "daily-briefing"])

    def test_briefings_that_cannot_be_read_hold_up_only_the_briefing(self):
        with self.assertLogs("run_analyser", "WARNING"):
            self.assertEqual(self.due(today=RuntimeError("MISP down"), ANALYSER_DAILY_BRIEFING=True),
                             ["flash-intel"])
        self.briefed.assert_not_called()

    def test_a_draft_made_from_the_dashboard_gets_the_events_since(self):
        """It held up the scheduled briefing, and with it the day's closing."""
        self.assertEqual(self.due(today=["draft"], ANALYSER_DAILY_BRIEFING=True), ["flash-intel", "daily-briefing"])
        self.briefed.assert_not_called()

    def test_a_day_whose_briefing_is_published_gets_none(self):
        self.assertEqual(self.due(today=["rejected", "published"], ANALYSER_DAILY_BRIEFING=True), ["flash-intel"])
        self.briefed.assert_called_once_with("2026-10-24")

    def test_one_whose_briefing_was_rejected_gets_a_new_draft(self):
        self.assertEqual(self.due(today=["rejected"], ANALYSER_DAILY_BRIEFING=True), ["flash-intel", "daily-briefing"])


class RunScheduled(unittest.TestCase):
    def run_them(self, actions, result):
        jobs = []
        with mock.patch.object(run_analyser.job_store, "create_job",
                               side_effect=lambda action, **kw: jobs.append((action, kw["label"])) or {"id": action}), \
             mock.patch.object(run_analyser.analyser_pipeline, "run_action", return_value=result) as run, \
             mock.patch.object(run_analyser, "save_last_briefing") as briefed:
            self.results = run_analyser.run_scheduled_actions(actions, EVENING, "token")
        return jobs, run, briefed

    def test_each_runs_as_a_job_the_way_the_dashboard_starts_one(self):
        """And keeps the lock the run holds fresh while it goes."""
        jobs, run, _briefed = self.run_them(["flash-intel", "vea"], {"message": "Created 1 draft."})
        self.assertEqual(jobs, [("flash-intel", "Scheduled flash intel alert"),
                                ("vea", "Scheduled vulnerability advisory")])
        self.assertEqual(run.call_args_list, [
            mock.call("flash-intel", "analyser", triggered_by="schedule", lock_token="token"),
            mock.call("vea", "analyser", triggered_by="schedule", lock_token="token")])

    def test_the_day_is_briefed_only_when_the_briefing_went_through(self):
        _jobs, _run, briefed = self.run_them(["daily-briefing"], {"message": "Daily briefing draft created."})
        briefed.assert_called_once_with("2026-10-24")
        self.assertEqual(self.results, {"daily-briefing": {"message": "Daily briefing draft created."}})
        _jobs, _run, briefed = self.run_them(["daily-briefing"], None)
        briefed.assert_not_called()

    def test_a_source_that_could_not_be_read_keeps_the_day_open(self):
        """The next run adds that source's events to the draft once it is back."""
        result = {"message": "Daily briefing draft created.", "errors": ["MISP scraper: unavailable"]}
        _jobs, _run, briefed = self.run_them(["daily-briefing"], result)
        briefed.assert_not_called()
        self.assertEqual(self.results, {"daily-briefing": result})

    def test_an_event_left_for_the_next_run_keeps_the_day_open(self):
        """As when the model could not be reached for its relevance: once it
        is judged, the next run adds it to the draft."""
        result = {"message": "Daily briefing draft created.", "retried": 1}
        _jobs, _run, briefed = self.run_them(["daily-briefing"], result)
        briefed.assert_not_called()
        _jobs, _run, briefed = self.run_them(["daily-briefing"], dict(result, retried=0))
        briefed.assert_called_once_with("2026-10-24")


class RunAction(unittest.TestCase):
    """The dashboard's runner, which the schedule uses too."""

    def run_action(self, outcome, **kwargs):
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "run_vea_action", **outcome) as self.handler, \
             mock.patch.object(pipeline, "Reading", autospec=True) as self.reading, \
             mock.patch.object(pipeline.run_lock, "refresh") as self.refresh, \
             mock.patch.object(pipeline.job_store, "get_job", return_value={"action": "vea"}), \
             mock.patch.multiple(pipeline.job_store, update_job=mock.DEFAULT, append_log=mock.DEFAULT,
                                 set_step=mock.DEFAULT, complete_open_steps=mock.DEFAULT), \
             mock.patch.object(pipeline.audit, "record"), \
             mock.patch.object(pipeline, "log_pipeline_run_start", return_value=1) as started, \
             mock.patch.object(pipeline, "log_pipeline_run_end"):
            self.reading.return_value.retried = getattr(self, "retried", set())
            result = pipeline.run_action("job-1", "analyser", **kwargs)
        return result, started

    def test_it_says_who_ran_it_and_returns_what_it_made(self):
        result, started = self.run_action({"return_value": {"message": "Created 2 drafts."}})
        self.assertEqual(result, {"message": "Created 2 drafts.", "retried": 0})
        started.assert_called_once_with("vea", triggered_by="dashboard")

    def test_it_says_how_many_events_the_next_run_reads_again(self):
        self.retried = {"a" * 36, "b" * 36}
        result, _started = self.run_action({"return_value": {"message": "Done."}})
        self.assertEqual(result["retried"], 2)

    def test_a_dashboard_run_reads_from_the_same_watermarks_as_the_schedule(self):
        self.run_action({"return_value": {"message": "Done."}})
        self.reading.assert_called_once_with("vea", rescan_hours=None)
        self.assertIs(self.handler.call_args.args[0], self.reading.return_value)

    def test_a_rescan_reads_back_as_far_as_it_is_asked(self):
        self.run_action({"return_value": {"message": "Done."}}, rescan_hours=24)
        self.reading.assert_called_once_with("vea", rescan_hours=24)

    def test_only_a_run_that_completed_moves_its_watermarks(self):
        self.run_action({"return_value": {"message": "Done."}})
        self.reading.return_value.commit.assert_called_once_with()
        with self.assertLogs("webapp.analyser_pipeline", level="ERROR"):
            self.run_action({"side_effect": RuntimeError("MISP down")})
        self.reading.return_value.commit.assert_not_called()

    def test_its_progress_keeps_the_lock_fresh(self):
        def handler(reading, progress):
            progress(step="collect-events", state="completed", message="Read 3 event(s).")
            return {"message": "Done."}
        self.run_action({"side_effect": handler}, lock_token="token")
        self.refresh.assert_called_once_with("token")

    def test_a_failed_action_returns_nothing(self):
        with self.assertLogs("webapp.analyser_pipeline", level="ERROR"):
            result, _started = self.run_action({"side_effect": RuntimeError("MISP down")})
        self.assertIsNone(result)


class Candidates(unittest.TestCase):
    SCRAPER = Source("scraper", "scraper", "MISP scraper", "scraper", True)
    MANUAL = Source("manual", "manual", "Manual entries", "webapp", True)

    def setUp(self):
        # Nothing is flagged for follow-up, and this install's cache is left unread.
        self.enterContext(mock.patch.object(run_analyser.analyser_pipeline.collection_cache, "get_flagged_uuids", return_value=set()))

    def reading(self, pairs):
        reading = mock.create_autospec(Reading, instance=True)
        reading.read.return_value = pairs
        reading.counts, reading.errors = {}, []
        return reading

    def test_each_event_is_read_and_summarised_on_the_misp_it_is_on(self):
        pipeline = run_analyser.analyser_pipeline
        scraped = SimpleNamespace(uuid="a" * 36, info="Scraped", tags=[])
        entered = SimpleNamespace(uuid="m" * 36, info="Entered", tags=[])
        article = [SimpleNamespace(name="Article", content="An article")]
        used = []
        with mock.patch.object(pipeline, "read_event_reports",
                               side_effect=lambda misp, e: used.append((e.info, misp)) or article), \
             mock.patch.object(pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary",
                               side_effect=lambda source, e, r, g, p: used.append((e.info, source.client)) or ("", True)):
            found = pipeline._common_candidate_events(
                self.reading([(scraped, self.SCRAPER), (entered, self.MANUAL)]))
        self.assertEqual([e.info for e in found.events], ["Scraped", "Entered"])
        self.assertEqual(found.sources, {scraped.uuid: self.SCRAPER, entered.uuid: self.MANUAL})
        # Their reports first, then their summaries.
        self.assertEqual(used, [("Scraped", "scraper"), ("Entered", "webapp")] * 2)

    def test_a_report_read_failure_leaves_the_event_and_not_the_run(self):
        """Read as no reports the event would be rejected as empty, and raised
        it would hold up the other sources, on every run while a server is down."""
        pipeline = run_analyser.analyser_pipeline
        entered = SimpleNamespace(uuid="m" * 36, id="91", info="Manual entry", tags=[])
        scraped = SimpleNamespace(uuid="a" * 36, id="7", info="Scraped", tags=[])
        article = [SimpleNamespace(name="Article", content="An article")]
        for reply in ({"errors": ["Report access refused"]}, ConnectionError("Report access refused")):
            with self.subTest(reply=reply):
                webapp = mock.create_autospec(PyMISP, instance=True)
                if isinstance(reply, Exception):
                    webapp.get_event_reports.side_effect = reply
                else:
                    webapp.get_event_reports.return_value = reply
                scraper = mock.create_autospec(PyMISP, instance=True)
                scraper.get_event_reports.return_value = article
                manual = Source("manual", "manual", "Manual entries", webapp, True)
                other = Source("scraper", "scraper", "MISP scraper", scraper, False)
                reading = self.reading([(entered, manual), (scraped, other)])
                with mock.patch.object(pipeline, "_log"), \
                     mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
                     mock.patch.object(pipeline.tagger, "set_workflow_state") as state:
                    found = pipeline._common_candidate_events(reading)
                state.assert_not_called()
                reading.retry.assert_called_once_with(entered.uuid)
                self.assertEqual(found.events, [scraped])
                self.assertEqual([(d["uuid"], d["outcome"]) for d in found.stats["event_decisions"]],
                                 [(entered.uuid, "left open")])

    def test_another_server_s_event_without_an_article_is_closed_in_zsazsa(self):
        """Its workflow state is not zsazsa's to change."""
        pipeline = run_analyser.analyser_pipeline
        event = SimpleNamespace(uuid="r" * 36, id="7", info="Partner event", tags=[])
        partner = Source("partner", "misp", "Partner", "partner MISP", False)
        with mock.patch.object(pipeline, "read_event_reports", return_value=[SimpleNamespace(name="Empty", content="")]), \
             mock.patch.object(pipeline, "_log"), \
             mock.patch.object(pipeline.tagger, "set_workflow_state") as state, \
             mock.patch.object(pipeline.event_state, "close") as closed:
            found = pipeline._common_candidate_events(self.reading([(event, partner)]))
        self.assertEqual(found.events, [])
        state.assert_not_called()
        closed.assert_called_once_with("partner", event.uuid, "No report content")

    def test_a_source_that_cannot_take_a_report_gets_no_summary_written(self):
        pipeline = run_analyser.analyser_pipeline
        event = SimpleNamespace(uuid="r" * 36, id="7", info="Partner event", tags=[])
        partner = Source("partner", "misp", "Partner", mock.create_autospec(PyMISP, instance=True), False)
        with mock.patch.object(pipeline.llm, "summarise_report") as summarise:
            summary, written = pipeline._ensure_ai_summary(
                partner, event, [SimpleNamespace(name="Article", content="An article")], {})
        self.assertEqual((summary, written), ("", False))
        summarise.assert_not_called()
        partner.client.add_event_report.assert_not_called()

    def write_summary(self, source, event):
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline.llm, "summarise_report", return_value="What happened"), \
             mock.patch.object(pipeline.collection_cache, "mark_ai_summary") as cached, \
             mock.patch.object(pipeline, "_apply_misp_context_tags", return_value=0) as tagged, \
             mock.patch.object(pipeline, "parse_misp_context", return_value={}), \
             mock.patch.object(pipeline, "galaxy_names_with_commas", return_value=[]):
            written = pipeline._ensure_ai_summary(source, event, [SimpleNamespace(name="Article", content="An article")],
                                                  {"Energy": "sector"})
        return written, cached, tagged

    def test_a_summary_on_another_server_is_for_our_organisation_and_the_event_published_again(self):
        """As the data collection page writes one. Unpublished, the event would
        drop out of the server's search; its tags are that server's."""
        event = SimpleNamespace(uuid="r" * 36, id="7", info="Partner event", tags=[])
        partner = Source("partner", "misp", "Partner", mock.create_autospec(PyMISP, instance=True), True)
        partner.client.add_event_report.return_value = {}
        partner.client.publish.return_value = {}
        written, cached, tagged = self.write_summary(partner, event)
        self.assertEqual(written, ("What happened", True))
        self.assertEqual(partner.client.add_event_report.call_args.args[1].distribution, 0)
        partner.client.publish.assert_called_once_with(event, alert=False)
        tagged.assert_not_called()
        cached.assert_called_once_with(event.uuid, "partner")

    def test_a_partner_event_misp_did_not_publish_again_is_logged_as_an_error(self):
        """Unpublished, it is out of the server's search for good; the run
        said the summary was written and nothing more."""
        event = SimpleNamespace(uuid="r" * 36, id="7", info="Partner event", tags=[])
        partner = Source("partner", "misp", "Partner", mock.create_autospec(PyMISP, instance=True), True)
        partner.client.add_event_report.return_value = {}
        partner.client.publish.return_value = {"errors": "Publishing refused"}
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "_log") as logged, self.assertLogs("webapp.misp_store", level="WARNING"):
            written, cached, _tagged = self.write_summary(partner, event)
        self.assertEqual(written, ("What happened", True))
        self.assertEqual(logged.call_args.args[:3], (event, partner, "error"))
        cached.assert_called_once()

    def test_a_run_that_lost_its_lock_during_the_model_call_writes_no_summary(self):
        """Its process was suspended long enough for another run to take the
        lock, which writes the summary itself."""
        pipeline = run_analyser.analyser_pipeline
        event = SimpleNamespace(uuid="m" * 36, id="91", info="Entry", tags=[])
        webapp = mock.create_autospec(PyMISP, instance=True)

        def progress(step, state, message=""):
            if message.startswith("Writing"):
                raise pipeline.run_lock.Lost("taken over")
        with mock.patch.object(pipeline.llm, "summarise_report", return_value="What happened"), \
             self.assertRaises(pipeline.run_lock.Lost):
            pipeline._ensure_ai_summary(Source("manual", "manual", "Manual entries", webapp, True), event,
                                        [SimpleNamespace(name="Article", content="An article")], {}, progress)
        webapp.add_event_report.assert_not_called()

    def test_the_article_is_never_a_report_zsazsa_wrote(self):
        """A summary listed first was read as the article, and a quote from
        it grounded the verdict; so was the note of a rejection."""
        pipeline = run_analyser.analyser_pipeline
        reports = [SimpleNamespace(name=f"{pipeline.AI_SUMMARY_PREFIX} An event", content="What a model wrote"),
                   SimpleNamespace(name="zsazsa:analyser-rejection 2026-10-30 10:00:00Z", content="Rejected"),
                   SimpleNamespace(name="Article", content="What the source wrote")]
        self.assertEqual(pipeline._article_text(reports), "What the source wrote")

    def test_a_summary_older_than_its_article_is_written_again(self):
        """The article was updated to say the flaw is exploited; the draft
        came from the summary of the old one, which said it was not."""
        pipeline = run_analyser.analyser_pipeline
        event = SimpleNamespace(uuid="m" * 36, id="91", info="Entry", tags=[])
        old = SimpleNamespace(id="5", name=f"{pipeline.AI_SUMMARY_PREFIX} Entry", content="Not exploited",
                              timestamp=datetime(2026, 10, 30, 9, tzinfo=timezone.utc))
        article = SimpleNamespace(id="4", name="Article", content="Exploited now",
                                  timestamp=datetime(2026, 10, 30, 11, tzinfo=timezone.utc))
        self.assertEqual(pipeline._extract_ai_summary([article, old]), "")
        webapp = mock.create_autospec(PyMISP, instance=True)
        webapp.add_event_report.return_value = webapp.delete_event_report.return_value = {}
        manual = Source("manual", "manual", "Manual entries", webapp, True)
        with mock.patch.object(pipeline.llm, "summarise_report", return_value="Exploited") as summarise, \
             mock.patch.object(pipeline.collection_cache, "mark_ai_summary"), \
             mock.patch.object(pipeline, "_apply_misp_context_tags", return_value=0):
            self.assertEqual(pipeline._ensure_ai_summary(manual, event, [article, old], {}), ("Exploited", True))
        self.assertEqual(summarise.call_args.args[0], "Exploited now")
        webapp.delete_event_report.assert_called_once_with("5")
        # One written after the article stands.
        old.timestamp = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
        self.assertEqual(pipeline._extract_ai_summary([article, old]), "Not exploited")

    def test_a_manual_entry_s_summary_is_marked_on_its_collection_source(self):
        """The collection cache keeps a manual entry under its own source, not
        under "manual"."""
        event = SimpleNamespace(uuid="m" * 36, id="91", info="Entry",
                                tags=[SimpleNamespace(name='zsazsa:source="threat-reports"')])
        webapp = mock.create_autospec(PyMISP, instance=True)
        webapp.add_event_report.return_value = {}
        written, cached, tagged = self.write_summary(Source("manual", "manual", "Manual entries", webapp, True), event)
        self.assertEqual(webapp.add_event_report.call_args.args[1].distribution, 5)
        webapp.publish.assert_not_called()
        tagged.assert_called_once()
        cached.assert_called_once_with(event.uuid, "manual-threat-reports")

    def test_an_event_the_title_exclusions_name_is_set_apart_not_rejected(self):
        """An advisory still goes by its CVEs alone, and the closing step
        decides on it with the other products."""
        pipeline = run_analyser.analyser_pipeline
        events = [SimpleNamespace(uuid="a" * 36, info="Weekly Recap: 98 zero-days", tags=[]),
                  SimpleNamespace(uuid="b" * 36, info="New", tags=[])]
        with mock.patch.object(pipeline, "read_event_reports", return_value=[SimpleNamespace(name="A", content="A")]), \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary", return_value=("", False)), \
             mock.patch.object(pipeline, "_log"), \
             mock.patch.object(pipeline.event_state, "reject") as rejected:
            found = pipeline._common_candidate_events(self.reading([(e, self.SCRAPER) for e in events]),
                                                      title_exclusions=["weekly recap"])
        self.assertEqual([e.info for e in found.events], ["New"])
        self.assertEqual([e.info for e in found.excluded], ["Weekly Recap: 98 zero-days"])
        self.assertEqual(found.stats["excluded_by_title"], 1)
        rejected.assert_not_called()

    def test_the_title_exclusions_apply_to_the_alerts_and_the_briefing_not_the_advisories(self):
        """A roundup of the week's patches still names CVEs worth an advisory."""
        pipeline = run_analyser.analyser_pipeline
        empty = SimpleNamespace(sources={}, events=[], excluded=[], summaries={}, reports={},
                                stats={"event_decisions": []})
        for action in (pipeline.run_flash_intel_action, pipeline.run_daily_briefing_action, pipeline.run_vea_action):
            with self.subTest(action=action.__name__), \
                 mock.patch.object(pipeline, "_common_candidate_events", return_value=empty) as read, \
                 mock.patch.object(pipeline, "daily_briefing_title_exclusions", return_value=["weekly recap"]):
                action(mock.sentinel.reading)
            expected = None if action is pipeline.run_vea_action else ["weekly recap"]
            self.assertEqual(read.call_args.kwargs.get("title_exclusions"), expected)


class FlashIntelSources(unittest.TestCase):
    def test_every_alert_counts_whatever_became_of_it(self):
        alerts = [SimpleNamespace(source_event_uuids=["a" * 36], review_state="rejected"),
                  SimpleNamespace(source_event_uuids=["b" * 36, "c" * 36], review_state="pending-review")]
        with mock.patch.object(misp_store, "list_fias", return_value=alerts):
            self.assertEqual(misp_store.flash_intel_source_uuids(), {"a" * 36, "b" * 36, "c" * 36})


class LatestRun(unittest.TestCase):
    def test_runs_are_found_by_how_they_started_and_ended(self):
        """For the pipeline page, which says when the mail collector last went through."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")):
            db.init_db()
            run_analyser.audit.init()
            for triggered_by, status in (("schedule", "completed"), ("dashboard", "completed"),
                                         ("schedule", "failed")):
                run_id = db.log_pipeline_run_start("vea", triggered_by=triggered_by)
                db.log_pipeline_run_end(run_id, status)
            latest = db.get_latest_pipeline_run("vea", triggered_by="schedule", status="completed")
            self.assertEqual((latest["id"], latest["triggered_by"], latest["status"]), (1, "schedule", "completed"))
            self.assertEqual(db.get_latest_pipeline_run("vea")["id"], 3)


class BriefingDay(unittest.TestCase):
    def test_it_is_kept_in_the_state_file_with_what_else_is_there(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(json.dumps({"something_else": 1000}))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with mock.patch.object(config, "STATE_FILE", handle.name):
            self.assertIsNone(reader.load_last_briefing())
            reader.save_last_briefing("2026-10-24")
            self.assertEqual(reader.load_last_briefing(), "2026-10-24")
        with open(handle.name) as f:
            self.assertEqual(json.load(f), {"something_else": 1000, "analyser_last_briefing": "2026-10-24"})


class Main(unittest.TestCase):
    def run_main(self, due=(), busy=None, failure=None):
        self.order = []
        with contextlib.ExitStack() as stack:
            for patch in (
                mock.patch.object(run_analyser, "scheduled_actions", return_value=list(due)),
                mock.patch.object(run_analyser, "setup_logging"),
                mock.patch.object(run_analyser, "init_db"),
                mock.patch.object(run_analyser.audit, "init"),
                mock.patch.object(run_analyser, "log_pipeline_run_start", return_value=1),
            ):
                stack.enter_context(patch)
            self.ended = stack.enter_context(mock.patch.object(run_analyser, "log_pipeline_run_end"))
            self.feeds = stack.enter_context(mock.patch.object(
                run_analyser.feed_cache, "refresh_due", side_effect=lambda: self.order.append("feeds") or 2))
            self.acquire = stack.enter_context(mock.patch.object(
                run_analyser.run_lock, "acquire", return_value=(None, busy) if busy else ("token", None)))
            self.release = stack.enter_context(mock.patch.object(run_analyser.run_lock, "release"))

            def run(actions, now, token):
                if failure:
                    raise failure
                self.order.extend(actions)
                return {action: {"message": f"{action} done"} for action in actions}
            self.scheduled = stack.enter_context(mock.patch.object(run_analyser, "run_scheduled_actions",
                                                                   side_effect=run))
            run_analyser.main()

    def test_the_due_actions_run_then_the_feed_caches(self):
        self.run_main(due=["vea", "flash-intel"])
        self.assertEqual(self.order, ["vea", "flash-intel", "feeds"])
        # The message is what the Pipeline page shows of the run.
        self.ended.assert_called_once_with(1, "completed", {
            "message": "Vulnerability advisory: vea done; Flash intel alert: flash-intel done",
            "feed_caches_refreshed": 2})

    def test_the_run_holds_the_lock_and_gives_it_back(self):
        self.run_main(due=["vea"])
        self.acquire.assert_called_once_with("analyser", "Scheduled analyser run", "schedule")
        self.assertEqual(self.scheduled.call_args.args[2], "token")
        self.release.assert_called_once_with("token")

    def test_a_run_that_finds_the_analyser_busy_skips_its_hour(self):
        """The watermarks give its events to the next run. The feed caches are
        not the analyser's, and are refreshed all the same."""
        busy = {"action": "vea", "label": "Vulnerability advisory", "started_by": "a@example.org", "started_at": 0}
        with self.assertLogs("run_analyser", level="INFO") as logs:
            self.run_main(due=["vea"], busy=busy)
        self.assertEqual(self.order, ["feeds"])
        self.scheduled.assert_not_called()
        self.release.assert_not_called()
        self.assertIn("Vulnerability advisory", logs.output[-1])

    def test_a_run_that_fails_says_so_and_gives_the_lock_back(self):
        """Its run row would otherwise say "running" long after the process is gone."""
        with self.assertRaises(RuntimeError):
            self.run_main(due=["vea"], failure=RuntimeError("MISP down"))
        self.ended.assert_called_once_with(1, "failed")
        self.release.assert_called_once_with("token")


if __name__ == "__main__":
    unittest.main()
