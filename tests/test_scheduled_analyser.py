"""What the scheduled analyser makes, as Settings > System switches it on.

The flash intel alerts from focus points are what it always made, and stay on
by default; switched off, the run reads no scraper events and leaves the
watermark where it is, so switching them on again picks up from there. The
dashboard's three options run each only when switched on. The alerts from PIRs
and GIRs and the advisories go before the check against the focus points, which
rejects every event that matches no focus point and would take it out of both;
that check reads its events after them. The briefing, which rejects too, goes
last. They read yesterday's events as well as today's, or an event that came in
after the last run of a day would never be read; the hourly ones only those that
came in or changed since their last scheduled run that went through, so an event
is not checked and logged again every hour, unless a summary failed in it. The
briefing comes once a day, from its hour on, and a day only counts as briefed
when the run went through. An event gets one flash intel alert at most,
whichever run made it: the alerts themselves say which events they came from.
Manual collection entries with a report are read alongside the scraper's events,
from the webapp MISP they are kept on, and are summarised and tagged there.

The state file, the database and the log are temporary; every MISP and model
call is stubbed.

    python -m unittest tests.test_scheduled_analyser
"""

import contextlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

import config
import run_analyser
from analyser import reader

SWITCHES = {"ANALYSER_FLASH_INTEL": True, "ANALYSER_FLASH_INTEL_REQUIREMENTS": False,
            "ANALYSER_VULNERABILITY_ADVISORIES": False, "ANALYSER_DAILY_BRIEFING": False,
            "ANALYSER_DAILY_BRIEFING_HOUR": 21}
EVENING = datetime(2026, 10, 24, 21, 15, tzinfo=timezone.utc)


def _switches(**on):
    return mock.patch.multiple(config, create=True, **{**SWITCHES, **on})


class Due(unittest.TestCase):
    def due(self, now=EVENING, briefed=None, **on):
        with _switches(**on), mock.patch.object(run_analyser, "load_last_briefing", return_value=briefed):
            return run_analyser.scheduled_actions(now)

    def test_out_of_the_box_nothing_of_the_dashboard_runs(self):
        self.assertEqual(self.due(), [])

    def test_everything_switched_on_runs_with_the_briefing_last(self):
        self.assertEqual(self.due(ANALYSER_FLASH_INTEL_REQUIREMENTS=True, ANALYSER_VULNERABILITY_ADVISORIES=True,
                                  ANALYSER_DAILY_BRIEFING=True),
                         ["flash-intel", "vea", "daily-briefing"])

    def test_the_briefing_waits_for_its_hour_and_comes_once_a_day(self):
        self.assertEqual(self.due(EVENING.replace(hour=20), ANALYSER_DAILY_BRIEFING=True), [])
        self.assertEqual(self.due(briefed="2026-10-24", ANALYSER_DAILY_BRIEFING=True), [])
        self.assertEqual(self.due(briefed="2026-10-23", ANALYSER_DAILY_BRIEFING=True), ["daily-briefing"])


class RunScheduled(unittest.TestCase):
    def run_them(self, actions, result, last_run=None):
        jobs = []
        with mock.patch.object(run_analyser, "get_latest_pipeline_run", return_value=last_run) as self.latest, \
             mock.patch.object(run_analyser.job_store, "create_job",
                               side_effect=lambda action, **kw: jobs.append((action, kw["label"])) or {"id": action}), \
             mock.patch.object(run_analyser.analyser_pipeline, "run_action", return_value=result) as run, \
             mock.patch.object(run_analyser, "save_last_briefing") as briefed:
            self.results = run_analyser.run_scheduled_actions(actions, EVENING)
        return jobs, run, briefed

    def test_each_runs_as_a_job_the_way_the_dashboard_starts_one(self):
        jobs, run, _briefed = self.run_them(["flash-intel", "vea"], {"message": "Created 1 draft."})
        self.assertEqual(jobs, [("flash-intel", "Scheduled flash intel alert"),
                                ("vea", "Scheduled vulnerability advisory")])
        self.assertEqual(run.call_args_list, [
            mock.call("flash-intel", "analyser", triggered_by="schedule", days=2, since=None),
            mock.call("vea", "analyser", triggered_by="schedule", days=2, since=None)])

    def test_the_hourly_ones_read_only_what_changed_since_they_last_went_through(self):
        _jobs, run, _briefed = self.run_them(["vea", "daily-briefing"], {"message": "Done."},
                                             last_run={"started_at": "2026-10-24T20:15:00", "result": None})
        self.latest.assert_called_once_with("vea", triggered_by="schedule", status="completed")
        since = int(datetime(2026, 10, 24, 20, 15, tzinfo=timezone.utc).timestamp())
        self.assertEqual([c.kwargs["since"] for c in run.call_args_list], [since, None])

    def test_after_a_failed_summary_the_next_one_reads_the_same_events_again(self):
        """Nothing changes an event whose summary failed, so a run reading from
        when the last one started never read it again."""
        _jobs, run, _briefed = self.run_them(["flash-intel"], {"message": "Done."}, last_run={
            "started_at": "2026-10-24T20:15:00", "result": {"summary_failed": 1, "since": 1761333300}})
        self.assertEqual(run.call_args.kwargs["since"], 1761333300)

    def test_the_day_is_briefed_only_when_the_briefing_went_through(self):
        _jobs, _run, briefed = self.run_them(["daily-briefing"], {"message": "Daily briefing draft created."})
        briefed.assert_called_once_with("2026-10-24")
        self.assertEqual(self.results, {"daily-briefing": {"message": "Daily briefing draft created."}})
        _jobs, _run, briefed = self.run_them(["daily-briefing"], None)
        briefed.assert_not_called()


class RunAction(unittest.TestCase):
    """The dashboard's runner, which the schedule uses too."""

    def run_action(self, outcome):
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "run_vea_action", **outcome), \
             mock.patch.object(pipeline.job_store, "get_job", return_value={"action": "vea"}), \
             mock.patch.multiple(pipeline.job_store, update_job=mock.DEFAULT, append_log=mock.DEFAULT,
                                 set_step=mock.DEFAULT, complete_open_steps=mock.DEFAULT), \
             mock.patch.object(pipeline.audit, "record"), \
             mock.patch.object(pipeline, "save_last_action"), \
             mock.patch.object(pipeline, "log_pipeline_run_start", return_value=1) as started, \
             mock.patch.object(pipeline, "log_pipeline_run_end"):
            result = pipeline.run_action("job-1", "analyser", triggered_by="schedule")
        return result, started

    def test_it_says_who_ran_it_and_returns_what_it_made(self):
        result, started = self.run_action({"return_value": {"message": "Created 2 drafts."}})
        self.assertEqual(result, {"message": "Created 2 drafts."})
        started.assert_called_once_with("vea", triggered_by="schedule")

    def test_a_failed_action_returns_nothing(self):
        with self.assertLogs("webapp.analyser_pipeline", level="ERROR"):
            result, _started = self.run_action({"side_effect": RuntimeError("MISP down")})
        self.assertIsNone(result)


class Candidates(unittest.TestCase):
    def test_the_schedule_reads_yesterday_as_well(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = []
        today = datetime.now(timezone.utc).date()
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "scraper_enabled", return_value=True), \
             mock.patch.object(pipeline.misp_store, "_scraper_misp", return_value=misp):
            pipeline._incomplete_scraper_events()
            self.assertEqual(misp.search.call_args.kwargs["date_from"], today.isoformat())
            pipeline._incomplete_scraper_events(days=2)
            self.assertEqual(misp.search.call_args.kwargs["date_from"], (today - timedelta(days=1)).isoformat())
            self.assertNotIn("timestamp", misp.search.call_args.kwargs)
            pipeline._incomplete_scraper_events(days=2, since=1761336900)
            self.assertEqual(misp.search.call_args.kwargs["timestamp"], 1761336900)

    def test_an_error_answer_fails_the_run(self):
        """A run that completed on one moved the next run's window past its events."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = {"errors": (500, "Internal error")}
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline, "scraper_enabled", return_value=True), \
             mock.patch.object(pipeline.misp_store, "_scraper_misp", return_value=misp), \
             self.assertRaises(RuntimeError):
            pipeline._incomplete_scraper_events(days=2, since=1761336900)

    def test_manual_entries_with_a_report_are_read_from_the_webapp_misp(self):
        webapp = mock.create_autospec(PyMISP, instance=True)
        incomplete = [SimpleNamespace(name='workflow:state="incomplete"')]
        webapp.search.return_value = [SimpleNamespace(uuid="m1", tags=incomplete, event_reports=["Report"]),
                                      SimpleNamespace(uuid="m2", tags=incomplete, event_reports=[])]
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline.misp_store, "_misp", return_value=webapp):
            misp, entries = pipeline._incomplete_manual_entries(days=2)
        self.assertIs(misp, webapp)
        self.assertEqual([e.uuid for e in entries], ["m1"])
        self.assertEqual(webapp.search.call_args.kwargs["tags"], [pipeline.misp_store.TAG_MANUAL_ENTRY])

    def test_a_manual_entry_whose_report_was_deleted_is_not_read(self):
        webapp = mock.create_autospec(PyMISP, instance=True)
        deleted = SimpleNamespace(name="Report", deleted=True)
        webapp.search.return_value = [SimpleNamespace(uuid="m1", tags=[SimpleNamespace(name='workflow:state="incomplete"')],
                                                      event_reports=[deleted])]
        pipeline = run_analyser.analyser_pipeline
        with mock.patch.object(pipeline.misp_store, "_misp", return_value=webapp):
            _misp, entries = pipeline._incomplete_manual_entries(days=2)
        self.assertEqual(entries, [])

    def test_each_event_is_read_and_summarised_on_the_misp_it_is_on(self):
        pipeline = run_analyser.analyser_pipeline
        scraped = SimpleNamespace(uuid="a" * 36, info="Scraped", tags=[])
        entered = SimpleNamespace(uuid="m" * 36, info="Entered", tags=[])
        article = [SimpleNamespace(name="Article", content="An article")]
        used = []
        with mock.patch.object(pipeline, "_refresh_scraper_cache"), \
             mock.patch.object(pipeline, "_incomplete_scraper_events", return_value=("scraper", [scraped])), \
             mock.patch.object(pipeline, "_incomplete_manual_entries", return_value=("webapp", [entered])), \
             mock.patch.object(pipeline, "read_event_reports",
                               side_effect=lambda misp, e: used.append((e.info, misp)) or article), \
             mock.patch.object(pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary",
                               side_effect=lambda misp, e, r, g: used.append((e.info, misp)) or ("", True)):
            clients, kept, *_ = pipeline._common_candidate_events()
        self.assertEqual([e.info for e in kept], ["Scraped", "Entered"])
        self.assertEqual(clients, {scraped.uuid: "scraper", entered.uuid: "webapp"})
        # Their reports first, then their summaries.
        self.assertEqual(used, [("Scraped", "scraper"), ("Entered", "webapp")] * 2)

    def test_a_manual_entry_synced_to_the_scraper_is_processed_once(self):
        pipeline = run_analyser.analyser_pipeline
        scraped = SimpleNamespace(uuid="a" * 36, id="42", info="Synced entry", tags=[])
        entered = SimpleNamespace(uuid=scraped.uuid, id="91", info="Original entry", tags=[])
        reports = [SimpleNamespace(name="Article", content="An article")]
        with mock.patch.object(pipeline, "_refresh_scraper_cache"), \
             mock.patch.object(pipeline, "_incomplete_scraper_events", return_value=("scraper", [scraped])), \
             mock.patch.object(pipeline, "_incomplete_manual_entries", return_value=("webapp", [entered])), \
             mock.patch.object(pipeline, "read_event_reports", return_value=reports) as read, \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary", return_value=("", False)) as summarise:
            clients, kept, *_ = pipeline._common_candidate_events()
        self.assertEqual(kept, [entered])
        self.assertEqual(clients, {entered.uuid: "webapp"})
        read.assert_called_once_with("webapp", entered)
        summarise.assert_called_once_with("webapp", entered, reports, {})

    def test_a_report_read_failure_does_not_reject_a_manual_entry(self):
        pipeline = run_analyser.analyser_pipeline
        entered = SimpleNamespace(uuid="m" * 36, id="91", info="Manual entry", tags=[])
        for reply in ({"errors": ["Report access refused"]}, ConnectionError("Report access refused")):
            with self.subTest(reply=reply):
                webapp = mock.create_autospec(PyMISP, instance=True)
                if isinstance(reply, Exception):
                    webapp.get_event_reports.side_effect = reply
                else:
                    webapp.get_event_reports.return_value = reply
                with mock.patch.object(pipeline, "_refresh_scraper_cache"), \
                     mock.patch.object(pipeline, "_incomplete_scraper_events", return_value=("scraper", [])), \
                     mock.patch.object(pipeline, "_incomplete_manual_entries", return_value=(webapp, [entered])), \
                     mock.patch.object(pipeline, "_log"), \
                     mock.patch.object(pipeline.tagger, "set_workflow_state") as state, \
                     self.assertRaisesRegex((RuntimeError, ConnectionError), "Report access refused"):
                    pipeline._common_candidate_events()
                state.assert_not_called()

    def test_the_run_on_requirements_skips_an_event_with_an_alert(self):
        pipeline = run_analyser.analyser_pipeline
        events = [SimpleNamespace(uuid="a" * 36, info="Alerted", tags=[], galaxies=[]),
                  SimpleNamespace(uuid="b" * 36, info="New", tags=[], galaxies=[])]
        with mock.patch.object(pipeline, "_common_candidate_events", return_value=(None, events, {}, {}, {})), \
             mock.patch.object(pipeline.misp_store, "flash_intel_source_uuids", return_value={"a" * 36}), \
             mock.patch.object(pipeline.req_matching, "get_requirements", return_value=([], [])), \
             mock.patch.object(pipeline.req_matching, "match_events", return_value={}) as match, \
             mock.patch.object(pipeline, "_log"):
            pipeline.run_flash_intel_action(days=2)
        self.assertEqual([e["uuid"] for e in match.call_args.args[0]], ["b" * 36])


class FlashIntelSources(unittest.TestCase):
    def test_every_alert_counts_whatever_became_of_it(self):
        alerts = [SimpleNamespace(source_event_uuids=["a" * 36], review_state="rejected"),
                  SimpleNamespace(source_event_uuids=["b" * 36, "c" * 36], review_state="pending-review")]
        with mock.patch.object(run_analyser.misp_store, "list_fias", return_value=alerts):
            self.assertEqual(run_analyser.misp_store.flash_intel_source_uuids(), {"a" * 36, "b" * 36, "c" * 36})


class LatestRun(unittest.TestCase):
    def test_only_a_scheduled_run_that_went_through_counts(self):
        """A dashboard run reads today's events only, and a failed run did not
        get through its own."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")):
            run_analyser.init_db()
            run_analyser.audit.init()
            for triggered_by, status in (("schedule", "completed"), ("dashboard", "completed"),
                                         ("schedule", "failed")):
                run_id = run_analyser.log_pipeline_run_start("vea", triggered_by=triggered_by)
                run_analyser.log_pipeline_run_end(run_id, status)
            latest = run_analyser.get_latest_pipeline_run("vea", triggered_by="schedule", status="completed")
            self.assertEqual((latest["id"], latest["triggered_by"], latest["status"]), (1, "schedule", "completed"))
            self.assertEqual(run_analyser.get_latest_pipeline_run("vea")["id"], 3)


class BriefingDay(unittest.TestCase):
    def test_it_is_kept_next_to_the_watermark(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(json.dumps({"analyser_last_run": 1000}))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with mock.patch.object(config, "STATE_FILE", handle.name):
            self.assertIsNone(reader.load_last_briefing())
            reader.save_last_briefing("2026-10-24")
            self.assertEqual(reader.load_last_briefing(), "2026-10-24")
            self.assertEqual(reader.load_last_run(), 1000)


class Main(unittest.TestCase):
    def run_main(self, events=(), alerted=(), due=(), matched=(), advised=(), manual=(), on_webapp=(), synced=(),
                 search_error=False, **on):
        self.order = []
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.webapp = mock.create_autospec(PyMISP, instance=True)

        def found_on(webapp):
            """An advised event is on the scraper, or on the webapp MISP when in on_webapp."""
            if search_error:
                return lambda **kwargs: {"errors": ["Search refused"]}
            return lambda uuid, pythonify, **filters: ([SimpleNamespace(uuid=uuid, info="Advised")]
                                                      if (uuid in on_webapp) == webapp or uuid in synced else [])
        self.misp.search.side_effect = found_on(False)
        self.webapp.search.side_effect = found_on(True)
        results = {"vea": {"source_event_uuids": list(advised)}} if advised else {}
        with contextlib.ExitStack() as stack:
            for patch in (
                _switches(**on),
                mock.patch.object(run_analyser, "scheduled_actions", return_value=list(due)),
                mock.patch.object(run_analyser, "setup_logging"),
                mock.patch.object(run_analyser, "init_db"),
                mock.patch.object(run_analyser.audit, "init"),
                mock.patch.object(run_analyser, "log_pipeline_run_start", return_value=1),
                mock.patch.object(run_analyser, "log_pipeline_run_end"),
                mock.patch.object(run_analyser, "scraper_enabled", return_value=True),
                mock.patch.object(run_analyser, "get_misp", return_value=self.misp),
                mock.patch.object(run_analyser, "get_misp_webapp", return_value=self.webapp),
                mock.patch.object(run_analyser, "get_new_manual_entries", return_value=list(manual)),
                mock.patch.object(run_analyser.misp_store, "flash_intel_source_uuids", return_value=set(alerted)),
                mock.patch.object(run_analyser.analyser_pipeline, "requirement_matches",
                                  return_value={uuid: [{"id": "PIR-0003"}] for uuid in matched}),
                mock.patch.object(run_analyser, "log_event"),
                mock.patch.object(run_analyser.job_store, "create_job", return_value={"id": "job-1"}),
                mock.patch.object(run_analyser.job_store, "update_job"),
                mock.patch.object(run_analyser.feed_cache, "refresh_due", return_value=0),
            ):
                stack.enter_context(patch)
            read = stack.enter_context(mock.patch.object(
                run_analyser, "get_new_scraper_events",
                side_effect=lambda misp: self.order.append("focus points: read") or list(events)))
            self.process = stack.enter_context(mock.patch.object(
                run_analyser, "process_flash_intel",
                side_effect=lambda *a, **kw: self.order.append("focus points: check") or {"outcome": "not_relevant"}))
            watermark = stack.enter_context(mock.patch.object(run_analyser, "save_last_run"))
            scheduled = stack.enter_context(mock.patch.object(
                run_analyser, "run_scheduled_actions",
                side_effect=lambda actions, now: self.order.extend(actions) or results))
            run_analyser.main()
        return read, watermark, scheduled

    def test_the_alerts_from_focus_points_run_as_before(self):
        read, watermark, _scheduled = self.run_main(events=[SimpleNamespace(uuid="a" * 36, info="New")])
        read.assert_called_once()
        watermark.assert_called_once()
        self.assertEqual(self.order, ["focus points: read", "focus points: check"])

    def test_the_check_against_focus_points_rejects_only_after_alerts_and_advisories(self):
        """It rejects every event that matches no focus point, which took a
        CVE in a product we run, or an event a PIR matches, out of the run."""
        self.run_main(events=[SimpleNamespace(uuid="a" * 36, info="New")],
                      due=["flash-intel", "vea", "daily-briefing"])
        self.assertEqual(self.order, ["flash-intel", "vea", "focus points: read", "focus points: check",
                                      "daily-briefing"])

    def test_an_event_an_alert_was_made_from_gets_no_second_one(self):
        events = [SimpleNamespace(uuid="a" * 36, info="Alerted"), SimpleNamespace(uuid="b" * 36, info="New")]
        self.run_main(events=events, alerted={"a" * 36})
        self.assertEqual([c.args[2].uuid for c in self.process.call_args_list], ["b" * 36])

    def test_an_event_a_requirement_matches_is_kept_open(self):
        events = [SimpleNamespace(uuid="a" * 36, info="Matched"), SimpleNamespace(uuid="b" * 36, info="Other")]
        self.run_main(events=events, matched={"a" * 36})
        self.assertEqual([c.kwargs["keep_open_for"] for c in self.process.call_args_list],
                         ["its PIR/GIR match", ""])

    def test_with_the_daily_briefing_on_no_event_is_rejected_for_the_focus_points(self):
        """The briefing asks its own, wider question of every event of the day:
        an article about no focus point can still be useful to defenders."""
        events = [SimpleNamespace(uuid="a" * 36, info="Matched"), SimpleNamespace(uuid="b" * 36, info="Other")]
        self.run_main(events=events, matched={"a" * 36}, ANALYSER_DAILY_BRIEFING=True)
        self.assertEqual([c.kwargs["keep_open_for"] for c in self.process.call_args_list],
                         ["the daily briefing", "the daily briefing"])

    def test_the_watermark_is_where_the_events_were_read(self):
        """After the alerts and advisories, whose summaries change the events:
        taken at the start of the run, it had every new event read, and sent to
        the model, a second time on the next run."""
        clock = mock.Mock(side_effect=lambda: 1000 + len(self.order))
        with mock.patch.object(run_analyser.time, "time", clock):
            _read, watermark, _scheduled = self.run_main(events=[SimpleNamespace(uuid="a" * 36, info="New")],
                                                         due=["flash-intel", "vea"])
        watermark.assert_called_once_with(1002)

    def test_an_event_that_got_an_advisory_is_checked_for_an_alert_too(self):
        """An advisory moves its event on to ongoing, which the check reads past,
        and a CVE in a product we run exploited in one of our sectors deserves
        both. It is never rejected for the focus points: it is in an advisory."""
        self.run_main(events=[SimpleNamespace(uuid="a" * 36, info="New")], due=["vea"],
                      advised=["a" * 36, "b" * 36, "c" * 36], alerted=["c" * 36])
        self.misp.search.assert_called_once_with(uuid="b" * 36, pythonify=True)
        self.assertEqual([(c.args[2].uuid, c.kwargs["keep_open_for"]) for c in self.process.call_args_list],
                         [("a" * 36, "its advisory"), ("b" * 36, "its advisory")])

    def test_a_manual_entry_is_checked_on_the_webapp_misp(self):
        self.run_main(events=[SimpleNamespace(uuid="a" * 36, info="Scraped")],
                      manual=[SimpleNamespace(uuid="m" * 36, info="Entered")])
        self.assertEqual([(c.args[0], c.args[2].info) for c in self.process.call_args_list],
                         [(self.misp, "Scraped"), (self.webapp, "Entered")])

    def test_a_manual_entry_synced_to_the_scraper_is_checked_once(self):
        scraped = SimpleNamespace(uuid="a" * 36, id="42", info="Synced entry")
        entered = SimpleNamespace(uuid=scraped.uuid, id="91", info="Original entry")
        self.run_main(events=[scraped], manual=[entered])
        self.assertEqual([(c.args[0], c.args[2]) for c in self.process.call_args_list],
                         [(self.webapp, entered)])

    def test_an_advised_manual_entry_is_fetched_from_the_webapp_misp(self):
        self.run_main(due=["vea"], advised=["m" * 36], on_webapp={"m" * 36})
        self.assertEqual([(c.args[0], c.args[2].uuid) for c in self.process.call_args_list],
                         [(self.webapp, "m" * 36)])

    def test_an_advised_manual_entry_uses_its_original_not_a_synced_copy(self):
        uuid = "m" * 36
        self.run_main(due=["vea"], advised=[uuid], on_webapp={uuid}, synced={uuid})
        self.assertEqual([(c.args[0], c.args[2].uuid) for c in self.process.call_args_list],
                         [(self.webapp, uuid)])
        self.webapp.search.assert_called_once_with(uuid=uuid, pythonify=True,
                                                  tags=[run_analyser.misp_store.TAG_MANUAL_ENTRY])
        self.misp.search.assert_not_called()

    def test_an_advised_event_search_error_is_not_treated_as_not_found(self):
        with self.assertLogs("run_analyser", level="ERROR"), \
             self.assertRaisesRegex(RuntimeError, "Search refused"):
            self.run_main(due=["vea"], advised=["m" * 36], search_error=True)
        self.process.assert_not_called()

    def test_switched_off_the_scraper_queue_is_left_where_it_is(self):
        """Moving the watermark over events nobody read would skip them for good."""
        read, watermark, _scheduled = self.run_main(due=["vea"], ANALYSER_FLASH_INTEL=False)
        read.assert_not_called()
        watermark.assert_not_called()
        self.assertEqual(self.order, ["vea"])


if __name__ == "__main__":
    unittest.main()
