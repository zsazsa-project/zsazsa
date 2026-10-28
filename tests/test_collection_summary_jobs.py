"""AI summaries in data collection run as jobs, and cover manual entries.

The manual entry form has no MISP event yet, so it summarises the text on the
page; that call goes through a job like every other LLM run, or the analyst is
left watching a request that can outlive its proxy. An event typed in by hand
lives on the webapp MISP rather than the scraper one, which is what kept it out
of the summary path. An event from another MISP server is summarised only when
that server allows adding reports, and then gets the report alone. And while a summary runs, the table holds back the actions
of its events: a flag or a reject set meanwhile is undone when it finishes.

    python -m unittest tests.test_collection_summary_jobs
"""

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template
from pymisp import PyMISP

import config as _config
from webapp import analyser_pipeline, collection_cache, create_app, job_store, misp_store
from webapp.routes import api, data_collection


class SummariseContentEndpoint(unittest.TestCase):
    """The manual entry form posts what is on the page and follows a job."""

    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()

    def post(self, **body):
        """Post with the worker thread stubbed out.

        Returns (reply, thread_args), where thread_args is what the job thread
        would have run with, or None when no job was started.
        """
        started = []
        with mock.patch.object(api.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(api.misp_session, "current_user_email", return_value="koen@example.org"), \
             mock.patch.object(api.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            reply = self.client.post("/api/summarise-content", json=body)
        return reply, (started[0] if started else None)

    def test_it_answers_with_a_job_to_follow(self):
        reply, args = self.post(content="An article.", title="An article")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json(), {"ok": True, "job_id": "job-1"})
        _job_id, content, title, user = args
        self.assertEqual((content, title, user), ("An article.", "An article", "koen@example.org"))

    def test_nothing_to_summarise_starts_no_job(self):
        reply, args = self.post(content="   ")
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)


class SummariseContentJob(unittest.TestCase):
    """The form applies whatever a completed job carries, so an answer the model
    declined to give has to fail the job rather than complete it empty. A form
    saved while the job ran has handed it the event to write into. The job's
    result also has the scope the summary's "MISP context" names, which the
    form ticks."""

    NO_SCOPE = {"sectors": [], "geographies": [], "attack_techniques": [], "threat_actors": [], "vendor": []}

    def _run(self, summarised, event=None):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch.object(api.analyser_pipeline, "galaxy_names_with_commas", return_value=frozenset()), \
             mock.patch.object(api.job_store, "get_job", return_value={"event": event} if event else {}), \
             mock.patch.object(api, "_add_summary_to_event") as self.added, \
             mock.patch.object(api.audit, "record"), \
             mock.patch("analyser.llm.summarise_report", return_value=summarised):
            api._run_summarise_content_job("job-1", "An article.", "An article", "koen@example.org")
        return dict(update.call_args.kwargs)

    def test_a_summary_completes_the_job_with_the_text(self):
        final = self._run("Two hauliers were hit.")
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["result"], {"summary": "Two hauliers were hit.", "scope": self.NO_SCOPE})
        self.added.assert_not_called()

    def test_the_scope_the_summary_names_comes_with_it(self):
        summary = ("**What happened:** Two hauliers were hit.\n\n**MISP context**\n"
                   "- **Targeted sector:** Transportation\n- **Geographic scope:** Belgium, France\n"
                   "- **MITRE ATT&CK techniques:** T1566.001 T1486\n- **Threat actor:** None identified\n"
                   "- **Vendor/Technology:** None identified")
        scope = self._run(summary)["result"]["scope"]
        self.assertEqual((scope["sectors"], scope["geographies"], scope["attack_techniques"], scope["threat_actors"]),
                         (["Transportation"], ["Belgium", "France"], ["T1566.001", "T1486"], []))

    def test_the_summary_goes_into_an_event_saved_meanwhile(self):
        event = {"uuid": "e" * 36, "source": "Newsletter", "title": "An article"}
        final = self._run("Two hauliers were hit.", event=event)
        self.added.assert_called_once_with(event, "Two hauliers were hit.")
        self.assertEqual(final["result"], {"summary": "Two hauliers were hit.", "scope": self.NO_SCOPE,
                                           "added_to": "e" * 36})

    def test_an_empty_answer_fails_the_job(self):
        final = self._run("  ")
        self.assertEqual(final["status"], "failed")
        self.assertIn("empty", final["error"])

    def test_a_broken_model_call_fails_the_job_with_its_reason(self):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch("analyser.llm.summarise_report", side_effect=RuntimeError("no API key")):
            api._run_summarise_content_job("job-1", "An article.", "", "")
        final = dict(update.call_args.kwargs)
        self.assertEqual(final["status"], "failed")
        self.assertIn("no API key", final["error"])


class HandSummaryToEvent(unittest.TestCase):
    """The event the form saved without its summary, handed to the job writing it.
    Whichever of the two sees the finished summary first writes it, never both."""

    def hand(self, *states, action="summarise-content"):
        jobs = [dict(job, action=action) if job else None for job in states]
        with mock.patch.object(api.job_store, "get_job", side_effect=jobs), \
             mock.patch.object(api.job_store, "update_job") as self.update, \
             mock.patch.object(api, "_add_summary_to_event") as self.added:
            return api.hand_summary_to_event("job-1", "e" * 36, "Newsletter", "An article")

    def test_a_running_job_is_told_where_to_write(self):
        self.assertTrue(self.hand({"status": "running"}, {"status": "running"}))
        self.update.assert_called_once_with(
            "job-1", event={"uuid": "e" * 36, "source": "Newsletter", "title": "An article"})
        self.added.assert_not_called()

    def test_a_job_that_finishes_during_the_hand_over_is_written_here(self):
        done = {"status": "completed", "result": {"summary": "Two hauliers were hit."}}
        self.assertTrue(self.hand({"status": "running"}, done))
        self.added.assert_called_once()

    def test_a_summary_finished_before_the_save_is_written_here(self):
        done = {"status": "completed", "result": {"summary": "Two hauliers were hit."}}
        self.assertTrue(self.hand(done))
        self.added.assert_called_once_with(
            {"uuid": "e" * 36, "source": "Newsletter", "title": "An article"}, "Two hauliers were hit.")
        self.update.assert_not_called()

    def test_nothing_comes_of_a_failed_unknown_or_other_job(self):
        for states, action in ((({"status": "failed"},), "summarise-content"), ((None,), "summarise-content"),
                               (({"status": "running"},), "bulk-summarise")):
            self.assertFalse(self.hand(*states, action=action))
            self.update.assert_not_called()
            self.added.assert_not_called()


class AddSummaryToEvent(unittest.TestCase):
    def test_the_report_goes_into_the_saved_event_and_its_row_shows_it(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = SimpleNamespace(id=7)
        with mock.patch.object(api.misp_store, "_misp", return_value=misp), \
             mock.patch.object(api.misp_store, "add_ai_summary_report") as add, \
             mock.patch.object(api.collection_cache, "mark_ai_summary") as mark:
            api._add_summary_to_event({"uuid": "e" * 36, "source": "Newsletter", "title": "An article"},
                                      "Two hauliers were hit.")
        add.assert_called_once_with(misp, 7, "An article", "Two hauliers were hit.")
        mark.assert_called_once_with("e" * 36, api.collection_cache.manual_source_id("Newsletter"))


class ManualEntrySavedDuringASummary(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()
        for patcher in (
            mock.patch.object(data_collection.misp_store, "list_collection_sources",
                              return_value=[SimpleNamespace(name="Newsletter", enabled=True)]),
            mock.patch.object(data_collection.misp_store, "create_manual_collection_event", return_value="e" * 36),
            mock.patch.object(data_collection, "_cache_manual_event"),
            mock.patch.object(data_collection.audit, "record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, hand_over=None, **form):
        with mock.patch.object(api, "hand_summary_to_event", hand_over or mock.Mock(return_value=True)) as hand:
            reply = self.client.post("/collection/manual/new",
                                     data={"source": "Newsletter", "title": "An article", **form})
            with self.client.session_transaction() as session:
                flashes = [message for _, message in session.get("_flashes", [])]
        return reply, hand, flashes

    def test_the_event_is_handed_to_the_job_still_writing_its_summary(self):
        reply, hand, flashes = self.save(summary_job="job-1")
        hand.assert_called_once_with("job-1", "e" * 36, "Newsletter", "An article")
        self.assertTrue(reply.headers["Location"].endswith("/collection/manual/" + "e" * 36))
        self.assertIn("The AI summary goes into the event when it is done.", flashes)

    def test_a_form_with_its_own_summary_hands_nothing_over(self):
        _reply, hand, _flashes = self.save(summary_job="job-1", summary="Written by hand.")
        hand.assert_not_called()

    def test_the_scope_ticked_on_the_form_is_saved_with_it(self):
        self.client.post("/collection/manual/new", data={
            "source": "Newsletter", "title": "An article", "sectors": ["Finance"],
            "mitre_attack_techniques": ["Phishing - T1566", "Spearphishing Attachment - T1566.001"]})
        data = data_collection.misp_store.create_manual_collection_event.call_args.args[0]
        self.assertEqual((data["sectors"], data["mitre_attack_techniques"]),
                         (["Finance"], ["Phishing - T1566", "Spearphishing Attachment - T1566.001"]))

    def test_a_failed_hand_over_leaves_the_event_saved(self):
        reply, _hand, flashes = self.save(hand_over=mock.Mock(side_effect=RuntimeError("MISP down")),
                                          summary_job="job-1")
        self.assertTrue(reply.headers["Location"].endswith("/collection/manual/" + "e" * 36))
        self.assertIn("The event was saved, but its AI summary could not be added.", flashes)


class AiSummaryReport(unittest.TestCase):
    def test_it_is_named_the_way_the_pages_recognise_one(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event_report.return_value = {}
        misp_store.add_ai_summary_report(misp, 7, "An article", "Two hauliers were hit.")
        event_id, report = misp.add_event_report.call_args.args
        self.assertEqual(event_id, 7)
        self.assertEqual(report.name, f"{misp_store.AI_SUMMARY_PREFIX} An article")
        self.assertEqual(report.content, "Two hauliers were hit.")

    def test_a_refusal_from_misp_is_raised(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event_report.return_value = {"errors": "Invalid event"}
        with self.assertRaises(RuntimeError):
            misp_store.add_ai_summary_report(misp, 7, "An article", "Two hauliers were hit.")


_SCRAPER_SOURCE = {"id": "scraper", "kind": "scraper", "label": "MISP scraper"}
_MANUAL_SOURCE = {"id": "manual-slack", "kind": "manual", "label": "Slack"}
_EXTERNAL_SOURCE = {"id": "partner-misp", "kind": "misp", "label": "Partner"}
_REPORTING_SOURCE = {"id": "intern-misp", "kind": "misp", "label": "Intern", "url": "https://misp.intern.example",
                     "api_key": "k", "verify_tls": True, "allow_reports": True}
_ALL_SOURCES = [_SCRAPER_SOURCE, _MANUAL_SOURCE, _EXTERNAL_SOURCE, _REPORTING_SOURCE]


class SummarisableSources(unittest.TestCase):
    """The summary is written back as a report, so it needs a MISP we may write
    to: the scraper, the webapp instance holding the manual entries, or a MISP
    server whose settings allow adding reports."""

    def _ids(self, sources=_ALL_SOURCES):
        with mock.patch.object(data_collection, "_sources", return_value=sources):
            return set(data_collection._summarisable_sources())

    def test_scraper_and_manual_events_can_be_summarised(self):
        self.assertLessEqual({"scraper", "manual-slack"}, self._ids())

    def test_a_third_party_misp_server_is_left_out(self):
        self.assertNotIn("partner-misp", self._ids())

    def test_a_misp_server_that_allows_reports_is_summarised(self):
        self.assertIn("intern-misp", self._ids())

    def test_the_setting_reaches_the_source_list(self):
        servers = [{"id": "intern-misp", "label": "Intern", "url": "https://misp.intern.example",
                    "allow_reports": True},
                   {"id": "partner-misp", "label": "Partner", "url": "https://misp.partner.example"}]
        with mock.patch.object(_config, "MISP_SERVERS", servers), \
             mock.patch.object(collection_cache, "scraper_enabled", return_value=False):
            sources = collection_cache._build_sources(with_manual=False)
        self.assertEqual(self._ids(sources), {"intern-misp"})

    def test_manual_events_are_read_from_the_webapp_misp(self):
        """They are created there, so the scraper connection would not find them."""
        with mock.patch.object(data_collection.misp_store, "_misp", return_value="webapp"), \
             mock.patch.object(data_collection.misp_store, "_scraper_misp", return_value="scraper"):
            self.assertEqual(data_collection._connect_source(_MANUAL_SOURCE), ("webapp", None))
            self.assertEqual(data_collection._connect_source(_SCRAPER_SOURCE), ("scraper", None))


class SummariseRoute(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()
        patcher = mock.patch.object(data_collection.job_store, "update_job")
        self.update_job = patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, body, path="/collection/" + "u" * 36 + "/summarise"):
        started = []
        with mock.patch.object(data_collection, "_sources", return_value=_ALL_SOURCES), \
             mock.patch.object(data_collection.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(data_collection.misp_session, "current_user_email", return_value="koen@example.org"), \
             mock.patch.object(data_collection.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            reply = self.client.post(path, json=body)
        return reply, (started[0] if started else None)

    def test_a_manual_event_starts_a_summary_job(self):
        reply, args = self.post({"source": "manual-slack"})
        self.assertEqual(reply.status_code, 200)
        self.assertTrue(reply.get_json()["ok"])
        _job_id, batch, _user = args
        self.assertEqual(batch, [{"uuid": "u" * 36, "sourceId": "manual-slack"}])

    def test_the_job_records_the_event_it_works_on(self):
        self.post({"source": "manual-slack"})
        self.update_job.assert_called_once_with("job-1", events=["u" * 36])

    def test_a_batch_records_every_event_it_works_on(self):
        events = [{"uuid": "a" * 36, "sourceId": "scraper"}, {"uuid": "b" * 36, "sourceId": "manual-slack"}]
        self.post({"events": events}, path="/collection/bulk-summarise")
        self.update_job.assert_called_once_with("job-1", events=["a" * 36, "b" * 36])

    def test_an_event_from_a_third_party_misp_is_refused(self):
        reply, args = self.post({"source": "partner-misp"})
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)

    def test_an_event_from_a_misp_server_that_allows_reports_starts_a_job(self):
        reply, args = self.post({"source": "intern-misp"})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(args[1], [{"uuid": "u" * 36, "sourceId": "intern-misp"}])


class EventsBeingSummarised(unittest.TestCase):
    def test_only_an_unfinished_live_summary_holds_its_events(self):
        now = time.time()
        jobs = [
            {"id": "running", "action": "summarise", "status": "running", "updated_at": now, "events": ["a"]},
            {"id": "queued", "action": "bulk-summarise", "status": "queued", "updated_at": now,
             "events": ["b", "c"]},
            {"id": "done", "action": "summarise", "status": "completed", "updated_at": now, "events": ["d"]},
            # A worker that died with its process never moves its job off "running".
            {"id": "dead", "action": "summarise", "status": "running",
             "updated_at": now - job_store.STALE_AFTER_SECONDS - 60, "events": ["e"]},
            {"id": "other", "action": "collection-refresh", "status": "running", "updated_at": now,
             "events": ["f"]},
        ]
        with mock.patch.object(data_collection.job_store, "list_jobs", return_value=jobs):
            self.assertEqual(data_collection._events_being_summarised(),
                             {"a": "running", "b": "queued", "c": "queued"})


class BusyRowsInTheTable(unittest.TestCase):
    """What the server sends for a row whose event a summary is working on."""

    def setUp(self):
        def no_network(*args, **kwargs):
            raise requests.ConnectionError("tests run offline")

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rows = [{"uuid": uuid, "source_id": "scraper", "info": "Collected event", "tags": [],
                 "orgc": "CIRCL", "date": "2026-10-01"} for uuid in ("a" * 36, "b" * 36)]
        for patcher in (
            mock.patch("requests.adapters.HTTPAdapter.send", no_network),
            mock.patch.object(_config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(_config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(collection_cache, "get_events", return_value=rows),
            mock.patch.object(collection_cache, "get_source_status", return_value={}),
            mock.patch.object(collection_cache, "interval_s", return_value=300),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_store, "list_briefings", return_value=[]),
            mock.patch.object(data_collection, "_events_being_summarised", return_value={"a" * 36: "job-7"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        page = BeautifulSoup(create_app().test_client().get("/collection/").data, "html.parser")
        self.cells = {row["data-uuid"]: row.select_one(".event-actions")
                      for row in page.select("tr.event-row")}

    def test_a_busy_row_names_its_job_and_has_its_actions_disabled(self):
        cell = self.cells["a" * 36]
        self.assertEqual(cell["data-busy-job"], "job-7")
        self.assertIsNotNone(cell.select_one(".busy-indicator"))
        buttons = cell.select("button")
        self.assertTrue(buttons)
        self.assertTrue(all(b.has_attr("disabled") for b in buttons))

    def test_the_other_rows_are_left_alone(self):
        cell = self.cells["b" * 36]
        self.assertFalse(cell.has_attr("data-busy-job"))
        self.assertFalse(any(b.has_attr("disabled") for b in cell.select("button")))


class BatchAcrossSources(unittest.TestCase):
    """A selection can mix scraper events with manual entries, so the batch has
    to reach for the right connection per event rather than one for all."""

    def _run(self, batch, sources=_ALL_SOURCES, cached=None, outcomes=None):
        """Run the batch job with both MISP connections and the LLM stubbed out.

        ``cached`` is what the collection cache holds, by default the batch
        itself. The returned namespace holds the stubs, so a check can see which
        connection each event was loaded from and how often the source list and
        the connections themselves were opened. ``outcomes`` are what the
        summaries come back with, in turn; by default every one is written.
        """
        if cached is None:
            cached = [{"uuid": ev["uuid"], "source_id": ev["sourceId"], "source_report_count": 1} for ev in batch]
        scraper_misp, webapp_misp = mock.MagicMock(), mock.MagicMock()
        server_misp = mock.create_autospec(PyMISP, instance=True)
        for misp in (scraper_misp, webapp_misp, server_misp):
            misp.get_event.return_value = {"Event": {"id": "7", "info": "An event", "date": "2026-10-20"}}
        with mock.patch.object(data_collection, "_sources", return_value=sources) as list_sources, \
             mock.patch.object(data_collection, "PyMISP", return_value=server_misp), \
             mock.patch.object(data_collection.collection_cache, "get_events_by_uuids",
                               side_effect=lambda uuids: [row for row in cached if row["uuid"] in uuids]), \
             mock.patch.object(data_collection.misp_store, "_scraper_misp", return_value=scraper_misp), \
             mock.patch.object(data_collection.misp_store, "_misp", return_value=webapp_misp) as open_webapp, \
             mock.patch.object(data_collection.job_store, "update_job") as update, \
             mock.patch.object(data_collection.job_store, "append_log"), \
             mock.patch.object(data_collection.job_store, "heartbeat"), \
             mock.patch.object(data_collection, "_generate_ai_summary",
                               side_effect=outcomes or (lambda *a, **kw: (True, "ok", 200))) as generate:
            data_collection._run_summarise_job("job-1", batch, "koen@example.org")
        return SimpleNamespace(list_sources=list_sources, open_webapp=open_webapp,
                               scraper_misp=scraper_misp, webapp_misp=webapp_misp, server_misp=server_misp,
                               generate=generate, update=update)

    def test_each_event_is_loaded_from_its_own_source(self):
        run = self._run([{"uuid": "a" * 36, "sourceId": "scraper"},
                         {"uuid": "b" * 36, "sourceId": "manual-slack"}])
        self.assertEqual(run.scraper_misp.get_event.call_args[0][0], "a" * 36)
        self.assertEqual(run.webapp_misp.get_event.call_args[0][0], "b" * 36)
        self.assertEqual([call[0][2] for call in run.generate.call_args_list],
                         ["scraper", "manual-slack"])

    def test_an_event_from_a_misp_server_is_loaded_from_that_server(self):
        run = self._run([{"uuid": "d" * 36, "sourceId": "intern-misp"}])
        self.assertEqual(run.server_misp.get_event.call_args[0][0], "d" * 36)
        self.assertEqual(run.generate.call_args.kwargs["kind"], "misp")

    def test_the_source_list_is_read_once_for_the_whole_batch(self):
        """It is fetched from MISP, so reading it per event would put two extra
        round trips in front of every summary in the batch."""
        run = self._run([{"uuid": "a" * 36, "sourceId": "scraper"},
                         {"uuid": "b" * 36, "sourceId": "manual-slack"},
                         {"uuid": "c" * 36, "sourceId": "manual-slack"}])
        run.list_sources.assert_called_once()

    def test_all_manual_sources_share_one_connection(self):
        """Opening a PyMISP client costs a round trip of its own."""
        run = self._run(
            [{"uuid": "b" * 36, "sourceId": "manual-slack"},
             {"uuid": "c" * 36, "sourceId": "manual-newsletter"}],
            sources=_ALL_SOURCES + [{"id": "manual-newsletter", "kind": "manual", "label": "News"}])
        self.assertEqual(run.webapp_misp.get_event.call_count, 2)
        run.open_webapp.assert_called_once()

    def test_an_event_without_a_report_is_skipped(self):
        """There is nothing to summarise, and one that only has an AI summary has
        nothing either."""
        run = self._run([{"uuid": "b" * 36, "sourceId": "manual-slack"}],
                        cached=[{"uuid": "b" * 36, "source_id": "manual-slack", "source_report_count": 0}])
        run.generate.assert_not_called()

    def test_an_event_the_collection_does_not_list_is_skipped(self):
        """A manual source writes to zsazsa's own MISP, where an id from the
        request could name a stakeholder or a product."""
        run = self._run([{"uuid": "b" * 36, "sourceId": "manual-slack"}], cached=[])
        run.generate.assert_not_called()
        run.webapp_misp.get_event.assert_not_called()

    def test_a_batch_that_made_nothing_fails_with_the_reason(self):
        """It ended green, with only "1 error(s)" in its message to say it had
        not worked."""
        run = self._run([{"uuid": "b" * 36, "sourceId": "manual-slack"}],
                        outcomes=[(False, "QUALITY: insufficient content for analysis", 422)])
        final = run.update.call_args.kwargs
        self.assertEqual((final["status"], final["error"]),
                         ("failed", "An event: QUALITY: insufficient content for analysis"))

    def test_a_batch_that_made_some_completes_and_counts_its_errors(self):
        run = self._run([{"uuid": "a" * 36, "sourceId": "scraper"}, {"uuid": "b" * 36, "sourceId": "manual-slack"}],
                        outcomes=[(True, "ok", 200), (False, "QUALITY: insufficient content for analysis", 422)])
        final = run.update.call_args.kwargs
        self.assertEqual((final["status"], final["result"]["summarised"], final["result"]["errors"]),
                         ("completed", 1, 1))

    def test_an_event_from_an_unwritable_source_is_skipped(self):
        run = self._run([{"uuid": "c" * 36, "sourceId": "partner-misp"}])
        run.generate.assert_not_called()
        self.assertEqual(run.update.call_args.kwargs["result"]["skipped"], 1)


# The layout zsazsaprompts/summarise_misp_report.md asks the model for. The
# context lines are what the scope tags are read from.
_SUMMARY = """**Summary**

**What happened:** A campaign delivered Overlord RAT to hauliers.
**Recommended action:** Investigate.

**Severity:** High
**Urgency:** This week

**MISP context** (extract from the article content - always include all five lines):
- **Targeted sector:** Transportation
- **Geographic scope:** Belgium
- **MITRE ATT&CK techniques:** T1190
- **Threat actor:** Lazarus Group
- **Vendor/Technology:** None identified
"""

_MITRE_CLUSTERS = {
    "Exploit Public-Facing Application - T1190":
        'misp-galaxy:mitre-attack-pattern="Exploit Public-Facing Application - T1190"',
    "Phishing - T1566": 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
}


class _FakeMisp:
    def __init__(self, article="An article about a RAT."):
        self.reports = [SimpleNamespace(name="Article", content=article)]
        self.tagged = []

    def get_event_reports(self, event_id, pythonify=True):
        return self.reports

    def add_event_report(self, event_id, report):
        self.reports.append(report)

    def tag(self, event, tag_name):
        self.tagged.append(tag_name)


class SummaryScopeTags(unittest.TestCase):
    """Summarising from data collection tags the event with the scope its
    summary names, the same tags the analyser applies when it writes one. The
    two read the same model output, so they have to read it the same way: the
    page had its own parser for an older, plain-text layout and silently tagged
    nothing once the prompt moved to markdown."""

    def summarise(self, summary, galaxies=None):
        """`galaxies` maps a galaxy to its clusters; a galaxy not in it gets the ATT&CK ones."""
        misp = _FakeMisp()
        event = SimpleNamespace(id=7, uuid="u" * 36, info="Overlord RAT campaign", tags=[])
        scope_calls = []

        def build_scope_tags(data):
            scope_calls.append(data)
            tags = []
            for sector in data.get("sectors") or []:
                tags.append(f'misp-galaxy:sector="{sector}"')
            for geo in data.get("geographic_scope") or []:
                tags.append(f'misp-galaxy:country="{geo}"')
            for actor in data.get("threat_actors") or []:
                tags.append(f'misp-galaxy:threat-actor="{actor}"')
            return tags

        with mock.patch("analyser.llm.summarise_report", return_value=summary), \
             mock.patch("analyser.tagger.set_workflow_state"), \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary"), \
             mock.patch.object(data_collection, "_refresh_cached_event"), \
             mock.patch.object(data_collection.audit, "record") as audit_record, \
             mock.patch.object(data_collection.misp_store, "_build_scope_tags", build_scope_tags), \
             mock.patch.object(data_collection.misp_store, "_galaxy_tag_map",
                               side_effect=lambda galaxy: (galaxies or {}).get(galaxy, _MITRE_CLUSTERS)):
            ok, message, status = data_collection._generate_ai_summary(misp, event, "scraper")

        self.assertEqual((ok, status), (True, 200), message)
        return misp.tagged, (scope_calls[0] if scope_calls else {}), dict(audit_record.call_args.kwargs)

    def test_the_context_lines_become_galaxy_tags(self):
        tagged, scope, _audit = self.summarise(_SUMMARY)
        self.assertEqual(scope["sectors"], ["Transportation"])
        self.assertEqual(scope["geographic_scope"], ["Belgium"])
        self.assertEqual(scope["threat_actors"], ["Lazarus Group"])
        self.assertIn('misp-galaxy:sector="Transportation"', tagged)
        self.assertIn('misp-galaxy:country="Belgium"', tagged)
        self.assertIn('misp-galaxy:threat-actor="Lazarus Group"', tagged)

    def test_only_the_techniques_named_are_tagged(self):
        tagged, _scope, _audit = self.summarise(_SUMMARY)
        self.assertIn(_MITRE_CLUSTERS["Exploit Public-Facing Application - T1190"], tagged)
        self.assertNotIn(_MITRE_CLUSTERS["Phishing - T1566"], tagged)

    def test_the_applied_tags_are_recorded_in_the_audit_trail(self):
        _tagged, _scope, audit = self.summarise(_SUMMARY)
        self.assertIn('misp-galaxy:sector="Transportation"', audit["details"])

    def test_a_sector_whose_name_holds_a_comma_stays_one_sector(self):
        """The line is split on commas, which cut "Government, Administration"
        in two and matched neither half."""
        summary = _SUMMARY.replace("Transportation", "Finance, Government, Administration")
        sectors = {"Finance": "s1", "Government, Administration": "s2"}
        _tagged, scope, _audit = self.summarise(summary, {misp_store.GALAXY_SECTOR: sectors})
        self.assertEqual(scope["sectors"], ["Finance", "Government, Administration"])

    def test_a_summary_that_identifies_nothing_tags_nothing(self):
        empty = _SUMMARY.replace("Transportation", "None identified") \
                        .replace("Belgium", "None identified") \
                        .replace("T1190", "None identified") \
                        .replace("Lazarus Group", "None identified")
        tagged, scope, _audit = self.summarise(empty)
        self.assertEqual(tagged, [])
        self.assertEqual(scope, {})


class NamesWithCommas(unittest.TestCase):
    """Galaxy names that hold a comma, read off a comma-separated context line."""

    LINE = """- **Targeted sector:** Finance, Government, Administration
- **Geographic scope:** Belgium, Bonaire, Saint Eustatius and Saba
"""
    NAMES = frozenset({"government, administration", "bonaire, saint eustatius and saba"})

    def test_two_neighbours_that_make_a_known_name_stay_together(self):
        context = analyser_pipeline.parse_misp_context(self.LINE, self.NAMES)
        self.assertEqual(context["sectors"], ["Finance", "Government, Administration"])
        self.assertEqual(context["geographies"], ["Belgium", "Bonaire, Saint Eustatius and Saba"])

    def test_without_the_names_the_line_is_split_as_before(self):
        context = analyser_pipeline.parse_misp_context(self.LINE)
        self.assertEqual(context["sectors"], ["Finance", "Government", "Administration"])

    def test_the_names_come_from_the_sector_and_country_galaxies(self):
        galaxies = {misp_store.GALAXY_SECTOR: {"Finance": "s1", "Government, Administration": "s2"},
                    misp_store.GALAXY_COUNTRY: {"bonaire, saint eustatius and saba ": "c1", "belgium": "c2"}}
        with mock.patch.object(misp_store, "_galaxy_tag_map", side_effect=lambda g: galaxies.get(g, {})):
            self.assertEqual(analyser_pipeline.galaxy_names_with_commas(), self.NAMES)

    def test_the_analyser_tags_them_too_trailing_space_and_all(self):
        """MISP's country galaxy writes Bonaire with a space at the end, so it
        never matched a name read off a line, comma or not."""
        galaxies = {misp_store.GALAXY_SECTOR: {"Government, Administration": "sector-tag"},
                    misp_store.GALAXY_COUNTRY: {"bonaire, saint eustatius and saba ": "country-tag"}}
        misp = _FakeMisp()
        with mock.patch.object(misp_store, "_galaxy_tag_map", side_effect=lambda g: galaxies.get(g, {})):
            lookup = analyser_pipeline._build_galaxy_lookup()
            context = analyser_pipeline.parse_misp_context(self.LINE, analyser_pipeline.galaxy_names_with_commas())
            analyser_pipeline._apply_misp_context_tags(misp, SimpleNamespace(uuid="e"), context, lookup)
            scope_tags = misp_store._build_scope_tags({"geographic_scope": context["geographies"],
                                                       "sectors": context["sectors"]})
        self.assertEqual(sorted(misp.tagged), ["country-tag", "sector-tag"])
        self.assertEqual(sorted(scope_tags), ["country-tag", "sector-tag"])


class SummaryOnAnotherMispServer(unittest.TestCase):
    """A MISP server that allows adding reports gets the summary report and
    nothing else: for our organisation alone, with the event published again
    without an e-mail, because MISP unpublishes an event a report is added to
    and only published events are read from such a server. The workflow state
    and the tags belong to that server."""

    def summarise(self, kind="misp", published=None):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event_reports.return_value = [SimpleNamespace(content="An article about a RAT.")]
        misp.add_event_report.return_value = {"EventReport": {"id": "3"}}
        misp.publish.return_value = published or {"saved": True, "success": True}
        event = SimpleNamespace(id=7, uuid="u" * 36, info="Overlord RAT campaign", tags=[])
        with mock.patch("analyser.llm.summarise_report", return_value="## Summary\nA RAT."), \
             mock.patch("analyser.tagger.set_workflow_state") as workflow, \
             mock.patch.object(data_collection, "_tag_event_scope", return_value=[]) as scope, \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary"), \
             mock.patch.object(data_collection, "_refresh_cached_event"), \
             mock.patch.object(data_collection.audit, "record"):
            result = data_collection._generate_ai_summary(misp, event, "intern-misp", kind=kind)
        return result, misp, workflow, scope

    def test_the_report_is_for_our_organisation_only(self):
        _result, misp, _workflow, _scope = self.summarise()
        report = misp.add_event_report.call_args[0][1]
        self.assertEqual(report.distribution, 0)
        self.assertTrue(report.name.startswith(misp_store.AI_SUMMARY_PREFIX))

    def test_the_event_is_published_again_without_an_email(self):
        (ok, _message, _status), misp, _workflow, _scope = self.summarise()
        self.assertTrue(ok)
        misp.publish.assert_called_once_with(7, alert=False)

    def test_the_workflow_state_and_tags_are_left_alone(self):
        _result, misp, workflow, scope = self.summarise()
        workflow.assert_not_called()
        scope.assert_not_called()
        misp.tag.assert_not_called()

    def test_an_event_that_could_not_be_published_again_is_said_so(self):
        with self.assertLogs("webapp.misp_store", level="WARNING"):
            (ok, message, _status), *_ = self.summarise(published={"errors": (403, "Not allowed")})
        self.assertTrue(ok)
        self.assertIn("could not be published again", message)

    def test_a_scraper_event_keeps_the_event_distribution_and_is_not_published(self):
        _result, misp, workflow, _scope = self.summarise(kind="scraper")
        self.assertEqual(misp.add_event_report.call_args[0][1].distribution, 5)
        misp.publish.assert_not_called()
        workflow.assert_called_once()


class SummaryButton(unittest.TestCase):
    """The table offers the summary on an event of a source zsazsa may write to,
    that has a report to summarise and no summary yet."""

    def buttons(self, *events):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log")), \
             mock.patch.object(collection_cache, "start_worker"):
            app = create_app()
            with app.test_request_context():
                html = render_template("data_collection/_list_table.html", events=list(events),
                                       flagged_uuids=set(), events_being_summarised={},
                                       summarisable_source_ids={"intern-misp"}, event_summary_source_ids=set())
        return [b["data-uuid"] for b in BeautifulSoup(html, "html.parser").select(".create-summary-btn")]

    def row(self, uuid, source_id="intern-misp", report_count=1, has_ai_summary=False):
        return {"uuid": uuid, "source_id": source_id, "source_kind": "misp", "info": "Event", "tags": [],
                "report_count": report_count, "source_report_count": report_count, "has_ai_summary": has_ai_summary}

    def test_only_an_event_with_a_report_and_no_summary_gets_the_button(self):
        self.assertEqual(self.buttons(self.row("with-report"),
                                      self.row("no-report", report_count=0),
                                      self.row("summarised", has_ai_summary=True),
                                      self.row("partner", source_id="partner-misp")),
                         ["with-report"])


if __name__ == "__main__":
    unittest.main()
