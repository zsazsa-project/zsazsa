"""An event from another MISP server can be summarised by the AI-connector MISP module.

Offered on a MISP server that allows adding reports, while the module is
enabled. An event with a report gets a dropdown next to the LLM summary: that
summary, that summary and the event summary, or the event summary alone. An
event without a report gets the event summary on an icon of its own. The event
summary is a report of its own, named so that it is told apart from the
article and from the LLM summary of it, for our organisation only, and the
event is published again; a batch never asks for one. The module is asked the
way MISP asks it, with the event as MISP's JSON has it.

MISP is an autospec of PyMISP; the module, the LLM and the database are stubbed.

    python -m unittest tests.test_event_summary
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask, render_template
from pymisp import MISPEvent, MISPEventReport, PyMISP

import config as _config
from core import ai_connector
from webapp import collection_cache, create_app
from webapp.routes import api, data_collection

SERVER = {"id": "intern-misp", "kind": "misp", "label": "Intern", "url": "https://misp.intern.example",
          "api_key": "k", "verify_tls": True, "allow_reports": True}
PARTNER = {"id": "partner-misp", "kind": "misp", "label": "Partner", "url": "https://misp.partner.example",
           "api_key": "k", "verify_tls": True}
SCRAPER = {"id": "scraper", "kind": "scraper", "label": "MISP scraper"}
SETTINGS = {**ai_connector.DEFAULTS, "AI_CONNECTOR_URL": "http://ai-connector", "AI_CONNECTOR_MODEL_ID": "m"}
UUID = "00000000-0000-4000-8000-000000000001"
MISP_JSON = {"Event": {"id": "7", "uuid": UUID, "info": "Overlord RAT campaign", "date": "2026-10-20",
                       "EventReport": [{"name": "Article", "content": "The article"}]}}


def _event(*report_names):
    event = MISPEvent()
    event.uuid = UUID
    event.id = 7
    event.info = "Overlord RAT campaign"
    event.date = "2026-10-20"
    for name in report_names:
        report = MISPEventReport()
        report.name, report.content = name, f"Content of {name}"
        event.event_reports.append(report)
    return event


class ModuleCall(unittest.TestCase):
    def summarise(self, answer):
        response = mock.Mock(status_code=200)
        response.json.return_value = answer
        with mock.patch.object(ai_connector.requests, "post", return_value=response) as post:
            return ai_connector.summarise_event(SETTINGS, {"uuid": UUID, "info": "Overlord"}), post

    def test_the_event_is_sent_as_misp_sends_it(self):
        summary, post = self.summarise({"results": {
            "EventReport": {"name": f"AI summary of event {UUID}", "content": "## What happened"},
            "Tag": [{"name": 'ai-computer-assisted:assistance-level="ai-generated"'}]}})
        self.assertEqual(summary, "## What happened")
        body = post.call_args.kwargs["json"]
        self.assertEqual((body["use_case"], body["data"]),
                         ("summarization_on_event", {"Event": {"uuid": UUID, "info": "Overlord"}}))
        self.assertEqual(post.call_args.kwargs["timeout"], SETTINGS["AI_CONNECTOR_TIMEOUT"])

    def test_an_error_or_an_empty_summary_is_raised(self):
        for answer in ({"error": "summary failed the structural check"},
                       {"results": {"EventReport": {"name": "x", "content": " "}}}):
            with self.subTest(answer=answer), self.assertRaises(ai_connector.ModuleError):
                self.summarise(answer)


class CachedReports(unittest.TestCase):
    def test_the_cache_tells_ai_summaries_from_the_reports_they_are_made_of(self):
        row = collection_cache._extract_row(
            _event("Article", "[AI-Summary] Overlord", "[AI-Event-Summary] Overlord"), "intern-misp")
        self.assertEqual((row["report_count"], row["source_report_count"]), (3, 1))
        self.assertTrue(row["has_ai_summary"])
        self.assertTrue(row["has_ai_event_summary"])

    def test_an_event_summary_is_not_the_summary_of_the_report(self):
        row = collection_cache._extract_row(_event("[AI-Event-Summary] Overlord"), "intern-misp")
        self.assertEqual(row["source_report_count"], 0)
        self.assertFalse(row["has_ai_summary"])

    def test_a_cache_from_before_the_event_summary_gets_its_report_count(self):
        """Filled in when zsazsa starts, rather than at the next refresh, which on a
        server that does not answer can be a long while."""
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp) / "cache.db")):
            with collection_cache._db() as conn:
                conn.execute("CREATE TABLE events (source_id TEXT, uuid TEXT, date TEXT, report_count INTEGER"
                             " DEFAULT 0, has_ai_summary INTEGER DEFAULT 0, PRIMARY KEY (source_id, uuid))")
                conn.executemany("INSERT INTO events (source_id, uuid, report_count, has_ai_summary)"
                                 " VALUES (?, ?, ?, ?)",
                                 [("intern-misp", "a", 2, 1), ("intern-misp", "b", 1, 0), ("intern-misp", "c", 0, 0)])
            collection_cache.init_db()
            with collection_cache._db() as conn:
                counts = dict(conn.execute("SELECT uuid, source_report_count FROM events").fetchall())
        self.assertEqual(counts, {"a": 1, "b": 1, "c": 0})

    def test_raw_report_content_leaves_the_event_summary_out(self):
        reports = [{"name": "[AI-Event-Summary] Overlord", "content": "The module's summary"},
                   {"name": "Article", "content": "The article"}]
        self.assertEqual(api._report_content([{"reports": reports}], raw_only=True), "The article")


class Buttons(unittest.TestCase):
    def actions(self, row, enabled=True):
        """The summary modes offered on a row: each button's mode, in page order,
        with "hidden" for one that only shows once the dropdown is gone."""
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log")), \
             mock.patch.object(collection_cache, "start_worker"):
            app = create_app()
            with app.test_request_context():
                html = render_template(
                    "data_collection/_list_table.html", flagged_uuids=set(), events_being_summarised={},
                    events=[{"uuid": UUID, "source_id": "intern-misp", "source_kind": "misp", "info": "Event",
                             "tags": [], "report_count": row.get("source_report_count", 0),
                             "has_ai_summary": False, "has_ai_event_summary": False, **row}],
                    summarisable_source_ids={"intern-misp"},
                    event_summary_source_ids={"intern-misp"} if enabled else set())
        page = BeautifulSoup(html, "html.parser")
        return [(b.get("data-mode"), b.i["class"][-1] if b.i else "item") + (("hidden",) if "d-none" in b["class"] else ())
                for b in page.select(".create-summary-btn")]

    def test_an_event_with_a_report_gets_the_dropdown(self):
        self.assertEqual(self.actions({"source_report_count": 1}),
                         [("report", "fa-wand-magic-sparkles"), ("report", "item"), ("both", "item"),
                          ("event", "item"), ("event", "fa-robot", "hidden")])

    def test_an_event_without_a_report_gets_the_event_summary_icon(self):
        self.assertEqual(self.actions({}), [("event", "fa-robot")])

    def test_without_the_module_only_the_llm_summary_is_offered(self):
        self.assertEqual(self.actions({"source_report_count": 1}, enabled=False),
                         [("report", "fa-wand-magic-sparkles")])
        self.assertEqual(self.actions({}, enabled=False), [])

    def test_an_event_summary_already_there_is_not_offered_again(self):
        self.assertEqual(self.actions({"source_report_count": 1, "has_ai_event_summary": True}),
                         [("report", "fa-wand-magic-sparkles")])

    def test_an_event_whose_report_is_summarised_keeps_the_event_summary(self):
        self.assertEqual(self.actions({"source_report_count": 1, "has_ai_summary": True}),
                         [("event", "fa-robot")])


class Route(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def post(self, body, enabled=True):
        started = []
        with mock.patch.object(data_collection, "_sources", return_value=[SCRAPER, SERVER, PARTNER]), \
             mock.patch.object(data_collection.config, "AI_CONNECTOR_ENABLED", enabled, create=True), \
             mock.patch.object(data_collection.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(data_collection.job_store, "update_job"), \
             mock.patch.object(data_collection.misp_session, "current_user_email", return_value="koen@example.org"), \
             mock.patch.object(data_collection.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw) or mock.MagicMock()
            reply = self.client.post(f"/collection/{UUID}/summarise", json=body)
        return reply, (started[0] if started else None)

    def test_the_mode_reaches_the_job(self):
        for mode in ("report", "both", "event"):
            with self.subTest(mode=mode):
                reply, thread = self.post({"source": "intern-misp", "mode": mode})
                self.assertEqual(reply.status_code, 200)
                self.assertEqual(thread["kwargs"], {"mode": mode})

    def test_an_event_summary_is_refused_where_it_is_not_offered(self):
        for body, enabled in (({"source": "scraper", "mode": "event"}, True),
                              ({"source": "intern-misp", "mode": "both"}, False),
                              ({"source": "intern-misp", "mode": "anything"}, True)):
            with self.subTest(body=body, enabled=enabled):
                reply, thread = self.post(body, enabled)
                self.assertEqual(reply.status_code, 400)
                self.assertIsNone(thread)


class Job(unittest.TestCase):
    def run_job(self, mode, cached=None, source=SERVER):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = MISP_JSON
        cached = cached if cached is not None else [{"uuid": UUID, "source_id": source["id"], "source_report_count": 1}]
        updates = []
        with mock.patch.object(data_collection, "_sources", return_value=[source]), \
             mock.patch.object(data_collection.config, "AI_CONNECTOR_ENABLED", True, create=True), \
             mock.patch.object(data_collection.misp_store, "_scraper_misp", return_value=misp), \
             mock.patch.object(data_collection.collection_cache, "get_events_by_uuids", return_value=cached), \
             mock.patch.object(data_collection, "PyMISP", return_value=misp), \
             mock.patch.object(data_collection.job_store, "update_job",
                               side_effect=lambda job_id, **kw: updates.append(kw)), \
             mock.patch.object(data_collection.job_store, "append_log"), \
             mock.patch.object(data_collection.job_store, "heartbeat"), \
             mock.patch.object(data_collection, "_generate_ai_summary", return_value=(True, "ok", 200)) as report, \
             mock.patch.object(data_collection, "_generate_event_summary",
                               return_value=(True, "ok", 200)) as event:
            data_collection._run_summarise_job("job-1", [{"uuid": UUID, "sourceId": source["id"]}],
                                               "koen@example.org", mode=mode)
        result = next(u["result"] for u in updates if "result" in u)
        return result, report, event

    def test_the_module_is_given_misp_s_own_json(self):
        """PyMISP writes a date such as "created" with its time zone, and the
        module adds one again: "Invalid isoformat string: '...+00:00+00:00'"."""
        _result, _report, event = self.run_job("event")
        self.assertIs(event.call_args.args[2], MISP_JSON["Event"])
        misp_event = event.call_args.args[1]
        self.assertEqual((misp_event.uuid, misp_event.info), (UUID, "Overlord RAT campaign"))

    def test_each_mode_runs_its_summaries(self):
        for mode, counts in (("report", (1, 0)), ("both", (1, 1)), ("event", (0, 1))):
            with self.subTest(mode=mode):
                result, report, event = self.run_job(mode)
                self.assertEqual((result["summarised"], result["event_summaries"]), counts)
                self.assertEqual((report.call_count, event.call_count), counts)

    def test_a_summary_the_event_already_has_is_not_made_again(self):
        """The page may be older than the summary, or the click a double one."""
        cached = [{"uuid": UUID, "source_id": "intern-misp", "source_report_count": 1,
                   "has_ai_summary": True, "has_ai_event_summary": False}]
        result, report, event = self.run_job("both", cached)
        self.assertEqual((report.call_count, event.call_count), (0, 1))
        cached[0]["has_ai_event_summary"] = True
        result, _report, event = self.run_job("event", cached)
        event.assert_not_called()
        self.assertEqual(result["skipped"], 1)

    def test_the_same_event_cached_from_another_source_is_not_read_for_this_one(self):
        cached = [{"uuid": UUID, "source_id": "intern-misp", "source_report_count": 1},
                  {"uuid": UUID, "source_id": "scraper", "source_report_count": 1, "has_ai_summary": True}]
        _result, report, _event = self.run_job("report", cached)
        report.assert_called_once()

    def test_the_job_message_names_only_what_was_asked_for(self):
        self.assertEqual(self.run_job("event")[0]["message"], "1 event summary/summaries created")
        self.assertEqual(self.run_job("report")[0]["message"], "1 summary/summaries created")

    def test_the_job_makes_no_event_summary_where_the_page_offers_none(self):
        """The route refuses it, but the job is what writes to MISP."""
        result, report, event = self.run_job("both", source=SCRAPER)
        event.assert_not_called()
        report.assert_called_once()
        self.assertEqual(result["event_summaries"], 0)

    def test_an_event_without_a_report_still_gets_the_event_summary(self):
        cached = [{"uuid": UUID, "source_id": "intern-misp", "source_report_count": 0}]
        result, report, _event_summary = self.run_job("event", cached)
        self.assertEqual(result["event_summaries"], 1)
        report.assert_not_called()


class EventSummary(unittest.TestCase):
    def summarise(self, module=None, published=None, event_json=MISP_JSON["Event"]):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event_report.return_value = {"EventReport": {"id": "3"}}
        misp.publish.return_value = published or {"saved": True, "success": True}
        summarise = mock.Mock(**({"side_effect": module} if module else {"return_value": "## What happened"}))
        with mock.patch.object(data_collection.ai_connector, "summarise_event", summarise), \
             mock.patch.object(data_collection.ai_connector, "settings", return_value=SETTINGS), \
             mock.patch.object(data_collection, "_refresh_cached_event"), \
             mock.patch.object(data_collection.audit, "record") as audit:
            result = data_collection._generate_event_summary(misp, _event("Article"), event_json, "intern-misp")
        return result, misp, summarise, audit

    def test_the_summary_is_a_report_of_its_own_for_our_organisation(self):
        (ok, _message, _status), misp, summarise, audit = self.summarise()
        self.assertTrue(ok)
        report = misp.add_event_report.call_args.args[1]
        self.assertEqual(report.name, "[AI-Event-Summary] Overlord RAT campaign")
        self.assertEqual((report.content, report.distribution), ("## What happened", 0))
        misp.publish.assert_called_once_with(7, alert=False)
        misp.tag.assert_not_called()
        self.assertEqual(audit.call_args.args[0], "summarise-event")

    def test_the_module_reads_misp_s_json_of_the_event(self):
        _result, _misp, summarise, _audit = self.summarise()
        self.assertEqual(summarise.call_args.args[1], MISP_JSON["Event"])

    def test_the_module_is_not_given_deleted_reports_or_zsazsa_s_summaries(self):
        """MISP's JSON keeps a deleted report, text someone took back."""
        reports = [{"name": "Article", "content": "The article"},
                   {"name": "Retracted", "content": "Wrong", "deleted": True},
                   {"name": "[AI-Summary] Overlord", "content": "AI"}]
        _result, _misp, summarise, _audit = self.summarise(event_json={**MISP_JSON["Event"], "EventReport": reports})
        self.assertEqual(summarise.call_args.args[1]["EventReport"], reports[:1])

    def test_a_module_error_adds_nothing(self):
        with self.assertLogs("webapp.routes.data_collection", level="WARNING"):
            (ok, message, _status), misp, _summarise, audit = self.summarise(
                module=ai_connector.ModuleError("The module answered: model not found"))
        self.assertFalse(ok)
        self.assertIn("model not found", message)
        misp.add_event_report.assert_not_called()
        audit.assert_not_called()


class FirstReport(unittest.TestCase):
    def test_the_llm_summary_skips_a_report_that_is_an_ai_summary(self):
        """An event summary added first must not be taken for the article."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event_reports.return_value = [SimpleNamespace(name="[AI-Event-Summary] Overlord", content="AI"),
                                               SimpleNamespace(name="Article", content="The article")]
        event = SimpleNamespace(id=7, uuid=UUID, info="Overlord", tags=[])
        with mock.patch("analyser.llm.summarise_report", return_value="## Summary") as llm, \
             mock.patch.object(data_collection.misp_store, "add_own_report"), \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary"), \
             mock.patch.object(data_collection, "_refresh_cached_event"), \
             mock.patch.object(data_collection.audit, "record"):
            data_collection._generate_ai_summary(misp, event, "intern-misp", kind="misp")
        self.assertEqual(llm.call_args.args[0], "The article")


if __name__ == "__main__":
    unittest.main()
