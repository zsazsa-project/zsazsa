"""Importing a long report on Data collection (webapp/routes/report_import.py).

The form takes a PDF or its address, the manual source and the provider, and
starts a job; what it refuses starts none. The job downloads the PDF when it
has to, opens the earlier import of the same file instead of making a second,
reads the PDF, and stores the report with its drafts, taking the title, date
and TLP from the PDF where the analyst left them. A failure says why. The
import's page shows the drafts; its details are saved only over the version
the analyst was looking at. The list offers each import's review, PDF and
delete, with no delete while a job writes the import. Once deleted, it opens a page of the stories made
from it, which stay. The record (webapp/misp_store.py) is a zsazsa
record with its PDF and reading attached, deleted again when it could not be
written whole.

MISP is an autospec, the jobs stay in memory, the database and log are temporary.

    python -m unittest tests.test_report_import
"""

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP

import config
from core.report_document import ReportError
from webapp import audit, collection_cache, create_app, job_store, misp_store, report_stories
from webapp.routes import report_import

PDF = b"%PDF-1.7\n" + b"0" * 200
SOURCES = [SimpleNamespace(name="CTI reports", enabled=True, source_reliability="B"),
           SimpleNamespace(name="ISAC Mattermost", enabled=True, source_reliability="")]
BLOCKS = [{"id": i, "page": 1 + i // 3, "text": ("China" if i == 4 else "Text of block %d. " % i * 20),
           "size": 1.6 if i == 4 else 1.0, "kind": "h" if i == 4 else "p"} for i in range(9)]


def _story(sid, title, start, end, path=(), kind="", event="", context=None):
    return {"id": sid, "title": title, "start": start, "end": end, "pages": [BLOCKS[start]["page"], BLOCKS[end - 1]["page"]],
            "chars": sum(len(b["text"]) for b in BLOCKS[start:end]), "path": list(path), "kind": kind,
            "context": context, "context_for": [start, end] if context else None, "context_failed": False, "event": event}


STORIES = [_story("aaaa1111", "Opening pages", 0, 4, kind="context"),
           _story("bbbb2222", "China", 4, 9, ["Section II"], kind="assessment",
                  context={"summary": "The publisher assesses that China kept access to telecom networks.",
                           "period": "2025"})]
DRAFTS = [{k: s[k] for k in ("title", "start", "end", "pages", "chars", "path")} for s in STORIES]
READING = {"pages": 3, "characters": 10100, "title": "2026 State of Security", "created": "2026-02-13", "tlp": "",
           "running": ["CYBER THREAT ANALYSIS"], "blocks": BLOCKS,
           "outline": [{"level": 1, "title": "China", "block": 4}], "outline_skipped": 77,
           "structure": "outline", "drafts": DRAFTS}
MANIFEST = {"read": {"blocks": 9, "outline": 56, "outline_skipped": 77, "running": ["CTA-#-#"], "tlp": "",
                     "created": "2026-02-13", "structure": "outline", "title": ""},
            "stories": STORIES, "ai": {"parts": [[0, 9]], "split": [0], "closed": False}}


GALAXY = {"sectors": ["Telecommunications", "Government"], "geographic_scope": ["China", "Belgium"],
          "threat_actors": ["APT28"], "techniques": ["Exploit Public-Facing Application - T1190"]}


def _report(**fields):
    values = dict(uuid="5f0c1d2e-0000-4000-8000-000000000001", id="41", title="2026 State of Security",
                  provider="Recorded Future", published="2026-02-12", collection_source="CTI reports",
                  source_reliability="B", filename="cta-2026-0212.pdf", sha256="ab" * 32, source_url="",
                  pages=54, characters=123782, structure="outline", import_state="drafted", version=3, tlp="clear",
                  stories=2, manifest="attr-manifest", pdf="attr-pdf", reading="attr-read",
                  misp_url="https://misp.example/events/view/x")
    values.update(fields)
    return SimpleNamespace(**values)


class App(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            # The built-in kinds, whatever this install's Settings has ticked.
            mock.patch.object(config, "REPORT_STORY_KINDS", report_stories.DEFAULT_KINDS, create=True),
            mock.patch.object(misp_store, "list_collection_sources", return_value=SOURCES),
            mock.patch.object(misp_store, "list_report_documents",
                              return_value=[_report(), _report(uuid="u2", provider="ESET", id="40")]),
            mock.patch.object(misp_store, "report_manifest", side_effect=lambda r: json.loads(json.dumps(MANIFEST))),
            mock.patch.object(misp_store, "report_reading", return_value=READING),
            mock.patch.object(misp_store, "find_report_document", return_value=None),
            mock.patch.multiple(misp_store, galaxy_sectors=mock.Mock(return_value=GALAXY["sectors"]),
                                galaxy_geography=mock.Mock(return_value=GALAXY["geographic_scope"]),
                                galaxy_threat_actors=mock.Mock(return_value=GALAXY["threat_actors"]),
                                galaxy_mitre_attack_patterns=mock.Mock(return_value=GALAXY["techniques"])),
        ):
            self.enterContext(patch)
        job_store._memory.clear()
        self.addCleanup(job_store._memory.clear)
        self.client = create_app().test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")


class Form(App):
    def test_without_a_manual_source_it_sends_the_analyst_back(self):
        with mock.patch.object(misp_store, "list_collection_sources", return_value=[]):
            response = self.client.get("/collection/reports/new")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/collection/"))

    def test_the_form_offers_the_sources_providers_and_tlp_as_marked(self):
        page = self.page("/collection/reports/new")
        form = page.select_one("form#report-form")
        self.assertEqual(form["enctype"], "multipart/form-data")
        self.assertEqual([i["value"] for i in page.select('input[name="source"]')], ["CTI reports", "ISAC Mattermost"])
        self.assertEqual(page.select_one('input[name="source"]')["data-reliability"], "B")
        self.assertEqual([b.text for b in page.select(".provider-pick")], ["ESET", "Recorded Future"])
        self.assertEqual(page.select_one('input[name="tlp"][checked]')["value"], "document")
        self.assertEqual(len(page.select('input[name="source_reliability"]')), 6)
        self.assertIsNone(page.select_one("#import-progress"))
        self.assertEqual(len(page.select(".list-group-item")), 2)


class Start(App):
    def post(self, data, upload=PDF, name="cta-2026-0212.pdf"):
        fields = {"csrf_token": "tok", "source": "CTI reports", "provider": "Recorded Future", "tlp": "document", **data}
        if upload is not None:
            fields["document"] = (io.BytesIO(upload), name)
        started = []
        with mock.patch.object(report_import.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            response = self.client.post("/collection/reports/new", data=fields, content_type="multipart/form-data")
        return response, (started[0] if started else None)

    def test_an_upload_starts_the_job_without_a_download(self):
        response, args = self.post({"title": " 2026  State of Security ", "source_reliability": ""})
        self.assertEqual(response.status_code, 302)
        job_id, pdf, details, _user, with_ai = args
        self.assertFalse(with_ai)
        self.assertIn(f"job={job_id}", response.location)
        self.assertEqual(pdf, PDF)
        self.assertEqual(details["title"], "2026 State of Security")
        self.assertEqual(details["filename"], "cta-2026-0212.pdf")
        # "Not rated" on the form is not rated, whatever the source's rating.
        self.assertEqual(details["source_reliability"], "")
        job = job_store.get_job(job_id)
        self.assertEqual([s["id"] for s in job["steps"]], ["read", "draft", "store"])
        self.assertEqual(job["action"], "report-import")

    def test_an_upload_over_the_limit_of_settings_starts_nothing(self):
        with mock.patch.object(config, "REPORT_IMPORT_MAX_MB", 1, create=True):
            page = self.page("/collection/reports/new")
            response, args = self.post({}, upload=PDF + b"0" * (1024 * 1024))
        self.assertIn("up to 1 MB", page.select_one("#report-file-hint").text)
        self.assertIsNone(args)
        self.assertIn("The PDF is larger than 1 MB.", response.get_data(as_text=True))
        self.assertEqual(job_store.list_jobs(), [])

    def test_a_pdf_imported_before_opens_its_import_without_a_job(self):
        with mock.patch.object(misp_store, "find_report_document", return_value="old-uuid") as find:
            response, args = self.post({})
        find.assert_called_once_with(hashlib.sha256(PDF).hexdigest())
        self.assertIsNone(args)
        self.assertTrue(response.location.endswith("/collection/reports/old-uuid?earlier=1"))
        self.assertEqual(job_store.list_jobs(), [])

    def test_the_form_knows_the_imports_to_warn_about(self):
        page = self.page("/collection/reports/new")
        known = json.loads(page.select_one("#report-known").string)
        self.assertEqual([(k["title"], k["provider"], k["sha256"]) for k in known],
                         [("2026 State of Security", "Recorded Future", "ab" * 32), ("2026 State of Security", "ESET", "ab" * 32)])
        self.assertTrue(page.select_one("#report-earlier").has_attr("hidden"))

    def test_an_address_adds_the_download_step(self):
        _, args = self.post({"url": "https://example.org/report.pdf", "source_reliability": "a"}, upload=None)
        job_id, pdf, details, _user, _with_ai = args
        self.assertIsNone(pdf)
        self.assertEqual((details["source_url"], details["source_reliability"]), ("https://example.org/report.pdf", "A"))
        self.assertEqual(job_store.get_job(job_id)["steps"][0]["id"], "fetch")

    def test_with_the_ai_the_job_has_its_two_steps(self):
        _, args = self.post({"with_ai": "1"})
        job_id, *_rest, with_ai = args
        self.assertTrue(with_ai)
        self.assertEqual([s["id"] for s in job_store.get_job(job_id)["steps"]], ["read", "draft", "store", "split", "context"])

    def test_what_is_refused_starts_no_job(self):
        cases = [
            ({"source": "Somewhere else"}, PDF, "Pick the manual source"),
            ({"provider": "  "}, PDF, "Name the provider"),
            ({"tlp": "purple"}, PDF, "Pick a TLP"),
            ({"published": "12 February"}, PDF, "not a date"),
            ({"source_reliability": "G"}, PDF, "from A to F"),
            ({}, b"<html>Download</html>", "not a PDF"),
            ({}, None, "Choose a PDF"),
            ({"url": "ftp://example.org/r.pdf"}, None, "must start with http"),
        ]
        for data, upload, message in cases:
            with self.subTest(message):
                response, args = self.post(data, upload=upload)
                self.assertIsNone(args)
                self.assertEqual(response.status_code, 200)
                self.assertIn(message, response.get_data(as_text=True))
        self.assertEqual(job_store.list_jobs(), [])

    def test_a_second_import_waits_for_the_first(self):
        first = job_store.create_job("report-import")
        job_store.update_job(first["id"], status="running")
        response, args = self.post({})
        self.assertIsNone(args)
        self.assertIn("Another threat report is being imported", response.get_data(as_text=True))

    def test_the_progress_shows_the_jobs_steps(self):
        job = job_store.create_job("report-import", steps=[{"id": "read", "label": "Read the text", "state": "completed"}])
        job_store.update_job(job["id"], notes={"read": "10,100 characters in 9 blocks"})
        page = self.page(f"/collection/reports/new?job={job['id']}")
        panel = page.select_one("#import-progress")
        self.assertEqual(panel.select_one("li")["class"], ["completed"])
        self.assertIn("10,100 characters", panel.select_one("li small").text)
        self.assertTrue(panel["data-record-url"].endswith("/collection/reports/UUID"))

    def test_a_job_of_another_kind_is_not_shown_as_an_import(self):
        job = job_store.create_job("summarise")
        self.assertIsNone(self.page(f"/collection/reports/new?job={job['id']}").select_one("#import-progress"))


class Job(unittest.TestCase):
    DETAILS = {"title": "", "provider": "Recorded Future", "published": "", "collection_source": "CTI reports",
               "source_reliability": "B", "tlp": "document", "filename": "cta.pdf", "source_url": ""}

    def setUp(self):
        self.enterContext(mock.patch.object(job_store, "_command", return_value=None))
        job_store._memory.clear()
        self.addCleanup(job_store._memory.clear)
        self.audit = self.enterContext(mock.patch.object(report_import.audit, "record"))
        self.run_start = self.enterContext(mock.patch.object(report_import, "log_pipeline_run_start", return_value=7))
        self.run_end = self.enterContext(mock.patch.object(report_import, "log_pipeline_run_end"))
        steps = [{"id": s, "label": s, "state": "pending"} for s in ("fetch", "read", "draft", "store")]
        self.job = job_store.create_job("report-import", steps=steps)["id"]

    def run_job(self, pdf=PDF, reading=None, earlier=None, read_error=None, with_ai=False, ai_error=None, **details):
        with mock.patch.object(misp_store, "find_report_document", return_value=earlier) as self.find, \
                mock.patch.object(misp_store, "create_report_document", return_value="new-uuid") as self.create, \
                mock.patch.object(report_import.report_document, "read_pdf",
                                  return_value=reading or READING, side_effect=read_error) as self.read, \
                mock.patch.object(report_import.report_document, "fetch_pdf",
                                  return_value=(PDF, "fetched.pdf")) as self.fetch, \
                mock.patch.object(report_import.report_stories, "run_split", side_effect=ai_error) as self.split, \
                mock.patch.object(report_import.report_stories, "run_context") as self.context:
            report_import._run_import(self.job, pdf, {**self.DETAILS, **details}, "koen@example.org", with_ai)
        return job_store.get_job(self.job)

    def test_an_import_stores_the_report_with_what_the_pdf_says(self):
        job = self.run_job()
        self.assertEqual((job["status"], job["result"]), ("completed", {"uuid": "new-uuid"}))
        data, pdf, reading, manifest = self.create.call_args.args
        self.assertEqual(pdf, PDF)
        self.assertIs(reading, READING)
        self.assertEqual((data["title"], data["published"], data["tlp"]), ("2026 State of Security", "2026-02-13", "amber"))
        self.assertEqual(data["sha256"], hashlib.sha256(PDF).hexdigest())
        self.assertEqual([(s["title"], s["start"], s["end"], s["kind"]) for s in manifest["stories"]],
                         [("Opening pages", 0, 4, ""), ("China", 4, 9, "")])
        self.assertEqual(manifest["read"]["outline"], 1)
        self.split.assert_not_called()
        self.assertEqual(job["notes"]["draft"], "From 1 entry of the outline")
        self.audit.assert_called_once_with("create", "report-import", entity_id="new-uuid",
                                           entity_label="2026 State of Security", user="koen@example.org")
        self.run_start.assert_called_once_with("report-import", triggered_by="data collection")
        self.run_end.assert_called_once_with(7, "completed", {"message": "Imported 2026 State of Security, 2 stories drafted"})
        self.fetch.assert_not_called()

    def test_with_the_ai_the_stories_are_named_and_read_after_the_report_is_saved(self):
        job = self.run_job(with_ai=True)
        self.split.assert_called_once_with(self.job, "new-uuid")
        self.context.assert_called_once_with(self.job, "new-uuid")
        self.assertEqual((job["status"], job["result"]), ("completed", {"uuid": "new-uuid"}))

    def test_an_ai_that_stops_keeps_the_report_and_says_how_to_go_on(self):
        with self.assertLogs("webapp.routes.report_import", "ERROR"):
            job = self.run_job(with_ai=True, ai_error=RuntimeError("model unreachable"))
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["result"], {"uuid": "new-uuid"})
        # Imported, which the audit log says too, and only the AI stopped.
        self.assertTrue(job["error"].startswith("The threat report is imported, but the AI stopped before it was done."))
        self.assertIn("continue with AI", job["error"])
        self.assertEqual(self.run_end.call_args.args[1:], ("failed", {"message": job["error"]}))
        self.assertNotIn("unreachable", job["error"])
        self.context.assert_not_called()

    def test_what_the_analyst_gave_wins_over_the_pdf(self):
        self.run_job(title="State of Security", published="2026-02-12", tlp="green", reading={**READING, "tlp": "clear"})
        data = self.create.call_args.args[0]
        self.assertEqual((data["title"], data["published"], data["tlp"]), ("State of Security", "2026-02-12", "green"))

    def test_the_marking_in_the_pdf_is_the_tlp_as_marked(self):
        self.run_job(reading={**READING, "tlp": "clear"})
        self.assertEqual(self.create.call_args.args[0]["tlp"], "clear")

    def test_an_address_is_downloaded_first(self):
        job = self.run_job(pdf=None, source_url="https://example.org/r.pdf")
        self.fetch.assert_called_once_with("https://example.org/r.pdf")
        self.assertEqual(self.create.call_args.args[0]["filename"], "fetched.pdf")
        self.assertEqual(job["steps"][0]["state"], "completed")

    def test_the_same_file_opens_its_earlier_import(self):
        job = self.run_job(earlier="old-uuid")
        self.assertEqual((job["status"], job["result"]), ("completed", {"uuid": "old-uuid", "earlier": True}))
        self.read.assert_not_called()
        self.create.assert_not_called()

    def test_a_report_that_cannot_be_read_fails_with_why(self):
        job = self.run_job(read_error=ReportError("The PDF is protected with a password."))
        self.assertEqual((job["status"], job["error"]), ("failed", "The PDF is protected with a password."))
        self.assertEqual({s["id"]: s["state"] for s in job["steps"]}["read"], "failed")
        self.create.assert_not_called()

    def test_an_unexpected_failure_is_logged_and_named(self):
        with self.assertLogs("webapp.routes.report_import", "ERROR"):
            job = self.run_job(read_error=RuntimeError("MISP is down"))
        self.assertEqual(job["status"], "failed")
        self.assertIn("The log says why", job["error"])
        self.assertNotIn("MISP is down", job["error"])


class Detail(App):
    def test_the_page_lists_the_stories_with_their_kind_and_summary(self):
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()):
            page = self.page("/collection/reports/5f0c1d2e-0000-4000-8000-000000000001")
        self.assertEqual(page.select_one(".record-hero h1").text, "2026 State of Security")
        self.assertEqual([a.get("class") for a in page.select(".doc-map a")], [["k-context"], ["k-assessment"]])
        rows = page.select(".drafts li")
        self.assertEqual([r.select_one(".story-kind").text for r in rows], ["context", "assessment"])
        self.assertIn("China kept access", rows[1].select_one(".summary").text)
        self.assertEqual(page.select_one('input[name="version"]')["value"], "3")
        self.assertEqual(page.select_one('input[name="tlp"][checked]')["value"], "clear")
        self.assertIn("CTA-#-#", page.select_one(".running-lines").text)
        self.assertIsNone(page.select_one(".alert-info"))
        # The opening story has no context yet; nothing is made yet.
        self.assertIn("1 call", page.select_one('form[action$="/ai"] button').text)
        self.assertNotIn("Its stories on Data collection", page.text)

    def test_what_the_ai_has_left_is_offered_with_its_calls(self):
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["stories"][0]["context"] = None
        manifest["ai"]["split"] = []
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "report_manifest", return_value=manifest):
            page = self.page("/collection/reports/x")
        self.assertIn("2 calls", page.select_one('form[action$="/ai"] button').text)

    def test_made_stories_link_to_their_events_and_the_list(self):
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["stories"][1]["event"] = "e" * 8 + "-0000-4000-8000-000000000002"
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "report_manifest", return_value=manifest):
            page = self.page("/collection/reports/x")
        self.assertIn("/collection/manual/", page.select(".drafts li")[1].select_one("a")["href"])
        link = next(a for a in page.select(".hero-actions a") if "Data collection" in a.text)
        self.assertIn("?tag=zsazsa:report%3D%225f0c1d2e-0000-4000-8000-000000000001%22", link["href"])

    def test_a_threat_report_like_an_earlier_one_is_flagged(self):
        others = [_report(uuid="u2", title="2026  state of SECURITY", sha256="cd" * 32, published="2026-02-10"),
                  _report(uuid="u3", title="Other", filename="cta-2026-0212.pdf", sha256="ef" * 32),
                  _report(uuid="u4", provider="ESET", sha256="aa" * 32), _report()]
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "list_report_documents", return_value=others):
            page = self.page("/collection/reports/5f0c1d2e-0000-4000-8000-000000000001")
        warning = page.select_one(".alert-warning")
        # The same provider with the same title, or the same file name; not another provider's.
        self.assertEqual([a["href"].rsplit("/", 1)[1] for a in warning.select("a")], ["u2", "u3"])

    def test_an_earlier_import_says_so(self):
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()):
            page = self.page("/collection/reports/x?earlier=1")
        self.assertIn("imported before", page.select_one(".alert-info").text)

    def test_any_other_event_is_not_found(self):
        with mock.patch.object(misp_store, "get_report_document", return_value=None):
            self.assertEqual(self.client.get("/collection/reports/1234").status_code, 404)
            self.assertEqual(self.client.get("/collection/reports/1234/pdf").status_code, 404)

    def test_the_pdf_is_downloaded_under_its_name(self):
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "report_pdf", return_value=PDF):
            response = self.client.get("/collection/reports/x/pdf")
        self.assertEqual((response.data, response.mimetype), (PDF, "application/pdf"))
        self.assertIn("cta-2026-0212.pdf", response.headers["Content-Disposition"])

    def save(self, **fields):
        data = {"csrf_token": "tok", "title": "State of Security", "provider": "Recorded Future",
                "published": "2026-02-12", "tlp": "green", "version": "3", **fields}
        with mock.patch.object(report_import.audit, "record"), \
                mock.patch.object(misp_store, "update_report_details") as update:
            response = self.client.post("/collection/reports/x/details", data=data, follow_redirects=False)
        return response, update

    def test_details_are_saved_over_the_version_shown(self):
        response, update = self.save()
        self.assertEqual(response.status_code, 302)
        update.assert_called_once_with("x", {"title": "State of Security", "provider": "Recorded Future",
                                             "published": "2026-02-12", "tlp": "green"}, 3)

    def test_details_that_do_not_hold_are_not_saved(self):
        for fields in ({"title": " "}, {"tlp": "white"}, {"published": "soon"}):
            with self.subTest(fields):
                _, update = self.save(**fields)
                update.assert_not_called()

    def test_details_wait_for_a_job_writing_the_report(self):
        job = job_store.create_job("report-ai")
        job_store.update_job(job["id"], entity="x", status="running")
        _, update = self.save()
        update.assert_not_called()

    def test_a_save_over_a_newer_version_says_so(self):
        with mock.patch.object(misp_store, "update_report_details", side_effect=misp_store.ReportChanged("v4")), \
                mock.patch.object(misp_store, "get_report_document", return_value=_report()):
            response = self.client.post("/collection/reports/x/details", follow_redirects=True,
                                        data={"csrf_token": "tok", "title": "T", "provider": "P", "tlp": "green",
                                              "version": "3"})
        self.assertIn("Someone saved this threat report after you opened it", response.get_data(as_text=True))


class ListAndDelete(App):
    UUID = "5f0c1d2e-0000-4000-8000-000000000001"

    def test_the_imported_threat_reports_are_listed(self):
        page = self.page("/collection/reports/")
        self.assertEqual([a.text for a in page.select("tbody td:first-child a")], ["2026 State of Security"] * 2)
        self.assertIn("threat landscape reports zsazsa writes", page.select_one(".record-hero").text)

    def row_actions(self, page, uuid):
        row = page.find("a", href=f"/collection/reports/{uuid}").find_parent("tr")
        return row.select("td")[-1]

    def test_each_threat_report_has_review_pdf_and_delete(self):
        actions = self.row_actions(self.page("/collection/reports/"), self.UUID)
        self.assertEqual(actions.find("a", title="Review the stories")["href"], f"/collection/reports/{self.UUID}/review")
        self.assertEqual(actions.find("a", title="Download PDF")["href"], f"/collection/reports/{self.UUID}/pdf")
        form = actions.select_one("form")
        self.assertEqual((form["method"], form["action"]), ("post", f"/collection/reports/{self.UUID}/delete"))
        self.assertIn("2026 State of Security", form["data-submit-confirm"])
        self.assertIsNone(actions.find("button", disabled=True))

    def test_a_threat_report_with_every_story_made_is_marked(self):
        reports = [_report(import_state="created"), _report(uuid="u2", import_state="reviewed")]
        with mock.patch.object(misp_store, "list_report_documents", return_value=reports):
            page = self.page("/collection/reports/")
        made, reviewed = (page.find("a", href=f"/collection/reports/{u}").find_parent("tr") for u in (self.UUID, "u2"))
        self.assertEqual(made.select_one(".story-all-made")["title"], "Every story is made into an event")
        self.assertIsNone(reviewed.select_one(".story-all-made"))

    def test_a_threat_report_without_its_pdf_offers_no_download(self):
        with mock.patch.object(misp_store, "list_report_documents", return_value=[_report(pdf=None)]):
            actions = self.row_actions(self.page("/collection/reports/"), self.UUID)
        self.assertIsNone(actions.find("a", title="Download PDF"))

    def test_a_threat_report_a_job_works_on_cannot_be_deleted_from_the_list(self):
        job = job_store.create_job("report-create")
        job_store.update_job(job["id"], entity=self.UUID, status="running")
        page = self.page("/collection/reports/")
        busy, other = self.row_actions(page, self.UUID), self.row_actions(page, "u2")
        self.assertIsNone(busy.select_one("form"))
        self.assertTrue(busy.find("button", class_="btn-outline-danger").has_attr("disabled"))
        self.assertEqual(other.select_one("form")["action"], "/collection/reports/u2/delete")

    def test_a_threat_report_is_deleted_and_its_stories_stay(self):
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["stories"][1]["event"] = "e-1"
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "report_manifest", return_value=manifest), \
                mock.patch.object(misp_store, "delete_report_document") as delete, \
                mock.patch.object(report_import.audit, "record") as audit:
            response = self.client.post(f"/collection/reports/{self.UUID.upper()}/delete", data={"csrf_token": "tok"},
                                        follow_redirects=True)
        # By the record's own UUID, which the page of a deleted threat report looks it up by.
        delete.assert_called_once_with(self.UUID)
        audit.assert_called_once_with("delete", "report-import", entity_id="5f0c1d2e-0000-4000-8000-000000000001",
                                      entity_label="2026 State of Security")
        self.assertIn("The 1 story made from it stay on Data collection", response.get_data(as_text=True))

    def deleted_page(self, path, stories=(), status=410):
        with mock.patch.object(misp_store, "get_report_document", return_value=None), \
                mock.patch.object(collection_cache, "cached_source_ids", return_value=["manual-cti-reports"]), \
                mock.patch.object(collection_cache, "get_events", return_value=list(stories)) as cached:
            response = self.client.get(path)
        self.assertEqual(response.status_code, status, path)
        return BeautifulSoup(response.data, "html.parser"), cached

    def story(self, uuid, event_id, kind="assessment"):
        tags = [misp_store.report_tag(self.UUID), f'zsazsa:report-kind="{kind}"', 'zsazsa:provider="Recorded Future"']
        return {"uuid": uuid, "id": event_id, "info": f"Story {event_id}", "date": "2026-02-12", "tags": tags}

    def test_a_deleted_threat_report_opens_a_page_of_the_stories_left(self):
        # A real entry in the test's own audit log, as the delete writes it.
        audit.record("delete", "report-import", entity_id=self.UUID, entity_label="2026 State of Security",
                     user="analyst@example.org")
        page, cached = self.deleted_page(f"/collection/reports/{self.UUID.upper()}",
                                         [self.story("s9", "9", "outlook"), self.story("s7", "7")])
        cached.assert_called_once_with(["manual-cti-reports"], [misp_store.report_tag(self.UUID)], limit=500)
        self.assertEqual(page.select_one(".record-hero h1").text, "2026 State of Security")
        self.assertEqual(page.select_one(".eyebrow").text, "Recorded Future")
        self.assertRegex(page.select_one(".report-facts").text, r"Deleted by analyst@example.org on 20\d\d-\d\d-\d\d \d\d:\d\d UTC")
        rows = page.select(".drafts li")
        self.assertEqual([r.select_one("a").text for r in rows], ["Story 7", "Story 9"])
        self.assertEqual(rows[0].select_one("a")["href"], "/collection/manual/s7")
        self.assertEqual([r.select_one(".story-kind").text for r in rows], ["assessment", "outlook"])
        link = page.select_one(".hero-actions a")
        self.assertIn("?tag=zsazsa:report%3D%225f0c1d2e-0000-4000-8000-000000000001%22", link["href"])

    def test_a_threat_report_deleted_in_misp_still_shows_its_stories(self):
        page, _ = self.deleted_page(f"/collection/reports/{self.UUID}", [self.story("s7", "7")])
        self.assertEqual(page.select_one(".record-hero h1").text, "A deleted threat report")
        self.assertIn("Deleted outside zsazsa, in MISP", page.select_one(".report-facts").text)

    def test_a_deleted_threat_report_without_stories_says_so(self):
        audit.record("delete", "report-import", entity_id=self.UUID, entity_label="T", user="analyst@example.org")
        page, _ = self.deleted_page(f"/collection/reports/{self.UUID}")
        self.assertIn("No story made from it is left", " ".join(page.select_one(".lead-text").text.split()))
        self.assertIsNone(page.select_one(".drafts"))
        self.assertIsNone(page.select_one(".record-kpis"))

    def test_a_threat_report_that_never_was_is_not_found(self):
        _, cached = self.deleted_page(f"/collection/reports/{self.UUID}", status=404)
        cached.assert_called_once()
        _, cached = self.deleted_page("/collection/reports/42", [self.story("s7", "7")], status=404)
        cached.assert_not_called()

    def test_a_threat_report_a_job_works_on_is_not_deleted(self):
        job = job_store.create_job("report-create")
        job_store.update_job(job["id"], entity=self.UUID, status="running")
        with mock.patch.object(misp_store, "get_report_document", return_value=_report()), \
                mock.patch.object(misp_store, "delete_report_document") as delete:
            self.client.post(f"/collection/reports/{self.UUID}/delete", data={"csrf_token": "tok"})
        delete.assert_not_called()

    def test_the_landscape_page_names_both_kinds_of_report(self):
        with mock.patch.object(misp_store, "list_tlrs", return_value=[]), \
                mock.patch.object(collection_cache, "get_events", return_value=[{"uuid": "e", "info": "E", "date": "",
                                                                                "tags": [], "source_id": "scraper"}]), \
                mock.patch("webapp.misp_session.current_user_can_publish", return_value=True):
            page = self.page("/products/threat-landscape/")
        self.assertIn("threat landscape reports", page.select_one(".record-kpis").text)
        self.assertEqual(page.select_one('a.btn-hero-ghost[href$="/collection/reports/"]').text.strip(),
                         "Imported threat reports")
        self.assertEqual(page.select_one('#tlr-build-target option[value=""]').text, "A new threat landscape report")


class Record(unittest.TestCase):
    DATA = {"title": "2026 State of Security", "provider": 'Recorded "Future"', "published": "2026-02-12",
            "collection_source": "CTI reports", "source_reliability": "B", "filename": "cta.pdf", "sha256": "ab" * 32,
            "source_url": "", "pages": 54, "characters": 123782, "structure": "outline", "import_state": "drafted",
            "stories": 2, "manifest": "attr-manifest", "version": 1, "tlp": "clear"}

    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.enterContext(mock.patch.object(misp_store, "_misp", return_value=self.misp))
        created = MISPEvent()
        created.uuid, created.id = "5f0c1d2e-0000-4000-8000-000000000001", "41"
        self.misp.add_event.return_value = created
        self.added = []

        def add_attribute(_uuid, attr, pythonify=True):
            attr.uuid = f"attr-{len(self.added) + 1}"
            self.added.append(attr)
            return attr

        self.misp.add_attribute.side_effect = add_attribute
        self.misp.tag.return_value = {"saved": True}

    def stored(self, **data):
        """The event as MISP would give it back after create_report_document."""
        event = MISPEvent()
        event.uuid, event.id, event.date = "5f0c1d2e-0000-4000-8000-000000000001", "41", "2026-02-12"
        event.add_tag("tlp:clear")
        event.add_tag(misp_store.TAG_REPORT_DOCUMENT)
        event.add_tag(misp_store.provider_tag("Recorded Future"))
        event.add_object(misp_store._report_document_obj({**self.DATA, **data}))
        for comment in (misp_store.REPORT_PDF_COMMENT, misp_store.REPORT_READING_COMMENT):
            event.add_attribute("attachment", "f", comment=comment)
        return event

    def test_the_report_is_stored_with_its_pdf_reading_and_manifest(self):
        data = {k: v for k, v in self.DATA.items() if k not in ("manifest", "stories")}
        misp_store.create_report_document(data, PDF, READING, MANIFEST)
        event = self.misp.add_event.call_args.args[0]
        self.assertEqual(event.info, "[zsazsa:report] 2026 State of Security")
        self.assertEqual([t.name for t in event.tags], ["tlp:clear"])
        tags = [c.args[1] for c in self.misp.tag.call_args_list]
        self.assertEqual(tags, [misp_store.TAG_REPORT_DOCUMENT, "zsazsa:provider=\"Recorded 'Future'\""])
        self.assertTrue(all(c.kwargs.get("local") for c in self.misp.tag.call_args_list))
        self.assertEqual([(a.value, a.comment) for a in self.added],
                         [("cta.pdf", misp_store.REPORT_PDF_COMMENT), ("reading.json", misp_store.REPORT_READING_COMMENT),
                          ("manifest-1.json", misp_store.REPORT_MANIFEST_COMMENT)])
        self.assertFalse(any(a.to_ids for a in self.added))
        obj = self.misp.add_object.call_args.args[1]
        self.assertEqual((misp_store._obj_attr(obj, "manifest"), misp_store._obj_attr(obj, "stories")), ("attr-3", "2"))
        self.misp.delete_event.assert_not_called()

    def test_a_report_that_cannot_be_stored_whole_is_deleted_again(self):
        self.misp.add_attribute.side_effect = lambda *a, **k: {"errors": "too large"}
        with self.assertRaises(RuntimeError):
            misp_store.create_report_document(self.DATA, PDF, READING, MANIFEST)
        self.misp.delete_event.assert_called_once_with("5f0c1d2e-0000-4000-8000-000000000001")

    def test_a_stored_report_reads_back(self):
        self.misp.get_event.return_value = self.stored()
        report = misp_store.get_report_document("5f0c1d2e-0000-4000-8000-000000000001")
        self.assertEqual((report.title, report.provider, report.tlp), ("2026 State of Security", 'Recorded "Future"', "clear"))
        self.assertEqual((report.pages, report.version, report.manifest, report.stories), (54, 1, "attr-manifest", 2))
        self.assertTrue(report.pdf and report.reading)

    def test_an_event_that_is_no_report_is_none(self):
        self.misp.get_event.return_value = MISPEvent()
        self.assertIsNone(misp_store.get_report_document("5f0c1d2e-0000-4000-8000-000000000001"))
        self.assertIsNone(misp_store.get_report_document("../events"))

    def test_the_same_file_is_found_by_its_sha256(self):
        self.misp.search.return_value = [self.stored()]
        self.assertEqual(misp_store.find_report_document("ab" * 32), "5f0c1d2e-0000-4000-8000-000000000001")
        self.assertIsNone(misp_store.find_report_document("cd" * 32))
        self.assertEqual(self.misp.search.call_args.kwargs["tags"], [misp_store.TAG_REPORT_DOCUMENT])

    def test_a_search_that_fails_stops_the_import(self):
        self.misp.search.return_value = {"errors": "timeout"}
        with self.assertRaises(RuntimeError):
            misp_store.find_report_document("ab" * 32)

    def test_details_are_not_written_over_a_newer_version(self):
        self.misp.get_event.return_value = self.stored(version=4)
        with self.assertRaises(misp_store.ReportChanged):
            misp_store.update_report_details("5f0c1d2e-0000-4000-8000-000000000001",
                                             {"title": "T", "provider": "P", "published": "", "tlp": "green"}, 3)
        self.misp.update_object.assert_not_called()
        self.misp.update_event.assert_not_called()

    def test_details_change_the_object_title_tlp_and_provider_tag(self):
        self.misp.get_event.return_value = self.stored(version=3)
        self.misp.update_object.return_value = {}
        self.misp.update_event.return_value = {}
        self.misp.untag.return_value = {}
        misp_store.update_report_details("5f0c1d2e-0000-4000-8000-000000000001",
                                         {"title": "State of Security", "provider": "Insikt Group",
                                          "published": "2026-02-12", "tlp": "green"}, 3)
        obj = self.misp.update_object.call_args.args[0]
        self.assertEqual(misp_store._obj_attr(obj, "version"), "4")
        self.assertEqual(misp_store._obj_attr(obj, "title"), "State of Security")
        self.assertEqual(misp_store._obj_attr(obj, "manifest"), "attr-manifest")
        self.assertEqual(self.misp.update_event.call_args.args[0]["Event"]["info"], "[zsazsa:report] State of Security")
        untagged = [c.args[1] for c in self.misp.untag.call_args_list]
        self.assertEqual(untagged, ["tlp:clear", misp_store.provider_tag("Recorded Future")])
        tagged = [c.args[1] for c in self.misp.tag.call_args_list]
        self.assertEqual(tagged, ["tlp:green", 'zsazsa:provider="Insikt Group"'])

    def test_providers_are_listed_once_each(self):
        reports = [SimpleNamespace(provider="ESET"), SimpleNamespace(provider="eset"), SimpleNamespace(provider=""),
                   SimpleNamespace(provider="CERT-EU")]
        self.assertEqual(misp_store.report_providers(reports), ["CERT-EU", "ESET"])


class Review(App):
    UUID = "5f0c1d2e-0000-4000-8000-000000000001"

    def setUp(self):
        super().setUp()
        self.enterContext(mock.patch.object(misp_store, "get_report_document", return_value=_report()))
        self.audit = self.enterContext(mock.patch.object(report_import.audit, "record"))

    def sent(self, **changes):
        stories = [{k: s[k] for k in ("id", "start", "title", "kind", "context", "context_for")} for s in STORIES]
        for key, value in changes.items():
            index, field = key.split("__")
            stories[int(index)][field] = value
        return stories

    def post(self, body, path="review"):
        return self.client.post(f"/collection/reports/{self.UUID}/{path}", json=body, headers={"X-CSRF-Token": "tok"})

    def test_the_page_holds_the_report_its_stories_and_the_galaxies(self):
        page = self.page(f"/collection/reports/{self.UUID}/review")
        data = json.loads(page.select_one("#review-data").string)
        self.assertEqual((data["version"], len(data["blocks"]), len(data["stories"])), (3, 9, 2))
        self.assertEqual(set(data["blocks"][0]), {"id", "page", "text", "kind"})
        self.assertEqual(data["lists"]["threat_actors"], ["APT28"])
        self.assertEqual(set(data["kind_notes"]), set(data["kinds"]))
        self.assertNotIn("is-locked", page.select_one("#splitter")["class"])

    def test_the_threat_types_are_those_of_settings(self):
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", ["Insider threat"], create=True):
            page = self.page(f"/collection/reports/{self.UUID}/review")
            self.assertEqual(json.loads(page.select_one("#review-data").string)["threat_types"], ["Insider threat"])
            self.assertEqual(report_stories._threat_type("insider THREAT"), "Insider threat")
            self.assertEqual(report_stories._threat_type("Ransomware"), "")
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", [], create=True):
            self.assertEqual(misp_store.tlr_threat_types(), misp_store.DEFAULT_THREAT_TYPES)

    def test_the_page_is_read_only_while_a_job_writes_the_report(self):
        job = job_store.create_job("report-ai")
        job_store.update_job(job["id"], entity=self.UUID, status="running", message="Reading the context of story 3 of 9")
        page = self.page(f"/collection/reports/{self.UUID}/review")
        self.assertIn("is-locked", page.select_one("#splitter")["class"])
        self.assertIn("story 3 of 9", page.select_one(".alert-primary").text)

    def test_a_review_is_saved_over_the_version_shown_and_closes_the_ai_split(self):
        with mock.patch.object(misp_store, "save_report_manifest", return_value=4) as save:
            reply = self.post({"version": 3, "stories": self.sent(**{"1__start": 5, "1__title": "China's access"})})
        self.assertEqual((reply.status_code, reply.get_json()["version"]), (200, 4))
        uuid, manifest, version = save.call_args.args
        self.assertEqual((uuid, version, save.call_args.kwargs), (self.UUID, 3, {"import_state": "reviewed"}))
        self.assertTrue(manifest["ai"]["closed"])
        self.assertEqual([(s["title"], s["start"], s["end"]) for s in manifest["stories"]],
                         [("Opening pages", 0, 5), ("China's access", 5, 9)])
        self.assertEqual(reply.get_json()["stories"][1]["pages"], [2, 3])

    def test_the_paragraphs_left_out_are_saved_with_the_review(self):
        with mock.patch.object(misp_store, "save_report_manifest", return_value=4) as save:
            reply = self.post({"version": 3, "skipped": [6, 2], "stories": self.sent()})
        manifest = save.call_args.args[1]
        self.assertEqual((manifest["skipped"], reply.get_json()["skipped"]), ([2, 6], [2, 6]))
        self.assertEqual(manifest["stories"][1]["chars"], sum(len(b["text"]) for b in BLOCKS[4:9] if b["id"] != 6))
        with mock.patch.object(misp_store, "save_report_manifest") as save:
            self.assertEqual(self.post({"version": 3, "skipped": [42], "stories": self.sent()}).status_code, 400)
        save.assert_not_called()

    def test_a_review_that_does_not_hold_is_not_saved(self):
        cases = [(self.sent(**{"0__start": 2}), "beginning of the report"),
                 (self.sent(**{"1__start": 0}), "does not start after"),
                 (self.sent(**{"1__title": " "}), "has no title"),
                 (self.sent(**{"1__id": "aaaa1111"}), "id of its own"),
                 ([], "no stories")]
        for stories, message in cases:
            with self.subTest(message), mock.patch.object(misp_store, "save_report_manifest") as save:
                reply = self.post({"version": 3, "stories": stories})
                self.assertEqual(reply.status_code, 400)
                self.assertIn(message, reply.get_json()["error"])
                save.assert_not_called()
        self.assertEqual(self.post({"stories": []}).status_code, 400)

    def test_a_review_over_a_newer_version_says_so(self):
        with mock.patch.object(misp_store, "save_report_manifest", side_effect=misp_store.ReportChanged("v4")):
            reply = self.post({"version": 3, "stories": self.sent()})
        self.assertEqual(reply.status_code, 409)
        self.assertIn("Reload the page", reply.get_json()["error"])

    def test_no_review_is_saved_while_a_job_writes_the_report(self):
        job = job_store.create_job("report-create")
        job_store.update_job(job["id"], entity=self.UUID, status="running")
        with mock.patch.object(misp_store, "save_report_manifest") as save:
            reply = self.post({"version": 3, "stories": self.sent()})
        self.assertEqual(reply.status_code, 409)
        save.assert_not_called()

    def test_one_story_is_read_again_on_a_job(self):
        with mock.patch.object(report_import.threading, "Thread") as thread:
            reply = self.post({"id": "bbbb2222", "start": 4, "end": 9, "title": "China", "kind": "", "path": []},
                              path="analyse")
        self.assertTrue(reply.get_json()["ok"])
        job = job_store.get_job(reply.get_json()["job"])
        self.assertEqual((job["action"], job["entity"]), ("report-story-context", self.UUID))
        self.assertEqual(thread.call_args.kwargs["args"][2]["end"], 9)
        self.assertEqual(thread.call_args.kwargs["args"][3], set())
        reply = self.post({"id": "bbbb2222", "start": 4, "end": 99, "title": "China"}, path="analyse")
        self.assertEqual(reply.status_code, 400)

    def test_a_report_deleted_meanwhile_is_not_found_as_the_save_says(self):
        story = {"id": "bbbb2222", "start": 4, "end": 9, "title": "China"}
        with mock.patch.object(misp_store, "get_report_document", return_value=None):
            for path, body in (("analyse", story), ("review", {"version": 3, "stories": self.sent()})):
                with self.subTest(path):
                    reply = self.post(body, path=path)
                    self.assertEqual(reply.status_code, 404)
                    self.assertIn("no longer exists", reply.get_json()["error"])

    def test_asking_the_ai_for_one_story_is_rate_limited(self):
        from webapp import rate_limit
        story = {"id": "bbbb2222", "start": 4, "end": 9, "title": "China"}
        with mock.patch.dict(rate_limit._WINDOWS, clear=True), mock.patch.object(report_import.threading, "Thread"):
            codes = [self.post(story, path="analyse").status_code for _ in range(21)]
        self.assertEqual((codes[:20], codes[20]), ([200] * 20, 429))

    def create(self, version="3", manifest=None):
        with mock.patch.object(report_import.threading, "Thread") as thread, \
                mock.patch.object(misp_store, "report_manifest", return_value=manifest or json.loads(json.dumps(MANIFEST))):
            response = self.client.post(f"/collection/reports/{self.UUID}/create",
                                        data={"csrf_token": "tok", "version": version})
        return response, thread

    def test_the_stories_are_made_on_a_job(self):
        response, thread = self.create()
        self.assertTrue(response.location.endswith(f"/collection/reports/{self.UUID}"))
        job_id, uuid, user = thread.call_args.kwargs["args"]
        self.assertEqual((job_store.get_job(job_id)["action"], uuid), ("report-create", self.UUID))

    def test_stories_are_not_made_from_a_page_older_than_the_save(self):
        response, thread = self.create(version="2")
        thread.assert_not_called()
        self.assertTrue(response.location.endswith("/review"))

    def test_every_story_needs_a_kind_before_it_is_made(self):
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["stories"][1]["kind"] = ""
        _response, thread = self.create(manifest=manifest)
        thread.assert_not_called()

    def test_the_ai_goes_on_only_with_something_left(self):
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["stories"][0]["context"] = {}
        with mock.patch.object(misp_store, "report_manifest", return_value=manifest), \
                mock.patch.object(report_import.threading, "Thread") as thread:
            self.client.post(f"/collection/reports/{self.UUID}/ai", data={"csrf_token": "tok"})
        thread.assert_not_called()
        with mock.patch.object(report_import.threading, "Thread") as thread:
            self.client.post(f"/collection/reports/{self.UUID}/ai", data={"csrf_token": "tok"})
        job_id, uuid = thread.call_args.kwargs["args"]
        self.assertEqual([s["id"] for s in job_store.get_job(job_id)["steps"]], ["split", "context"])


class Queue(App):
    """The threat landscape queue lists a report's stories under it."""

    def queued(self, uuid, kind="", date="2026-02-12"):
        tags = [misp_store.report_tag(_report().uuid), f'zsazsa:report-kind="{kind}"'] if kind else []
        return {"uuid": uuid, "info": f"Event {uuid}", "date": date, "tags": tags, "source_id": "manual-cti-reports"}

    def test_the_stories_of_a_report_are_grouped_and_outlook_is_not_ticked_by_select_all(self):
        events = [self.queued("s1", "assessment"), self.queued("plain", date="2026-11-01"), self.queued("s2", "outlook")]
        with mock.patch.object(misp_store, "list_tlrs", return_value=[]), \
                mock.patch.object(collection_cache, "get_events", return_value=events), \
                mock.patch("webapp.misp_session.current_user_can_publish", return_value=True):
            page = self.page("/products/threat-landscape/")
        rows = page.select("#tlr-build-form tbody tr")
        self.assertEqual([r.get("class") for r in rows],
                         [["queue-report"], ["queue-story"], ["queue-story", "queue-story-last"], ["queue-others"], None])
        self.assertIn("2026 State of Security", rows[0].text)
        self.assertIn("2 stories · one source", rows[0].text)
        self.assertEqual([r.select_one(".tlr-pick").has_attr("data-unticked") for r in rows[1:3] + rows[4:]],
                         [False, True, False])
        self.assertEqual(rows[3].text.strip(), "Other queued events")
        self.assertEqual(rows[2].select_one(".story-kind").text, "outlook")


if __name__ == "__main__":
    unittest.main()
