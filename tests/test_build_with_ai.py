"""Build with AI on the flash intel and vulnerability advisory wizards.

The advisory wizard drafts from its source event reports, with or without a
Vulnerability Lookup first, from the same place in the source events header as
the flash intel wizard. Both offer it when editing too. /api/draft-vea reads the
reports itself, and /api/build-fia still leaves the AI summaries out when asked
for the raw reports only. The model and MISP are patched out.

    python -m unittest tests.test_build_with_ai
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store, rate_limit
from webapp.routes import api, flash_intel, vea

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _event(reports):
    return {"uuid": UUID, "info": "Exploited flaw", "date": "2026-10-01", "tags": [],
            "attributes": [], "reports": reports}


RAW = {"name": "Vendor advisory", "content": "The raw article."}
SUMMARY = {"name": "[AI-Summary] Vendor advisory", "content": "The AI summary."}


def _stored(routes, **ids):
    """A stored product with every field empty, shaped the way its wizard reads it."""
    data = routes._form_data(MultiDict())
    data.update(uuid=UUID, review_state="draft", tlp="amber", source_event_uuids=[UUID], **ids)
    return SimpleNamespace(**data)


class DraftVea(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()
        rate_limit._WINDOWS.clear()
        self.addCleanup(rate_limit._WINDOWS.clear)

    def draft(self, body, events):
        with mock.patch.object(misp_store, "fetch_source_events", return_value=events), \
             mock.patch("analyser.llm.draft_vea_sections", return_value={"worst_case": "Bad"}) as llm:
            reply = self.client.post("/api/draft-vea", json=body).get_json()
        return reply, llm

    def test_the_source_reports_go_to_the_model(self):
        reply, llm = self.draft({"cve_id": "CVE-2026-1", "source_uuids": [UUID]}, [_event([RAW, SUMMARY])])
        self.assertIsNone(reply["error"])
        cve_id, _product, article = llm.call_args[0]
        self.assertEqual(cve_id, "CVE-2026-1")
        self.assertIn("The raw article.", article)
        self.assertIn("The AI summary.", article)

    def test_reports_without_a_cve_are_enough(self):
        reply, llm = self.draft({"source_uuids": [UUID]}, [_event([SUMMARY])])
        self.assertIsNone(reply["error"])
        llm.assert_called_once()

    def test_neither_a_cve_nor_a_report_asks_for_one(self):
        reply, llm = self.draft({"source_uuids": [UUID]}, [_event([])])
        self.assertTrue(reply["error"])
        llm.assert_not_called()


class BuildFiaReportMode(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()
        rate_limit._WINDOWS.clear()
        self.addCleanup(rate_limit._WINDOWS.clear)

    def content(self, mode):
        with mock.patch.object(misp_store, "fetch_source_events", return_value=[_event([RAW, SUMMARY])]), \
             mock.patch.object(misp_store, "galaxy_sectors", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_geography", return_value=[]), \
             mock.patch("analyser.llm.generate_fia_draft", return_value="## Summary\nText") as llm:
            self.client.post("/api/build-fia", json={"source_uuids": [UUID], "report_mode": mode})
        return llm.call_args[0][0]

    def test_both_sends_the_summary_and_the_article(self):
        content = self.content("both")
        self.assertIn("The raw article.", content)
        self.assertIn("The AI summary.", content)

    def test_raw_only_leaves_the_summary_out(self):
        content = self.content("raw_only")
        self.assertIn("The raw article.", content)
        self.assertNotIn("The AI summary.", content)


class Wizards(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "get_vea", return_value=_stored(vea, vea_id="VEA-00042")),
            mock.patch.object(misp_store, "get_fia", return_value=_stored(flash_intel, fia_id="FIA-00042")),
        ]
        for name in ("list_pirs", "list_selectable_pirs", "galaxy_geography", "galaxy_sectors",
                     "galaxy_threat_actors", "galaxy_mitre_attack_patterns"):
            patches.append(mock.patch.object(misp_store, name, return_value=[]))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, path, events):
        with mock.patch.object(misp_store, "fetch_source_events", return_value=events):
            reply = self.client.get(path)
        self.assertEqual(reply.status_code, 200)
        return BeautifulSoup(reply.data, "html.parser")

    def test_the_advisory_offers_both_ways_to_build(self):
        for path in (f"/products/vea/new?source={UUID}", f"/products/vea/{UUID}/edit"):
            with self.subTest(path=path):
                page = self.page(path, [_event([RAW])])
                self.assertTrue(page.select_one("#vea-source-events-header #build-ai-btn"))
                modes = [a["data-mode"] for a in page.select(".build-ai-option")]
                self.assertEqual(modes, ["lookup", "summary"])
                self.assertIsNone(page.select_one("#btn-draft-vea"))

    def test_an_advisory_without_source_events_keeps_draft_sections(self):
        page = self.page("/products/vea/new", [])
        self.assertTrue(page.select_one("#btn-draft-vea"))
        self.assertIsNone(page.select_one("#build-ai-btn"))

    def test_editing_an_alert_offers_build_with_ai_and_asks_first(self):
        page = self.page(f"/products/flash-intel/{UUID}/edit", [_event([RAW])])
        button = page.select_one("#source-events-header #build-ai-btn")
        self.assertTrue(button)
        self.assertTrue(button.get("data-confirm"))

    def test_a_new_alert_builds_without_asking(self):
        page = self.page(f"/products/flash-intel/new?source={UUID}", [_event([RAW])])
        self.assertFalse(page.select_one("#build-ai-btn").get("data-confirm"))


if __name__ == "__main__":
    unittest.main()
