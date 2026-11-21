"""A threat landscape report page offers only what its routes will do.

A published report offers no Edit (GHSA-rqcp-gv9j-jgv6), the way the briefing
and alert pages already do, and only a publisher is offered Resend.

    python -m unittest tests.test_threat_landscape_pages
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
EDIT = f"/products/threat-landscape/{UUID}/edit"


def _report(review_state):
    return SimpleNamespace(
        uuid=UUID, tlr_id="TLR-00001", title="Q3", reporting_period="2026 Q3", tlp="amber",
        review_state=review_state, author="", creator="", approved_by="", created_at=None,
        audience="", misp_url="", top_threats=[], trending_actors=[], key_incidents=[],
        recommendations="", outlook="", purpose="", audience_level="", period_start="", period_end="", methodology="",
        scope_sectors=[], scope_geography=[], linked_pir_uuids=[], threat_sections=[], review_log=[], corrections=[], entries=[],
        executive_summary="", key_judgements=[], ai_drafted=[], threat_ranking=[], hidden_figures=[])


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(threat_landscape, "_queued_events", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=[]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=[]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def edit_links(self, path, report):
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[report]):
            html = self.client.get(path).data
        return BeautifulSoup(html, "html.parser").select(f'a[href="{EDIT}"]')

    def test_a_published_report_offers_no_edit(self):
        for path in (f"/products/threat-landscape/{UUID}", "/products/threat-landscape/"):
            with self.subTest(path=path):
                self.assertEqual(self.edit_links(path, _report("published")), [])

    def test_a_draft_still_offers_edit(self):
        for path in (f"/products/threat-landscape/{UUID}", "/products/threat-landscape/"):
            with self.subTest(path=path):
                self.assertTrue(self.edit_links(path, _report("draft")))

    def test_resend_is_offered_only_to_publishers(self):
        """The route refuses anyone else, so the page should not invite it."""
        for can_publish in (True, False):
            for path in (f"/products/threat-landscape/{UUID}", "/products/threat-landscape/"):
                with self.subTest(can_publish=can_publish, path=path), \
                     mock.patch.object(misp_store, "get_tlr", return_value=_report("published")), \
                     mock.patch.object(misp_store, "list_tlrs", return_value=[_report("published")]), \
                     mock.patch.object(threat_landscape.misp_session, "current_user_can_publish",
                                       return_value=can_publish):
                    page = BeautifulSoup(self.client.get(path).data, "html.parser")
                    resend = page.select_one(f'form[action="/products/threat-landscape/{UUID}/resend"]')
                    self.assertEqual(resend is not None, can_publish)

    def detail(self, report):
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[report]):
            return BeautifulSoup(self.client.get(f"/products/threat-landscape/{UUID}").data, "html.parser")

    def test_a_report_without_events_offers_triage_greyed_out_and_says_why(self):
        page = self.detail(_report("draft"))
        self.assertIsNone(page.select_one(f'a[href="/products/threat-landscape/{UUID}/entries"]'))
        blocked = page.select_one(".btn-blocked")
        self.assertIn("Triage and statistics", blocked.button.get_text())
        self.assertTrue(blocked.button.has_attr("disabled"))
        self.assertIsNotNone(blocked.select_one(".fa-xmark"))
        self.assertIn("nothing to triage yet", page.select_one(".hero-note").get_text())

    def test_a_report_with_events_links_to_its_triage(self):
        report = _report("draft")
        report.entries = [SimpleNamespace(excluded=False)]
        with mock.patch.object(threat_landscape, "_threat_ranking", return_value=[]), \
             mock.patch.object(threat_landscape, "_charts", return_value={"threat_types": []}), \
             mock.patch.object(threat_landscape, "_own_incidents", return_value=[]), \
             mock.patch.object(threat_landscape, "_detection_coverage", return_value=None), \
             mock.patch.object(threat_landscape, "_vulnerabilities", return_value=[]), \
             mock.patch.object(threat_landscape, "_shown_figures", return_value={}), \
             mock.patch.object(misp_store, "tlr_annex", return_value=[]):
            page = self.detail(report)
        self.assertIsNotNone(page.select_one(f'a[href="/products/threat-landscape/{UUID}/entries"]'))
        self.assertIsNone(page.select_one(".btn-blocked"))
        self.assertIsNone(page.select_one(".hero-note"))


if __name__ == "__main__":
    unittest.main()
