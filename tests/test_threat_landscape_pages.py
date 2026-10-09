"""A published threat landscape report offers no Edit (GHSA-rqcp-gv9j-jgv6).

The edit route refuses a published report; these check the pages stop offering
it too, the way the briefing and alert pages already do.

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
        recommendations="", outlook="")


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(threat_landscape, "_queued_events", return_value=[]),
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


if __name__ == "__main__":
    unittest.main()
