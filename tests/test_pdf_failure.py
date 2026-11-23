"""A product PDF that cannot be made: the route answers with a fixed message and
keeps what went wrong in the log, never in the page. The error from WeasyPrint
can name server paths and library internals (code scanning alert 260).

The app and the records come from test_product_markdown_fields: MISP is
patched; the database, the collection cache and the log are temporary.

    python -m unittest tests.test_pdf_failure
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from test_product_markdown_fields import UUID, App, der, fia, tap, tlr, vea  # noqa: E402

from webapp import misp_store
from webapp.routes import threat_landscape

FAILURE = "Permission denied: '/srv/zsazsa/fonts/secret.ttf'"


class PdfFailure(App):
    def setUp(self):
        super().setUp()
        for patch in (mock.patch.object(misp_store, "get_fia", return_value=fia()),
                      mock.patch.object(misp_store, "get_vea", return_value=vea()),
                      mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap()),
                      mock.patch.object(misp_store, "get_tlr", return_value=tlr()),
                      mock.patch.object(misp_store, "list_tlrs", return_value=[tlr()]),
                      mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
                      mock.patch.object(misp_store, "list_veas", return_value=[]),
                      mock.patch.object(threat_landscape, "_queued_events", return_value=[]),
                      mock.patch.object(misp_store, "get_der", return_value=der()),
                      mock.patch.object(misp_store, "fetch_source_events", return_value=[])):
            self.enterContext(patch)

    def test_the_error_stays_in_the_log(self):
        for path in (f"/products/flash-intel/{UUID}/pdf", f"/products/vea/{UUID}/pdf",
                     f"/products/threat-actor-profile/{UUID}/pdf", f"/products/threat-landscape/{UUID}/pdf",
                     f"/products/threat-landscape/{UUID}/brief.pdf", f"/products/detection-eng/{UUID}/pdf"):
            with self.subTest(path):
                with mock.patch("weasyprint.HTML", side_effect=OSError(FAILURE)), \
                        self.assertLogs("webapp.routes", "WARNING") as logged:
                    response = self.client.get(path)
                self.assertEqual(response.status_code, 500)
                self.assertEqual(response.get_data(as_text=True), "The PDF could not be made.")
                self.assertIn(FAILURE, "\n".join(logged.output))


if __name__ == "__main__":
    unittest.main()
