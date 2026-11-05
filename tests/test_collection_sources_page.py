"""What the Collection sources page says of an additional MISP server.

Its events reach the analyser, and so the models of the AI features, only once
"Analyse its events" is switched on. The switch stays off for a server saved
before it existed, and each server's card says what switching it on means.

    python -m unittest tests.test_collection_sources_page
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

import config as _config
from webapp import collection_cache, create_app
from webapp.routes import collection_sources, config_page

OLDER = {"id": "older", "label": "Older", "url": "https://older.example", "api_key": "k", "enabled": True}
ANALYSED = {**OLDER, "id": "analysed", "label": "Analysed", "analyse": True}


def _page():
    with tempfile.TemporaryDirectory() as tmp, \
         mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                             LOG_FILE=str(Path(tmp) / "test.log"), MISP_SERVERS=[OLDER, ANALYSED],
                             MISP_SESSION_REDIRECT_TO_LOGIN=False, MISP_SESSION_COOKIE_NAME="MISP-test"), \
         mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
         mock.patch.object(collection_sources.misp_store, "list_collection_sources", return_value=[]), \
         mock.patch.object(collection_cache, "start_worker"):
        return BeautifulSoup(create_app().test_client().get("/config/sources/").get_data(as_text=True), "html.parser")


class AnalyseSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = _page()

    def test_it_is_on_only_for_a_server_it_was_switched_on_for(self):
        ticked = [box.has_attr("checked") for box in self.page.select("input.server-analyse-switch")]
        # The two servers, then the form for a new one.
        self.assertEqual(ticked, [False, True, False])

    def test_each_server_says_what_switching_it_on_sends(self):
        notes = [row for row in self.page.select("div.small.text-muted") if "whatever their TLP" in str(row)]
        self.assertEqual(len(notes), 3)


if __name__ == "__main__":
    unittest.main()
