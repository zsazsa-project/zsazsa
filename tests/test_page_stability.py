"""What keeps a page from moving under the analyst, on every page.

A server message was put in the page above the content, so the content moved
down as it opened and back up when it closed four seconds later. It now floats
over the page. The icon font comes from the CDN after the page is drawn, and an
icon without it has no width, so the buttons widened when it arrived and moved
the tables of every product list; every icon now has the width of the widest.
Measured in a browser, with Chrome's layout shift entries; this pins the CSS
and markup that do it.

    python -m unittest tests.test_page_stability
"""

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_store

APP_CSS = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "css" / "app.css").read_text()


def rule(selector):
    found = re.search(re.escape(selector) + r" \{([^}]*)\}", APP_CSS)
    return found.group(1) if found else ""


class ServerMessages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.multiple(config, create=True, DB_FILE=str(Path(tmp.name) / "test.db"),
                                            LOG_FILE=str(Path(tmp.name) / "test.log"),
                                            MISP_SESSION_REDIRECT_TO_LOGIN=False, MISP_SESSION_COOKIE_NAME=""),
                        mock.patch.object(collection_cache, "start_worker"),
                        mock.patch.object(misp_store, "list_fias", return_value=[])):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def test_a_message_is_shown_in_the_floating_container(self):
        with self.client.session_transaction() as session:
            session["_flashes"] = [("success", "Saved.")]
        page = BeautifulSoup(self.client.get("/products/flash-intel/").data, "html.parser")
        message = page.select_one("#flash-container .alert-flash")
        self.assertIn("Saved.", message.get_text())

    def test_the_container_floats_over_the_page(self):
        self.assertIn("position: fixed", rule("#flash-container"))
        self.assertNotIn("padding", rule("#flash-container"))


class Icons(unittest.TestCase):
    def test_every_icon_has_the_width_of_the_widest(self):
        self.assertIn("width: 1.25em", rule(".fa, .fas, .far, .fab, .fa-solid, .fa-regular, .fa-brands"))

    def test_the_rule_comes_after_font_awesome_so_it_wins(self):
        base = (Path(__file__).resolve().parent.parent / "webapp" / "templates" / "base.html").read_text()
        self.assertLess(base.index("font-awesome"), base.index("css/app.css"))
