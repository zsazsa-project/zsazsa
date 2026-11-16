"""What the Collection sources page says of an additional MISP server, and
what a manual source's row holds.

Its events reach the analyser, and so the models of the AI features, only once
"Analyse its events" is switched on. The switch stays off for a server saved
before it existed, and each server's card says what switching it on means. A
manual source's row leaves a field the source does not have empty, so saving
the row does not store the word None. A bar at the top jumps to each section of
the page.

    python -m unittest tests.test_collection_sources_page
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config as _config
from webapp import collection_cache, create_app
from webapp.routes import collection_sources, config_page

OLDER = {"id": "older", "label": "Older", "url": "https://older.example", "api_key": "k", "enabled": True}
ANALYSED = {**OLDER, "id": "analysed", "label": "Analysed", "analyse": True}


def _page(sources=()):
    with tempfile.TemporaryDirectory() as tmp, \
         mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                             LOG_FILE=str(Path(tmp) / "test.log"), MISP_SERVERS=[OLDER, ANALYSED],
                             MISP_SESSION_REDIRECT_TO_LOGIN=False, MISP_SESSION_COOKIE_NAME="MISP-test"), \
         mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
         mock.patch.object(collection_sources.misp_store, "list_collection_sources", return_value=list(sources)), \
         mock.patch.object(collection_cache, "start_worker"):
        return BeautifulSoup(create_app().test_client().get("/config/sources/").get_data(as_text=True), "html.parser")


def _servers_then_new(page, css):
    """The matches in the cards of the saved servers, then those in the form
    for a new one.

    The form is a <template>. soupsieve 4 leaves a template's contents out of a
    select on the page, as a browser does, while the 2.x that Python older than
    3.11.5 installs does not, so the two parts are selected separately."""
    saved = [el for el in page.select(css) if el.find_parent("template") is None]
    return saved + page.find("template", id="misp-server-template").select(css)


class AnalyseSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = _page()

    def test_it_is_on_only_for_a_server_it_was_switched_on_for(self):
        ticked = [box.has_attr("checked") for box in _servers_then_new(self.page, "input.server-analyse-switch")]
        # The two servers, then the form for a new one.
        self.assertEqual(ticked, [False, True, False])

    def test_each_server_says_what_switching_it_on_sends(self):
        notes = [row for row in _servers_then_new(self.page, "div.small.text-muted") if "whatever their TLP" in str(row)]
        self.assertEqual(len(notes), 3)


class ManualSourceRow(unittest.TestCase):
    def test_a_field_the_source_does_not_have_is_empty(self):
        source = SimpleNamespace(uuid="93626a33-08af-4c81-a5a7-0c48303252bc", misp_url="", name="Partner portal",
                                 owner=None, location=None, description=None, enabled=True, source_reliability="")
        form = _page([source]).select_one("form#manual-edit-1")
        self.assertEqual(form.select_one("input[name=name]")["value"], "Partner portal")
        self.assertEqual(form.select_one("input[name=owner]")["value"], "")
        self.assertEqual(form.select_one("input[name=location]")["value"], "")
        self.assertEqual(form.select_one("textarea[name=description]").get_text(), "")

    def test_its_reliability_letter_says_what_it_means(self):
        source = SimpleNamespace(uuid="93626a33-08af-4c81-a5a7-0c48303252bc", misp_url="", name="ISAC", owner="",
                                 location="", description="", enabled=True, source_reliability="B")
        chip = _page([source]).select_one(".manual-source-header .rel-chip")
        self.assertEqual(chip.get_text(), "B")
        self.assertIn("rel-B", chip["class"])
        self.assertEqual(chip["title"], "B: Usually reliable")


class SectionBar(unittest.TestCase):
    def test_it_jumps_to_each_section_in_page_order(self):
        page = _page()
        bar = page.select_one("nav.settings-tabs[data-section-nav]")
        links = [(a.get_text(strip=True), a["href"]) for a in bar.select("a")]
        self.assertEqual([name for name, _ in links], ["MISP scraper", "Manual sources for the scraper", "MISP servers",
                                                       "Manual sources", "IMAP mailboxes"])
        sections = [f"#{s['id']}" for s in page.select(".settings-section[id]")]
        self.assertEqual([href for _, href in links], sections)


if __name__ == "__main__":
    unittest.main()
