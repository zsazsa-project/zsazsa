"""The toolbar above the data collection list, and the parts of its table that
filter.

The source buttons changed size while the page loaded: their layout was styled
after the event table, so they were drawn without it until the table was in,
and every refresh or reject reloads the page. They are now all of one size and
styled before the table. This pins that, where the toolbar's buttons sit, that
the script's messages float over the page rather than move it, that what the
script fills in after the load keeps its size, that the actions column has no
gear that looks clickable, and that an event's organisation filters the list. What the page's script does with a click is
checked in a browser, not here.

    python -m unittest tests.test_collection_toolbar
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, job_store, misp_store
from webapp.routes import data_collection

SOURCES = [{"id": "scraper", "kind": "scraper", "label": "MISP scraper", "url": "https://scraper.example",
            "imap_sources": ["Gmail - test/ETDA CTI Robot", "Gmail - test/IT-ISAC Open Source News"]},
           {"id": "manual-demo", "kind": "manual", "label": "A source with a label far too long to fit", "url": ""}]


class TheToolbar(unittest.TestCase):
    def setUp(self):
        def no_network(*args, **kwargs):
            raise requests.ConnectionError("tests run offline")

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rows = [{"uuid": "a" * 36, "source_id": "scraper", "info": "Collected event", "tags": [],
                 "orgc": "CIRCL", "date": "2026-10-01"},
                {"uuid": "b" * 36, "source_id": "scraper", "info": "Event without an org", "tags": [],
                 "orgc": "", "date": "2026-10-02"}]
        for patcher in (
            mock.patch("requests.adapters.HTTPAdapter.send", no_network),
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(collection_cache, "get_events", return_value=rows),
            mock.patch.object(collection_cache, "get_source_status", return_value={}),
            mock.patch.object(collection_cache, "interval_s", return_value=300),
            mock.patch.object(collection_cache, "get_flagged_uuids", return_value=set()),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_store, "list_briefings", return_value=[]),
            mock.patch.object(data_collection, "_sources", return_value=SOURCES),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.html = create_app().test_client().get("/collection/").get_data(as_text=True)
        self.page = BeautifulSoup(self.html, "html.parser")

    def test_the_source_buttons_are_styled_before_the_table(self):
        after_the_table = self.html[self.html.index('id="events-tbody"'):]
        styles = "".join(s.get_text() for s in BeautifulSoup(after_the_table, "html.parser").select("style"))
        self.assertNotIn(".source-toggle", styles)

    def test_every_source_button_has_the_same_width(self):
        styles = "".join(s.get_text() for s in self.page.select("style"))
        self.assertIn("grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr))", styles)
        self.assertEqual(self.page.select_one("#style-current")["class"], ["chip-sources"])

    def test_a_label_cut_short_is_in_the_tooltip(self):
        source = self.page.select_one('[data-source-id="manual-demo"]')
        self.assertTrue(source["title"].startswith("A source with a label far too long to fit"))

    def test_the_mailboxes_of_the_scraper_take_one_line(self):
        lines = self.page.select('[data-source-id="scraper"] .source-chip-sub')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].get_text(strip=True), "2 mailboxes")
        self.assertIn("Gmail - test/IT-ISAC Open Source News", lines[0]["title"])

    def test_show_rejected_follows_the_filter_buttons(self):
        rejected = self.page.select_one("#hide-rejected-btn")
        self.assertEqual(rejected.find_previous_sibling("button")["id"], "cti-toggle-btn")
        self.assertIs(rejected.parent, self.page.select_one("#date-dd-btn").find_parent(class_="toolbar-row"))

    def test_the_presets_are_at_the_top_of_the_card_after_the_cache_info(self):
        head = self.page.select_one(".action-panel-head")
        for control in ("#refresh-info", "#save-preset-btn", "#load-preset-btn", "#preset-active-indicator"):
            with self.subTest(control):
                self.assertIsNotNone(head.select_one(control))
        ids = [el.get("id") for el in head.select("[id]")]
        self.assertLess(ids.index("refresh-info"), ids.index("save-preset-btn"))

    def test_the_scripts_messages_go_where_the_servers_float(self):
        """A message such as "Table updated" pushed the table down when it opened
        and pulled it back up when it closed. It now goes into #flash-container,
        which floats over every page (tests/test_page_stability.py)."""
        script = "".join(s.get_text() for s in self.page.select("script"))
        self.assertIn("getElementById('flash-container')", script)

    def test_the_top_words_keep_their_height_while_empty(self):
        """Drawn after the page, or emptied by a filter, they moved the table.
        The hidden attribute would not do: Bootstrap takes it out of the layout."""
        styles = "".join(s.get_text() for s in self.page.select("style"))
        self.assertRegex(styles, r"\.title-words \{[^}]*height: 32px")
        self.assertRegex(styles, r"\.title-words\.is-empty \{[^}]*visibility: hidden")
        chart = self.page.select_one("#title-words")
        self.assertFalse(chart.has_attr("hidden"))
        self.assertIn("is-empty", chart["class"])

    def test_the_count_note_is_there_before_the_script_runs(self):
        self.assertEqual(self.page.select_one("#total-count-note").get_text(strip=True), "of 2 matching")

    def test_the_actions_column_has_no_gear(self):
        actions = self.page.select("thead th")[-1]
        self.assertIsNone(actions.select_one(".fa-gear"))
        self.assertIn("width:12rem", actions["style"])

    def test_an_events_organisation_filters_on_it(self):
        rows = {row["data-uuid"]: row for row in self.page.select("tr.event-row")}
        link = rows["a" * 36].select_one(".org-filter-link")
        self.assertEqual((link["data-org"], link.get_text(strip=True)), ("CIRCL", "CIRCL"))
        self.assertIsNone(rows["b" * 36].select_one(".org-filter-link"))
