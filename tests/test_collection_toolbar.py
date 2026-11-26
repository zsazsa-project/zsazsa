"""The toolbar above the data collection list, and the parts of its table that
filter.

The source buttons changed size while the page loaded: their layout was styled
after the event table, so they were drawn without it until the table was in,
and every refresh or reject reloads the page. They are now all of one size and
styled before the table. This pins that, where the toolbar's buttons sit, that
the script's messages float over the page rather than move it, that what the
script fills in after the load keeps its size, that the actions column has no
gear that looks clickable, that an event's organisation filters the list, that
a TLP tag has the colour of its level, and
that the Filters and actions card has the look of the stakeholder banner
without cutting off its menus, that a filter button stays white and readable
while its panel is open or a filter is set and shows a green check for the
latter, and that a finished summary reloads the table keeping what the
analyst had, and that Threat report has an arrow with a menu to all imported
threat reports, also when no manual source allows a new one. What the page's script does with a click is checked in a
browser, not here.

    python -m unittest tests.test_collection_toolbar
"""

import re
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
        rows = [{"uuid": "a" * 36, "source_id": "scraper", "info": "Collected event", "tags": ["tlp:amber+strict"],
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

    def test_a_tlp_tag_has_the_colour_of_its_level(self):
        """AMBER+STRICT lost its "+strict" and was coloured as AMBER."""
        badge = self.page.select_one('tr.event-row .tlp-badge[data-tag="tlp:amber+strict"]')
        self.assertIn("tlp-amber-strict", badge["class"])
        self.assertEqual(badge.get_text(strip=True), "TLP:AMBER+STRICT")

    def threat_report_menu(self, page):
        split = page.select_one(".chip-split")
        chip = split.select_one(".action-chip")
        self.assertIn("Threat report", chip.get_text())
        return chip, split.select_one("button.dropdown-toggle"), split.select_one(".dropdown-menu a")

    def test_threat_report_has_a_menu_with_all_threat_reports(self):
        _chip, toggle, link = self.threat_report_menu(self.page)
        self.assertEqual(toggle["data-bs-toggle"], "dropdown")
        self.assertEqual((link["href"], link.get_text(strip=True)), ("/collection/reports/", "Show all threat reports"))

    def test_without_a_manual_source_the_threat_reports_are_still_listed(self):
        with mock.patch.object(data_collection, "_sources", return_value=SOURCES[:1]):
            html = create_app().test_client().get("/collection/").get_data(as_text=True)
        chip, toggle, link = self.threat_report_menu(BeautifulSoup(html, "html.parser"))
        self.assertIn("disabled", chip["class"])
        self.assertNotIn("disabled", toggle["class"])
        self.assertEqual(link["href"], "/collection/reports/")

    def styles(self):
        return "".join(s.get_text() for s in self.page.select("style"))

    def test_the_card_looks_like_the_stakeholder_banner(self):
        card = self.page.select_one(".action-panel.collection-panel")
        self.assertIsNotNone(card.select_one(".panel-decor"))
        self.assertIsNotNone(card.select_one(".action-panel-head .hero-icon"))
        count = card.select_one(".panel-count")
        self.assertEqual(count.select_one("b#visible-count").get_text(strip=True), "2")
        self.assertEqual(count.get_text(" ", strip=True), "2 of 2 matching events")
        self.assertRegex(self.styles(), r"\.collection-panel \{[^}]*background: var\(--brand-gradient\)")

    def test_the_sources_are_in_a_panel_the_cards_colour_shows_through(self):
        """White, the panel stood out too much from the card."""
        row = self.page.select_one("#style-current").find_parent(class_="toolbar-row")
        self.assertIn("collection-sources", row["class"])
        self.assertRegex(self.styles(), r"\.collection-panel \.toolbar-row\.collection-sources \{[^}]*"
                                        r"background: color-mix\(in srgb, var\(--card-bg\) 80%, transparent\)")

    def test_the_card_does_not_cut_off_its_menus(self):
        """The corner circle of the banner is clipped in a layer of its own,
        not by the card, which holds the date and preset menus. The parts of
        the card get no z-index: as layers of their own, the row after the
        filters covered the open date menu."""
        styles = self.styles()
        card = re.search(r"\.collection-panel \{([^}]*)\}", styles).group(1)
        self.assertNotIn("overflow", card)
        self.assertRegex(styles, r"\.collection-panel \.panel-decor \{[^}]*overflow: hidden")
        self.assertIn(".collection-panel > :not(.panel-decor) { position: relative; }", styles)

    def test_counts_results_and_errors_stay_readable_on_the_card(self):
        """A Tags or Org button in use turns white, and its count was white on
        a faint grey; the result of a set aside is green or red text, which
        the card's colour swallowed; a source in error lost its red edge."""
        styles = self.styles()
        self.assertRegex(styles, r"\.collection-panel \.alt4-panel-toggle \.badge \{[^}]*background: var\(--misp-navy\) !important")
        self.assertRegex(styles, r"\.collection-panel #bulk-reject-result \{[^}]*background: #fff")
        self.assertIn(".collection-panel .chip-sources .source-toggle-err { border-color: var(--source-toggle-err-border); }", styles)

    def test_a_filter_button_open_and_filtered_stays_readable(self):
        """With "More" open and "Has reports" set, the button was dark blue
        under navy text; under the mouse it went back to the card's colour."""
        styles = self.styles()
        white = re.search(r"/\* A filter button is white.*?\{([^}]*)\}", styles, re.S)
        for selector in ('.alt4-panel-toggle.has-filter[aria-expanded="true"]',
                         '.toolbar-row > .alt4-panel-toggle.has-filter:hover',
                         '.toolbar-row > .alt4-panel-toggle[aria-expanded="true"]:hover',
                         '.toolbar-row > .dropdown > .btn.show'):
            self.assertIn(selector, white.group(0))
        self.assertIn("background: #fff", white.group(1))

    def test_each_filter_button_has_its_check_for_a_filter_set(self):
        for button in ("date-dd-btn", "tags-toggle-btn", "org-toggle-btn", "more-toggle-btn", "cti-toggle-btn"):
            self.assertIsNotNone(self.page.select_one(f"#{button} .filter-check"), button)
        self.assertIn(".collection-panel .has-filter .filter-check { display: inline-block; }", self.styles())

    def test_a_finished_summary_reloads_and_keeps_what_the_analyst_had(self):
        """It offered a Reload button whenever a row was ticked, and the reload
        dropped the ticked rows and the open panels."""
        script = "".join(s.get_text() for s in self.page.select("script"))
        self.assertNotIn("Reload the table to see the result", script)
        self.assertIn("job.label + ' is finished.'", script)
        self.assertIn("selected: clearSelection ? [] : getSelectedEvents()", script)
        self.assertIn("document.querySelectorAll('.collapse.show[id^=\"alt4-\"]')", script)
