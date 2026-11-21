"""The settings page, as a site admin sees it.

The Analyser tab holds every setting of the analyser, the schedule and the
analyser's logs, laid out by section; none is left on the System tab, which
keeps the audit log's retention. Every other tab but Prompts is laid out the
same way, with a menu of its sections, and the asset database is on
Connections. The focus point lists offer the names of their MISP galaxy to pick
from, and mark a name the galaxy does not have, unless the galaxy could not be
read. The threat landscape threat types are a list as the product types are,
ENISA's prime threats while none is set.

The database and the log are temporary, and the galaxies are stubbed.

    python -m unittest tests.test_settings_page
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

import config
from analyser import settings
from webapp import collection_cache, create_app, misp_store
from webapp.routes import config_page


class FocusPoints(unittest.TestCase):
    def choices(self, countries=("Belgium", "Luxembourg")):
        with mock.patch.multiple(config, create=True, FOCUS_POINTS_GEOGRAPHIES=["Belgium", "Luxemburg"],
                                 FOCUS_POINTS_SECTORS=[], FOCUS_POINTS_THREAT_ACTORS=[], FOCUS_POINTS_THREAT_TYPES=[],
                                 FOCUS_POINTS_VENDORS=[], FOCUS_POINTS_TECHNOLOGIES=[]), \
             mock.patch.object(config_page.misp_store, "_fetch_galaxy_clusters",
                               side_effect=lambda g: list(countries) if g == config_page.misp_store.GALAXY_COUNTRY
                               else []), \
             mock.patch.object(config_page.misp_store, "galaxy_mitre_attack_patterns",
                               return_value=["Phishing - T1566"]):
            return config_page._focus_point_choices()

    def test_a_name_the_galaxy_does_not_have_is_marked(self):
        """The demo had "Luxemburg"; the country galaxy has "Luxembourg"."""
        choices, missing = self.choices()
        self.assertEqual(missing, {"FOCUS_POINTS_GEOGRAPHIES": ["Luxemburg"]})
        self.assertIn("Luxembourg", choices["FOCUS_POINTS_GEOGRAPHIES"])
        # A threat type is picked by the technique's name.
        self.assertEqual(choices["FOCUS_POINTS_THREAT_TYPES"], ["Phishing"])

    def test_without_a_galaxy_nothing_is_marked(self):
        self.assertEqual(self.choices(countries=())[1], {})

    def test_the_page_offers_the_galaxy_and_shows_the_mark_and_the_workflow(self):
        page = render_page()
        self.assertIn('<option value="Luxembourg">', page)
        self.assertIn("Not in the MISP galaxy", page)
        self.assertIn('name="FOCUS_POINTS_VENDORS"', page)


class AnalyserTab(unittest.TestCase):
    # On the tab besides the workflow settings: the schedule and the logs.
    OTHERS = ("ANALYSER_FLASH_INTEL", "ANALYSER_VULNERABILITY_ADVISORIES", "ANALYSER_DAILY_BRIEFING",
              "ANALYSER_DAILY_BRIEFING_HOUR", "EVENT_LOG_RETENTION_DAYS", "PIPELINE_RUN_LOG_RETENTION_DAYS")

    @classmethod
    def setUpClass(cls):
        page = BeautifulSoup(render_page(), "html.parser")
        cls.tab, cls.system = page.find(id="tab-analyser"), page.find(id="tab-system")

    def fields(self, pane, key):
        return pane.find_all(attrs={"name": key})

    def test_it_holds_every_analyser_setting_once(self):
        for key in [setting.key for setting in settings.ALL] + list(self.OTHERS):
            with self.subTest(key):
                fields = self.fields(self.tab, key)
                # A switch is a checkbox and the hidden field that says it is off.
                self.assertEqual(len(fields), 2 if fields and fields[0].get("type") == "checkbox" else 1, key)

    def test_none_is_left_on_the_system_tab(self):
        for key in [setting.key for setting in settings.ALL] + list(self.OTHERS):
            with self.subTest(key):
                self.assertEqual(self.fields(self.system, key), [])
        self.assertEqual(len(self.fields(self.system, "AUDIT_LOG_RETENTION_DAYS")), 1)



class TabLayout(unittest.TestCase):
    """The other tabs are laid out as the Analyser tab is, and the asset
    database is on Connections."""

    @classmethod
    def setUpClass(cls):
        cls.page = BeautifulSoup(render_page(), "html.parser")

    def test_each_tab_has_its_sections_in_its_menu(self):
        for tab in ("tab-connections", "tab-products", "tab-analyser", "tab-system", "tab-ai", "tab-context",
                    "tab-notifications", "tab-styling"):
            with self.subTest(tab):
                pane = self.page.find(id=tab)
                menu = [a["href"] for a in pane.find("nav").find_all("a")]
                self.assertEqual(menu, [f"#{card['id']}" for card in pane.select(".card[id]")])

    def test_the_asset_database_is_on_connections(self):
        connections, products = self.page.find(id="tab-connections"), self.page.find(id="tab-products")
        for key in ("ASSET_INVENTORY_ENABLED", "ASSET_INVENTORY_FILE", "ASSET_INVENTORY_REFRESH_MINUTES"):
            with self.subTest(key):
                self.assertTrue(connections.find_all(attrs={"name": key}))
                self.assertEqual(products.find_all(attrs={"name": key}), [])


class NamedLists(unittest.TestCase):
    """The threat actor types and the story kinds are laid out as the product
    types are: a row of one input group each, written by the server."""

    def test_each_row_has_its_name_meaning_and_remove(self):
        types = [{"name": "Hacktivists", "description": 'Driven by "causes" <b>'}]
        kinds = [{"name": "incident", "description": "One attack.", "ticked": True},
                 {"name": "outlook", "description": "Forecasts.", "ticked": False}]
        with mock.patch.multiple(config, create=True, THREAT_ACTOR_TYPES=types, REPORT_STORY_KINDS=kinds):
            page = BeautifulSoup(render_page(), "html.parser")
        rows = page.select("#tat-list .named-row .input-group")
        self.assertEqual([(r.select_one(".named-name")["value"], r.select_one(".named-desc").text) for r in rows],
                         [("Hacktivists", 'Driven by "causes" <b>')])
        self.assertEqual(rows[0].select_one(".named-remove")["aria-label"], "Remove Hacktivists")
        self.assertIsNone(rows[0].select_one(".named-ticked"))
        kind_rows = page.select("#kind-list .named-row")
        self.assertEqual([(r.select_one(".named-name")["value"], r.select_one(".named-ticked").has_attr("checked"))
                          for r in kind_rows], [("incident", True), ("outlook", False)])
        # What is saved is filled in by the page's script, under the names the form posts.
        self.assertEqual(page.select_one("#tat-json")["name"], "THREAT_ACTOR_TYPES")
        self.assertEqual(page.select_one("#kind-json")["name"], "REPORT_STORY_KINDS")

    def test_the_threat_types_are_a_list_as_the_product_types(self):
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", ["Ransomware", 'Say "no" <b>'], create=True):
            page = BeautifulSoup(render_page(), "html.parser")
        card = page.select_one("#tab-products #products-threat-types")
        self.assertIn("ENISA Threat Landscape", card.text)
        rows = card.select("#threat-type-list .threat-type-row")
        self.assertEqual([r.select_one(".threat-type-name")["value"] for r in rows], ["Ransomware", 'Say "no" <b>'])
        self.assertEqual(rows[0].select_one(".threat-type-remove")["aria-label"], "Remove Ransomware")
        saved = card.select_one("textarea#threat_landscape_threat_types")
        self.assertEqual((saved["name"], saved.text), ("THREAT_LANDSCAPE_THREAT_TYPES", 'Ransomware\nSay "no" <b>'))
        self.assertIsNotNone(card.select_one("#threat-type-new"))
        self.assertIsNotNone(card.select_one("#threat-type-add"))

    def test_without_threat_types_set_the_enisa_ones_are_shown(self):
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", [], create=True):
            page = BeautifulSoup(render_page(), "html.parser")
        names = [i["value"] for i in page.select("#threat-type-list .threat-type-name")]
        self.assertEqual(names, misp_store.DEFAULT_THREAT_TYPES)


def render_page() -> str:
    """The settings page as a site admin sees it, the galaxies stubbed."""
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch.multiple(config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log"), MISP_SESSION_REDIRECT_TO_LOGIN=False), \
             mock.patch.object(config_page, "importlib"), \
             mock.patch.object(config_page, "_focus_point_choices",
                               return_value=({"FOCUS_POINTS_GEOGRAPHIES": ["Luxembourg"]},
                                             {"FOCUS_POINTS_GEOGRAPHIES": ["Luxemburg"]})), \
             mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
             mock.patch.object(config_page.misp_store, "webapp_key_shortcomings", return_value=None), \
             mock.patch.object(collection_cache, "start_worker"):
            return create_app().test_client().get("/config").get_data(as_text=True)


if __name__ == "__main__":
    unittest.main()
