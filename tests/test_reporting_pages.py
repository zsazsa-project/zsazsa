"""The pipeline's banner and the stakeholder matrix.

The pipeline opens on the compact banner of the other pages: its figures, what
needs a look as the banner's panel, and Sources, Activity and, for a site
admin, Settings at its bottom left. The matrix plots each stakeholder with its
initials, filled for an internal one and outlined for an external one, with the
quadrant names outside the field so none sits under a stakeholder in a corner,
and lists each quadrant's stakeholders, the most influential and interested
first, with how to engage them.

MISP is patched; the database, the collection cache and the log are temporary.

    python -m unittest tests.test_reporting_pages
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_session, misp_store


def _stakeholder(n, name, influence, interest, kind="Internal"):
    return SimpleNamespace(id=f"s{n}", uuid=f"{n:036d}", name=name, role="SOC", stakeholder_type=kind,
                           influence=influence, interest=interest)


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp) / "cache.db")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(config, "IMAP_SOURCES", [], create=True),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch("webapp.routes.data_collection._sources", return_value=[]),
            mock.patch.object(misp_store, "_test_connection", return_value={"ok": True}),
            mock.patch.object(misp_store, "test_scraper_misp", return_value={"ok": True}),
            mock.patch.object(misp_store, "test_webapp_misp", return_value={"ok": True}),
            mock.patch.object(misp_store, "data_collection_source_counts", return_value=[]),
        ):
            self.enterContext(patch)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")


class PipelineBanner(Pages):
    def banner(self, admin):
        with mock.patch.object(misp_session, "current_user_is_admin", return_value=admin):
            return self.page("/pipeline").select_one("section.record-hero")

    def test_the_buttons_are_at_the_bottom_left(self):
        actions = self.banner(admin=True).select_one(".hero-actions.hero-actions-below")
        self.assertEqual([a.get_text(strip=True) for a in actions.select("a")], ["Sources", "Activity", "Settings"])
        self.assertEqual([a.get("data-pipeline-tab") for a in actions.select("a")[:2]], ["sources", "activity"])
        self.assertEqual(actions.select("a")[2]["href"], "/config?tab=tab-analyser")

    def test_settings_only_for_a_site_admin(self):
        """The settings pages refuse everyone else, so the banner offers them nothing."""
        actions = self.banner(admin=False).select_one(".hero-actions")
        self.assertEqual([a.get_text(strip=True) for a in actions.select("a")], ["Sources", "Activity"])

    def test_what_needs_a_look_is_the_banners_panel(self):
        panel = self.banner(admin=False).select_one(".record-panel.needs-a-look")
        self.assertIn("Nothing needs a look", panel.get_text())


class Matrix(Pages):
    STAKEHOLDERS = [_stakeholder(1, "Internal SOC", 4, 10), _stakeholder(2, "Local board", 10, 6),
                    _stakeholder(3, "External CTI", 5, 5, kind="External"), _stakeholder(4, "CTI team", 10, 10)]

    def matrix(self, stakeholders=STAKEHOLDERS):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=list(stakeholders)):
            return self.page("/stakeholders/matrix")

    def test_each_stakeholder_is_plotted_with_its_initials(self):
        dots = {d.select_one(".label").get_text(): d for d in self.matrix().select("a.pim-dot")}
        self.assertEqual(set(dots), {"Internal SOC", "Local board", "External CTI", "CTI team"})
        self.assertEqual(dots["Internal SOC"].select_one(".pim-mark").get_text(), "IS")
        self.assertIn("external", dots["External CTI"].select_one(".pim-mark")["class"])
        # On the right, the name goes to the left of the mark, inside the field.
        self.assertIn("flip", dots["CTI team"]["class"])
        self.assertNotIn("flip", dots["External CTI"]["class"])

    def test_the_quadrant_names_are_outside_the_field(self):
        page = self.matrix()
        self.assertIsNone(page.select_one(".pim-field .pim-name"))
        names = [n.get_text(" ", strip=True) for n in page.select(".pim-names .pim-name")]
        self.assertEqual(names, ["Keep satisfied 0", "Manage closely 2", "Monitor 1", "Keep informed 1"])

    def test_a_quadrants_list_starts_with_the_most_influence_and_interest(self):
        card = next(c for c in self.matrix().select(".quad-card") if "Manage closely" in c.select_one(".card-header").get_text())
        self.assertEqual([a.get_text() for a in card.select(".quad-list a")], ["CTI team", "Local board"])
        self.assertEqual(card.select_one(".scores").get_text(), "10 · 10")

    def test_without_stakeholders_it_says_how_to_start(self):
        page = self.matrix([])
        self.assertIsNone(page.select_one(".pim"))
        self.assertIn("No stakeholders yet", page.get_text())


if __name__ == "__main__":
    unittest.main()
