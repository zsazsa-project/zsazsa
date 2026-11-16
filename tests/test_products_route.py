"""Regression coverage for the products page: product type mapping, titles, the PIR
filter and the menu the product pages sit under. The overview has the TLP and
workflow state in columns, the newest four of a type with the rest behind "Show
all", and links to each type's list that keep the path zsazsa is served under.

    python -m unittest tests.test_products_route
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import config
from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent, PyMISP

from webapp import collection_cache, create_app, misp_store
from webapp.routes import indicator_feed, products, threat_actor_profile
from webapp.utils import product_detail_url, product_type_label, product_type_tag_value, record_title


class ProductTypeMapping(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"
        self.app.register_blueprint(products.bp)
        self.app.register_blueprint(indicator_feed.bp)
        self.app.register_blueprint(threat_actor_profile.bp)

    def test_filter_uses_the_configured_tag_value(self):
        fake_misp = mock.MagicMock()
        fake_misp.search.return_value = []
        with mock.patch.object(products.misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(config, "TAG_THREAT_ACTOR_PROFILE",
                               'zsazsa:ctiproduct="threat-actor-profile"', create=True):
            products._list_product_events("Threat actor profile", None)
        self.assertEqual(fake_misp.search.call_args.kwargs["tags"],
                         ['zsazsa:ctiproduct="threat-actor-profile"'])

    def test_rows_use_the_display_name_not_the_tag_slug(self):
        event = SimpleNamespace(
            uuid="u" * 36,
            id="7",
            info="[zsazsa:tap] Example",
            date="2026-09-01",
            tags=[SimpleNamespace(name='zsazsa:ctiproduct="indicator-feed"')],
            event_reports=[],
        )
        fake_misp = mock.MagicMock()
        fake_misp.search.return_value = [event]
        with self.app.test_request_context("/products"), \
             mock.patch.object(products.misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(config, "MISP_WEBAPP_URL", "https://misp.example.test", create=True), \
             mock.patch.object(config, "TAG_INDICATOR_FEED",
                               'zsazsa:ctiproduct="indicator-feed"', create=True):
            rows = products._list_product_events(None, None)
        self.assertEqual(rows[0]["product_type"], "Indicator feed")

    def test_the_pir_filter_finds_a_product_that_answers_the_pir(self):
        """Products record the PIR on their object, never in the title or a
        tag, which is all the filter looked at, so it found nothing."""
        def product(uuid, info):
            event = MISPEvent()
            event.uuid, event.id, event.info, event.date = uuid, "7", info, "2026-09-01"
            event.add_tag('zsazsa:ctiproduct="flash-intel"')
            return event

        answering = product("a" * 36, "[zsazsa:fia] Wiper on the grid")
        other = product("b" * 36, "[zsazsa:fia] Phishing")
        obj = misp_store._build_obj("zsazsa-flash-intel")
        obj.add_attribute("linked-pir-uuid", value="p" * 36, type="text")
        answering.add_object(obj)
        fake_misp = mock.create_autospec(PyMISP, instance=True)
        fake_misp.search.return_value = [answering, other]
        pir = SimpleNamespace(uuid="p" * 36, pir_id="PIR-001")
        with self.app.test_request_context("/products"), \
             mock.patch.object(products.misp_store, "_misp", return_value=fake_misp):
            rows = products._list_product_events(None, pir)
        self.assertEqual([r["info"] for r in rows], ["[zsazsa:fia] Wiper on the grid"])

    def test_the_legacy_advisory_name_still_resolves(self):
        """Events created before the rename carry the old product name."""
        with mock.patch.object(config, "TAG_VEA", 'zsazsa:ctiproduct="vea"', create=True):
            self.assertEqual(product_type_tag_value("Vulnerability exploitation advisory"), "vea")
            self.assertEqual(product_type_label("Vulnerability exploitation advisory"),
                             "Vulnerability advisory")

    def test_an_unusable_configured_tag_falls_back_to_the_shipped_value(self):
        for broken in ["", "not-a-tag", 'zsazsa:ctiproduct=']:
            with mock.patch.object(config, "TAG_VEA", broken, create=True):
                self.assertEqual(product_type_tag_value("Vulnerability advisory"), "vea", broken)

    def test_a_product_type_without_a_page_is_left_alone(self):
        # The config page lets an admin add product types zsazsa has no page for.
        self.assertEqual(product_type_tag_value("Campaign profile"), "Campaign profile")
        self.assertEqual(product_type_label("Campaign profile"), "Campaign profile")
        with self.app.test_request_context("/"):
            self.assertEqual(
                product_detail_url("Campaign profile", "x", fallback_url="/fallback"),
                "/fallback",
            )

    def test_product_detail_url_covers_indicator_feed_and_threat_actor_profile(self):
        with self.app.test_request_context("/"):
            self.assertEqual(
                product_detail_url("indicator-feed", "feed-1", fallback_url="/fallback"),
                "/products/indicator-feed/feed-1",
            )
            self.assertEqual(
                product_detail_url("Threat actor profile", "tap-1", fallback_url="/fallback"),
                "/products/threat-actor-profile/tap-1",
            )


class ProductTitles(unittest.TestCase):
    def test_the_overview_shows_titles_without_the_record_marker(self):
        """The products are grouped by type, so "[zsazsa:der]" in front of each
        title only repeated the heading above it."""
        event = MISPEvent()
        event.from_dict(Event={"uuid": "d" * 36, "id": "9", "date": "2026-11-01",
                               "info": "[zsazsa:der] Detect Greeter log tampering",
                               "Tag": [{"name": 'zsazsa:ctiproduct="detection-engineering-request"'}]})
        fake_misp = mock.create_autospec(PyMISP, instance=True)
        fake_misp.search.return_value = [event]
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True), \
             mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(collection_cache, "start_worker"), \
             mock.patch.object(misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(misp_store, "list_pirs", return_value=[]):
            page = BeautifulSoup(create_app().test_client().get("/products/").data, "html.parser")
        titles = [a.get_text(strip=True) for a in page.select("tbody td a.title")]
        self.assertEqual(titles, ["Detect Greeter log tampering"])

    def _overview(self, events, script_root=""):
        fake_misp = mock.create_autospec(PyMISP, instance=True)
        fake_misp.search.return_value = events
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True), \
             mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(collection_cache, "start_worker"), \
             mock.patch.object(misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(misp_store, "list_pirs", return_value=[]):
            headers = {"X-Forwarded-Prefix": script_root} if script_root else {}
            response = create_app().test_client().get("/products/", headers=headers)
            return BeautifulSoup(response.data, "html.parser")

    @staticmethod
    def _feed_event(n, tags=()):
        event = MISPEvent()
        event.from_dict(Event={"uuid": f"{n:036d}", "id": str(n), "date": f"2026-11-{n:02d}", "info": f"Feed {n}",
                               "Tag": [{"name": 'zsazsa:ctiproduct="indicator-feed"'}] + [{"name": t} for t in tags]})
        return event

    def test_tlp_and_workflow_are_columns_and_other_tags_stay_chips(self):
        page = self._overview([self._feed_event(1, ["tlp:amber", 'workflow:state="draft"', "kev"])])
        row = page.select_one("tbody tr:not(.lane-head)")
        cells = row.find_all("td")
        self.assertEqual(cells[2].get_text(strip=True), "TLP:AMBER")
        self.assertEqual(cells[3].get_text(strip=True), "draft")
        self.assertEqual([c.get_text() for c in row.select(".chip-tag-generic")], ["kev"])
        self.assertEqual(page.select_one("tr.lane-head a.lane-hint")["href"], "/products/indicator-feed/")

    def test_the_link_to_a_list_keeps_the_path_zsazsa_is_served_under(self):
        page = self._overview([self._feed_event(1)], script_root="/zsazsa")
        self.assertEqual(page.select_one("tr.lane-head a.lane-hint")["href"], "/zsazsa/products/indicator-feed/")

    def test_a_type_shows_its_newest_four_and_offers_the_rest(self):
        page = self._overview([self._feed_event(n) for n in range(1, 7)])
        rows = page.select("tbody tr:not(.lane-head):not(.show-more-row)")
        self.assertEqual(len(rows), 6)
        self.assertEqual([r.has_attr("data-more") for r in rows], [False] * 4 + [True] * 2)
        self.assertIn("Show all 6", page.select_one("[data-show-more]").get_text())

    def test_only_the_marker_at_the_start_is_taken_off(self):
        self.assertEqual(record_title("[zsazsa:vea] CVE-2026-1: [zsazsa:x] in title"), "CVE-2026-1: [zsazsa:x] in title")
        self.assertEqual(record_title("Imported [zsazsa:fia] report"), "Imported [zsazsa:fia] report")
        self.assertEqual(record_title(None), "")


class ProductsMenu(unittest.TestCase):
    def test_a_detection_engineering_page_opens_under_products(self):
        """It is listed there, but the menu did not light up on its pages."""
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True), \
             mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(collection_cache, "start_worker"), \
             mock.patch.object(misp_store, "list_ders", return_value=[]):
            page = BeautifulSoup(create_app().test_client().get("/products/detection-eng/").data,
                                 "html.parser")
        menu = next(a for a in page.select("a.topnav-link.dropdown-toggle") if "Products" in a.text)
        self.assertIn("active", menu["class"])


if __name__ == "__main__":
    unittest.main()
