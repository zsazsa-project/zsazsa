"""How each product is made: the flows on the product lists.

Each flow is static apart from what is pinned here. The analyser line follows
the schedule settings: the briefing's hour, the alert checks that are switched
on, whether advisories are scheduled. The advisory flow says whether the asset
inventory is on, and the detection request flow whether Rulezet is. Links to
the settings pages are only shown to site admins, since those pages refuse
everyone else. Each list route passes the settings in.

    python -m unittest tests.test_product_flows
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from flask import render_template, render_template_string, url_for

import config
from core import asset_inventory
from webapp import collection_cache, create_app, job_store, misp_store
from webapp.routes import daily_briefing, flash_intel, vea

# What each flow is rendered with when a test does not care.
FLOWS = {
    "daily_briefing/_flow.html": {"briefing_hour": 21},
    "flash_intel/_flow.html": {"schedule_focus": True},
    "vea/_flow.html": {"schedule_advisories": True, "assets_enabled": False},
    "indicator_feed/_flow.html": {},
    "threat_actor_profile/_flow.html": {},
    "detection_eng/_flow.html": {"rulezet_enabled": True},
}


class Flows(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
                      mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
                      mock.patch.object(collection_cache, "start_worker")):
            self.enterContext(patch)
        self.app = create_app()

    def render(self, template, is_site_admin=True, **context):
        with self.app.test_request_context("/"):
            return BeautifulSoup(render_template(template, is_site_admin=is_site_admin, **context), "html.parser")

    def analyser_line(self, page):
        return " ".join(page.select_one(".flow-mode.flow-auto").get_text(" ").split())

    def settings_links(self, page):
        return [a["href"] for a in page.select("a") if "/config" in a["href"]]

    def test_each_flow_has_its_steps(self):
        for template, steps in (("daily_briefing/_flow.html", 6), ("flash_intel/_flow.html", 6),
                                ("vea/_flow.html", 6), ("indicator_feed/_flow.html", 4),
                                ("threat_actor_profile/_flow.html", 5), ("detection_eng/_flow.html", 6)):
            with self.subTest(template):
                page = self.render(template, **FLOWS[template])
                self.assertEqual([s.get_text() for s in page.select(".flow-step .flow-head small")],
                                 [f"Step {n}" for n in range(1, steps + 1)])

    def test_the_line_in_the_filter_box_opens_the_panel(self):
        with self.app.test_request_context("/"):
            line = BeautifulSoup(render_template_string(
                '{% from "_flow_macros.html" import flow_help %}{{ flow_help("How a daily briefing is made") }}'),
                "html.parser").button
        panel = self.render("daily_briefing/_flow.html", **FLOWS["daily_briefing/_flow.html"]).select_one(".collapse")
        self.assertEqual(line["data-bs-target"], f"#{panel['id']}")
        self.assertEqual(line.get_text(strip=True), "How a daily briefing is made")

    def test_flowintel_is_only_shown_where_a_case_is_made(self):
        """Publishing an alert or an advisory opens a Flowintel case; the other
        products only go out on the chat and mail channels."""
        for template, flowintel in (("daily_briefing/_flow.html", False), ("flash_intel/_flow.html", True),
                                    ("vea/_flow.html", True), ("indicator_feed/_flow.html", False),
                                    ("threat_actor_profile/_flow.html", False), ("detection_eng/_flow.html", False)):
            with self.subTest(template):
                channels = [c.get_text(strip=True) for c in self.render(template, **FLOWS[template]).select(".flow-channel")]
                self.assertEqual(channels, ["E-mail", "Mattermost", "Teams"] + (["Flowintel"] if flowintel else []))

    def test_a_detection_request_says_when_rulezet_is_missing(self):
        """Without Rulezet no rule can be validated, so nothing can be marked Active."""
        def rulezet_line(enabled):
            page = self.render("detection_eng/_flow.html", rulezet_enabled=enabled)
            return page.select_one(".flow-mode.flow-rulezet").get_text(" ", strip=True)
        self.assertIn("checks a rule before it goes live", rulezet_line(True))
        self.assertIn("no request can be marked Active", rulezet_line(False))

    def test_the_briefing_names_its_hour_or_says_the_schedule_is_off(self):
        self.assertIn("every day from 07:00 UTC",
                      self.analyser_line(self.render("daily_briefing/_flow.html", briefing_hour=7)))
        off = self.analyser_line(self.render("daily_briefing/_flow.html", briefing_hour=None))
        self.assertIn("Its daily schedule is off", off)
        self.assertNotIn("every day", off)

    def test_the_alerts_say_whether_they_are_scheduled(self):
        for on, said in ((True, "against your focus points and your PIRs and GIRs."),
                         (False, "The scheduled alerts are off")):
            with self.subTest(on=on):
                self.assertIn(said, self.analyser_line(self.render("flash_intel/_flow.html", schedule_focus=on)))

    def test_the_advisories_say_whether_they_are_scheduled_and_the_inventory_is_on(self):
        on = self.render("vea/_flow.html", schedule_advisories=True, assets_enabled=True)
        self.assertIn("On every scheduled run", self.analyser_line(on))
        self.assertIn("a CVE has to be in a product you run", on.get_text(" ", strip=True))
        off = self.render("vea/_flow.html", schedule_advisories=False, assets_enabled=False)
        self.assertIn("The scheduled advisories are off", self.analyser_line(off))
        self.assertIn("every CVE makes an advisory", off.get_text(" ", strip=True))

    def test_only_a_site_admin_is_sent_to_the_settings(self):
        with self.app.test_request_context("/"):
            products = url_for("config_page.index", tab="tab-products")
            connections = url_for("config_page.index", tab="tab-connections")
            analyser = url_for("config_page.index", tab="tab-analyser")
        # The advisories link to the asset database, which is on Connections.
        for template, context, tab in (("daily_briefing/_flow.html", {"briefing_hour": None}, products),
                                       ("flash_intel/_flow.html", {"schedule_focus": False}, products),
                                       ("vea/_flow.html", {"schedule_advisories": False, "assets_enabled": False},
                                        connections)):
            for admin in (True, False):
                with self.subTest(template, admin=admin):
                    page = self.render(template, is_site_admin=admin, **context)
                    self.assertEqual(set(self.settings_links(page)), {tab, analyser} if admin else set())
        with self.app.test_request_context("/"):
            sources = url_for("collection_sources.index")
        for admin in (True, False):
            with self.subTest("indicator_feed/_flow.html", admin=admin):
                page = self.render("indicator_feed/_flow.html", is_site_admin=admin)
                self.assertEqual(self.settings_links(page), [sources] if admin else [])

    def test_the_lists_pass_their_schedule(self):
        listed = {name: mock.Mock(return_value=[]) for name in ("list_briefings", "list_fias", "list_veas")}
        settings = dict(ANALYSER_DAILY_BRIEFING=True, ANALYSER_DAILY_BRIEFING_HOUR=18, ANALYSER_FLASH_INTEL=False,
                        ANALYSER_VULNERABILITY_ADVISORIES=True)
        for module, route, passed in (
                (daily_briefing, daily_briefing.list_briefings, {"briefing_hour": 18}),
                (flash_intel, flash_intel.review, {"schedule_focus": False}),
                (vea, vea.review, {"schedule_advisories": True, "assets_enabled": True})):
            with self.subTest(module.__name__), \
                 mock.patch.multiple(config, create=True, **settings), \
                 mock.patch.multiple(misp_store, **listed), \
                 mock.patch.object(asset_inventory, "enabled", return_value=True), \
                 mock.patch.object(job_store, "by_entity", return_value={}), \
                 mock.patch.object(module, "render_template", return_value="") as render, \
                 self.app.test_request_context("/"):
                route()
            self.assertEqual({key: render.call_args.kwargs[key] for key in passed}, passed)


if __name__ == "__main__":
    unittest.main()
