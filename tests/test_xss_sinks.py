"""Text from MISP, from a model or from another user must stay text on the page.

GHSA-2hmh-2qrq-872r and GHSA-4rw2-wpj5-m23p. Event titles, galaxy and CTI tags,
tag colours, organisation names, overlap reasons, threat actor types and names
someone saved reached the page as markup: through innerHTML, and through inline
onsubmit handlers that a quote in the name could break out of. Each one ran
script in the session of whoever opened the page or clicked the button. The
check on saving an organisation filter is in test_config_form.

RenderedPages and BriefingDate run offline with the rest of the suite.
HostileTextInTheBrowser drives a real Chromium against the webapp, with every
MISP call mocked and every outbound request blocked, so it is opt-in like the
other browser checks:

    python -m unittest tests.test_xss_sinks
    ZSAZSA_UI_TESTS=1 python -m unittest tests.test_xss_sinks
"""

import os
import re
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests
from bs4 import BeautifulSoup
from flask import Flask

import config as _config

UI_TESTS = os.environ.get("ZSAZSA_UI_TESTS") == "1"
CHROME = os.environ.get("ZSAZSA_UI_CHROME") or None

EVENT_UUID = "11111111-2222-3333-4444-555555555555"
BRIEFING_UUID = "b" * 36

# Each payload sets window.__xss when it runs, so the browser checks can tell.
MARKUP = '<img src=x onerror="window.__xss=1">'
EVENT_ORG = '<svg onload="window.__xss=1">'
ORG_FILTER = "<img/src=x/onerror=window.__xss=1>"
SOURCE_NAME = "x onmouseover=window.__xss=1 y"
BREAKOUT = "x');window.__xss=1;('"
# The badge drops quotes from the value, so this one does without them.
CTI_TAG = "cti-evaluation:x=<img src=x onerror=window.__xss=1>"
TAG_COLOUR = '#fff"><img src=x onerror="window.__xss=1">'

BOOTSTRAP_STAND_IN = """
class Component {
  static getInstance() { return null; }
  static getOrCreateInstance() { return new this(); }
  show() {} hide() {} toggle() {} close() {} dispose() {}
}
window.bootstrap = {Alert: Component, Collapse: Component, Dropdown: Component, Modal: Component,
                    Offcanvas: Component, Popover: Component, Tab: Component, Tooltip: Component};
"""


def _story(n):
    return SimpleNamespace(title=f"Story {n}", content=f"Text {n}", source_event_uuid=EVENT_UUID,
                           source_id="scraper", source_url="", drafted_by="", threat_actor_types=[])


def _offline_patches():
    """Everything the pages ask MISP for, answered with hostile data. The
    organisation filter and the briefing date are stored as an install from
    before the save checks would hold them."""
    def no_network(*args, **kwargs):
        raise requests.ConnectionError("tests run offline")

    event = {"uuid": EVENT_UUID, "info": MARKUP, "orgc": EVENT_ORG,
             "date": "2026-10-01", "source_id": "scraper", "source_label": "Scraper"}
    source = SimpleNamespace(uuid="66666666-7777-8888-9999-000000000000",
                             name=SOURCE_NAME, enabled=True)
    stakeholder = SimpleNamespace(id="sh-1", name=BREAKOUT, organization="",
                                  tlp_clearance="amber", influence=5, interest=5)
    feed = SimpleNamespace(uuid="f" * 36, id="f" * 36, feed_id="FEED-001", name=BREAKOUT,
                           tlp="clear", review_state="draft", cache_interval="")
    briefing = SimpleNamespace(
        uuid=BRIEFING_UUID, date=BREAKOUT, title="Daily briefing", author="", tlp="amber",
        escalations="", notes="", detection_rules="", summary="", summary_stale=False,
        review_state="draft", story_count=2, creator="", approved_by="", created_at="",
        stories=[_story(1), _story(2)], geographic_scope=[], sectors=[], threat_actors=[],
        mitre_attack_techniques=[], threat_types=[], technology=[], vendor=[], incident=[],
        campaign=[])
    organisation = SimpleNamespace(uuid="o" * 36, name=BREAKOUT, local=True)
    server = {"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
              "api_key": "k", "org_filter_type": "include",
              "org_filter": f"{ORG_FILTER} 55f6ea5e-2c60-40e5-964f-47a8950d210f"}
    collected = {"uuid": EVENT_UUID, "source_id": "scraper", "info": "Collected event",
                 "tags": [], "orgc": "CIRCL", "date": "2026-10-01"}
    misp = mock.Mock()
    misp.get_organisation.return_value = SimpleNamespace(name=MARKUP)

    empty = ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors",
             "galaxy_mitre_attack_patterns", "list_selectable_pirs", "list_pirs",
             "pirs_for_stakeholder", "pirs_distributed_to_stakeholder",
             "girs_for_stakeholder", "girs_distributed_to_stakeholder",
             "products_for_stakeholder")
    store = {name: mock.Mock(return_value=[]) for name in empty}
    store.update(
        fetch_source_events=mock.Mock(return_value=[event]),
        list_collection_sources=mock.Mock(return_value=[source]),
        list_stakeholders=mock.Mock(return_value=[stakeholder]),
        get_stakeholder=mock.Mock(return_value=stakeholder),
        list_indicator_feeds=mock.Mock(return_value=[feed]),
        list_briefings=mock.Mock(return_value=[briefing]),
        get_briefing=mock.Mock(return_value=briefing),
        delete_stakeholder=mock.Mock(),
        delete_collection_source=mock.Mock(),
    )
    from webapp import audit, collection_cache, misp_store, org_store, sso_users
    return [
        mock.patch("requests.adapters.HTTPAdapter.send", no_network),
        mock.patch("pymisp.PyMISP", return_value=misp),
        mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
        mock.patch.object(_config, "MISP_SERVERS", [server]),
        mock.patch.object(_config, "THREAT_ACTOR_TYPES", [{"name": MARKUP, "description": ""}]),
        mock.patch.object(audit, "record"),
        mock.patch.multiple(misp_store, **store),
        mock.patch.object(org_store, "list_organisations", return_value=[organisation]),
        mock.patch.object(sso_users, "organisation_uuids_in_use", return_value=set()),
        mock.patch.object(collection_cache, "get_events", return_value=[collected]),
        mock.patch.object(collection_cache, "get_source_status", return_value={}),
        mock.patch.object(collection_cache, "interval_s", return_value=300),
    ]


def _start(testcase_cls, patches):
    for patcher in patches:
        patcher.start()
        testcase_cls.addClassCleanup(patcher.stop)


class RenderedPages(unittest.TestCase):
    """What the server sends, before any script on the page has run."""

    @classmethod
    def setUpClass(cls):
        _start(cls, _offline_patches())
        from webapp import create_app
        cls.client = create_app().test_client()

    def test_no_template_puts_data_in_an_inline_handler(self):
        """The browser decodes &#39; back into a quote before an inline handler
        runs, so autoescaping cannot keep a value inside its JavaScript string."""
        handler = re.compile(r"""(?<![\w-])on[a-z]+=("[^"]*|'[^']*)\{\{""")
        for path in Path("webapp/templates").rglob("*.html"):
            for match in handler.finditer(path.read_text()):
                self.fail(f"{path}: {match.group(0)}")

    def test_names_stay_inside_their_confirmation(self):
        for url, message in (
            ("/config/sources/", f"Delete source {SOURCE_NAME}?"),
            ("/stakeholders/", f"Delete {BREAKOUT}?"),
            ("/stakeholders/sh-1", f"Delete {BREAKOUT}?"),
            ("/products/indicator-feed/", f"Delete FEED-001 ({BREAKOUT})? This cannot be undone."),
            ("/briefing/", f"Delete briefing {BREAKOUT}?"),
            ("/community/organisations", f"Sync local details for {BREAKOUT} from MISP?"),
            ("/community/organisations", f"Remove organisation {BREAKOUT}?"),
        ):
            with self.subTest(url=url, message=message):
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 200)
                page = BeautifulSoup(resp.data, "html.parser")
                forms = [f for f in page.select("form[data-submit-confirm]")
                         if f["data-submit-confirm"] == message]
                self.assertEqual(len(forms), 1)
                self.assertEqual([k for k in forms[0].attrs if k.startswith("on")], [])

    def test_the_wizards_set_event_details_as_text(self):
        """The event title, creator organisation and date come straight from MISP."""
        for path, func in (("webapp/templates/flash_intel/wizard.html", "renderUuidMeta"),
                           ("webapp/templates/vea/wizard.html", "renderVeaUuidMeta")):
            source = Path(path).read_text()
            body = re.search(r"function %s\(.*?\n  \}\n" % func, source, re.S).group(0)
            self.assertNotIn("innerHTML", body, path)


class BriefingDate(unittest.TestCase):
    """The date is shown back in page markup, so only a real date is kept."""

    def test_only_a_date_is_kept(self):
        from webapp.routes.daily_briefing import _form_date
        self.assertEqual(_form_date({"date": " 2026-10-07 "}, "fallback"), "2026-10-07")
        self.assertEqual(_form_date({"date": BREAKOUT}, "fallback"), "fallback")
        self.assertEqual(_form_date({}, "fallback"), "fallback")

    def test_an_edit_keeps_the_stored_date_over_anything_else(self):
        from webapp.routes import daily_briefing as briefing_routes
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(briefing_routes.bp)
        briefing = SimpleNamespace(date="2026-09-25", title="", author="", tlp="amber",
                                   review_state="draft")
        with mock.patch.object(briefing_routes.misp_store, "get_briefing", return_value=briefing), \
             mock.patch.object(briefing_routes.misp_store, "update_briefing") as update, \
             mock.patch.object(briefing_routes.audit, "record"):
            app.test_client().post(f"/briefing/{BRIEFING_UUID}/edit", data={"date": BREAKOUT})
        self.assertEqual(update.call_args.args[1]["date"], "2026-09-25")


@unittest.skipUnless(UI_TESTS, "set ZSAZSA_UI_TESTS=1 to run the browser checks")
class HostileTextInTheBrowser(unittest.TestCase):
    """The pages as an analyst would open them, with the hostile data loaded."""

    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        from werkzeug.serving import make_server

        _start(cls, _offline_patches())
        from webapp import create_app, misp_store
        cls.store = misp_store

        cls._server = make_server("127.0.0.1", 0, create_app(), threaded=True)
        cls.base_url = f"http://127.0.0.1:{cls._server.server_port}"
        threading.Thread(target=cls._server.serve_forever, daemon=True).start()

        cls._playwright = sync_playwright().start()
        cls.browser = cls._playwright.chromium.launch(executable_path=CHROME)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._playwright.stop()
        cls._server.shutdown()

    def setUp(self):
        self.dialogs = []
        self.answer = False
        self.page = self.browser.new_page()
        # Nothing leaves the machine. Bootstrap comes from a CDN, and some pages
        # stop at their first line without it, so they get a stand-in that does
        # nothing.
        self.page.route("**/*", lambda route: route.continue_()
                        if route.request.url.startswith(self.base_url) else route.abort())
        self.page.add_init_script(BOOTSTRAP_STAND_IN)
        self.page.on("dialog", self.on_dialog)
        self.store.delete_stakeholder.reset_mock()
        self.store.delete_collection_source.reset_mock()

    def tearDown(self):
        self.page.close()

    def on_dialog(self, dialog):
        self.dialogs.append(dialog.message)
        if self.answer:
            dialog.accept()
        else:
            dialog.dismiss()

    def open(self, path):
        self.page.goto(self.base_url + path, wait_until="networkidle")

    def reply(self, path, body):
        """Answer a request to the webapp with this JSON instead of the webapp."""
        self.page.route(self.base_url + path, lambda route: route.fulfill(json=body))

    def finished_job(self, job_id, result):
        self.reply(f"/pipeline/run/{job_id}",
                   {"ok": True, "job": {"status": "completed", "result": result}})

    def assert_nothing_ran(self):
        # Give any onerror a moment to fire on the broken image.
        self.page.wait_for_timeout(300)
        self.assertIsNone(self.page.evaluate("window.__xss"))

    def assert_shown_as_text(self, locator, text):
        locator.get_by_text(text).first.wait_for()
        self.assert_nothing_ran()
        self.assertEqual(locator.locator("img, svg").count(), 0)

    def check_wizard(self, path, box):
        self.open(f"{path}?source={EVENT_UUID}|scraper")
        meta = self.page.locator(box).first
        self.assert_shown_as_text(meta, MARKUP)
        self.assertIn(EVENT_ORG, meta.inner_text())

    def test_fia_wizard_shows_the_event_title_as_text(self):
        self.check_wizard("/products/flash-intel/new", ".uuid-meta")

    def test_vea_wizard_shows_the_event_title_as_text(self):
        self.check_wizard("/products/vea/new", ".vea-uuid-meta")

    def test_org_filter_and_org_names_are_shown_as_text(self):
        self.open("/config/sources/")
        labels = self.page.locator(".org-uuid-labels").first
        self.assert_shown_as_text(labels, MARKUP)
        self.assertIn(ORG_FILTER, labels.inner_text())

    def test_source_name_stays_inside_the_delete_confirmation(self):
        self.open("/config/sources/")
        form = self.page.locator(f'form[data-submit-confirm="Delete source {SOURCE_NAME}?"]')
        form.hover()
        form.locator("button").click()
        self.assert_nothing_ran()
        self.assertEqual(self.dialogs, [f"Delete source {SOURCE_NAME}?"])
        self.store.delete_collection_source.assert_not_called()

    def test_stakeholder_name_stays_inside_the_delete_confirmation(self):
        self.open("/stakeholders/")
        self.page.locator("form[data-submit-confirm] button").click()
        self.assert_nothing_ran()
        self.assertEqual(self.dialogs, [f"Delete {BREAKOUT}?"])
        self.store.delete_stakeholder.assert_not_called()

    def test_accepting_the_confirmation_still_deletes(self):
        self.answer = True
        self.open("/stakeholders/")
        with self.page.expect_navigation():
            self.page.locator("form[data-submit-confirm] button").click()
        self.store.delete_stakeholder.assert_called_once_with("sh-1")

    def test_scope_from_a_drafted_story_is_shown_as_text(self):
        self.reply("/api/draft-story", {"story": "Drafted.", "scope": {"sectors": [MARKUP]}})
        self.open(f"/briefing/{BRIEFING_UUID}/edit")
        self.page.locator("#pane-story-1 .btn-draft-story").dispatch_event("click")
        self.assert_shown_as_text(self.page.locator(".scope-chips-1"), MARKUP)

    def test_overlap_reasons_are_shown_as_text(self):
        self.reply("/api/briefing-overlap-check", {"ok": True, "job_id": "overlap"})
        self.finished_job("overlap", {"overlaps": [{"a": 1, "b": 2, "score": 0.9, "reason": MARKUP}]})
        self.open(f"/briefing/{BRIEFING_UUID}/edit")
        self.page.locator("#btn-check-overlap").dispatch_event("click")
        self.assert_shown_as_text(self.page.locator("#overlap-results"), MARKUP)

    def test_threat_actor_types_in_a_new_story_are_text(self):
        self.open(f"/briefing/{BRIEFING_UUID}/edit")
        self.page.locator("#btn-add-story").dispatch_event("click")
        pills = self.page.locator("#pane-story-3 .actor-type-pills")
        self.assert_shown_as_text(pills, MARKUP)
        self.assertEqual(pills.locator("input").get_attribute("value"), MARKUP)

    def test_cti_tags_after_a_summary_are_shown_as_text(self):
        self.reply(f"/collection/{EVENT_UUID}/summarise", {"ok": True, "job_id": "summary"})
        self.finished_job("summary", {"summarised": True})
        self.reply(f"/collection/{EVENT_UUID}/preview?source=scraper",
                   {"ok": True, "event": {"tags": [{"name": CTI_TAG}]}, "reports": []})
        self.open("/collection/")
        self.page.locator(".create-summary-btn").dispatch_event("click")
        badge = self.page.locator('.tag-row-badge[data-tag^="cti-evaluation:"]')
        badge.wait_for()
        self.assert_nothing_ran()
        self.assertIn("onerror=window.__xss=1>", badge.inner_text())
        self.assertEqual(badge.locator("img").count(), 0)

    def test_a_tag_colour_cannot_add_markup_to_the_preview(self):
        self.reply(f"/collection/{EVENT_UUID}/preview?source=scraper",
                   {"ok": True, "event": {"tags": [{"name": "tlp:clear", "colour": TAG_COLOUR}]},
                    "reports": []})
        self.open("/collection/")
        self.page.locator(".event-preview-link").first.dispatch_event("click")
        self.assert_shown_as_text(self.page.locator("#event-preview-content"), "tlp:clear")


if __name__ == "__main__":
    unittest.main()
