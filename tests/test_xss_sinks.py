"""Text from MISP or from another user must stay text on the page (GHSA-2hmh-2qrq-872r).

An event title from a sync partner or the scraper, an organisation filter or a
name someone saved reached the page as markup: through innerHTML in the FIA and
VEA wizards and on the collection sources page, and through inline onsubmit
handlers that the name could break out of. Each one ran script in the session of
whoever opened the page. The check on saving an organisation filter is in
test_config_form.

RenderedPages runs offline with the rest of the suite. HostileTextInTheBrowser
drives a real Chromium against the webapp, with every MISP call mocked and every
outbound request blocked, so it is opt-in like the other browser checks:

    python -m unittest tests.test_xss_sinks
    ZSAZSA_UI_TESTS=1 python -m unittest tests.test_xss_sinks
"""

import os
import re
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests

import config as _config

UI_TESTS = os.environ.get("ZSAZSA_UI_TESTS") == "1"
CHROME = os.environ.get("ZSAZSA_UI_CHROME") or None

EVENT_UUID = "11111111-2222-3333-4444-555555555555"

# Each payload sets window.__xss when it runs, so the browser checks can tell.
EVENT_TITLE = '<img src=x onerror="window.__xss=1">'
EVENT_ORG = '<svg onload="window.__xss=1">'
ORG_FILTER = "<img/src=x/onerror=window.__xss=1>"
ORG_NAME = '<img src=x onerror="window.__xss=1">'
SOURCE_NAME = "x onmouseover=window.__xss=1 y"
STAKEHOLDER_NAME = "x');window.__xss=1;('"


class _FormAttrs(HTMLParser):
    """The attributes of every form, entity-decoded as a browser sees them."""

    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.forms.append(dict(attrs))


def _offline_patches():
    """Everything the four pages ask MISP for, answered with hostile data. The
    filter is stored as an install from before the save check would hold it."""
    def no_network(*args, **kwargs):
        raise requests.ConnectionError("tests run offline")

    event = {"uuid": EVENT_UUID, "info": EVENT_TITLE, "orgc": EVENT_ORG,
             "date": "2026-10-01", "source_id": "scraper", "source_label": "Scraper"}
    source = SimpleNamespace(uuid="66666666-7777-8888-9999-000000000000",
                             name=SOURCE_NAME, enabled=True)
    stakeholder = SimpleNamespace(id="sh-1", name=STAKEHOLDER_NAME, organization="",
                                  tlp_clearance="amber")
    server = {"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
              "api_key": "k", "org_filter_type": "include",
              "org_filter": f"{ORG_FILTER} 55f6ea5e-2c60-40e5-964f-47a8950d210f"}
    misp = mock.Mock()
    misp.get_organisation.return_value = SimpleNamespace(name=ORG_NAME)

    store = {name: mock.Mock(return_value=[]) for name in (
        "galaxy_geography", "galaxy_sectors", "galaxy_threat_actors",
        "galaxy_mitre_attack_patterns", "list_selectable_pirs", "list_pirs")}
    store.update(
        fetch_source_events=mock.Mock(return_value=[event]),
        list_collection_sources=mock.Mock(return_value=[source]),
        list_stakeholders=mock.Mock(return_value=[stakeholder]),
        get_stakeholder=mock.Mock(return_value=stakeholder),
        delete_stakeholder=mock.Mock(),
        delete_collection_source=mock.Mock(),
    )
    from webapp import audit, misp_store
    return [
        mock.patch("requests.adapters.HTTPAdapter.send", no_network),
        mock.patch("pymisp.PyMISP", return_value=misp),
        mock.patch.object(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
        mock.patch.object(_config, "MISP_SERVERS", [server]),
        mock.patch.object(audit, "record"),
        mock.patch.multiple(misp_store, **store),
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

    def assert_delete_form_asks(self, url, message):
        """The name sits whole inside the confirmation text, with no handler to escape into."""
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        forms = [f for f in _FormAttrs(resp.get_data(as_text=True)).forms
                 if f.get("data-submit-confirm") == message]
        self.assertEqual(len(forms), 1)
        self.assertEqual([k for k in forms[0] if k.startswith("on")], [])

    def test_a_source_name_cannot_add_attributes_to_its_delete_form(self):
        self.assert_delete_form_asks("/config/sources/", f"Delete source {SOURCE_NAME}?")

    def test_a_stakeholder_name_cannot_break_out_of_its_delete_confirmation(self):
        self.assert_delete_form_asks("/stakeholders/", f"Delete {STAKEHOLDER_NAME}?")

    def test_the_wizards_set_event_details_as_text(self):
        """The event title, creator organisation and date come straight from MISP."""
        for path, func in (("webapp/templates/flash_intel/wizard.html", "renderUuidMeta"),
                           ("webapp/templates/vea/wizard.html", "renderVeaUuidMeta")):
            source = Path(path).read_text()
            body = re.search(r"function %s\(.*?\n  \}\n" % func, source, re.S).group(0)
            self.assertNotIn("innerHTML", body, path)


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
        # Nothing leaves the machine: CDN scripts are not needed for these checks.
        self.page.route("**/*", lambda route: route.continue_()
                        if route.request.url.startswith(self.base_url) else route.abort())
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

    def assert_nothing_ran(self):
        # Give any onerror a moment to fire on the broken image.
        self.page.wait_for_timeout(300)
        self.assertIsNone(self.page.evaluate("window.__xss"))

    def check_wizard(self, path, box):
        self.open(f"{path}?source={EVENT_UUID}|scraper")
        meta = self.page.locator(box).first
        meta.get_by_text("Title:").wait_for()
        self.assert_nothing_ran()
        text = meta.inner_text()
        self.assertIn(EVENT_TITLE, text)
        self.assertIn(EVENT_ORG, text)
        self.assertEqual(meta.locator("img, svg").count(), 0)

    def test_fia_wizard_shows_the_event_title_as_text(self):
        self.check_wizard("/products/flash-intel/new", ".uuid-meta")

    def test_vea_wizard_shows_the_event_title_as_text(self):
        self.check_wizard("/products/vea/new", ".vea-uuid-meta")

    def test_org_filter_and_org_names_are_shown_as_text(self):
        self.open("/config/sources/")
        labels = self.page.locator(".org-uuid-labels").first
        labels.get_by_text(ORG_NAME).first.wait_for()
        self.assert_nothing_ran()
        self.assertIn(ORG_FILTER, labels.inner_text())
        self.assertEqual(labels.locator("img").count(), 0)

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
        self.assertEqual(self.dialogs, [f"Delete {STAKEHOLDER_NAME}?"])
        self.store.delete_stakeholder.assert_not_called()

    def test_accepting_the_confirmation_still_deletes(self):
        self.answer = True
        self.open("/stakeholders/")
        with self.page.expect_navigation():
            self.page.locator("form[data-submit-confirm] button").click()
        self.store.delete_stakeholder.assert_called_once_with("sh-1")


if __name__ == "__main__":
    unittest.main()
