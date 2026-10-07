"""Text from MISP or from another user must stay text on the page (GHSA-2hmh-2qrq-872r).

An event title from a sync partner or the scraper, an organisation filter or a
name someone saved reached the page as markup: through innerHTML in the FIA and
VEA wizards and on the collection sources page, and through inline onsubmit
handlers that the name could break out of. Each one ran script in the session of
whoever opened the page.

The first two classes run offline as part of the normal suite. The last one
drives a real Chromium against the webapp with every MISP call mocked and every
outbound request blocked, so it is opt-in like the other browser checks:

    python -m unittest tests.test_xss_sinks
    ZSAZSA_UI_TESTS=1 python -m unittest tests.test_xss_sinks
"""

import os
import re
import shutil
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests
from flask import Flask

import config as _config
from webapp.routes import config_page

UI_TESTS = os.environ.get("ZSAZSA_UI_TESTS") == "1"
CHROME = os.environ.get("ZSAZSA_UI_CHROME") or None

ORG_UUID = "55f6ea5e-2c60-40e5-964f-47a8950d210f"
EVENT_UUID = "11111111-2222-3333-4444-555555555555"
SOURCE_UUID = "66666666-7777-8888-9999-000000000000"

# Each payload sets window.__xss when it runs, so the browser checks can tell.
EVENT_TITLE = '<img src=x onerror="window.__xss=1">'
EVENT_ORG = '<svg onload="window.__xss=1">'
ORG_FILTER = "<img/src=x/onerror=window.__xss=1>"
ORG_NAME = '<img src=x onerror="window.__xss=1">'
SOURCE_NAME = "x onmouseover=window.__xss=1 y"
STAKEHOLDER_NAME = "x');window.__xss=1;('"


class _Forms(HTMLParser):
    """Collects the attributes of every form, entity-decoded as a browser sees them."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.forms.append(dict(attrs))


def _forms(html):
    parser = _Forms()
    parser.feed(html)
    return parser.forms


def _offline_patches():
    """Everything the four pages ask MISP for, answered with hostile data."""
    def no_network(*args, **kwargs):
        raise requests.ConnectionError("tests run offline")

    event = {"uuid": EVENT_UUID, "info": EVENT_TITLE, "orgc": EVENT_ORG,
             "date": "2026-10-01", "source_id": "scraper", "source_label": "Scraper"}
    source = SimpleNamespace(uuid=SOURCE_UUID, name=SOURCE_NAME, enabled=True,
                             source_reliability="", description="", location="", owner="")
    stakeholder = SimpleNamespace(id="sh-1", name=STAKEHOLDER_NAME, stakeholder_type="Internal",
                                  email="", role="", organization="", tlp_clearance="amber",
                                  products=[])
    server = {"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
              "api_key": "k", "verify_tls": True, "enabled": True, "tags": "", "tags_and": "",
              "tags_not": "", "org_filter_type": "include",
              "org_filter": f"{ORG_FILTER} {ORG_UUID}", "since_days": 7, "limit": 500}

    misp = mock.Mock()
    misp.get_organisation.side_effect = lambda uuid, pythonify: SimpleNamespace(name=ORG_NAME)

    store = {name: mock.Mock(return_value=[]) for name in (
        "galaxy_geography", "galaxy_sectors", "galaxy_threat_actors",
        "galaxy_mitre_attack_patterns", "list_selectable_pirs", "list_pirs")}
    store.update(
        fetch_source_events=mock.Mock(return_value=[event]),
        list_collection_sources=mock.Mock(return_value=[source]),
        list_stakeholders=mock.Mock(return_value=[stakeholder]),
        get_stakeholder=mock.Mock(return_value=stakeholder),
        get_collection_source=mock.Mock(return_value=source),
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

    def get(self, url):
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200, url)
        return resp.get_data(as_text=True)

    def assert_name_only_in_confirm(self, html, name, message):
        """The name reaches the delete form as one attribute's text and nothing else."""
        carrying = [f for f in _forms(html) if any(name in (v or "") for v in f.values())]
        self.assertEqual(len(carrying), 1)
        form = carrying[0]
        self.assertEqual(form.get("data-submit-confirm"), message)
        self.assertEqual([k for k in form if k.startswith("on")], [])

    def test_a_source_name_cannot_add_attributes_to_its_delete_form(self):
        html = self.get("/config/sources/")
        self.assert_name_only_in_confirm(html, SOURCE_NAME, f"Delete source {SOURCE_NAME}?")
        for form in _forms(html):
            self.assertNotIn("onmouseover", form)

    def test_a_stakeholder_name_cannot_break_out_of_its_delete_confirmation(self):
        html = self.get("/stakeholders/")
        self.assert_name_only_in_confirm(html, STAKEHOLDER_NAME, f"Delete {STAKEHOLDER_NAME}?")

    def test_the_wizards_set_event_details_as_text(self):
        """The event title, creator organisation and date come straight from MISP."""
        for path, func in (("webapp/templates/flash_intel/wizard.html", "renderUuidMeta"),
                           ("webapp/templates/vea/wizard.html", "renderVeaUuidMeta")):
            source = Path(path).read_text()
            body = re.search(r"function %s\(.*?\n  \}\n" % func, source, re.S).group(0)
            self.assertNotIn("innerHTML", body, path)


class OrgFilterIsValidated(unittest.TestCase):
    """The organisation filter is a list of organisation UUIDs and nothing else."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        for patcher in (
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, org_filter):
        return self.client.post("/config/sources/save-server", json={
            "label": "Partner", "url": "https://misp.partner.example",
            "org_filter_type": "include", "org_filter": org_filter,
        })

    def test_markup_is_refused_and_nothing_is_written(self):
        before = self.target.read_text()
        resp = self.save(ORG_FILTER)
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()["ok"])
        self.assertEqual(self.target.read_text(), before)

    def test_one_bad_entry_among_uuids_is_refused(self):
        self.assertEqual(self.save(f"{ORG_UUID}, not-a-uuid").status_code, 400)

    def test_uuids_separated_by_commas_or_spaces_are_kept(self):
        value = f"{ORG_UUID}, {ORG_UUID.upper()}\n{ORG_UUID}"
        resp = self.save(value)
        self.assertTrue(resp.get_json()["ok"])
        self.assertIn(repr(value), self.target.read_text())

    def test_an_empty_filter_is_still_allowed(self):
        self.assertTrue(self.save("").get_json()["ok"])


@unittest.skipUnless(UI_TESTS, "set ZSAZSA_UI_TESTS=1 to run the browser checks")
class HostileTextInTheBrowser(unittest.TestCase):
    """The pages as an analyst would open them, with the hostile data loaded."""

    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        from werkzeug.serving import make_server

        cls.patches = _offline_patches()
        _start(cls, cls.patches)
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
