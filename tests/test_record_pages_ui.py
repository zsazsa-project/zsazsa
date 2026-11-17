"""Browser checks for the stakeholder, PIR, GIR and RFI pages: what only shows
once a browser lays the page out.

A record's banner is as tall as a stakeholder's, with its buttons at the bottom
left. A status badge in a stakeholder's requirements stays inside the card.
A form's "As it will appear" card stays where it is when the page scrolls;
the stakeholder form's side column follows it. "Triage it on the list" opens the record's triage form on the list and
brings its row into view.

The app is served with the records stubbed, so these need no MISP, but they
drive a real Chromium and are opt-in like the other browser checks:

    ZSAZSA_UI_TESTS=1 python -m unittest tests.test_record_pages_ui
"""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from test_requirement_pages import _gir, _pir, _rfi, _uuid  # noqa: E402
from test_stakeholders import UUID, _stakeholder  # noqa: E402

UI_TESTS = os.environ.get("ZSAZSA_UI_TESTS") == "1"
CHROME = os.environ.get("ZSAZSA_UI_CHROME") or None

PIRS = ([_pir(1, status="Active", owner_uuid=UUID, out_of_scope=["Consumer fraud"])]
        + [_pir(n, status="Active") for n in range(10, 40)]
        + [_pir(2, status="Under Evaluation", distribution=[UUID]), _pir(3, status="Pending")])
GIRS = [_gir(4, status="Active", description="Track the affiliates and the access brokers.")]
RFIS = [_rfi(5, "In Progress"), _rfi(6, "New")]
RECORDS = {r.id: r for r in PIRS + GIRS + RFIS}


@unittest.skipUnless(UI_TESTS, "set ZSAZSA_UI_TESTS=1 to run the browser checks")
class RecordPagesInTheBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from unittest import mock

        from playwright.sync_api import sync_playwright
        from werkzeug.serving import make_server

        import config
        from webapp import collection_cache, create_app, misp_store

        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        ada = _stakeholder(influence=8, interest=8)
        galaxies = {name: mock.Mock(return_value=[]) for name in (
            "galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        found = {"pirs_for_stakeholder": [PIRS[0]], "girs_for_stakeholder": [],
                 "pirs_distributed_to_stakeholder": [PIRS[-2]], "girs_distributed_to_stakeholder": [],
                 "products_for_stakeholder": [], "records_owned_by_stakeholders": {}, "list_product_feedback": [],
                 "list_stakeholders": [ada], "get_stakeholder": ada,
                 "list_pirs": PIRS, "list_girs": GIRS, "list_rfis": RFIS}
        # The theme with the sticky menu across the top, which the Save card
        # once stuck behind.
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        # Without a name the app asks MISP for the session cookie's.
                        mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
                        mock.patch.object(config, "THEME", "overmind", create=True),
                        mock.patch.object(collection_cache, "start_worker"),
                        mock.patch.multiple(misp_store, **{name: mock.Mock(return_value=value) for name, value in found.items()}),
                        mock.patch.multiple(misp_store, **{name: mock.Mock(side_effect=RECORDS.get)
                                                           for name in ("get_pir", "get_gir", "get_rfi")}),
                        mock.patch.multiple(misp_store, **galaxies)):
            patcher.start()
            cls.addClassCleanup(patcher.stop)

        cls._server = make_server("127.0.0.1", 0, create_app(), threaded=True)
        cls.base_url = f"http://127.0.0.1:{cls._server.server_port}"
        thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(cls._server.shutdown)

        cls._playwright = sync_playwright().start()
        cls.addClassCleanup(cls._playwright.stop)
        cls.browser = cls._playwright.chromium.launch(executable_path=CHROME)
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.errors = []
        self.page = self.browser.new_page(viewport={"width": 1440, "height": 900})
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))

    def tearDown(self):
        self.assertEqual(self.errors, [], "the page raised JavaScript errors")
        self.page.close()

    def open(self, path):
        response = self.page.goto(self.base_url + path, wait_until="load")
        self.assertEqual(response.status, 200)
        self.page.wait_for_timeout(300)

    def test_every_record_banner_is_as_tall_as_a_stakeholders_with_its_buttons_at_the_bottom_left(self):
        heights = {}
        for path in (f"/stakeholders/{UUID}", f"/pirs/{_uuid(1)}", f"/girs/{_uuid(4)}", f"/rfis/{_uuid(5)}"):
            with self.subTest(path):
                self.open(path)
                hero, edit = self.page.evaluate("""() => {
                    const box = el => { const r = el.getBoundingClientRect(); return [r.left, r.bottom, r.height]; };
                    const hero = document.querySelector('.record-hero');
                    return [box(hero), box(hero.querySelector('.hero-actions .btn'))]; }""")
                heights[path] = round(hero[2])
                self.assertLess(edit[0] - hero[0], 30, "the buttons start at the left of the banner")
                self.assertLess(hero[1] - edit[1], 20, "the buttons are at the bottom of the banner")
        self.assertEqual(len(set(heights.values())), 1, heights)

    def test_a_status_badge_stays_inside_the_requirements_card(self):
        self.open(f"/stakeholders/{UUID}")
        outside = self.page.evaluate("""() => [...document.querySelectorAll('.req-row .badge')]
            .filter(b => b.getBoundingClientRect().right > b.closest('.card').getBoundingClientRect().right)
            .map(b => b.textContent.trim())""")
        self.assertEqual(outside, [])

    def test_the_save_card_stays_where_it_is_when_the_page_scrolls(self):
        """It followed the page down, which confused more than it helped. The
        stakeholder form's side column still follows it."""
        for path, card, moves in (("/pirs/new", ".form-save", False), ("/girs/new", ".form-save", False),
                                  ("/rfis/new", ".form-save", False), (f"/pirs/{_uuid(1)}/edit", ".form-save", False),
                                  (f"/stakeholders/{UUID}/edit", ".form-aside", True)):
            with self.subTest(path):
                self.open(path)
                tops = []
                for share in (0, .5, 1):
                    self.page.evaluate("share => window.scrollTo({top: document.documentElement.scrollHeight * share,"
                                       " behavior: 'instant'})", share)
                    self.page.wait_for_timeout(100)
                    # Where the card is on the page, not in the window.
                    tops.append(self.page.evaluate(
                        "sel => Math.round(document.querySelector(sel).getBoundingClientRect().top + scrollY)", card))
                self.assertEqual(len(set(tops)) > 1, moves, tops)

    def test_triage_on_the_list_opens_the_records_triage_form(self):
        """The pending PIR is under thirty active ones, so the list has to
        scroll to reach it."""
        for path, record, form, scrolls in ((f"/pirs?triage={_uuid(3)}", _uuid(3), f"triage-row-{_uuid(3)}", True),
                                            (f"/rfis/?triage={_uuid(6)}", _uuid(6), f"rfi-triage-row-{_uuid(6)}", None)):
            with self.subTest(path):
                self.open(path)
                self.page.wait_for_timeout(700)
                shown = self.page.evaluate(f"""() => {{
                    const record = document.querySelector('tr[data-req-id="{record}"]').getBoundingClientRect();
                    const menu = document.getElementById('topnav').getBoundingClientRect();
                    return [document.getElementById('{form}').classList.contains('d-none'),
                            record.top >= menu.bottom && record.bottom <= innerHeight, scrollY > 0]; }}""")
                self.assertEqual(shown[:2], [False, True])
                if scrolls:
                    self.assertTrue(shown[2], "the list did not scroll to the record")


if __name__ == "__main__":
    unittest.main()
