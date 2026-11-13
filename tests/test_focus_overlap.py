"""The overlap of a PIR's or GIR's scope with the organisation-wide focus points.

The Scope card opens a list of the focus points beside the record's scope items,
with the ones they share marked, and a scope item that is not a focus point can
be added to them, by a site admin only. A scope item that is a focus point has
the bullseye wherever it is listed or picked. Adding writes the config file,
here a temporary copy, and goes back to the record whatever the form says.

MISP and the galaxies are patched; the database and log are temporary.

    python -m unittest tests.test_focus_overlap
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

from pymisp import MISPEvent

import config
from core import db as core_db
from webapp import collection_cache, create_app, misp_session, misp_store
from webapp.routes import config_page

UUID = "8006520f-a3a7-4f2d-b2e6-c94c79c7f2c4"
FOCUS = {"FOCUS_POINTS_GEOGRAPHIES": ["Belgium"], "FOCUS_POINTS_SECTORS": ["Energy"],
         "FOCUS_POINTS_VENDORS": ["Fortinet"], "FOCUS_POINTS_TECHNOLOGIES": [],
         "FOCUS_POINTS_THREAT_TYPES": [], "FOCUS_POINTS_THREAT_ACTORS": []}
HOSTILE = 'Acme "><script>alert(1)</script>'


def _scope(*pairs):
    return [SimpleNamespace(id=f"fp{n}", category=c, value=v) for n, (c, v) in enumerate(pairs)]


SCOPE = _scope(("Geography", "Belgium"), ("Geography", "Europe"), ("Vendor", "fortinet"),
               ("Vendor", HOSTILE), ("Incident", "SolarWinds"))


def _record(kind, **data):
    """A PIR or GIR as the store reads it from MISP, with SCOPE as its scope items."""
    event = MISPEvent()
    event.id = "12"
    event.uuid = UUID
    event.date = "2026-10-01"
    event.add_object(getattr(misp_store, f"_{kind}_obj")({"status": "Active", **data}))
    record = getattr(misp_store, f"_{kind}_ns")(event)
    record.focus_points = SCOPE
    return record


class _App(unittest.TestCase):
    admin = True

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        galaxies = {"galaxy_geography": mock.Mock(return_value=["Belgium", "Europe", "France"]),
                    "galaxy_sectors": mock.Mock(return_value=["Energy", "Finance"]),
                    "galaxy_threat_actors": mock.Mock(return_value=[]),
                    "galaxy_mitre_attack_patterns": mock.Mock(return_value=[])}
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.multiple(config, create=True, **FOCUS),
            mock.patch.multiple(misp_store, **galaxies),
            mock.patch.object(misp_session, "current_user_is_admin", return_value=self.admin),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        core_db.init_db()
        self.client = create_app().test_client()

    def soup(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")


class RequirementPages(_App):
    def setUp(self):
        super().setUp()
        pir = _record("pir", pir_id="PIR-00003", question="Who takes over accounts?")
        gir = _record("gir", gir_id="GIR-00001", topic="Grid", geographic_scope=["Belgium", "Europe"],
                      vendor=["fortinet"])
        for patcher in (
            mock.patch.object(misp_store, "get_pir", return_value=pir),
            mock.patch.object(misp_store, "get_gir", return_value=gir),
            mock.patch.object(misp_store, "list_stakeholders", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "list_girs", return_value=[]),
            mock.patch.object(misp_store, "pir_collection_gap", return_value={}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_overlap_opens_from_the_scope_card(self):
        for kind in ("pirs", "girs"):
            page = self.soup(f"/{kind}/{UUID}")
            button = page.select_one('[data-bs-target="#scope-overlap"]')
            self.assertIn("Overlap with focus points", button.get_text())
            self.assertNotIn("show", page.select_one("#scope-overlap")["class"])
            self.assertIn("show", self.soup(f"/{kind}/{UUID}?overlap=1").select_one("#scope-overlap")["class"])

    def test_the_shared_items_are_marked_on_both_sides(self):
        overlap = self.soup(f"/pirs/{UUID}").select_one("#scope-overlap")
        text = " ".join(overlap.get_text(" ", strip=True).split())
        self.assertIn("2 of the 5 scope items of this PIR are focus points.", text)
        columns = overlap.select(".col-md-6")
        shared = [[c.get_text(strip=True) for c in col.select(".overlap-chip.is-shared")] for col in columns]
        self.assertEqual(shared, [["Belgium", "Fortinet"], ["Belgium", "fortinet"]])
        self.assertIn("Energy", columns[0].get_text())

    def test_a_scope_item_can_be_added_to_the_focus_points(self):
        overlap = self.soup(f"/pirs/{UUID}").select_one("#scope-overlap")
        forms = overlap.select("form")
        self.assertEqual([f.select_one('[name="value"]')["value"] for f in forms], ["Europe", HOSTILE])
        europe = forms[0]
        self.assertEqual(europe["action"], "/config/focus-points/add")
        self.assertEqual({i["name"]: i["value"] for i in europe.select("input")},
                         {"kind": "pir", "id": UUID, "category": "Geography", "value": "Europe"})
        self.assertIn("Add Europe to the geography focus points?", europe["data-submit-confirm"])
        self.assertIsNone(europe.select_one("button").get("disabled"))

    def test_untrusted_text_stays_text(self):
        page = self.soup(f"/pirs/{UUID}")
        self.assertEqual([s for s in page.find_all("script") if "alert(1)" in s.text], [])
        hostile = page.select("#scope-overlap form")[1]
        self.assertEqual(hostile["data-submit-confirm"].split("?")[0], f"Add {HOSTILE} to the vendor focus points")

    def test_a_record_without_scope(self):
        with mock.patch.object(misp_store.get_pir.return_value, "focus_points", []):
            overlap = self.soup(f"/pirs/{UUID}").select_one("#scope-overlap")
        text = " ".join(overlap.get_text(" ", strip=True).split())
        self.assertIn("This PIR has no scope items yet.", text)
        self.assertIn("Belgium", text)
        self.assertEqual(overlap.select("form"), [])

    def test_no_focus_point_list_no_button(self):
        overlap = self.soup(f"/pirs/{UUID}").select_one("#scope-overlap")
        solarwinds = [c for c in overlap.select(".overlap-chip") if "SolarWinds" in c.get_text()][0]
        self.assertIsNone(solarwinds.select_one("form"))
        self.assertIn("no focus point list", solarwinds.get_text())

    def test_the_scope_list_marks_the_focus_points(self):
        for kind in ("pirs", "girs"):
            page = self.soup(f"/{kind}/{UUID}")
            marked = [v.get_text(strip=True) for v in page.select(".fp-value") if v.select_one(".focus-mark")]
            self.assertEqual(marked, ["Belgium", "fortinet"], kind)
            self.assertEqual(page.select_one(".fp-value .focus-mark")["title"], "Also a focus point of the organisation")

    def test_the_second_scope_card_of_a_gir_marks_them_too(self):
        page = self.soup(f"/girs/{UUID}")
        tags = [t.get_text(strip=True) for t in page.select(".detail-list .source-tag") if t.select_one(".focus-mark")]
        self.assertEqual(tags, ["Belgium", "fortinet"])

    def test_the_pickers_mark_the_focus_points(self):
        """The detail page's add form and the edit form, galaxy and free text."""
        for path in (f"/pirs/{UUID}", f"/pirs/{UUID}/edit", f"/girs/{UUID}/edit", "/pirs/new"):
            page = self.soup(path)
            marked = {cb["value"] for cb in page.select('.gms-list input[data-focus]')}
            self.assertEqual(marked, {"Belgium", "Energy"}, path)
            label = page.select_one('.gms-list input[value="Belgium"]').find_parent("label")
            self.assertIsNotNone(label.select_one(".focus-mark"), path)
        vendor = self.soup(f"/pirs/{UUID}/edit").select_one('[data-ti-field="vendor"]')
        self.assertEqual(vendor["data-ti-focus"], '{"fortinet": "Fortinet"}')


    def test_the_edit_forms_have_the_overlap_too(self):
        """It follows the pickers in the page, so the server sends only what it
        needs, and nothing the form would save."""
        for kind in ("pir", "gir"):
            for path in (f"/{kind}s/{UUID}/edit", f"/{kind}s/new"):
                page = self.soup(path)
                button = page.select_one('[data-bs-target="#scope-overlap"]')
                self.assertIn("Overlap with focus points", button.get_text(), path)
                self.assertEqual(button["type"], "button", path)
                panel = page.select_one("form #scope-overlap")
                self.assertEqual(panel["data-kind"], kind.upper(), path)
                self.assertEqual(json.loads(panel["data-focus"])["Vendor"], {"fortinet": "Fortinet"}, path)
                self.assertEqual(panel["data-admin"], "true" if self.admin else "false", path)
                self.assertEqual(panel["data-url"], "/config/focus-points/add", path)
                self.assertEqual(panel.select("[name]"), [], path)


class NotAnAdmin(RequirementPages):
    admin = False

    def test_a_scope_item_can_be_added_to_the_focus_points(self):
        overlap = self.soup(f"/pirs/{UUID}").select_one("#scope-overlap")
        button = overlap.select_one("form button")
        self.assertIsNotNone(button.get("disabled"))
        self.assertEqual(button.find_parent("span")["title"], "Only a site admin can change the focus points")


class AddFocusPoint(_App):
    def setUp(self):
        super().setUp()
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder)
        self.target = folder / "__init__.py"
        shutil.copy2("config/__init__.py.example", self.target)
        self.audit = mock.Mock()
        for patcher in (
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", folder / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record", self.audit),
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        namespace = {}
        exec(compile(self.target.read_text(), str(self.target), "exec"), namespace)
        return namespace

    def add(self, **form):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        return self.client.post("/config/focus-points/add",
                                data={"csrf_token": "test-token", "kind": "pir", "id": UUID, **form})

    def test_it_is_added_and_the_record_shown_again(self):
        response = self.add(category="Geography", value=" Europe ")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], f"/pirs/{UUID}?overlap=1#scope-overlap")
        saved = self.saved()
        self.assertEqual(saved["FOCUS_POINTS_GEOGRAPHIES"], ["Belgium", "Europe"])
        self.assertEqual(saved["FOCUS_POINTS_VENDORS"], ["Fortinet"])
        self.audit.assert_called_once_with("update", "config", entity_label="focus-points",
                                           details="FOCUS_POINTS_GEOGRAPHIES: added Europe")

    def test_a_gir_goes_back_to_the_gir(self):
        response = self.add(kind="gir", category="Sector", value="Finance")
        self.assertEqual(response.headers["Location"], f"/girs/{UUID}?overlap=1#scope-overlap")
        self.assertEqual(self.saved()["FOCUS_POINTS_SECTORS"], ["Energy", "Finance"])

    def test_a_value_with_quotes_stays_a_value(self):
        self.add(category="Vendor", value=HOSTILE + "'\\")
        self.assertEqual(self.saved()["FOCUS_POINTS_VENDORS"], ["Fortinet", HOSTILE + "'\\"])

    def test_nothing_is_written_for_what_cannot_be_a_focus_point(self):
        before = self.target.read_text()
        for form in ({"category": "Geography", "value": "BELGIUM"}, {"category": "Incident", "value": "SolarWinds"},
                     {"category": "Geography", "value": "  "}, {"category": "nope", "value": "x"}, {}):
            response = self.add(**form)
            self.assertEqual(response.status_code, 302, form)
        self.assertEqual(self.target.read_text(), before)
        self.audit.assert_not_called()

    def test_the_way_back_is_always_inside_zsazsa(self):
        for kind, record_id in (("pir", "https://evil.example"), ("pir", "../config"), ("x", UUID), ("pir", "")):
            response = self.add(kind=kind, id=record_id, category="Geography", value="France")
            self.assertEqual(response.headers["Location"], "/config?tab=tab-products#products-focus",
                             (kind, record_id))

    def post_json(self, body):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        return self.client.post("/config/focus-points/add", json=body, headers={"X-CSRF-Token": "test-token"})

    def test_the_edit_form_adds_without_leaving(self):
        response = self.post_json({"category": "Vendor", "value": " Cisco "})
        self.assertEqual((response.status_code, response.get_json()),
                         (200, {"ok": True, "message": "Cisco is now a focus point."}))
        self.assertEqual(self.saved()["FOCUS_POINTS_VENDORS"], ["Fortinet", "Cisco"])
        self.audit.reset_mock()
        with mock.patch.object(config, "FOCUS_POINTS_VENDORS", ["Fortinet", "Cisco"]):
            again = self.post_json({"category": "Vendor", "value": "CISCO"})
        self.assertEqual(again.get_json(), {"ok": True, "message": "CISCO is already a focus point."})
        self.audit.assert_not_called()

    def test_the_edit_form_is_told_what_was_refused(self):
        before = self.target.read_text()
        for body in ({"category": "Campaign", "value": "x"}, {"category": "Vendor", "value": ""},
                     {"category": ["Vendor"], "value": {"a": 1}}, ["Vendor", "x"]):
            response = self.post_json(body)
            self.assertEqual(response.status_code, 400, body)
            self.assertFalse(response.get_json()["ok"], body)
        self.assertEqual(self.target.read_text(), before)

    def test_a_failed_save_says_so(self):
        with mock.patch.object(config_page, "write_atomically", side_effect=OSError("disk full")), \
             self.assertLogs(config_page.logger, "ERROR"):
            response = self.post_json({"category": "Vendor", "value": "Cisco"})
        self.assertEqual((response.status_code, response.get_json()["ok"]), (500, False))
        self.audit.assert_not_called()

    def test_only_a_site_admin(self):
        before = self.target.read_text()
        with mock.patch.object(config_page.misp_session, "refuse_unless_site_admin",
                               return_value=("Only MISP site admins can open the zsazsa settings.", 403)):
            response = self.add(category="Geography", value="Europe")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.target.read_text(), before)


if __name__ == "__main__":
    unittest.main()
