"""Creating and editing PIRs and GIRs, where the scope lists are deduplicated.

The galaxy pickers hand back whatever casing the analyst clicked, so the same
country can arrive twice. requirements.py runs those lists through dedup_lower
before storing them, and for a while it did so without importing the function:
every PIR and GIR create and edit answered HTTP 500. These checks post the forms
the way a browser does, so a missing name fails here rather than in production.

    python -m unittest tests.test_requirements_scope_dedup
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp.routes import requirements


def _app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test"
    app.register_blueprint(requirements.bp)
    return app


class CreatingAndEditing(unittest.TestCase):
    def setUp(self):
        self.client = _app().test_client()

    def _post(self, path, store_call, **fields):
        """Post a minimal form and return the data the store was handed."""
        captured = {}

        def remember(*args, **kwargs):
            captured.update(args[-1] if isinstance(args[-1], dict) else {})
            return "u" * 36

        existing = SimpleNamespace(uuid="u" * 36, pir_id="PIR-00001", gir_id="GIR-00001",
                                   question="q", topic="t", focus_points=[], status="Active")
        with mock.patch.object(requirements.misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(requirements.misp_store, "get_pir", return_value=existing), \
             mock.patch.object(requirements.misp_store, "get_gir", return_value=existing), \
             mock.patch.object(requirements.misp_store, store_call, side_effect=remember), \
             mock.patch.object(requirements.misp_store, "get_all_collection_source_labels", return_value=[]), \
             mock.patch.object(requirements.audit, "record"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            reply = self.client.post(path, data={"question": "Q?", "topic": "T", **fields})
        return reply, captured

    def test_a_new_pir_is_stored_rather_than_erroring(self):
        reply, data = self._post("/pirs/new", "create_pir",
                                 geographic_scope=["Belgium", "belgium", "France"])
        self.assertNotEqual(reply.status_code, 500)
        self.assertEqual(data["geographic_scope"], ["Belgium", "France"])

    def test_editing_a_pir_dedups_its_scope_too(self):
        reply, data = self._post(f"/pirs/{'u' * 36}/edit", "update_pir",
                                 sectors=["Energy", "energy"])
        self.assertNotEqual(reply.status_code, 500)
        self.assertEqual(data["sectors"], ["Energy"])

    def test_a_new_gir_is_stored_rather_than_erroring(self):
        reply, data = self._post("/girs/new", "create_gir",
                                 threat_actors=["Luna Moth", "luna moth"])
        self.assertNotEqual(reply.status_code, 500)
        self.assertEqual(data["threat_actors"], ["Luna Moth"])

    def test_editing_a_gir_dedups_its_scope_too(self):
        reply, data = self._post(f"/girs/{'u' * 36}/edit", "update_gir",
                                 geographic_scope=["Poland", "POLAND"])
        self.assertNotEqual(reply.status_code, 500)
        self.assertEqual(data["geographic_scope"], ["Poland"])


def _fp(category, value, notes=""):
    return SimpleNamespace(id=f"{category}-{value}", uuid=f"{category}-{value}",
                           category=category, value=value, notes=notes)


class FocusPointsSurviveAnEdit(unittest.TestCase):
    """Saving the PIR form replaces every focus point on the requirement, so each
    category is rebuilt from the scope list posted for it. The notes an analyst
    typed, and any category the form has no field for, have to be carried over or
    each save quietly deletes them."""

    def setUp(self):
        self.client = _app().test_client()

    def edit(self, focus_points, **fields):
        captured = {}
        pir = SimpleNamespace(uuid="u" * 36, pir_id="PIR-00001", question="q",
                              status="Active", focus_points=focus_points)

        def remember(uuid, data):
            captured.update(data)
            return uuid

        with mock.patch.object(requirements.misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(requirements.misp_store, "get_pir", return_value=pir), \
             mock.patch.object(requirements.misp_store, "update_pir", side_effect=remember), \
             mock.patch.object(requirements.misp_store, "get_all_collection_source_labels", return_value=[]), \
             mock.patch.object(requirements.audit, "record"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            self.client.post(f"/pirs/{'u' * 36}/edit", data={"question": "Q?", **fields})
        return captured["focus_points"]

    def test_every_scope_field_on_the_form_becomes_a_focus_point(self):
        """Technology, vendor, incident and campaign are scope like any other, so
        a value typed into the form shows on the detail page and is matched."""
        points = self.edit([], technology=["Fortinet VPN"], vendor=["Ivanti"],
                           incident=["Storm-0501 intrusion"], campaign=["Spring phishing"])
        self.assertEqual(
            [(p["category"], p["value"]) for p in points],
            [("Technology", "Fortinet VPN"), ("Vendor", "Ivanti"),
             ("Incident", "Storm-0501 intrusion"), ("Campaign", "Spring phishing")])

    def test_a_note_on_a_technology_item_is_kept(self):
        points = self.edit([_fp("Technology", "Fortinet VPN", "edge devices")],
                           technology=["Fortinet VPN"])
        self.assertEqual(points, [{"category": "Technology", "value": "Fortinet VPN",
                                   "notes": "edge devices"}])

    def test_a_technology_item_left_off_the_form_is_dropped(self):
        points = self.edit([_fp("Technology", "Fortinet VPN")], sectors=["Energy"])
        self.assertEqual(points, [{"category": "Sector", "value": "Energy", "notes": ""}])

    def test_a_category_the_form_has_no_field_for_is_kept(self):
        """Nothing offered today lands here, but a record written before a
        category was renamed must not be deleted by a save that cannot see it."""
        points = self.edit([_fp("Malware", "Emotet", "old category")], sectors=["Energy"])
        self.assertIn({"category": "Malware", "value": "Emotet", "notes": "old category"}, points)

    def test_the_note_on_a_scope_item_is_kept(self):
        points = self.edit([_fp("Geography", "Belgium", "EU headquarters")],
                           geographic_scope=["Belgium"])
        self.assertEqual(points, [{"category": "Geography", "value": "Belgium",
                                   "notes": "EU headquarters"}])

    def test_a_scope_value_removed_on_the_form_is_dropped(self):
        points = self.edit([_fp("Sector", "Energy"), _fp("Sector", "Transport")],
                           sectors=["Energy"])
        self.assertEqual([p["value"] for p in points], ["Energy"])

    def test_a_requirement_with_no_focus_points_gains_them_from_the_form(self):
        points = self.edit([], sectors=["Energy"], threat_actors=["Lazarus Group"])
        self.assertEqual(points, [
            {"category": "Sector", "value": "Energy", "notes": ""},
            {"category": "Threat Actor", "value": "Lazarus Group", "notes": ""},
        ])

    def test_every_category_the_detail_page_offers_can_be_posted(self):
        """The add form on the detail page offers FOCUS_CATEGORIES; each one has
        to round-trip through the edit form or it is lost on the next save."""
        from webapp.models import FOCUS_CATEGORIES
        self.assertEqual(sorted(FOCUS_CATEGORIES), sorted(requirements._SCOPE_FP_FIELDS))


class ScopeItemsSurviveAStatusChange(unittest.TestCase):
    """Moving a requirement to another status posts no scope at all. The store
    replaces the scope items with whatever it is handed, so it must only do that
    when the caller actually sent them, or a Kanban move empties the scope."""

    def setUp(self):
        self.client = _app().test_client()

    def move(self, kind, status):
        captured = {}
        req = SimpleNamespace(
            uuid="u" * 36, pir_id="PIR-00001", gir_id="GIR-00001", question="q", topic="t",
            status="Active", intake_status="approved", focus_points=[_fp("Vendor", "Ivanti")])
        store = requirements.misp_store
        with mock.patch.object(store, f"{kind}_to_data", return_value={"status": "Active"}), \
             mock.patch.object(store, f"get_{kind}", return_value=req), \
             mock.patch.object(store, f"update_{kind}",
                               side_effect=lambda _uuid, data: captured.update(data)), \
             mock.patch.object(requirements.audit, "record"):
            self.client.post(f"/{kind}s/{'u' * 36}/status", data={"status": status})
        return captured

    def test_a_pir_status_change_sends_no_scope_items(self):
        self.assertNotIn("focus_points", self.move("pir", "Implemented"))

    def test_a_gir_status_change_sends_no_scope_items(self):
        self.assertNotIn("focus_points", self.move("gir", "Retired"))


class GirScopeItems(unittest.TestCase):
    """A GIR keeps its scope items in step with its scope lists, as a PIR does,
    so a vendor typed into the edit form shows on the detail page."""

    def setUp(self):
        self.client = _app().test_client()

    def save(self, path, store_call, existing=(), **fields):
        captured = {}
        gir = SimpleNamespace(uuid="u" * 36, gir_id="GIR-00001", topic="t",
                              status="Active", focus_points=list(existing))

        def remember(*args):
            captured.update(args[-1])
            return "u" * 36

        with mock.patch.object(requirements.misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(requirements.misp_store, "get_gir", return_value=gir), \
             mock.patch.object(requirements.misp_store, store_call, side_effect=remember), \
             mock.patch.object(requirements.misp_store, "get_all_collection_source_labels", return_value=[]), \
             mock.patch.object(requirements.audit, "record"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            self.client.post(path, data={"topic": "T", **fields})
        return captured["focus_points"]

    def test_a_new_gir_gets_scope_items_from_its_form(self):
        points = self.save("/girs/new", "create_gir", vendor=["Bosch"])
        self.assertEqual(points, [{"category": "Vendor", "value": "Bosch", "notes": ""}])

    def test_editing_a_gir_adds_the_scope_item_for_a_new_vendor(self):
        points = self.save(f"/girs/{'u' * 36}/edit", "update_gir",
                           existing=[_fp("Vendor", "Moxa", "OT gateways")],
                           vendor=["Moxa", "Bosch"])
        self.assertEqual(points, [
            {"category": "Vendor", "value": "Moxa", "notes": "OT gateways"},
            {"category": "Vendor", "value": "Bosch", "notes": ""},
        ])


if __name__ == "__main__":
    unittest.main()
