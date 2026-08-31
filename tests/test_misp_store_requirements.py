"""What update_pir, update_gir and update_rfi refuse to lose.

A requirement and an RFI are each one MISP object, and an update writes whatever
the caller hands it: a relation left out of that object is soft-deleted. Three
callers legitimately send only part of the record, so the store has to hold on to
the rest itself. Every rule here was written after the data was already gone.

Stubs _misp and the object writers so it runs offline.

    python -m unittest tests.test_misp_store_requirements
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store


def _pir_data(**overrides):
    data = {"pir_id": "PIR-001", "question": "Are our hauliers targeted?",
            "status": "Active", "geographic_scope": ["Belgium"]}
    data.update(overrides)
    return data


def _gir_data(**overrides):
    data = {"gir_id": "GIR-001", "topic": "Ransomware in transport", "status": "Active"}
    data.update(overrides)
    return data


class RequirementScopeItems(unittest.TestCase):
    """Saving the form replaces the scope items; a status change or a Kanban move
    posts none and has to leave them where they are."""

    def setUp(self):
        self.misp = mock.MagicMock()
        self.misp.get_event.return_value = SimpleNamespace(id=7, uuid="u" * 36)
        patches = [
            mock.patch.object(misp_store, "_misp", return_value=self.misp),
            mock.patch.object(misp_store, "_get_obj", return_value=None),
            mock.patch.object(misp_store, "_sync_object_attributes"),
            mock.patch.object(misp_store, "_apply_scope_tags"),
            mock.patch.object(misp_store, "_replace_focus_points"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.replace = misp_store._replace_focus_points

    def test_a_pir_update_without_scope_items_leaves_them_alone(self):
        misp_store.update_pir("u" * 36, _pir_data())
        self.replace.assert_not_called()

    def test_a_pir_update_with_scope_items_replaces_them(self):
        points = [{"category": "Sector", "value": "Transport", "notes": ""}]
        misp_store.update_pir("u" * 36, _pir_data(focus_points=points))
        self.replace.assert_called_once_with("u" * 36, points)

    def test_a_pir_saved_with_no_scope_left_clears_its_items(self):
        """An empty list is a decision the form made, unlike a missing key."""
        misp_store.update_pir("u" * 36, _pir_data(focus_points=[]))
        self.replace.assert_called_once_with("u" * 36, [])

    def test_a_gir_update_without_scope_items_leaves_them_alone(self):
        misp_store.update_gir("u" * 36, _gir_data())
        self.replace.assert_not_called()

    def test_a_gir_update_with_scope_items_replaces_them(self):
        points = [{"category": "Vendor", "value": "Bosch", "notes": ""}]
        misp_store.update_gir("u" * 36, _gir_data(focus_points=points))
        self.replace.assert_called_once_with("u" * 36, points)


class RfiIdentity(unittest.TestCase):
    """The id is what an RFI is called everywhere it appears, and it lives in the
    object like any other field, so an update that omits it deletes it."""

    def setUp(self):
        self.misp = mock.MagicMock()
        self.misp.get_event.return_value = SimpleNamespace(id=7, uuid="u" * 36)
        stored = {"creator": "koen@example.org", "rfi-id": "RFI-007"}
        patches = [
            mock.patch.object(misp_store, "_misp", return_value=self.misp),
            mock.patch.object(misp_store, "_get_obj", return_value=SimpleNamespace()),
            mock.patch.object(misp_store, "_obj_attr", side_effect=lambda _obj, rel: stored.get(rel, "")),
            mock.patch.object(misp_store, "_sync_object_attributes"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def update(self, **data):
        data.setdefault("question", "Which hauliers were hit?")
        misp_store.update_rfi("u" * 36, data)
        return data, self.misp.update_event.call_args.args[0]["Event"]["info"]

    def test_an_update_that_forgets_the_id_keeps_the_stored_one(self):
        data, info = self.update()
        self.assertEqual(data.get("rfi_id"), "RFI-007")
        self.assertIn("RFI-007", info)

    def test_an_update_that_sends_the_id_uses_it(self):
        data, info = self.update(rfi_id="RFI-009")
        self.assertEqual(data["rfi_id"], "RFI-009")
        self.assertIn("RFI-009", info)

    def test_the_creator_is_carried_over_too(self):
        data, _info = self.update()
        self.assertEqual(data.get("creator"), "koen@example.org")


if __name__ == "__main__":
    unittest.main()
