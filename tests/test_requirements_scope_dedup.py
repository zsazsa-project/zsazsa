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


if __name__ == "__main__":
    unittest.main()
