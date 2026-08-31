"""RFI saves and the SLA clock.

An RFI is stored as one MISP object, and update_rfi writes whatever the caller
hands it: a field left out of that dict is removed from the object and, for the
id, from the event title too. So every save has to carry the whole RFI, not only
the part of the form the analyst touched.

    python -m unittest tests.test_rfi
"""

import unittest
from datetime import date, timedelta
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp.routes import rfi as rfi_routes


def _rfi(**overrides):
    stored = {
        "id": "rfi-uuid", "uuid": "rfi-uuid", "rfi_id": "RFI-007",
        "question": "Is our sector targeted?", "context": "Asked by the SOC lead",
        "requester_name": "Ada", "requester_team": "SOC",
        "owner_uuid": "stakeholder-uuid", "owner_name": "Ada",
        "priority": "High", "status": "Delivered", "assigned_analyst": "koen",
        "due_date": date(2026, 8, 20),
        "linked_pir_uuid": "pir-uuid", "linked_gir_uuid": "",
        "output_format_list": [{"format": "Flash Intel Alert", "tlp": "amber"}],
        "response": "Yes, twice this month.", "response_confidence": "High",
        "feedback_requirement_met": "", "feedback_on_time": "",
        "feedback_usefulness": "", "feedback_suggestions": "",
    }
    stored.update(overrides)
    return SimpleNamespace(**stored)


class Feedback(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(rfi_routes.bp)
        self.client = app.test_client()

    def post(self, **form):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=_rfi()), \
             mock.patch.object(rfi_routes.misp_store, "update_rfi") as update, \
             mock.patch.object(rfi_routes.audit, "record"):
            self.client.post("/rfis/rfi-uuid/feedback", data=form)
        return update.call_args.args[1]

    def test_the_feedback_is_written(self):
        saved = self.post(feedback_requirement_met="Partially", feedback_on_time="Yes",
                          feedback_usefulness="Very useful",
                          feedback_suggestions="  More IOCs next time  ")
        self.assertEqual(saved["feedback_requirement_met"], "Partially")
        self.assertEqual(saved["feedback_on_time"], "Yes")
        self.assertEqual(saved["feedback_usefulness"], "Very useful")
        self.assertEqual(saved["feedback_suggestions"], "More IOCs next time")

    def test_the_rfi_keeps_its_id(self):
        """Saving feedback used to leave rfi_id out of the update, which drops the
        attribute from the object and rewrites the event title without it."""
        self.assertEqual(self.post()["rfi_id"], "RFI-007")

    def test_the_rest_of_the_rfi_survives(self):
        saved = self.post()
        self.assertEqual(saved["question"], "Is our sector targeted?")
        self.assertEqual(saved["status"], "Delivered")
        self.assertEqual(saved["priority"], "High")
        self.assertEqual(saved["response"], "Yes, twice this month.")
        self.assertEqual(saved["response_confidence"], "High")
        self.assertEqual(saved["due_date"], "2026-08-20")
        self.assertEqual(saved["linked_pir_uuid"], "pir-uuid")
        self.assertEqual(saved["output_format_list"],
                         [{"format": "Flash Intel Alert", "tlp": "amber"}])

    def test_an_unknown_rfi_is_not_written(self):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=None), \
             mock.patch.object(rfi_routes.misp_store, "update_rfi") as update:
            reply = self.client.post("/rfis/nope/feedback", data={})
        self.assertEqual(reply.status_code, 404)
        update.assert_not_called()


class SlaStatus(unittest.TestCase):
    """What the SLA badge on the list page shows."""

    def state(self, **overrides):
        return rfi_routes._sla_status(_rfi(**overrides))

    def test_a_delivered_rfi_has_stopped_its_clock(self):
        self.assertEqual(self.state(status="Delivered"), ("done", None))
        self.assertEqual(self.state(status="Closed"), ("done", None))

    def test_an_open_rfi_without_a_due_date_is_unknown_rather_than_fine(self):
        self.assertEqual(self.state(status="In Progress", due_date=None), ("amber", None))

    def test_an_overdue_rfi_is_red_with_the_days_it_is_over(self):
        state, days = self.state(status="In Progress", due_date=date.today() - timedelta(days=3))
        self.assertEqual((state, days), ("red", -3))

    def test_due_today_or_tomorrow_is_amber(self):
        self.assertEqual(self.state(status="New", due_date=date.today())[0], "amber")
        self.assertEqual(self.state(status="New", due_date=date.today() + timedelta(days=1))[0], "amber")

    def test_further_out_is_green(self):
        self.assertEqual(self.state(status="New", due_date=date.today() + timedelta(days=2))[0], "green")


class SuggestedDueDate(unittest.TestCase):
    def test_it_follows_the_sla_for_the_priority(self):
        for priority, days in rfi_routes.misp_store.RFI_SLA_DAYS.items():
            expected = (date.today() + timedelta(days=days)).isoformat()
            self.assertEqual(rfi_routes._suggested_due_date(priority), expected, priority)

    def test_an_unknown_priority_falls_back_to_the_medium_sla(self):
        expected = (date.today() + timedelta(days=5)).isoformat()
        self.assertEqual(rfi_routes._suggested_due_date("Whenever"), expected)


if __name__ == "__main__":
    unittest.main()
