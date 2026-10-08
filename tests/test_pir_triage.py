"""What each PIR triage decision stores and which status it leaves the PIR in.

Only Approve and Merge move a PIR out of Pending, and Reject takes it off the
board. Acknowledge records receipt and Defer holds it for later, so both leave
it Pending until a final decision is taken.

    python -m unittest tests.test_pir_triage
"""

import unittest
from unittest import mock

from webapp import misp_store


class PirTriageDecision(unittest.TestCase):
    def decide(self, decision, **kwargs):
        stored = {}
        with mock.patch.object(misp_store, "_misp"), \
             mock.patch.object(misp_store, "_pir_ns"), \
             mock.patch.object(misp_store, "_pir_data_from_ns",
                               return_value={"status": "Pending", "intake_status": "submitted"}), \
             mock.patch.object(misp_store, "update_pir", side_effect=lambda uuid, data: stored.update(data)), \
             mock.patch.object(misp_store.misp_session, "current_user_email", return_value="analyst@example.org"):
            misp_store.update_pir_intake("pir-uuid", decision, **kwargs)
        return stored

    def test_acknowledge_records_who_and_keeps_the_pir_pending(self):
        stored = self.decide("acknowledged")
        self.assertEqual(stored["intake_status"], "acknowledged")
        self.assertEqual(stored["acknowledged_by"], "analyst@example.org")
        self.assertTrue(stored["acknowledged_at"])
        self.assertEqual(stored["status"], "Pending")

    def test_defer_keeps_the_pir_pending_with_its_reason(self):
        stored = self.decide("deferred", reason="Waiting for budget")
        self.assertEqual(stored["intake_status"], "deferred")
        self.assertEqual(stored["deferral_reason"], "Waiting for budget")
        self.assertEqual(stored["status"], "Pending")

    def test_reject_keeps_the_status_and_stores_the_reason(self):
        stored = self.decide("rejected", reason="Out of scope")
        self.assertEqual(stored["intake_status"], "rejected")
        self.assertEqual(stored["rejection_reason"], "Out of scope")
        self.assertEqual(stored["status"], "Pending")

    def test_approve_makes_the_pir_active(self):
        stored = self.decide("approved")
        self.assertEqual(stored["status"], "Active")
        self.assertEqual(stored["decision_by"], "analyst@example.org")

    def test_merge_retires_the_pir_and_links_it(self):
        stored = self.decide("merged", linked_pir_uuid="other-uuid")
        self.assertEqual(stored["status"], "Retired")
        self.assertEqual(stored["linked_pir_uuid"], "other-uuid")


if __name__ == "__main__":
    unittest.main()
