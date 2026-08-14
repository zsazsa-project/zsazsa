"""Tests for the unified notification dispatch model (N-1).

Verifies that _dispatch sends to channel types with a sender and reports types
without one (e.g. flowintel on the preview path) as skipped rather than
dropping them silently.

    python -m unittest tests.test_dispatcher
"""

import unittest
from types import SimpleNamespace

import config
from notifier import dispatcher


class Dispatch(unittest.TestCase):
    def setUp(self):
        self._orig_channels = config.NOTIFICATION_CHANNELS
        self._orig_instances = config.FLOWINTEL_INSTANCES
        config.NOTIFICATION_CHANNELS = [
            {"id": "mm1", "name": "MM", "type": "mattermost", "url": "x", "enabled": True},
            {"id": "em1", "name": "Mail", "type": "email", "recipient": "soc@x.test", "enabled": True},
            {"id": "em2", "name": "Paused", "type": "email", "recipient": "old@x.test", "enabled": False},
        ]
        config.FLOWINTEL_INSTANCES = [
            {"id": "fi1", "name": "FI", "enabled": True},
        ]

    def tearDown(self):
        config.NOTIFICATION_CHANNELS = self._orig_channels
        config.FLOWINTEL_INSTANCES = self._orig_instances

    def test_mattermost_sent_and_channel_ids_passed(self):
        received = {}

        def fake_sender(channel_ids):
            received["ids"] = channel_ids
            return True

        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1"])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": fake_sender}, "rfi", "RFI-001")

        self.assertEqual(summary["sent_types"], ["mattermost"])
        self.assertEqual(summary["skipped_types"], [])
        self.assertEqual(received["ids"], ["mm1"])

    def test_email_routed_to_email_sender(self):
        received = {}

        def email_sender(channel_ids):
            received["ids"] = channel_ids
            return True

        stakeholder = SimpleNamespace(name="Acme", notification_channels=["em1"])
        summary = dispatcher._dispatch(
            [stakeholder],
            {"mattermost": lambda ids: True, "email": email_sender},
            "rfi", "RFI-001",
        )

        self.assertEqual(summary["sent_types"], ["email"])
        self.assertEqual(received["ids"], ["em1"])

    def test_mattermost_and_email_both_sent(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1", "em1"])
        summary = dispatcher._dispatch(
            [stakeholder],
            {"mattermost": lambda ids: True, "email": lambda ids: True},
            "rfi", "RFI-001",
        )
        self.assertEqual(sorted(summary["sent_types"]), ["email", "mattermost"])

    def test_type_without_sender_is_skipped_not_dropped(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["flowintel:fi1"])
        # Preview path only has a mattermost sender.
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: True}, "rfi", "RFI-001")

        self.assertEqual(summary["sent_types"], [])
        self.assertEqual(summary["skipped_types"], ["flowintel"])
        self.assertEqual(summary["attempted_types"], ["flowintel"])

    def test_failed_sender_reported_as_failed_not_skipped(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1"])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: False}, "rfi", "RFI-001")
        self.assertEqual(summary["sent_types"], [])
        self.assertEqual(summary["failed_types"], ["mattermost"])
        self.assertEqual(summary["skipped_types"], [])

    def test_raising_sender_counts_as_failed(self):
        def boom(ids):
            raise RuntimeError("smtp down")

        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1"])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": boom}, "rfi", "RFI-001")
        self.assertEqual(summary["failed_types"], ["mattermost"])

    def test_no_channels_reports_nothing_attempted(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=[])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: True}, "rfi", "RFI-001")
        self.assertEqual(summary["attempted_types"], [])
        self.assertEqual(summary["sent_types"], [])

    def test_a_deleted_channel_is_not_a_delivery_failure(self):
        """A subscription outliving its channel used to be read as a Mattermost
        one, handed to the sender, and reported as a channel that could not be
        reached, failing an otherwise complete delivery."""
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["gone", "em1"])
        summary = dispatcher._dispatch(
            [stakeholder],
            {"mattermost": lambda ids: False, "email": lambda ids: True},
            "rfi", "RFI-001",
        )
        self.assertEqual(summary["sent_types"], ["email"])
        self.assertEqual(summary["failed_types"], [])
        self.assertTrue(dispatcher.delivery_outcome(summary)[0])

    def test_a_disabled_channel_is_left_alone(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["em2"])
        summary = dispatcher._dispatch([stakeholder], {"email": lambda ids: True}, "rfi", "RFI-001")
        self.assertEqual(summary["attempted_types"], [])

    def test_only_the_live_ids_reach_the_sender(self):
        received = {}
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["em1", "em2", "gone"])
        dispatcher._dispatch(
            [stakeholder],
            {"email": lambda ids: received.setdefault("ids", ids) or True},
            "rfi", "RFI-001",
        )
        self.assertEqual(received["ids"], ["em1"])


class DeliveryOutcome(unittest.TestCase):
    def test_all_sent_is_ok(self):
        ok, msg = dispatcher.delivery_outcome(
            {"recipients": 2, "sent_types": ["mattermost", "email"], "failed_types": []}
        )
        self.assertTrue(ok)
        self.assertIn("sent via email, mattermost", msg)

    def test_partial_is_not_ok_and_names_failure(self):
        ok, msg = dispatcher.delivery_outcome(
            {"recipients": 2, "sent_types": ["email"], "failed_types": ["mattermost"]}
        )
        self.assertFalse(ok)
        self.assertIn("sent via email", msg)
        self.assertIn("could not reach mattermost", msg)

    def test_no_recipients(self):
        ok, msg = dispatcher.delivery_outcome({"recipients": 0})
        self.assertFalse(ok)
        self.assertIn("no eligible recipients", msg)

    def test_recipients_without_channels(self):
        ok, msg = dispatcher.delivery_outcome({"recipients": 3, "sent_types": [], "failed_types": []})
        self.assertFalse(ok)
        self.assertIn("no message channels", msg)


if __name__ == "__main__":
    unittest.main()
