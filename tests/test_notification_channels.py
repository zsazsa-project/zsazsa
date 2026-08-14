"""Channel identity: stakeholders subscribe by channel id, so the id has to hold
still. A rename that changes it, or two channels that share one, silently sends
products to the wrong place or to nowhere at all.

    python -m unittest tests.test_notification_channels
"""

import unittest
from unittest import mock

from flask import Flask
from werkzeug.datastructures import MultiDict

import config as _config
from webapp.routes import config_page, stakeholders


class ChannelIds(unittest.TestCase):
    """Saving a channel, with the config file itself standing in as a plain dict:
    what is under test is which id the route settles on, not how it is written."""

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        self.store = {"NOTIFICATION_CHANNELS": []}
        patches = [
            mock.patch.object(config_page, "_read", lambda: dict(self.store)),
            mock.patch.object(config_page, "_write", self.store.update),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, **payload):
        return self.client.post("/config/save-notification-channel", json=payload).get_json()

    def channels(self):
        return self.store["NOTIFICATION_CHANNELS"]

    def test_a_rename_keeps_the_id_stakeholders_subscribed_under(self):
        created = self.save(name="SOC", type="email", recipient="soc@x.test", enabled=True)
        self.assertEqual(created["new_id"], "soc")

        renamed = self.save(original_id="soc", name="SOC team", type="email",
                            recipient="soc@x.test", enabled=True)

        self.assertEqual(renamed["new_id"], "soc")
        self.assertEqual([(c["id"], c["name"]) for c in self.channels()], [("soc", "SOC team")])

    def test_two_channels_named_alike_get_distinct_ids(self):
        first = self.save(name="SOC", type="email", recipient="a@x.test", enabled=True)
        second = self.save(name="SOC", type="email", recipient="b@x.test", enabled=True)

        self.assertNotEqual(first["new_id"], second["new_id"])
        self.assertEqual({c["id"] for c in self.channels()}, {"soc", "soc-2"})

    def test_an_edit_does_not_add_a_second_channel(self):
        self.save(name="SOC", type="email", recipient="soc@x.test", enabled=True)
        self.save(original_id="soc", name="SOC", type="email",
                  recipient="newsoc@x.test", enabled=False)

        saved = self.channels()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["recipient"], "newsoc@x.test")
        self.assertFalse(saved[0]["enabled"])


class Subscriptions(unittest.TestCase):
    """The stakeholder form only renders active channels, so a disabled one is
    absent from the submission rather than unchecked."""

    def setUp(self):
        self._orig = _config.NOTIFICATION_CHANNELS
        _config.NOTIFICATION_CHANNELS = [
            {"id": "soc", "name": "SOC", "type": "email", "recipient": "soc@x.test", "enabled": True},
            {"id": "paused", "name": "Paused", "type": "email", "recipient": "p@x.test", "enabled": False},
        ]

    def tearDown(self):
        _config.NOTIFICATION_CHANNELS = self._orig

    def parse(self, submitted, current=None):
        form = MultiDict([("notification_channels", cid) for cid in submitted])
        return stakeholders._parse_notification_channels(form, current)

    def test_editing_a_stakeholder_keeps_a_disabled_channel_subscription(self):
        self.assertEqual(sorted(self.parse(["soc"], current=["soc", "paused"])),
                         ["paused", "soc"])

    def test_a_deleted_channel_falls_away(self):
        self.assertEqual(self.parse(["soc"], current=["soc", "gone"]), ["soc"])

    def test_an_unchecked_active_channel_is_unsubscribed(self):
        self.assertEqual(self.parse([], current=["soc"]), [])

    def test_a_new_stakeholder_takes_only_what_was_submitted(self):
        self.assertEqual(self.parse(["soc", "paused"]), ["soc"])

    def test_a_malformed_stored_subscription_does_not_break_the_form(self):
        """notification-channels is read back with json.loads and not type-checked,
        so the kept channels are worked out from the configured list rather than by
        hashing whatever came out of MISP."""
        self.assertEqual(self.parse(["soc"], current=[{"id": "paused"}, "paused"]),
                         ["soc", "paused"])


if __name__ == "__main__":
    unittest.main()
