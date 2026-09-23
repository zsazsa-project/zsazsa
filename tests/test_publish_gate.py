"""Every way of putting a product in front of recipients takes MISP's publish right.

The detail pages disable the buttons for an analyst without perm_publish, but the
routes behind them take a plain POST, so each one has to refuse on its own:
approving or publishing, publishing from the wizard, resending and notifying.
A published alert or advisory cannot be edited at all, or a resend would deliver
something other than what was approved.

Nothing is published or delivered for real here: the store and the delivery
jobs are stubbed.

    python -m unittest tests.test_publish_gate
"""

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from werkzeug.datastructures import MultiDict

from webapp.routes import (daily_briefing, flash_intel, stakeholders, threat_actor_profile,
                           threat_landscape, vea)

UUID = "u" * 36


def _client(*blueprints):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test"
    for bp in blueprints:
        app.register_blueprint(bp)
    return app.test_client()


class _Gate(unittest.TestCase):
    """Runs each request with the publish right given or withheld."""

    can_publish = False

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch("webapp.misp_session.current_user_can_publish",
                                       return_value=self.can_publish))
        self.stack = stack

    def stub(self, target, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(target, name, **kwargs))

    def assertRefused(self, reply):
        self.assertEqual(reply.status_code, 302)
        with self.client.session_transaction() as session:
            messages = [m for _cat, m in session.get("_flashes", [])]
        self.assertTrue(any("MISP publish rights" in m or "cannot be edited" in m
                            for m in messages), messages)


class _FlashIntelFixture(_Gate):
    def setUp(self):
        super().setUp()
        self.client = _client(flash_intel.bp)
        self.fia = SimpleNamespace(uuid=UUID, fia_id="FIA-00042", audience="SOC",
                                   review_state="pending-review", tlp="amber")
        self.stub(flash_intel.misp_store, "get_fia", return_value=self.fia)
        self.update = self.stub(flash_intel.misp_store, "update_fia")
        self.publish = self.stub(flash_intel.misp_store, "publish_fia")
        self.stub(flash_intel.misp_store, "fetch_source_events", return_value=[])
        self.stub(flash_intel, "_form_data", return_value={"audience": "SOC"})
        self.deliver = self.stub(flash_intel, "_start_flash_intel_delivery")
        self.stub(flash_intel.audit, "record")


class FlashIntel(_FlashIntelFixture):
    def test_approve_is_refused(self):
        self.assertRefused(self.client.post(f"/products/flash-intel/{UUID}/approve"))
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_publishing_from_the_wizard_only_saves(self):
        reply = self.client.post(f"/products/flash-intel/{UUID}/edit", data={"action": "publish"})
        self.assertRefused(reply)
        self.assertEqual(self.update.call_args.args[1]["review_state"], "pending-review")
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_a_published_alert_cannot_be_edited(self):
        self.fia.review_state = flash_intel.misp_store.FIA_REVIEW_APPROVED
        self.assertRefused(self.client.post(f"/products/flash-intel/{UUID}/edit",
                                            data={"action": "save"}))
        self.update.assert_not_called()

    def test_resend_is_refused(self):
        self.fia.review_state = flash_intel.misp_store.FIA_REVIEW_APPROVED
        self.assertRefused(self.client.post(f"/products/flash-intel/{UUID}/resend"))
        self.deliver.assert_not_called()


class FlashIntelPublisher(_FlashIntelFixture):
    """The same requests with the right: the gate must not get in the way."""

    can_publish = True

    def test_approve_publishes_and_delivers(self):
        self.client.post(f"/products/flash-intel/{UUID}/approve")
        self.publish.assert_called_once_with(UUID)
        self.deliver.assert_called_once_with("FIA-00042", UUID, "publish")

    def test_publishing_from_the_wizard_publishes(self):
        self.client.post(f"/products/flash-intel/{UUID}/edit", data={"action": "publish"})
        self.assertEqual(self.update.call_args.args[1]["review_state"], "approved")
        self.publish.assert_called_once_with(UUID)

    def test_resend_delivers(self):
        self.fia.review_state = flash_intel.misp_store.FIA_REVIEW_APPROVED
        self.client.post(f"/products/flash-intel/{UUID}/resend")
        self.deliver.assert_called_once_with("FIA-00042", UUID, "resend")


class _VeaFixture(_Gate):
    def setUp(self):
        super().setUp()
        self.client = _client(vea.bp)
        self.vea = SimpleNamespace(uuid=UUID, vea_id="VEA-00042", audience="SOC",
                                   review_state="pending-review", tlp="amber")
        self.stub(vea.misp_store, "get_vea", return_value=self.vea)
        self.update = self.stub(vea.misp_store, "update_vea")
        self.publish = self.stub(vea.misp_store, "publish_vea")
        self.stub(vea.misp_store, "fetch_source_events", return_value=[])
        self.stub(vea, "_form_data", return_value={"audience": "SOC"})
        self.deliver = self.stub(vea, "_start_vea_delivery")
        self.stub(vea.audit, "record")


class Vea(_VeaFixture):
    def test_approve_is_refused(self):
        self.assertRefused(self.client.post(f"/products/vea/{UUID}/approve"))
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_publishing_from_the_wizard_only_saves(self):
        reply = self.client.post(f"/products/vea/{UUID}/edit", data={"action": "publish"})
        self.assertRefused(reply)
        self.assertEqual(self.update.call_args.args[1]["review_state"], "pending-review")
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_a_published_advisory_cannot_be_edited(self):
        self.vea.review_state = vea.misp_store.VEA_REVIEW_APPROVED
        self.assertRefused(self.client.post(f"/products/vea/{UUID}/edit", data={"action": "save"}))
        self.update.assert_not_called()

    def test_resend_is_refused(self):
        self.vea.review_state = vea.misp_store.VEA_REVIEW_APPROVED
        self.assertRefused(self.client.post(f"/products/vea/{UUID}/resend"))
        self.deliver.assert_not_called()


class VeaPublisher(_VeaFixture):
    can_publish = True

    def test_approve_publishes_and_delivers(self):
        self.client.post(f"/products/vea/{UUID}/approve")
        self.publish.assert_called_once_with(UUID)
        self.deliver.assert_called_once_with("VEA-00042", UUID, "publish")

    def test_publishing_from_the_wizard_publishes(self):
        self.client.post(f"/products/vea/{UUID}/edit", data={"action": "publish"})
        self.assertEqual(self.update.call_args.args[1]["review_state"], "approved")
        self.publish.assert_called_once_with(UUID)

    def test_resend_delivers(self):
        self.vea.review_state = vea.misp_store.VEA_REVIEW_APPROVED
        self.client.post(f"/products/vea/{UUID}/resend")
        self.deliver.assert_called_once_with("VEA-00042", UUID, "resend")


class _DailyBriefingFixture(_Gate):
    def setUp(self):
        super().setUp()
        self.client = _client(daily_briefing.bp)
        self.briefing = SimpleNamespace(uuid=UUID, date="2026-09-23", review_state="draft")
        self.stub(daily_briefing.misp_store, "get_briefing", return_value=self.briefing)
        self.publish = self.stub(daily_briefing.misp_store, "publish_briefing")
        self.deliver = self.stub(daily_briefing, "_start_briefing_delivery")
        self.stub(daily_briefing.audit, "record")


class DailyBriefing(_DailyBriefingFixture):
    def test_publish_is_refused(self):
        self.assertRefused(self.client.post(f"/briefing/{UUID}/publish"))
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_resend_is_refused(self):
        self.briefing.review_state = daily_briefing.misp_store.BRIEFING_REVIEW_PUBLISHED
        self.assertRefused(self.client.post(f"/briefing/{UUID}/resend"))
        self.deliver.assert_not_called()


class DailyBriefingPublisher(_DailyBriefingFixture):
    can_publish = True

    def test_publish_publishes(self):
        self.client.post(f"/briefing/{UUID}/publish")
        self.publish.assert_called_once_with(UUID)
        self.deliver.assert_called_once()

    def test_resend_delivers(self):
        self.briefing.review_state = daily_briefing.misp_store.BRIEFING_REVIEW_PUBLISHED
        self.client.post(f"/briefing/{UUID}/resend")
        self.deliver.assert_called_once()


class _ThreatLandscapeFixture(_Gate):
    def setUp(self):
        super().setUp()
        self.client = _client(threat_landscape.bp)
        self.stub(threat_landscape.misp_store, "get_tlr",
                  return_value=SimpleNamespace(uuid=UUID, tlr_id="TLR-00042"))
        self.publish = self.stub(threat_landscape.misp_store, "publish_tlr")
        self.stub(threat_landscape.audit, "record")


class ThreatLandscape(_ThreatLandscapeFixture):
    def test_publish_is_refused(self):
        self.assertRefused(self.client.post(f"/products/threat-landscape/{UUID}/publish"))
        self.publish.assert_not_called()


class ThreatLandscapePublisher(_ThreatLandscapeFixture):
    can_publish = True

    def test_publish_publishes(self):
        self.client.post(f"/products/threat-landscape/{UUID}/publish")
        self.publish.assert_called_once_with(UUID)


class _ThreatActorProfileFixture(_Gate):
    def setUp(self):
        super().setUp()
        self.client = _client(threat_actor_profile.bp)
        self.tap = SimpleNamespace(uuid=UUID, tap_id="TAP-00042", status="Draft")
        self.stub(threat_actor_profile.misp_store, "get_threat_actor_profile", return_value=self.tap)
        self.publish = self.stub(threat_actor_profile.misp_store, "publish_threat_actor_profile")
        self.deliver = self.stub(threat_actor_profile.notify_jobs, "start")
        self.stub(threat_actor_profile.audit, "record")


class ThreatActorProfile(_ThreatActorProfileFixture):
    def test_publish_is_refused(self):
        self.assertRefused(self.client.post(f"/products/threat-actor-profile/{UUID}/publish"))
        self.publish.assert_not_called()

    def test_notify_is_refused(self):
        self.tap.status = "Published"
        self.assertRefused(self.client.post(f"/products/threat-actor-profile/{UUID}/notify"))
        self.deliver.assert_not_called()


class ThreatActorProfilePublisher(_ThreatActorProfileFixture):
    can_publish = True

    def test_publish_publishes(self):
        self.client.post(f"/products/threat-actor-profile/{UUID}/publish")
        self.publish.assert_called_once_with(UUID)

    def test_notify_delivers(self):
        self.tap.status = "Published"
        self.client.post(f"/products/threat-actor-profile/{UUID}/notify")
        self.deliver.assert_called_once()


class AutomatedDelivery(unittest.TestCase):
    """An automated subscription lets the analyser publish to that stakeholder
    with nobody reviewing, so switching one on takes the publish right too."""

    FORM = MultiDict([("products", "Flash intel alert"), ("mode__Flash intel alert", "automated")])

    def parse(self, can_publish, previous=None):
        app = Flask(__name__)
        app.secret_key = "test"
        with app.test_request_context("/"), \
             mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
            return stakeholders._parse_subscriptions(self.FORM, previous)[1]["Flash intel alert"]

    def test_switching_to_automated_is_refused(self):
        self.assertEqual(self.parse(False, {"Flash intel alert": "after-approval"}), "after-approval")

    def test_an_automated_mode_already_set_is_kept(self):
        self.assertEqual(self.parse(False, {"Flash intel alert": "automated"}), "automated")

    def test_a_publisher_may_switch_to_automated(self):
        self.assertEqual(self.parse(True), "automated")


if __name__ == "__main__":
    unittest.main()
