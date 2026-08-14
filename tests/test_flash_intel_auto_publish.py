"""Who receives an alert the analyser publishes on its own.

An unattended alert used to reach every channel on the instance: the analyser
asked whether any stakeholder was on automated mode, got a yes back, and
broadcast on the strength of it. It now delivers to the subscribers themselves,
through the same dispatcher an analyst pressing Publish goes through, with TLP
clearance deciding as it does everywhere else.

    python -m unittest tests.test_flash_intel_auto_publish
"""

import unittest
from types import SimpleNamespace
from unittest import mock

import config
from analyser.products import flash_intel
from webapp import misp_store

_PRODUCT = flash_intel._FLASH_INTEL_PRODUCT_NAME


def _stakeholder(name, clearance="amber", mode="automated", products=(_PRODUCT,)):
    return SimpleNamespace(
        name=name,
        tlp_clearance=clearance,
        products=list(products),
        product_modes={_PRODUCT: mode} if mode else {},
    )


def _draft_object():
    """The zsazsa-flash-intel object on the product event, as auto-publish finds it."""
    return SimpleNamespace(
        name="zsazsa-flash-intel",
        attributes=[SimpleNamespace(object_relation="review-state", value="pending-review")],
    )


class ProductName(unittest.TestCase):
    """Subscriptions and delivery modes are keyed by the PRODUCT_TYPES string, so a
    product name that is merely close matches no stakeholder and routes to nobody,
    without erroring. The analyser asked for "Flash intel" and never published."""

    def test_the_routing_constants_name_real_product_types(self):
        from webapp.routes import indicator_feed, threat_actor_profile

        for name in (flash_intel._FLASH_INTEL_PRODUCT_NAME,
                     indicator_feed.PRODUCT_NAME,
                     threat_actor_profile.PRODUCT_NAME):
            self.assertIn(name, config.PRODUCT_TYPES)


class AutomatedSubscribers(unittest.TestCase):
    def select(self, stakeholders, tlp="amber"):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders):
            return [s.name for s in misp_store.stakeholders_on_automated_mode(_PRODUCT, tlp)]

    def test_after_approval_subscribers_wait_for_an_analyst(self):
        self.assertEqual(
            self.select([_stakeholder("Auto"), _stakeholder("Manual", mode="after-approval")]),
            ["Auto"],
        )

    def test_a_mode_without_the_subscription_does_not_count(self):
        self.assertEqual(self.select([_stakeholder("Lapsed", products=[])]), [])

    def test_clearance_below_the_alert_is_excluded(self):
        picked = self.select([
            _stakeholder("Clear", clearance="clear"),
            _stakeholder("Green", clearance="green"),
            _stakeholder("Amber", clearance="amber"),
            _stakeholder("Red", clearance="red"),
        ])
        self.assertEqual(picked, ["Amber", "Red"])

    def test_a_lower_classification_reaches_everyone_cleared_above_it(self):
        picked = self.select(
            [_stakeholder("Clear", clearance="clear"), _stakeholder("Red", clearance="red")],
            tlp="clear",
        )
        self.assertEqual(picked, ["Clear", "Red"])

    def test_no_mode_recorded_means_not_automated(self):
        self.assertEqual(self.select([_stakeholder("Silent", mode=None)]), [])

    def test_nobody_on_automated_mode_leaves_nothing_to_publish_to(self):
        with mock.patch.object(misp_store, "list_stakeholders",
                               return_value=[_stakeholder("Manual", mode="after-approval")]):
            self.assertEqual(flash_intel._automated_subscribers(), [])

    def test_an_unreachable_misp_does_not_stop_the_run(self):
        with mock.patch.object(misp_store, "list_stakeholders", side_effect=OSError("MISP down")):
            self.assertEqual(flash_intel._automated_subscribers(), [])


class AutoPublishDelivery(unittest.TestCase):
    def publish(self, recipients, objects=None):
        product_event = SimpleNamespace(uuid="u" * 36, id=42)
        # Auto-publish re-fetches the event to reach the draft object it just wrote.
        misp_webapp = mock.Mock()
        misp_webapp.get_event.return_value = SimpleNamespace(
            objects=[_draft_object()] if objects is None else objects)
        summary = {"recipients": len(recipients), "sent_types": ["email"], "failed_types": []}
        with mock.patch("notifier.dispatcher.send_flash_intel", return_value=summary) as send, \
             mock.patch.object(flash_intel.tagger, "set_workflow_state"):
            flash_intel._auto_publish(misp_webapp, product_event, "FIA-00042", "# Alert", recipients)
        return send, misp_webapp

    def test_the_alert_goes_to_the_subscribers_not_to_every_channel(self):
        recipients = [_stakeholder("Acme")]
        send, _misp = self.publish(recipients)
        self.assertIs(send.call_args.args[2], recipients)

    def test_the_dispatched_alert_carries_its_id_and_classification(self):
        send, _misp = self.publish([_stakeholder("Acme")])
        fia = send.call_args.args[0]
        self.assertEqual(fia.fia_id, "FIA-00042")
        self.assertEqual(fia.tlp, "amber")
        # Mattermost builds the "Open in MISP" link from this.
        self.assertEqual(fia.id, 42)

    def test_the_event_is_published_before_anything_is_sent(self):
        _send, misp_webapp = self.publish([_stakeholder("Acme")])
        misp_webapp.publish.assert_called_once_with("u" * 36)

    def test_the_draft_is_marked_approved(self):
        _send, misp_webapp = self.publish([_stakeholder("Acme")])
        approved = misp_webapp.update_attribute.call_args.args[0]
        self.assertEqual(approved.value, "approved")

    def test_an_alert_still_goes_out_when_the_draft_object_did_not_come_back(self):
        """The object is written moments earlier, so a MISP that has not caught up
        must not cost the alert its delivery."""
        send, misp_webapp = self.publish([_stakeholder("Acme")], objects=[])
        misp_webapp.update_attribute.assert_not_called()
        misp_webapp.publish.assert_called_once()
        send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
