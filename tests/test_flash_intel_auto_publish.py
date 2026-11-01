"""Who receives an alert the analyser publishes on its own.

An unattended alert used to reach every channel on the instance: the analyser
asked whether any stakeholder was on automated mode, got a yes back, and
broadcast on the strength of it. It now delivers to the subscribers themselves,
through the same dispatcher an analyst pressing Publish goes through, with TLP
clearance deciding as it does everywhere else. The alert is approved and
published as an analyst's would be, before anything is sent. What went wrong,
MISP not publishing it or a channel not reached, is handed back for the run to
log on the alert's source event.

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

    def test_the_source_classification_limits_automated_delivery(self):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=[
                _stakeholder("Amber"), _stakeholder("Red", clearance="red")]):
            self.assertEqual([s.name for s in misp_store.stakeholders_on_automated_mode(_PRODUCT, "red")], ["Red"])


class AutoPublishDelivery(unittest.TestCase):
    def publish(self, recipients, tlp="amber", stakeholders_fail=False, published=True, failed_types=()):
        fia = SimpleNamespace(fia_id="FIA-00042", tlp=tlp, id="u" * 36)
        summary = {"recipients": len(recipients), "sent_types": ["email"], "failed_types": list(failed_types)}
        calls = []
        lookup = (mock.patch.object(misp_store, "stakeholders_on_automated_mode", side_effect=OSError("MISP down"))
                  if stakeholders_fail else
                  mock.patch.object(misp_store, "stakeholders_on_automated_mode", return_value=recipients))
        with lookup as asked, \
             mock.patch.object(misp_store, "publish_fia",
                               side_effect=lambda uuid: calls.append("publish") or published) as publish, \
             mock.patch.object(misp_store, "get_fia", return_value=fia), \
             mock.patch.object(misp_store, "render_fia_markdown", return_value="# Alert"), \
             mock.patch("notifier.dispatcher.send_flash_intel",
                        side_effect=lambda *a: calls.append("send") or summary) as send:
            problem = flash_intel._publish_to_automated_subscribers("u" * 36, "FIA-00042", tlp)
        return SimpleNamespace(send=send, publish=publish, asked=asked, calls=calls, fia=fia, problem=problem)

    def test_the_alert_goes_to_the_subscribers_not_to_every_channel(self):
        recipients = [_stakeholder("Acme")]
        self.assertIs(self.publish(recipients).send.call_args.args[2], recipients)

    def test_the_subscribers_are_those_cleared_for_its_classification(self):
        self.assertEqual(self.publish([_stakeholder("Acme", clearance="red")], tlp="red").asked.call_args.args,
                         (_PRODUCT, "red"))

    def test_the_alert_is_approved_and_published_before_anything_is_sent(self):
        done = self.publish([_stakeholder("Acme")])
        done.publish.assert_called_once_with("u" * 36)
        self.assertEqual(done.calls, ["publish", "send"])
        self.assertIs(done.send.call_args.args[0], done.fia)

    def test_nobody_on_automated_mode_leaves_it_a_draft(self):
        done = self.publish([])
        done.publish.assert_not_called()
        done.send.assert_not_called()

    def test_an_unreachable_misp_does_not_stop_the_run(self):
        with self.assertLogs(flash_intel.logger, "WARNING"):
            done = self.publish([_stakeholder("Acme")], stakeholders_fail=True)
        done.publish.assert_not_called()
        self.assertIn("not sent", done.problem)

    def test_one_sent_without_a_problem_says_none(self):
        self.assertEqual(self.publish([_stakeholder("Acme")]).problem, "")

    def test_one_misp_did_not_publish_is_sent_and_says_so(self):
        """As from the alert's page: it is approved by then. The run said the
        alert was made and nothing more."""
        done = self.publish([_stakeholder("Acme")], published=False)
        self.assertEqual(done.calls, ["publish", "send"])
        self.assertEqual(done.problem, "MISP did not publish it")

    def test_a_channel_that_could_not_be_reached_is_said(self):
        done = self.publish([_stakeholder("Acme")], failed_types=["mattermost"])
        self.assertIn("could not reach mattermost", done.problem)


if __name__ == "__main__":
    unittest.main()
