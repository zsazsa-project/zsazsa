"""What a threat actor profile actually says when it reaches a stakeholder.

The notification body carried the title, the actors, the summary and the
attribution, and stopped there. The recommendations were never in it, so the one
part a reader is meant to act on only existed on the product page, and a
detection rule attached to the profile never reached the mail or Mattermost at
all. Both channels send this same markdown.

    python -m unittest tests.test_tap_notification
"""

import unittest
from types import SimpleNamespace

from webapp.routes import threat_actor_profile as tap_routes


def _tap(**over):
    base = dict(title="Actor X", tap_id="TAP-00001", tlp="amber",
                threat_actors=["Bear"], summary="What they do.",
                attribution_rationale="Why we think so.",
                rec_prevention="", rec_detection="", rec_response="")
    base.update(over)
    return SimpleNamespace(**base)


class Recommendations(unittest.TestCase):
    def body(self, **over):
        return tap_routes._markdown(_tap(**over))

    def test_all_three_recommendations_are_in_the_body(self):
        md = self.body(rec_prevention="Segment the network.",
                       rec_detection="Watch for ARP floods.",
                       rec_response="Isolate the host.")
        self.assertIn("## Recommendations", md)
        for text in ("Segment the network.", "Watch for ARP floods.", "Isolate the host."):
            self.assertIn(text, md)

    def test_a_rulezet_rule_reaches_the_stakeholder(self):
        """Rules are attached to the profile as "title - url" lines in the
        detection recommendation, so they travel with it or not at all."""
        rule = "arp_poison.detection - https://rulezet.org/rule/detail_rule/740025"
        self.assertIn(rule, self.body(rec_detection=rule))

    def test_only_the_recommendations_that_were_filled_in_are_listed(self):
        md = self.body(rec_detection="Watch for ARP floods.")
        self.assertIn("**Detection:**", md)
        self.assertNotIn("**Prevention:**", md)
        self.assertNotIn("**Response:**", md)

    def test_a_profile_without_recommendations_has_no_empty_section(self):
        self.assertNotIn("Recommendations", self.body())

    def test_the_rest_of_the_body_is_unchanged(self):
        md = self.body()
        for text in ("# Actor X", "TAP-00001", "TLP:AMBER", "**Threat actors:** Bear",
                     "## Summary", "What they do.", "## Attribution", "Why we think so."):
            self.assertIn(text, md)


if __name__ == "__main__":
    unittest.main()
