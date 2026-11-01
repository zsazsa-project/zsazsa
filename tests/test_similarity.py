"""Whether a new alert or briefing story tells a story already told.

Only the products that share a CVE or a threat actor with the candidate, an
actor tagged on one and named in the text of the other included, or enough of
the words of their title, are put to the model: a shared topic alone is not the
same story, and every comparison is a model call. A candidate's CVEs are those
of its vulnerability attributes and its article as well as of its summary, and
an earlier alert's those of its summary and what happened. A comparison that
fails raises, for the caller to say so. The earlier ones are those of the last
month, in any state, a rejected one included. A match at the same-story score
or more is the same story; it is left out when it adds nothing, and when the
earlier one was rejected even if it does.

The model is stubbed.

    python -m unittest tests.test_similarity
"""

import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

from analyser import similarity

CANDIDATE = similarity.story("e" * 36, "LockBit hits Antwerp port operator",
                             "CVE-2026-1234 was exploited", ["LockBit"])


class Shortlist(unittest.TestCase):
    def compare(self, earlier, matches=()):
        with mock.patch.object(similarity.llm, "compare_stories", return_value=list(matches)) as asked:
            found = similarity.same_story(CANDIDATE, earlier)
        return found, asked

    def test_only_a_resemblance_is_put_to_the_model(self):
        earlier = [similarity.story("FIA-1", "A CVE", "CVE-2026-1234 again"),
                   similarity.story("FIA-2", "An actor", "", ["lockbit"]),
                   similarity.story("FIA-3", "LockBit hits Antwerp port", ""),
                   similarity.story("FIA-4", "Ransomware is on the rise", "Ransomware everywhere")]
        _found, asked = self.compare(earlier)
        self.assertEqual([s["id"] for s in asked.call_args.args[1]], ["FIA-1", "FIA-2", "FIA-3"])

    def test_an_actor_tagged_on_one_and_named_in_the_other_is_a_resemblance(self):
        """The event had no galaxy tag for the actor its article names."""
        untagged = similarity.story("e" * 36, "A new campaign", "Cozy Bear sent the mails")
        with mock.patch.object(similarity.llm, "compare_stories", return_value=[]) as asked:
            similarity.same_story(untagged, [similarity.story("FIA-1", "Phishing wave", "", ["Cozy Bear"])])
            similarity.same_story(similarity.story("e" * 36, "A new campaign", "", ["Cozy Bear"]),
                                  [similarity.story("FIA-2", "Phishing wave", "Cozy Bear again")])
        self.assertEqual(asked.call_count, 2)

    def test_without_one_the_model_is_not_asked(self):
        found, asked = self.compare([similarity.story("FIA-4", "Ransomware is on the rise", "")])
        self.assertIsNone(found)
        asked.assert_not_called()

    def test_the_closest_match_from_the_score_on_is_the_same_story(self):
        earlier = [similarity.story("FIA-1", "A CVE", "CVE-2026-1234"),
                   similarity.story("FIA-2", "An actor", "", ["LockBit"])]
        found, _asked = self.compare(earlier, [{"index": 1, "score": 0.7, "new_facts": False, "reason": "a"},
                                               {"index": 2, "score": 0.9, "new_facts": True, "reason": "b"}])
        self.assertEqual((found["story"]["id"], found["new_facts"]), ("FIA-2", True))

    def test_a_comparison_that_fails_raises(self):
        """Read as no match, the candidate went out without a word that it had
        not been compared; the caller drafts it and says so."""
        with mock.patch.object(similarity.llm, "compare_stories", side_effect=TimeoutError("no answer")), \
             self.assertRaises(TimeoutError):
            similarity.same_story(CANDIDATE, [similarity.story("FIA-1", "A CVE", "CVE-2026-1234")])

    def test_a_loose_resemblance_is_not(self):
        found, _asked = self.compare([similarity.story("FIA-1", "A CVE", "CVE-2026-1234")],
                                     [{"index": 1, "score": 0.5, "new_facts": False, "reason": "Same CVE"}])
        self.assertIsNone(found)

    def test_a_repeat_is_left_out_and_so_is_an_update_of_a_rejected_one(self):
        def found(new_facts, rejected):
            return {"story": {"rejected": rejected}, "new_facts": new_facts, "reason": ""}
        self.assertTrue(similarity.repeats(found(False, False)))
        self.assertFalse(similarity.repeats(found(True, False)))
        self.assertTrue(similarity.repeats(found(True, True)))
        self.assertFalse(similarity.repeats(None))


class Earlier(unittest.TestCase):
    def test_the_alerts_of_the_last_month_in_any_state(self):
        now = datetime.now()
        alerts = [SimpleNamespace(fia_id="FIA-1", title="Recent", summary="", what_happened=["CVE-2026-1001 is used"],
                                  threat_actors=[], review_state="rejected", created_at=now - timedelta(days=3)),
                  SimpleNamespace(fia_id="FIA-2", title="Old", summary="", what_happened=[], threat_actors=[],
                                  review_state="approved", created_at=now - timedelta(days=45))]
        with mock.patch.object(similarity.misp_store, "list_fias", return_value=alerts):
            found = similarity.recent_alerts()
        self.assertEqual([(s["id"], s["rejected"]) for s in found], [("FIA-1", True)])
        # What happened names the CVEs as often as the summary does.
        self.assertEqual(found[0]["cves"], {"CVE-2026-1001"})

    def test_the_stories_of_the_briefings_of_the_last_month_but_today_s_draft(self):
        today = datetime.now().date()
        briefings = [SimpleNamespace(uuid="d" * 36, date=today.isoformat(), review_state="draft",
                                     stories=[SimpleNamespace(title="Today", content="")]),
                     SimpleNamespace(uuid="p" * 36, date=(today - timedelta(days=2)).isoformat(),
                                     review_state="published",
                                     stories=[SimpleNamespace(title="Before", content="", threat_actors=["APT29"])]),
                     SimpleNamespace(uuid="o" * 36, date=(today - timedelta(days=60)).isoformat(),
                                     review_state="published", stories=[SimpleNamespace(title="Long ago", content="")])]
        with mock.patch.object(similarity.misp_store, "list_briefings", return_value=briefings):
            found = similarity.recent_stories(but=briefings[0])
        self.assertEqual([(s["title"], s["actors"]) for s in found], [("Before", {"apt29"})])

    def test_an_event_s_threat_actors_come_from_its_galaxy_tags(self):
        event = SimpleNamespace(uuid="e" * 36, info="An event",
                                tags=[SimpleNamespace(name='misp-galaxy:threat-actor="APT29"'),
                                      SimpleNamespace(name="tlp:clear")])
        self.assertEqual(similarity.event_story(event, "text", "")["actors"], {"apt29"})

    def test_an_event_s_cves_are_those_of_its_attributes_and_article_too(self):
        """Its summary named neither, and the earlier alert on the same CVE was
        not shortlisted."""
        event = SimpleNamespace(uuid="e" * 36, info="A flaw in a VPN", tags=[],
                                attributes=[SimpleNamespace(type="vulnerability", value="CVE-2026-1001")])
        candidate = similarity.event_story(event, "A summary", "The article on CVE-2026-1002.")
        self.assertEqual(candidate["content"], "A summary")
        self.assertEqual(candidate["cves"], {"CVE-2026-1001", "CVE-2026-1002"})
        self.assertEqual(similarity.event_story(event, "", "The article")["content"], "The article")


if __name__ == "__main__":
    unittest.main()
