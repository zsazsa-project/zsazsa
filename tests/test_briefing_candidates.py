"""Which stories reach a daily briefing draft.

Two rules decide that beyond the relevance check: the configured title
exclusions, and the overlap check that drops a second write-up of the same
incident. The collection page shows the analyst what the first of those will
drop before the run happens, so both have to read the setting the same way.

The relevance check is asked about every event, with the focus points and the
active PIRs and GIRs. An event a requirement matched on keywords used to skip
it and was always briefed, which on a single word such as a country let in
stories that had nothing to do with the requirement.

    python -m unittest tests.test_briefing_candidates
"""

import contextlib
import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import analyser_pipeline
from webapp.routes import data_collection


class TitleExclusions(unittest.TestCase):
    def patterns(self, configured):
        with mock.patch.object(analyser_pipeline.config,
                               "DAILY_BRIEFING_TITLE_EXCLUSIONS", configured):
            return analyser_pipeline.daily_briefing_title_exclusions()

    def test_a_configured_list_is_lower_cased_for_matching(self):
        self.assertEqual(self.patterns(["Weekly Roundup", " Podcast "]),
                         ["weekly roundup", "podcast"])

    def test_the_setting_is_also_accepted_as_lines_of_text(self):
        """The config page writes a list, but a hand-edited config.py may hold
        the textarea's value as it was typed."""
        self.assertEqual(self.patterns("Weekly roundup\n\nPodcast\n"),
                         ["weekly roundup", "podcast"])

    def test_an_unset_option_excludes_nothing(self):
        self.assertEqual(self.patterns(None), [])
        self.assertEqual(self.patterns([]), [])

    def test_a_pattern_matches_anywhere_in_the_title_whatever_its_case(self):
        patterns = ["weekly roundup"]
        self.assertTrue(analyser_pipeline.title_excluded("CTI Weekly Roundup #12", patterns))
        self.assertFalse(analyser_pipeline.title_excluded("Ransomware at a haulier", patterns))

    def test_an_event_without_a_title_is_not_excluded(self):
        self.assertFalse(analyser_pipeline.title_excluded("", ["weekly roundup"]))

    def test_the_collection_page_applies_the_analyser_rule(self):
        """The page marks the events the run would drop, and offers to set them
        aside. It had its own copy of this and the two could drift apart."""
        self.assertIs(data_collection.analyser_pipeline.title_excluded,
                      analyser_pipeline.title_excluded)
        self.assertIs(data_collection.analyser_pipeline.daily_briefing_title_exclusions,
                      analyser_pipeline.daily_briefing_title_exclusions)


class DuplicateStories(unittest.TestCase):
    """Of two stories covering the same incident the later one goes."""

    def test_the_later_story_of_a_pair_is_dropped(self):
        self.assertEqual(analyser_pipeline._duplicate_story_indexes([(2, 5, 0.9)]), {5})

    def test_nothing_overlapping_drops_nothing(self):
        self.assertEqual(analyser_pipeline._duplicate_story_indexes([]), set())

    def test_a_story_already_dropped_does_not_take_another_with_it(self):
        """1 and 2 are the same incident, and so are 2 and 3. Dropping 2 for the
        first pair must not also drop 3, or one incident costs two stories."""
        self.assertEqual(
            analyser_pipeline._duplicate_story_indexes([(1, 2, 0.9), (2, 3, 0.8)]), {2})

    def test_the_closest_pair_is_settled_first(self):
        dropped = analyser_pipeline._duplicate_story_indexes([(1, 3, 0.7), (2, 3, 0.95)])
        self.assertEqual(dropped, {3})


class RelevanceReview(unittest.TestCase):
    def brief(self, manual=False):
        """Brief "Matched", which a PIR matched on keywords, "Off topic" and
        "On topic". The model keeps only "On topic"."""
        pipeline = analyser_pipeline
        self.events = events = [SimpleNamespace(uuid=c * 36, info=title, tags=[], galaxies=[])
                                for c, title in (("a", "Matched"), ("b", "Off topic"), ("c", "On topic"))]
        if manual:
            events[2].tags = [SimpleNamespace(name=pipeline.misp_store.TAG_MANUAL_ENTRY),
                              SimpleNamespace(name="tlp:red")]
        reports = [SimpleNamespace(name="Article", content="An article")]
        pir = SimpleNamespace(uuid="p", question="Which actors phish Belgian banks?", sectors=["Bank"],
                              out_of_scope=["Caribbean financial services"])
        self.created = []
        patches = [
            mock.patch.object(pipeline, "_common_candidate_events", return_value=(
                {e.uuid: f"MISP of {e.info}" for e in events}, events, {}, {"event_decisions": []},
                {e.uuid: reports for e in events})),
            mock.patch.object(pipeline, "daily_briefing_title_exclusions", return_value=[]),
            mock.patch.object(pipeline.req_matching, "get_requirements", return_value=([pir], [])),
            mock.patch.object(pipeline.config, "FOCUS_POINTS_SECTORS", ["Energy"], create=True),
            mock.patch.object(pipeline.llm, "draft_briefing_story", return_value=("A story", "")),
            mock.patch.object(pipeline.llm, "detect_story_overlaps", return_value={"overlaps": []}),
            mock.patch.object(pipeline.llm, "draft_briefing_summary", return_value="The day"),
            mock.patch.object(pipeline, "galaxy_names_with_commas", return_value=frozenset()),
            mock.patch.object(pipeline, "_add_briefing_rejection_note"),
            mock.patch.object(pipeline, "_log"),
            mock.patch.object(pipeline, "log_event"),
            mock.patch.object(pipeline.tagger, "get_source_feed", return_value="feed"),
            mock.patch.object(pipeline.misp_store, "extract_source_url", return_value=""),
            mock.patch.object(pipeline.misp_store, "briefing_scope_summary", return_value=""),
            mock.patch.object(pipeline.misp_store, "create_briefing",
                              side_effect=lambda data: self.created.append(data) or "u" * 36),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            self.asked = stack.enter_context(mock.patch.object(
                pipeline.llm, "review_briefing_relevance",
                side_effect=lambda **kw: ({"include": True, "reason": "About Belgian banks."}
                                          if kw["event_title"] == "On topic" else {"include": False, "reason": "Off"})))
            self.rejected = stack.enter_context(mock.patch.object(pipeline.tagger, "set_workflow_state",
                                                                  return_value=True))
            return pipeline.run_daily_briefing_action()

    def test_every_event_is_asked_about(self):
        result = self.brief()
        self.assertEqual([c.kwargs["event_title"] for c in self.asked.call_args_list],
                         ["Matched", "Off topic", "On topic"])
        self.assertEqual([s["title"] for s in self.created[0]["stories"]], ["On topic"])
        self.assertEqual([c.args[:2] for c in self.rejected.call_args_list],
                         [("MISP of Matched", self.events[0]), ("MISP of Off topic", self.events[1])])
        self.assertEqual(result["rejected_by_relevance"], 2)

    def test_the_model_is_told_what_the_organisation_follows(self):
        self.brief()
        asked = self.asked.call_args.kwargs
        self.assertEqual(asked["focus_points"]["sectors"], ["Energy"])
        self.assertEqual(asked["requirements"], [{"requirement": "Which actors phish Belgian banks?",
                                                  "sectors": ["Bank"],
                                                  "out_of_scope": ["Caribbean financial services"]}])

    def test_the_run_says_why_a_story_is_in(self):
        result = self.brief()
        included = {d["title"]: d["reason"] for d in result["event_decisions"] if d["outcome"] == "included"}
        self.assertEqual(included, {"On topic": "About Belgian banks."})

    def test_a_manual_story_keeps_its_source_server(self):
        self.brief(manual=True)
        self.assertEqual(self.created[0]["stories"][0]["source_id"], "webapp")
        self.assertEqual(self.created[0]["tlp"], "red")


if __name__ == "__main__":
    unittest.main()
