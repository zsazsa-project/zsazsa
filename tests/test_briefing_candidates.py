"""Which stories reach a daily briefing draft.

Two rules decide that beyond the relevance check: the configured title
exclusions, and the overlap check that drops a second write-up of the same
incident. The collection page shows the analyst what the first of those will
drop before the run happens, so both have to read the setting the same way.

Every event is judged by the relevance verdict, the same one the alerts use
(tests.test_relevance pins it). An event a requirement matched on keywords used
to skip that check and was always briefed, which on a single word such as a
country let in stories that had nothing to do with the requirement. The run
says why each story is in, a story keeps the source it was read from, and the
briefing is never classified below its sources. Nothing is rejected for
missing the briefing by the briefing itself: the closing step decides, with
the other products (tests.test_analyser_drafts).

    python -m unittest tests.test_briefing_candidates
"""

import contextlib
import unittest
from types import SimpleNamespace
from unittest import mock

from analyser.sources import Reading, Source
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


class Stories(unittest.TestCase):
    def brief(self, manual=False):
        """Brief "Matched", which a PIR matched on keywords, "Off topic" and
        "On topic". The verdicts want only "On topic"."""
        pipeline = analyser_pipeline
        self.events = events = [SimpleNamespace(uuid=c * 36, info=title, tags=[], galaxies=[], date=None)
                                for c, title in (("a", "Matched"), ("b", "Off topic"), ("c", "On topic"))]
        if manual:
            events[2].tags = [SimpleNamespace(name=pipeline.misp_store.TAG_MANUAL_ENTRY),
                              SimpleNamespace(name="tlp:red")]
        reports = [SimpleNamespace(name="Article", content="An article")]
        self.created = []
        sources = {e.uuid: Source("scraper", "scraper", "MISP scraper", f"MISP of {e.info}", True) for e in events}
        if manual:
            sources[events[2].uuid] = Source("manual", "manual", "Manual entries", "MISP of On topic", True)
        found = SimpleNamespace(sources=sources, events=events, excluded=[], summaries={},
                                reports={e.uuid: reports for e in events}, stats={"event_decisions": []})
        on_topic = {"relevant": True, "grounds": [{"focus_point": "Energy", "quote": "a grid"}],
                    "major_development": False, "reason": "About Belgian banks."}
        judge = mock.Mock(**{
            "verdict.side_effect": lambda event, *rest: {"briefing": on_topic if event.info == "On topic" else
                                                         {"relevant": False, "grounds": [], "reason": "Off",
                                                          "major_development": False},
                                                         "alert": {"relevant": False}},
            "wants.side_effect": lambda verdict, product, event: (verdict[product]["relevant"],
                                                           verdict[product].get("reason", "")),
            "pir_priority.return_value": 3,
        })
        patches = [
            mock.patch.object(pipeline, "_common_candidate_events", return_value=found),
            mock.patch.object(pipeline, "Judge", return_value=judge),
            mock.patch.object(pipeline.misp_store, "briefing_source_uuids", return_value=set()),
            mock.patch.object(pipeline.misp_store, "briefing_also_seen_uuids", return_value=set()),
            mock.patch.object(pipeline.event_state, "load", return_value={"verdict": None, "outcomes": {}}),
            mock.patch.object(pipeline, "todays_draft", return_value=None),
            mock.patch.object(pipeline, "focus_points", return_value={}),
            mock.patch.object(pipeline.llm, "draft_briefing_story", return_value=("A story", "")),
            mock.patch.object(pipeline.llm, "detect_story_overlaps", return_value={"overlaps": []}),
            mock.patch.object(pipeline.llm, "draft_briefing_summary", return_value="The day"),
            mock.patch.object(pipeline, "galaxy_names_with_commas", return_value=frozenset()),
            mock.patch.object(pipeline, "_log"),
            mock.patch.object(pipeline, "_close_declined", return_value=0),
            mock.patch.object(pipeline.similarity, "recent_stories", return_value=[]),
            mock.patch.object(pipeline.misp_store, "extract_source_url", return_value=""),
            mock.patch.object(pipeline.misp_store, "briefing_scope_summary", return_value=[]),
            mock.patch.object(pipeline.misp_store, "create_briefing",
                              side_effect=lambda data: self.created.append(data) or "u" * 36),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            self.rejected = stack.enter_context(mock.patch.object(pipeline.event_state, "reject"))
            self.judge = judge
            reading = mock.create_autospec(Reading, instance=True)
            reading.rescan_hours = None
            return pipeline.run_daily_briefing_action(reading)

    def test_every_event_is_judged(self):
        result = self.brief()
        self.assertEqual([c.args[0].info for c in self.judge.verdict.call_args_list],
                         ["Matched", "Off topic", "On topic"])
        self.assertEqual([s["title"] for s in self.created[0]["stories"]], ["On topic"])
        self.assertEqual(result["declined_by_relevance"], 2)
        self.rejected.assert_not_called()

    def test_the_run_says_why_a_story_is_in(self):
        result = self.brief()
        included = {d["title"]: d["reason"] for d in result["event_decisions"] if d["outcome"] == "included"}
        self.assertEqual(included, {"On topic": "About Belgian banks. Grounds: Energy."})

    def test_a_manual_story_keeps_its_source_server_and_classification(self):
        self.brief(manual=True)
        self.assertEqual(self.created[0]["stories"][0]["source_id"], "webapp")
        self.assertEqual(self.created[0]["tlp"], "red")


if __name__ == "__main__":
    unittest.main()
