"""Which stories reach a daily briefing draft.

Two rules decide that beyond the relevance check: the configured title
exclusions, and the overlap check that drops a second write-up of the same
incident. The collection page shows the analyst what the first of those will
drop before the run happens, so both have to read the setting the same way.

    python -m unittest tests.test_briefing_candidates
"""

import unittest
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


if __name__ == "__main__":
    unittest.main()
