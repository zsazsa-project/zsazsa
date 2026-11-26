"""Which report of an event is its article, and which its AI summary.

The analyser, the summary button of the collection page and a story added to
a daily briefing read them by the same rules. The article is the first report
with content that zsazsa did not write: not an AI summary, an indicator
lookup or the note of a rejection. The summary is the newest one, and none
when the article changed after it was written. MISP keeps a deleted report on
the event, and a summary the analyser replaced is one, so neither counts.
MISP and the model are patched out.

    python -m unittest tests.test_ai_summary_reports
"""

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

from webapp import collection_cache, misp_store
from webapp.routes import daily_briefing, data_collection

SUMMARY = collection_cache.AI_SUMMARY_PREFIX


def _report(name, content, hour=10, deleted=False):
    return SimpleNamespace(name=name, content=content, deleted=deleted,
                           timestamp=datetime(2026, 11, 20, hour, tzinfo=timezone.utc))


class Article(unittest.TestCase):
    def test_it_is_the_first_report_with_content_that_zsazsa_did_not_write(self):
        article = _report("Article", "What the source wrote")
        reports = [_report(f"{SUMMARY} Event", "What a model wrote"), _report("Empty", "  "),
                   _report(f"{collection_cache.REJECTION_PREFIX} 2026-11-20", "Rejected"),
                   _report("Removed", "Taken back", deleted=True), article]
        self.assertIs(collection_cache.article_report(reports), article)

    def test_without_one_there_is_none(self):
        self.assertIsNone(collection_cache.article_report([_report(f"{SUMMARY} Event", "Summary")]))


class Summary(unittest.TestCase):
    def test_it_is_the_newest_one_left_on_the_event(self):
        """The analyser deletes the summary it replaces, and MISP keeps it."""
        reports = [_report("Article", "Exploited now", hour=11),
                   _report(f"{SUMMARY} Event", "Not exploited", hour=9, deleted=True),
                   _report(f"{SUMMARY} Event", "Exploited", hour=12),
                   _report(f"{SUMMARY} Event", "Rewritten later and deleted", hour=13, deleted=True)]
        self.assertEqual(collection_cache.ai_summary(reports), "Exploited")

    def test_one_older_than_the_article_tells_the_old_story(self):
        reports = [_report("Article", "Exploited now", hour=11), _report(f"{SUMMARY} Event", "Not exploited", hour=9)]
        self.assertEqual(collection_cache.ai_summary(reports), "")

    def test_a_deleted_summary_is_no_summary(self):
        self.assertEqual(collection_cache.ai_summary([_report(f"{SUMMARY} Event", "Gone", deleted=True)]), "")


class BriefingStory(unittest.TestCase):
    def story(self, reports):
        event = SimpleNamespace(uuid="e" * 36, info="A story", tags=[], event_reports=reports)
        with mock.patch.object(misp_store, "resolve_source_event",
                               return_value=(event, mock.create_autospec(PyMISP, instance=True), "scraper")), \
             mock.patch.object(misp_store, "extract_source_url", return_value="https://example.org/a"), \
             mock.patch.object(misp_store, "extract_story_context", return_value={}):
            return daily_briefing._seed_story_from_event("e" * 36)

    def test_a_story_starts_from_the_summary_the_analyser_kept(self):
        """It took the first summary on the event, the one the analyser had
        deleted because the article changed after it."""
        story = self.story([_report("Article", "Exploited now", hour=11),
                            _report(f"{SUMMARY} A story", "Not exploited", hour=9, deleted=True),
                            _report(f"{SUMMARY} A story", "Exploited", hour=12)])
        self.assertEqual(story["ai_summary"], "Exploited")
        self.assertEqual(story["report_count"], 2)

    def test_an_outdated_summary_is_left_out(self):
        story = self.story([_report("Article", "Exploited now", hour=11),
                            _report(f"{SUMMARY} A story", "Not exploited", hour=9)])
        self.assertEqual(story["ai_summary"], "")


class SummaryButton(unittest.TestCase):
    def summarise(self, reports):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event_reports.return_value = reports
        misp.add_event_report.return_value = {"errors": (403, {"message": "Not allowed"})}
        event = SimpleNamespace(uuid="e" * 36, id="7", info="An event", tags=[])
        with mock.patch("analyser.llm.summarise_report", return_value="**Summary** A RAT.") as model, \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary"), \
             mock.patch.object(data_collection.audit, "record"):
            result = data_collection._generate_ai_summary(misp, event, "scraper")
        return result, model

    def test_it_summarises_the_article_as_the_analyser_reads_it(self):
        """It took the first report that was not a summary, and gave up when
        that one was empty or was the note of a rejection."""
        _result, model = self.summarise([_report("Empty", ""),
                                         _report(f"{collection_cache.REJECTION_PREFIX} 2026-11-20", "Rejected"),
                                         _report("Removed", "Taken back", deleted=True),
                                         _report("Article", "An article about a RAT.")])
        self.assertEqual(model.call_args.args[0], "An article about a RAT.")

    def test_without_an_article_there_is_nothing_to_summarise(self):
        (ok, message, status), model = self.summarise([_report(f"{SUMMARY} An event", "A summary"), _report("Empty", "")])
        self.assertEqual((ok, status), (False, 400))
        self.assertIn("article", message)
        model.assert_not_called()


if __name__ == "__main__":
    unittest.main()
