"""Saving a briefing writes only the story reports that changed.

Each story is an event report, and a save deleted and added every one of them
again: two requests and two audit log entries per story, which took a 73-story
briefing on the demo server ten seconds. MISP is a specced stand-in.

    python -m unittest tests.test_briefing_save
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

UUID = "627e72a2-6ef7-41be-a697-7ec7894b461b"


def _stories(*texts):
    return [{"title": f"Story {i}", "content": text} for i, text in enumerate(texts, 1)]


def _event(stories):
    """A stored briefing: its object, a report per story and the full report."""
    event = MISPEvent()
    event.uuid, event.id, event.date, event.info = UUID, 42, "2026-10-30", "briefing"
    event.add_object(misp_store._briefing_obj({"date": "2026-10-30", "title": "Briefing", "review_state": "draft"}))
    for i, story in enumerate(stories, 1):
        report = misp_store._briefing_story_report(i, story)
        event.add_event_report(name=report.name, content=report.content).id = i
    event.add_event_report(name="briefing-2026-10-30", content="The briefing as it was").id = 100
    return event


class Save(unittest.TestCase):
    def save(self, stored, edited):
        misp = mock.create_autospec(PyMISP, instance=True)
        event = _event(stored)
        misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_sync_object_attributes"), \
             mock.patch.object(misp_store, "_sync_tlp_tag"), \
             mock.patch.object(misp_store, "_retag_product_sources"):
            misp_store.update_briefing(UUID, {"title": "Briefing", "date": "2026-10-30", "review_state": "draft",
                                              "stories": edited})
        return misp

    def story_calls(self, method):
        return [c.args for c in method.call_args_list
                if str(getattr(c.args[0], "name", c.args[-1])).startswith("[story-")]

    def test_an_edited_story_is_the_only_one_written(self):
        misp = self.save(_stories("a", "b", "c"), _stories("a", "B", "c"))
        self.assertEqual([(report.name, report_id) for report, report_id in self.story_calls(misp.update_event_report)],
                         [("[story-02]", 2)])
        misp.add_event_report.assert_not_called()
        misp.delete_event_report.assert_not_called()

    def test_a_save_without_changes_writes_no_story(self):
        misp = self.save(_stories("a", "b"), _stories("a", "b"))
        self.assertEqual(self.story_calls(misp.update_event_report), [])
        misp.add_event_report.assert_not_called()

    def test_a_removed_story_is_hard_deleted(self):
        """A soft-deleted report stays on the event and is read again as a story."""
        misp = self.save(_stories("a", "b", "c"), _stories("a", "b"))
        misp.delete_event_report.assert_called_once_with(3, hard=True)
        misp.add_event_report.assert_not_called()

    def test_an_added_story_is_added(self):
        misp = self.save(_stories("a"), _stories("a", "b"))
        self.assertEqual([c.args[1].name for c in misp.add_event_report.call_args_list], ["[story-02]"])
        misp.delete_event_report.assert_not_called()

    def test_the_full_report_is_edited_in_place(self):
        misp = self.save(_stories("a"), _stories("a"))
        self.assertEqual([(c.args[0].name, c.args[1]) for c in misp.update_event_report.call_args_list],
                         [("briefing-2026-10-30", 100)])


if __name__ == "__main__":
    unittest.main()
