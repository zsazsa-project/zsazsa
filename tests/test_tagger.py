"""Tests for analyser.tagger source-feed extraction.

    python -m unittest tests.test_tagger
"""

import unittest
from types import SimpleNamespace

from analyser import tagger


class SourceFeed(unittest.TestCase):
    def test_from_tag_names(self):
        tags = ['tlp:clear', 'scraper:data-collection-source:ETDA CTI Robot', 'workflow:state="complete"']
        self.assertEqual(tagger.source_feed_from_tags(tags), "ETDA CTI Robot")

    def test_unknown_when_absent(self):
        self.assertEqual(tagger.source_feed_from_tags(['tlp:clear']), "unknown")
        self.assertEqual(tagger.source_feed_from_tags([]), "unknown")
        self.assertEqual(tagger.source_feed_from_tags(None), "unknown")

    def test_get_source_feed_reads_tag_objects(self):
        event = SimpleNamespace(tags=[
            SimpleNamespace(name="tlp:green"),
            SimpleNamespace(name="scraper:data-collection-source:HackerNews"),
        ])
        self.assertEqual(tagger.get_source_feed(event), "HackerNews")


class WorkflowState(unittest.TestCase):
    """PyMISP answers a refused tag with a dict instead of raising. An event
    left with its old state is picked up and processed again on every run, so
    the caller has to be able to see that happen."""

    class Misp:
        def __init__(self, untag_error="", tag_error=""):
            self.untag_error, self.tag_error = untag_error, tag_error
            self.calls = []

        def untag(self, event, name):
            self.calls.append(("untag", name))
            return {"errors": self.untag_error} if self.untag_error else {"saved": True}

        def tag(self, event, name, local=False):
            self.calls.append(("tag", name))
            return {"errors": self.tag_error} if self.tag_error else {"saved": True}

    def event(self):
        return SimpleNamespace(uuid="e" * 36, tags=[
            SimpleNamespace(name="tlp:clear"),
            SimpleNamespace(name='workflow:state="incomplete"'),
        ])

    def test_the_new_state_is_set_and_the_old_one_removed(self):
        misp = self.Misp()
        self.assertTrue(tagger.set_workflow_state(misp, self.event(), "rejected"))
        self.assertEqual(misp.calls, [("tag", 'workflow:state="rejected"'),
                                      ("untag", 'workflow:state="incomplete"')])

    def test_a_refused_untag_is_reported(self):
        misp = self.Misp(untag_error="Tag is locked")
        self.assertFalse(tagger.set_workflow_state(misp, self.event(), "rejected"))

    def test_a_refused_tag_is_reported_and_keeps_the_old_state(self):
        # Removed first, the event would have no state left, and no search of
        # the analyser would find it again to retry.
        misp = self.Misp(tag_error="no permission")
        self.assertFalse(tagger.set_workflow_state(misp, self.event(), "ongoing"))
        self.assertEqual(misp.calls, [("tag", 'workflow:state="ongoing"')])

    def test_the_state_it_already_has_is_not_removed(self):
        event = self.event()
        event.tags.append(SimpleNamespace(name='workflow:state="rejected"'))
        misp = self.Misp()
        tagger.set_workflow_state(misp, event, "rejected")
        self.assertNotIn(("untag", 'workflow:state="rejected"'), misp.calls)

    def test_add_tag_reports_a_refusal(self):
        self.assertTrue(tagger.add_tag(self.Misp(), object(), "osint:source-type=\"blog-post\""))
        self.assertFalse(tagger.add_tag(self.Misp(tag_error="nope"), object(), "x"))


if __name__ == "__main__":
    unittest.main()
