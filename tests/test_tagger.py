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
    left carrying its old state is picked up and processed again on every run,
    so the caller has to be able to see that happen."""

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

    def test_the_old_state_is_removed_and_the_new_one_set(self):
        misp = self.Misp()
        self.assertTrue(tagger.set_workflow_state(misp, self.event(), "rejected"))
        self.assertEqual(misp.calls, [("untag", 'workflow:state="incomplete"'),
                                      ("tag", 'workflow:state="rejected"')])

    def test_a_refused_untag_is_reported(self):
        misp = self.Misp(untag_error="Tag is locked")
        self.assertFalse(tagger.set_workflow_state(misp, self.event(), "rejected"))

    def test_a_refused_tag_is_reported(self):
        misp = self.Misp(tag_error="no permission")
        self.assertFalse(tagger.set_workflow_state(misp, self.event(), "ongoing"))

    def test_add_tag_reports_a_refusal(self):
        self.assertTrue(tagger.add_tag(self.Misp(), object(), "osint:source-type=\"blog-post\""))
        self.assertFalse(tagger.add_tag(self.Misp(tag_error="nope"), object(), "x"))


if __name__ == "__main__":
    unittest.main()
