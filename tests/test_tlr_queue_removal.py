"""Removing selected queue stories keeps the events and unrelated product tags.

Only ongoing events without another zsazsa product tag return to incomplete.
Refused MISP writes remain visible, and events held by reports cannot be removed.

    python -m unittest tests.test_tlr_queue_removal
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent, PyMISP

from webapp import collection_cache, misp_store
from webapp.routes import data_collection, threat_landscape

UUID = "6f4535bb-1b2c-4d5e-8f90-a1b2c3d4e5f6"
SOURCE = "manual-newsletter"
TAG = threat_landscape._TLR_QUEUE_TAG


class RemoveFromQueue(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.tag.return_value = self.misp.untag.return_value = {}
        for patcher in (
            mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
            mock.patch.object(collection_cache, "source_ids", return_value=[SOURCE]),
            mock.patch.object(data_collection, "_misp_for_source", return_value=(self.misp, "")),
            mock.patch.object(misp_store, "list_tlrs", return_value=[]),
            mock.patch.object(threat_landscape.audit, "record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_landscape.bp)
        self.client = app.test_client()
        self.seed()

    def seed(self, state="ongoing", extra=()):
        event = MISPEvent()
        event.uuid, event.id, event.info = UUID, 42, "A collected article"
        event.date = "2026-11-14"
        for name in [TAG, f'workflow:state="{state}"', "tlp:green", *extra]:
            event.add_tag(name)
        self.misp.get_event.return_value = event
        collection_cache.insert_event(collection_cache._extract_row(event, SOURCE))

    def remove(self, selection=None):
        return self.client.post("/products/threat-landscape/remove-from-queue",
                                data={"event": selection if selection is not None else [UUID]})

    def tags(self):
        return collection_cache.get_events_by_uuids([UUID])[0]["tags"]

    def messages(self):
        with self.client.session_transaction() as session:
            return session.get("_flashes", [])

    def test_removing_a_story_untags_it_and_restores_incomplete(self):
        reply = self.remove()
        self.assertEqual(reply.status_code, 302)
        self.misp.untag.assert_any_call(UUID, TAG)
        self.assertNotIn(TAG, self.tags())
        self.assertIn('workflow:state="incomplete"', self.tags())
        self.assertNotIn('workflow:state="ongoing"', self.tags())
        self.assertIn("tlp:green", self.tags())
        self.assertEqual(threat_landscape._queued_events([]), [])
        self.misp.delete_event.assert_not_called()
        self.assertTrue(any(category == "success" for category, _ in self.messages()))

    def test_other_products_keep_the_event_ongoing(self):
        other = 'zsazsa:product="flash-intel"'
        self.seed(extra=[other])
        self.remove()
        self.assertNotIn(TAG, self.tags())
        self.assertIn(other, self.tags())
        self.assertIn('workflow:state="ongoing"', self.tags())
        self.misp.tag.assert_not_called()

    def test_complete_events_stay_complete(self):
        self.seed("complete")
        self.remove()
        self.assertNotIn(TAG, self.tags())
        self.assertIn('workflow:state="complete"', self.tags())
        self.misp.tag.assert_not_called()

    def test_the_live_product_tags_not_stale_cache_decide_the_workflow(self):
        self.misp.get_event.return_value.add_tag('zsazsa:product="vea"')
        self.remove()
        self.misp.tag.assert_not_called()

    def test_an_event_a_report_holds_cannot_be_removed(self):
        report = SimpleNamespace(entries=[SimpleNamespace(event_uuid=UUID)])
        with mock.patch.object(misp_store, "list_tlrs", return_value=[report]):
            self.remove()
        self.misp.untag.assert_not_called()
        self.assertIn(TAG, self.tags())

    def test_an_event_outside_the_queue_cannot_be_removed(self):
        self.remove(["not-queued"])
        self.misp.untag.assert_not_called()

    def test_a_refused_untag_stays_in_the_queue_and_shows_a_warning(self):
        self.misp.untag.return_value = {"errors": "Refused"}
        with self.assertLogs(threat_landscape.logger, level="WARNING"):
            self.remove()
        self.assertIn(TAG, self.tags())
        self.misp.tag.assert_not_called()
        self.assertTrue(any(category == "warning" for category, _ in self.messages()))

    def test_a_refused_workflow_still_removes_the_story_but_warns(self):
        self.misp.tag.return_value = {"errors": "Refused"}
        with self.assertLogs("analyser.tagger", level="ERROR"):
            self.remove()
        self.assertNotIn(TAG, self.tags())
        self.assertIn('workflow:state="ongoing"', self.tags())
        self.assertTrue(any("workflow" in message for _, message in self.messages()))

    def test_a_workflow_connection_failure_still_confirms_removal(self):
        self.misp.tag.side_effect = ConnectionError("MISP disconnected")
        with self.assertLogs(threat_landscape.logger, level="WARNING"):
            self.remove()
        self.assertNotIn(TAG, self.tags())
        self.assertTrue(any(category == "success" for category, _ in self.messages()))
        self.assertTrue(any("workflow" in message for _, message in self.messages()))

    def test_a_partial_selection_removes_only_queued_stories(self):
        self.remove([UUID, UUID, "not-queued"])
        self.misp.untag.assert_any_call(UUID, TAG)
        self.assertEqual([call.args for call in self.misp.untag.call_args_list
                          if call.args[1] == TAG], [(UUID, TAG)])
        self.assertTrue(any(category == "success" for category, _ in self.messages()))
        self.assertTrue(any(category == "warning" for category, _ in self.messages()))

    def test_a_missing_source_does_not_remove_the_cached_tag(self):
        with mock.patch.object(data_collection, "_misp_for_source", return_value=(None, "Unknown source")), \
             self.assertLogs(threat_landscape.logger, level="WARNING"):
            self.remove()
        self.assertIn(TAG, self.tags())
        self.misp.untag.assert_not_called()

    def test_a_zsazsa_record_is_never_modified(self):
        self.misp.get_event.return_value.add_tag('zsazsa:type="stakeholder"')
        with self.assertLogs(threat_landscape.logger, level="WARNING"):
            self.remove()
        self.misp.untag.assert_not_called()


if __name__ == "__main__":
    unittest.main()
