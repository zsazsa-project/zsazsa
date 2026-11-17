"""Queuing collection events confirms MISP writes and keeps the table current.

An immediate MISP refetch may still have the old tags. The queue must keep its
confirmed cache changes, preserve complete events and report refused writes.
An event that could not be queued is named in the answer and the audit log with
the reason, which used to be "The log says why". Ids from the request must be on
Data collection; the stored sources of a product need not be, and an older one
is cached when it is queued, as an alert's June article could not be. One the
cache holds is queued under the source it is listed under, whatever the
product calls that source.

    python -m unittest tests.test_collection_tlr_queue
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask
from pymisp import MISPEvent, PyMISP

from webapp import collection_cache
from webapp.routes import data_collection

UUID = "6f4535bb-1b2c-4d5e-8f90-a1b2c3d4e5f6"
OLD_UUID = "001f09ac-c17e-433c-ad70-81a480a6b7de"
SOURCE = "manual-newsletter"
PRODUCT_TAG = 'zsazsa:product="threat-landscape-report"'


class ThreatLandscapeQueue(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.tag.return_value = self.misp.untag.return_value = {}
        for patcher in (
            mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
            mock.patch.object(data_collection, "_misp_for_source", return_value=(self.misp, "")),
            mock.patch.object(data_collection.audit, "record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(data_collection.bp)
        self.app = app
        self.client = app.test_client()
        self.seed()

    def seed(self, state="incomplete"):
        event = MISPEvent()
        event.uuid, event.id, event.info = UUID, 42, "A collected article"
        event.date = "2026-11-14"
        event.add_tag(f'workflow:state="{state}"')
        self.misp.get_event.return_value = event
        collection_cache.insert_event(collection_cache._extract_row(event, SOURCE))

    def queue(self, events=None):
        return self.client.post(
            "/collection/queue-for-tlr",
            json={"events": events if events is not None else [{"uuid": UUID, "sourceId": SOURCE}]},
        ).get_json()

    def tags(self):
        return collection_cache.get_events_by_uuids([UUID])[0]["tags"]

    def test_a_stale_misp_refetch_does_not_undo_the_confirmed_cache_changes(self):
        reply = self.queue()
        self.assertEqual(reply["tagged"], 1)
        self.assertIn(PRODUCT_TAG, self.tags())
        self.assertIn('workflow:state="ongoing"', self.tags())
        self.assertNotIn('workflow:state="incomplete"', self.tags())
        self.misp.tag.assert_any_call(UUID, PRODUCT_TAG, local=True)

    def test_a_complete_event_is_queued_without_regressing_its_state(self):
        self.seed("complete")
        reply = self.queue()
        self.assertEqual(reply["tagged"], 1)
        self.assertIn(PRODUCT_TAG, self.tags())
        self.assertIn('workflow:state="complete"', self.tags())
        self.assertNotIn('workflow:state="ongoing"', self.tags())

    def test_a_refused_product_tag_is_not_reported_as_queued(self):
        self.seed("complete")
        self.misp.tag.return_value = {"errors": "Tag refused"}
        with self.assertLogs("analyser.tagger", level="ERROR"):
            reply = self.queue()
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["tagged"], 0)
        self.assertEqual(reply["errors"], 1)
        self.assertNotIn(PRODUCT_TAG, self.tags())

    def test_a_refused_workflow_state_is_not_mirrored_as_ongoing(self):
        self.misp.tag.return_value = {"errors": "State refused"}
        with self.assertLogs("analyser.tagger", level="ERROR"):
            reply = self.queue()
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["tagged"], 0)
        self.assertIn('workflow:state="incomplete"', self.tags())
        self.assertNotIn('workflow:state="ongoing"', self.tags())

    def test_partial_success_is_reported(self):
        with self.assertLogs(data_collection.logger, level="WARNING"):
            reply = self.queue([
                {"uuid": UUID, "sourceId": SOURCE},
                {"uuid": "not-collected", "sourceId": SOURCE},
            ])
        self.assertFalse(reply["ok"])
        self.assertEqual((reply["tagged"], reply["errors"]), (1, 1))
        self.assertIn("1 event queued", reply["message"])
        self.assertIn("Not queued: not-collected: it is not on Data collection under the source manual-newsletter.",
                      reply["message"])
        self.assertNotIn("log", reply["message"])

    def test_a_selection_that_is_no_event_is_named_rather_than_failing(self):
        with self.assertLogs(data_collection.logger, level="WARNING"):
            reply = self.queue([{"uuid": 5, "sourceId": SOURCE}, {"uuid": UUID, "sourceId": ["x"]}, "x"])
        self.assertEqual((reply["tagged"], reply["errors"]), (0, 3))
        self.assertIn("an event: no event was named", reply["message"])
        self.misp.tag.assert_not_called()

    def test_a_refused_tag_is_named_with_the_reason(self):
        self.seed("complete")
        self.misp.tag.return_value = {"errors": "Tag refused"}
        with self.assertLogs("analyser.tagger", level="ERROR"), self.assertLogs(data_collection.logger, "WARNING"):
            reply = self.queue()
        self.assertIn(f'"A collected article": MISP refused the tag {PRODUCT_TAG}', reply["message"])
        details = data_collection.audit.record.call_args.kwargs["details"]
        self.assertIn(f'not queued: "A collected article": MISP refused the tag {PRODUCT_TAG}', details)

    def test_the_stored_source_of_a_product_is_queued_and_cached_though_not_collected(self):
        """The cache holds the last 30 days; an alert's source can be older."""
        old = MISPEvent()
        old.uuid, old.id, old.info, old.date = OLD_UUID, 43, "An article from June", "2026-06-23"
        old.add_tag('workflow:state="ongoing"')
        self.misp.get_event.return_value = old
        with self.app.test_request_context():
            reply = data_collection.queue_events_for_tlr([(OLD_UUID, SOURCE)], collected_only=False,
                                                         audit_type="fia", audit_id="f", audit_label="FIA-00001")
        self.assertEqual((reply["ok"], reply["tagged"]), (True, 1))
        self.misp.tag.assert_any_call(OLD_UUID, PRODUCT_TAG, local=True)
        rows = collection_cache.get_events_by_uuids([OLD_UUID])
        self.assertEqual([r["source_id"] for r in rows], [SOURCE])

    def test_a_manual_entry_named_as_the_analyser_names_it_is_queued_under_its_source(self):
        """The analyser stores "webapp" as the source of a manual entry; Data
        collection knows it by its manual source. Queued under "webapp", it
        failed as an unknown source, or was cached a second time under it."""
        with self.app.test_request_context():
            reply = data_collection.queue_events_for_tlr([(UUID, "webapp")], collected_only=False,
                                                         audit_type="fia", audit_id="f", audit_label="FIA-00001")
        self.assertTrue(reply["ok"], reply["message"])
        data_collection._misp_for_source.assert_called_once_with(SOURCE)
        self.assertEqual([r["source_id"] for r in collection_cache.get_events_by_uuids([UUID])], [SOURCE])

    def test_but_not_from_the_collection_page(self):
        with self.assertLogs(data_collection.logger, level="WARNING"):
            reply = self.queue([{"uuid": OLD_UUID, "sourceId": SOURCE}])
        self.assertEqual(reply["tagged"], 0)
        self.misp.tag.assert_not_called()


class QueueSelection(unittest.TestCase):
    def test_queuing_clears_selection_before_and_after_the_table_reload(self):
        script = (Path(data_collection.__file__).parents[1] / "templates"
                  / "data_collection" / "_list_js.html").read_text()
        self.assertIn("reloadTable(d.message, d.ok ? 'success' : 'warning', true)", script)
        self.assertIn("if (clearSelection) clearEventSelection();", script)
        self.assertIn("clearSelection: !!clearSelection", script)
        # After the reload the selection is the one the note kept: none when cleared.
        self.assertIn("selected: clearSelection ? [] : getSelectedEvents()", script)
        self.assertIn("clearEventSelection();\n      (note.selected || []).forEach", script)
        clear = script.split("function clearEventSelection() {", 1)[1].split(
            "document.querySelectorAll('.event-row-cb').forEach(function(cb) { cb.addEventListener", 1
        )[0]
        self.assertIn("cb.checked = false", clear)
        self.assertIn("selectAllCb.checked = false", clear)
        self.assertIn("selectAllCb.indeterminate = false", clear)
        self.assertIn("updateCreateProductBtn();", clear)


if __name__ == "__main__":
    unittest.main()
