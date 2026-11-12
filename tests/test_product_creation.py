"""Creating a flash intel alert, a vulnerability advisory or a detection
engineering request in MISP.

Each is an event, then its object, then a MISP report rendered from the two. The
report is rendered from the event as MISP has it once the object is on it: the
event add_event answers with has no object yet, and the report came out empty.
When the object or the report cannot be written, the event is deleted again.
Left behind, it would count as the product of its source event, so the
analyser would never make one for it, or, without an object, a new empty one on
every try.

MISP is an autospec of PyMISP; nothing is written anywhere.

    python -m unittest tests.test_product_creation
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

SOURCE_UUID = "8bff3417-1af2-4ccb-81be-26a8bc99605f"
PRODUCT_UUID = "p" * 36


class Creation(unittest.TestCase):
    def create(self, kind, data, refuse="", delete_refused=False):
        """Create a product of ``kind`` ("fia", "vea" or "der"), with MISP refusing
        the "object" or the "report" when asked."""
        misp = mock.create_autospec(PyMISP, instance=True)
        created, stored = MISPEvent(), MISPEvent()
        for event in (created, stored):
            event.id, event.uuid, event.date, event.info = 42, PRODUCT_UUID, "2026-11-01", data["title"]
        misp.add_event.return_value = created

        def add_object(_event, obj):
            if refuse == "object":
                return {"errors": "object refused"}
            stored.add_object(obj)
            return obj
        misp.add_object.side_effect = add_object
        misp.get_event.return_value = stored
        misp.add_event_report.return_value = {"errors": "report refused"} if refuse == "report" else {}
        misp.delete_event.return_value = {"errors": "delete refused"} if delete_refused else {}
        self.misp = misp
        create = {"fia": misp_store.create_fia, "vea": misp_store.create_vea, "der": misp_store.create_der}[kind]
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_tag_scraper_event_as_product_source") as self.tagged, \
             mock.patch.object(misp_store.misp_session, "current_user_email", return_value="analyser"):
            return create(dict(data))

    def report(self):
        return self.misp.add_event_report.call_args.args[1].content


class Alert(Creation):
    DATA = {"title": "Grid operator hit", "summary": "Ransomware stopped a grid operator.", "tlp": "amber",
            "source_event_uuids": [SOURCE_UUID], "source_event_hints": {SOURCE_UUID: "scraper"}}

    def test_its_report_is_rendered_with_what_the_object_holds(self):
        self.assertEqual(self.create("fia", self.DATA), (PRODUCT_UUID, "FIA-00042"))
        self.assertIn("Ransomware stopped a grid operator.", self.report())
        self.tagged.assert_called_once_with(SOURCE_UUID, "flash-intel", source_id="scraper")

    def test_one_whose_object_is_refused_is_deleted_again(self):
        with self.assertRaisesRegex(RuntimeError, "object refused"):
            self.create("fia", self.DATA, refuse="object")
        self.misp.delete_event.assert_called_once_with(PRODUCT_UUID)
        self.misp.add_event_report.assert_not_called()
        self.tagged.assert_not_called()

    def test_one_whose_report_is_refused_is_deleted_again(self):
        with self.assertRaisesRegex(RuntimeError, "report refused"):
            self.create("fia", self.DATA, refuse="report")
        self.misp.delete_event.assert_called_once_with(PRODUCT_UUID)
        self.tagged.assert_not_called()

    def test_a_delete_that_fails_too_is_logged_and_the_first_error_raised(self):
        with self.assertLogs("webapp.misp_store", level="WARNING") as logs, \
             self.assertRaisesRegex(RuntimeError, "object refused"):
            self.create("fia", self.DATA, refuse="object", delete_refused=True)
        self.assertIn("Could not delete the unfinished FIA", logs.output[0])


class Advisory(Creation):
    DATA = {"cve_id": "CVE-2026-1001", "title": "FortiOS flaw", "summary": "A heap overflow in FortiOS.",
            "tlp": "amber", "source_event_uuid": SOURCE_UUID, "source_event_hints": {SOURCE_UUID: "scraper"}}

    def test_its_report_is_rendered_with_what_the_object_holds(self):
        self.assertEqual(self.create("vea", self.DATA), (PRODUCT_UUID, "VEA-00042"))
        self.assertIn("A heap overflow in FortiOS.", self.report())

    def test_one_whose_object_is_refused_is_deleted_again(self):
        with self.assertRaisesRegex(RuntimeError, "object refused"):
            self.create("vea", self.DATA, refuse="object")
        self.misp.delete_event.assert_called_once_with(PRODUCT_UUID)
        self.tagged.assert_not_called()


class DetectionRequest(Creation):
    DATA = {"title": "Detect PAN-OS exploitation", "hypothesis": "A GlobalProtect session spawns a shell.",
            "cve_ids": ["CVE-2024-3400"], "tlp": "amber",
            "source_event_uuids": [SOURCE_UUID], "source_event_hints": {SOURCE_UUID: "scraper"}}

    def test_its_report_is_rendered_with_what_the_object_holds(self):
        self.assertEqual(self.create("der", self.DATA), (PRODUCT_UUID, "DER-00042"))
        self.assertIn("A GlobalProtect session spawns a shell.", self.report())
        self.assertIn("CVE-2024-3400", self.report())
        self.tagged.assert_called_once_with(SOURCE_UUID, "detection-eng-request", source_id="scraper")

    def test_one_whose_object_is_refused_is_deleted_again(self):
        with self.assertRaisesRegex(RuntimeError, "object refused"):
            self.create("der", self.DATA, refuse="object")
        self.misp.delete_event.assert_called_once_with(PRODUCT_UUID)
        self.misp.add_event_report.assert_not_called()
        self.tagged.assert_not_called()

    def test_one_whose_report_is_refused_is_deleted_again(self):
        with self.assertRaisesRegex(RuntimeError, "report refused"):
            self.create("der", self.DATA, refuse="report")
        self.misp.delete_event.assert_called_once_with(PRODUCT_UUID)
        self.tagged.assert_not_called()


if __name__ == "__main__":
    unittest.main()
