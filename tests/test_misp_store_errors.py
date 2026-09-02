"""Failed MISP writes have to reach the caller.

PyMISP answers a rejected call with a dict holding "errors" instead of raising,
so a delete or an attribute write that silently returned one used to look like a
success: the page flashed "deleted" and the record was still there. Deleting
something that is already gone is the one error worth swallowing.

    python -m unittest tests.test_misp_store_errors
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store

_ERROR = {"errors": (403, {"message": "Could not delete Event."})}
_GONE = {"errors": (404, {"message": "Invalid attribute."})}


class DeleteFailures(unittest.TestCase):
    def setUp(self):
        self.misp = mock.MagicMock()
        patcher = mock.patch.object(misp_store, "_misp", return_value=self.misp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_refused_event_delete_raises(self):
        self.misp.delete_event.return_value = _ERROR
        for delete in (misp_store.delete_pir, misp_store.delete_gir, misp_store.delete_rfi,
                       misp_store.delete_briefing, misp_store.delete_tlr,
                       misp_store.delete_indicator_feed, misp_store.delete_fia,
                       misp_store.delete_vea, misp_store.delete_threat_actor_profile):
            with self.subTest(delete=delete.__name__):
                with self.assertRaises(RuntimeError):
                    delete("u" * 36)

    def test_a_successful_event_delete_is_quiet(self):
        self.misp.delete_event.return_value = {"message": "Event deleted."}
        misp_store.delete_pir("u" * 36)

    def test_a_refused_stakeholder_delete_raises(self):
        self.misp.delete_event.return_value = _ERROR
        with mock.patch.object(misp_store, "_stakeholder_event",
                               return_value=SimpleNamespace(uuid="u" * 36)):
            with self.assertRaises(RuntimeError):
                misp_store.delete_stakeholder("u" * 36)

    def test_a_refused_attribute_delete_raises(self):
        self.misp.delete_attribute.return_value = _ERROR
        with self.assertRaises(RuntimeError):
            misp_store.delete_focus_point("a" * 36)

    def test_an_attribute_that_is_already_gone_is_not_an_error(self):
        # Re-submitting a delete, or a concurrent one, should not fail the page.
        self.misp.delete_attribute.return_value = _GONE
        misp_store.delete_focus_point("a" * 36)
        misp_store.delete_rfi_attachment("a" * 36)
        misp_store.delete_fia_attachment("a" * 36)


if __name__ == "__main__":
    unittest.main()
