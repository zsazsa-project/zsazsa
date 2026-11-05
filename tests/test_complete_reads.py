"""What the analyser decides from has to be read in full.

Which events already have a product, the earlier products a story is compared
with, the advisories covering a CVE and the requirements an article is judged
against all come from MISP searches. A search that failed, on its first page or
a later one, used to read as no products or no requirements, and an event would
then get a second alert, or every article be judged against nothing. For the
analyser such a read raises, so the run fails and its watermark stays where it
is. The pages keep showing what could be read.

A failed read of the requirements is never cached as having none.

Several steps of one action ask MISP for the same records: which events have a
product, the earlier products to compare with, today's draft, the advisories
covering a CVE. While the action runs they are kept for a minute, in its own
thread only, so a page shows what MISP has, and a product an analyst made
while the action waited on a model call is seen by its next steps. A write
through misp_store in that thread, such as the alert the action just made,
drops what was kept.

    python -m unittest tests.test_complete_reads
"""

import unittest
from unittest import mock

from pymisp import PyMISP

from webapp import matching, misp_store

ERROR = {"errors": (500, "Internal error")}


def _misp(*pages):
    misp = mock.create_autospec(PyMISP, instance=True)
    misp.search.side_effect = list(pages)
    return misp


class Searches(unittest.TestCase):
    def test_a_page_that_fails_after_the_first_raises_when_the_result_decides(self):
        full = [object()] * 2
        with self.assertRaises(RuntimeError):
            misp_store._search_all(_misp(full, ERROR), strict=True, limit=2)

    def test_a_page_can_still_show_what_it_read(self):
        full = [object()] * 2
        with self.assertLogs("webapp.misp_store", level="WARNING"):
            self.assertEqual(misp_store._search_all(_misp(full, ERROR), limit=2), full)

    def test_the_products_an_event_has_are_read_in_full_or_not_at_all(self):
        with mock.patch.object(misp_store, "_misp", side_effect=lambda: _misp(ERROR)):
            for lookup in (misp_store.flash_intel_source_uuids, misp_store.vea_source_uuids,
                           misp_store.briefing_source_uuids, misp_store.briefing_also_seen_uuids):
                with self.subTest(lookup.__name__), self.assertRaises(RuntimeError):
                    lookup()


class Requirements(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(matching._req_cache, {"data": None, "ts": 0.0})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_failed_read_raises_for_the_analyser_and_is_not_cached(self):
        with mock.patch.object(misp_store, "_misp", side_effect=lambda: _misp(ERROR, ERROR)):
            with self.assertRaises(RuntimeError):
                matching.get_requirements(strict=True)
            with self.assertLogs("webapp.matching", level="WARNING"):
                self.assertEqual(matching.get_requirements(), ([], []))
        pir = mock.Mock(status="Active")
        with mock.patch.object(misp_store, "list_pirs", return_value=[pir]), \
             mock.patch.object(misp_store, "list_girs", return_value=[]):
            self.assertEqual(matching.get_requirements(), ([pir], []))


if __name__ == "__main__":
    unittest.main()
