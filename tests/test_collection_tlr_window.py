"""The threat landscape queue keeps an older article an analyst put in it.

The queue is read from the collection cache, which holds what a source
collected in its date window (30 days for the scraper by default). An alert's
June article queued in November was tagged, but no refresh brought it back, so
it never showed in the queue. A refresh now also asks for the events queued
for the threat landscape, without the date, through the source's own filters;
a failure of that search keeps the cache as it was, as a failed refresh does.

MISP is an autospec of PyMISP; the cache is temporary.

    python -m unittest tests.test_collection_tlr_window
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pymisp import MISPEvent, MISPOrganisation, PyMISP

import config
from webapp import collection_cache

SCRAPER = {"id": "scraper", "kind": "scraper", "label": "MISP scraper"}
PARTNER = {"id": "partner", "kind": "misp", "label": "Partner", "url": "https://partner.example.org",
           "api_key": "k", "verify_tls": True, "tags": [], "tags_and": [], "tags_not": [],
           "org_filter_type": "exclude", "org_filter": ["org-b"], "since_days": 7, "limit": 50}


def _event(n, date, org="org-a"):
    event = MISPEvent()
    event.uuid = f"00000000-0000-4000-8000-{n:012d}"
    event.id, event.info, event.date = n, f"Event {n}", date
    event.Orgc = MISPOrganisation()
    event.Orgc.uuid = event.Orgc.name = org
    return event


RECENT, JUNE = _event(1, "2026-11-10"), _event(2, "2026-06-23")


class QueuedBeyondTheWindow(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
                        mock.patch.object(config, "MISP_SCRAPER_SINCE_DAYS", 30)):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def refresh(self, src, *answers):
        """Refresh ``src`` from a MISP that answers each search in turn."""
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.search.side_effect = list(answers)
        with mock.patch.object(collection_cache, "PyMISP", return_value=self.misp):
            return collection_cache.refresh_source(src)

    def cached(self, source_id):
        return sorted(r["uuid"] for r in collection_cache.get_events_by_uuids([RECENT.uuid, JUNE.uuid])
                      if r["source_id"] == source_id)

    def test_a_queued_scraper_article_older_than_the_window_is_cached(self):
        self.refresh(SCRAPER, [RECENT], [JUNE, RECENT])
        self.assertEqual(self.cached("scraper"), [RECENT.uuid, JUNE.uuid])
        first, queued = (c.kwargs for c in self.misp.search.call_args_list)
        self.assertIn("date_from", first)
        self.assertNotIn("date_from", queued)
        self.misp.build_complex_query.assert_called_with(
            and_parameters=[config.SCRAPER_MARKER_TAG, collection_cache.TLR_QUEUE_TAG])
        self.assertEqual(queued["tags"], self.misp.build_complex_query.return_value)

    def test_a_server_s_queued_events_go_through_its_org_filter(self):
        excluded = _event(3, "2026-06-01", org="org-b")
        self.refresh(PARTNER, [RECENT], [JUNE, excluded])
        self.assertEqual(self.cached("partner"), [RECENT.uuid, JUNE.uuid])
        self.assertEqual(collection_cache.get_events_by_uuids([excluded.uuid]), [])
        self.assertEqual(self.misp.search.call_args.kwargs["tags"], [collection_cache.TLR_QUEUE_TAG])

    def test_a_failed_search_for_the_queue_keeps_the_cache_as_it_was(self):
        self.refresh(SCRAPER, [RECENT], [JUNE])
        with self.assertLogs(collection_cache.logger, "WARNING"):
            result = self.refresh(SCRAPER, [RECENT], ConnectionError("timed out"))
        self.assertEqual(result["error"], "timed out")
        self.assertEqual(self.cached("scraper"), [RECENT.uuid, JUNE.uuid])

    def test_without_a_window_there_is_no_second_search(self):
        with mock.patch.object(config, "MISP_SCRAPER_SINCE_DAYS", 0):
            self.refresh(SCRAPER, [RECENT, JUNE])
        self.assertEqual(self.misp.search.call_count, 1)


if __name__ == "__main__":
    unittest.main()
