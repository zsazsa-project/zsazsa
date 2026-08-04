"""A refresh triggered from the collection page reports as a background job.

The sweep runs on the cache worker thread, so the job it reports into is handed
over through trigger_refresh rather than started by the request.

    python -m unittest tests.test_collection_cache_sweep
"""

import unittest
from unittest import mock

from webapp import collection_cache, job_store


def _sources():
    return [{"id": "a", "label": "Source A"}, {"id": "b", "label": "Source B"}]


class Sweep(unittest.TestCase):
    def setUp(self):
        # Answering None for every Redis command keeps the jobs these tests
        # create in job_store's in-memory fallback. Without this they land in
        # the Redis the app is using and show up in its Background jobs panel.
        patcher = mock.patch.object(job_store, "_command", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(job_store._memory.clear)
        self.addCleanup(collection_cache._pending_jobs.clear)

    def _sweep_with(self, outcomes):
        job = job_store.create_job("collection-refresh", label="Refresh collection cache")
        collection_cache._pending_jobs.append(job["id"])
        with mock.patch.object(collection_cache, "_build_sources", _sources), \
             mock.patch.object(collection_cache, "refresh_source", side_effect=outcomes):
            collection_cache._sweep()
        return job_store.get_job(job["id"])

    def test_job_completes_with_what_was_fetched(self):
        job = self._sweep_with([
            {"events": 38, "new": 2, "error": ""},
            {"events": 5, "new": 0, "error": ""},
        ])
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["result"], {"events": 43, "new": 2, "sources": 2, "failures": 0})
        self.assertIn("43 event(s)", job["message"])

    def test_one_failing_source_is_logged_but_does_not_fail_the_job(self):
        """A source with no API key is a standing condition. Failing the job over
        it would leave the top bar red after every single refresh."""
        job = self._sweep_with([
            {"events": 38, "new": 0, "error": ""},
            {"events": 0, "new": 0, "error": "No URL or API key configured"},
        ])
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["result"]["failures"], 1)
        self.assertIn("1 source(s) failed", job["message"])
        self.assertTrue(any("No URL or API key configured" in entry["message"]
                            for entry in job["log"]))

    def test_job_fails_when_no_source_could_be_read(self):
        job = self._sweep_with([
            {"events": 0, "new": 0, "error": "Connection refused"},
            {"events": 0, "new": 0, "error": "No URL or API key configured"},
        ])
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["result"]["failures"], 2)

    def test_sweep_without_a_waiting_job_touches_no_job(self):
        with mock.patch.object(collection_cache, "_build_sources", _sources), \
             mock.patch.object(collection_cache, "refresh_source",
                               return_value={"events": 1, "new": 0, "error": ""}), \
             mock.patch.object(job_store, "update_job") as update:
            collection_cache._sweep()
        update.assert_not_called()

    def test_every_job_queued_during_one_sweep_gets_an_answer(self):
        """Two clicks in a row must not leave the first job hanging."""
        first = job_store.create_job("collection-refresh", label="Refresh collection cache")
        second = job_store.create_job("collection-refresh", label="Refresh collection cache")
        collection_cache._pending_jobs.extend([first["id"], second["id"]])
        with mock.patch.object(collection_cache, "_build_sources", _sources), \
             mock.patch.object(collection_cache, "refresh_source",
                               return_value={"events": 1, "new": 1, "error": ""}):
            collection_cache._sweep()

        for job in (job_store.get_job(first["id"]), job_store.get_job(second["id"])):
            self.assertEqual(job["status"], "completed")


if __name__ == "__main__":
    unittest.main()
