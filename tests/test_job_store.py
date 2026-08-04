"""Tests for the background job store's Redis / in-memory fallback.

The store keeps jobs in Redis and falls back to memory when it is unreachable.
The two copies have to stay in step, or a job written during an outage outlives
the Redis one and reappears on the next blip.

    python -m unittest tests.test_job_store
"""

import json
import time
import unittest
from unittest import mock

from webapp import job_store


class FakeRedis:
    """Just enough of the hash commands job_store issues, with an on/off switch."""

    def __init__(self):
        self.up = True
        self.hash = {}

    def __call__(self, *args):
        if not self.up:
            return None
        command = args[0]
        if command == "HSET":
            self.hash[args[2]] = args[3]
            return 1
        if command == "HGET":
            return self.hash.get(args[2])
        if command == "HDEL":
            return 1 if self.hash.pop(args[2], None) is not None else 0
        if command == "HGETALL":
            flat = []
            for field, value in self.hash.items():
                flat += [field, value]
            return flat
        return 1


class MemoryFallback(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()
        job_store._memory.clear()
        patcher = mock.patch.object(job_store, "_command", side_effect=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(job_store._memory.clear)

    def test_jobs_are_kept_in_memory_while_redis_is_down(self):
        self.redis.up = False
        job_store.create_job("analyser", "run")
        self.assertEqual(len(job_store.list_jobs()), 1)

    def test_a_forgotten_job_does_not_come_back_after_an_outage(self):
        self.redis.up = False
        job = job_store.create_job("analyser", "run")   # lands in memory

        self.redis.up = True
        job_store.update_job(job["id"], status="completed")
        job_store.forget_job(job["id"])

        self.redis.up = False
        self.assertEqual(job_store.list_jobs(), [])

    def test_redis_becomes_the_record_once_it_is_back(self):
        self.redis.up = False
        job = job_store.create_job("analyser", "run")

        self.redis.up = True
        job_store.update_job(job["id"], status="completed")
        self.assertNotIn(job["id"], job_store._memory)

        # The version served now is Redis's, not the stale in-memory one.
        self.redis.up = False
        self.assertEqual(job_store.list_jobs(), [])


class ForgetFinished(unittest.TestCase):
    """The Remove buttons in the jobs panel drop entries, never work in flight."""

    def setUp(self):
        self.redis = FakeRedis()
        job_store._memory.clear()
        patcher = mock.patch.object(job_store, "_command", side_effect=self.redis)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(job_store._memory.clear)
        for status in ("completed", "failed", "running", "queued"):
            job = job_store.create_job("analyser", status)
            job_store.update_job(job["id"], status=status)

    def _statuses(self):
        return sorted(job["status"] for job in job_store.list_jobs())

    def test_removing_completed_keeps_the_rest(self):
        self.assertEqual(job_store.forget_finished(("completed",)), 1)
        self.assertEqual(self._statuses(), ["failed", "queued", "running"])

    def test_removing_all_keeps_queued_and_running(self):
        self.assertEqual(job_store.forget_finished(), 2)
        self.assertEqual(self._statuses(), ["queued", "running"])

    def _quiet_for(self, status, seconds):
        """Backdate a job's last write. Every save stamps updated_at, so the
        stored record is edited in place instead."""
        for job_id, raw in self.redis.hash.items():
            stored = json.loads(raw)
            if stored["status"] == status:
                stored["updated_at"] = time.time() - seconds
                self.redis.hash[job_id] = json.dumps(stored)

    def test_only_long_abandoned_unfinished_entries_go(self):
        """A local LLM can be quiet for a while between progress messages, so a
        job that is merely slow has to survive the abandoned sweep."""
        self._quiet_for("running", 40 * 60)
        self._quiet_for("queued", 5 * 3600)

        self.assertEqual(job_store.forget_abandoned(4 * 3600), 1)
        self.assertEqual(self._statuses(), ["completed", "failed", "running"])


if __name__ == "__main__":
    unittest.main()
