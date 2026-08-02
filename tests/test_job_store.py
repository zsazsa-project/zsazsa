"""Tests for the background job store's Redis / in-memory fallback.

The store keeps jobs in Redis and falls back to memory when it is unreachable.
The two copies have to stay in step, or a job written during an outage outlives
the Redis one and reappears on the next blip.

    python -m unittest tests.test_job_store
"""

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


if __name__ == "__main__":
    unittest.main()
