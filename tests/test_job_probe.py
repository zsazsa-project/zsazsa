"""Telling a slow AI job apart from a dead one.

A local model can hold a summary for many minutes, and a chat completion cannot
be asked how far along it is. So the job keeps saying it is alive while it
waits, and the probe reports whether this instance still has a worker for it.

    python -m unittest tests.test_job_probe
"""

import threading
import time
import unittest
from unittest import mock

from webapp import job_store


class Heartbeat(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(job_store, "_command", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(job_store._memory.clear)
        self.job = job_store.create_job("summarise", label="AI summary")

    def test_a_long_call_keeps_the_job_looking_alive(self):
        before = job_store.get_job(self.job["id"])["updated_at"]
        with job_store.heartbeat(self.job["id"], "generating summary", every_s=0.05):
            time.sleep(0.2)
            during = job_store.get_job(self.job["id"])

        self.assertGreater(during["updated_at"], before)
        self.assertIn("generating summary (running", during["message"])

    def test_the_ticker_stops_with_the_call(self):
        with job_store.heartbeat(self.job["id"], "generating summary", every_s=0.05):
            time.sleep(0.2)
        settled = job_store.get_job(self.job["id"])["updated_at"]
        time.sleep(0.2)
        self.assertEqual(job_store.get_job(self.job["id"])["updated_at"], settled)

    def test_a_tick_still_in_flight_cannot_overwrite_the_final_message(self):
        """The job would otherwise sit on "still running" for good: nothing
        writes to it after the caller's last message."""
        writing = threading.Event()
        update = job_store.update_job

        def slow_update(job_id, **fields):
            if "running" in str(fields.get("message", "")):
                writing.set()
                time.sleep(0.1)
            update(job_id, **fields)

        with mock.patch.object(job_store, "update_job", slow_update):
            with job_store.heartbeat(self.job["id"], "generating summary", every_s=0.05):
                writing.wait(2)
        update(self.job["id"], status="completed", message="1 summary created.")

        # Long enough that a tick let loose would have landed by now.
        time.sleep(0.3)
        self.assertEqual(job_store.get_job(self.job["id"])["message"], "1 summary created.")


class WorkerAlive(unittest.TestCase):
    def test_a_running_worker_is_found_by_its_job_id(self):
        job_id = "abcdef1234567890"
        self.assertFalse(job_store.worker_alive(job_id))

        stop = threading.Event()
        worker = threading.Thread(target=stop.wait, daemon=True,
                                  name=job_store.thread_name(job_id))
        worker.start()
        try:
            self.assertTrue(job_store.worker_alive(job_id))
        finally:
            stop.set()
            worker.join()

        self.assertFalse(job_store.worker_alive(job_id))


if __name__ == "__main__":
    unittest.main()
