"""Tests for background notification delivery.

Publishing a product hands its delivery to a worker thread. What matters is that
the caller is not made to wait, that the outcome (including a failure) still
reaches the job store and the audit log, and that a double-clicked Publish
button does not mail every stakeholder twice.

    python -m unittest tests.test_notify_jobs
"""

import time
import unittest
from itertools import count
from unittest import mock

from webapp import job_store, notify_jobs

_ids = count()


def _wait_for_finish(job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = job_store.get_job(job_id)
        if job and job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.02)
    return job_store.get_job(job_id)


class JobTestCase(unittest.TestCase):
    """Runs against the in-memory job store.

    Deliveries are keyed on the product now, so a job left behind by another test
    (or by the running application, when Redis is reachable) would be handed back
    instead of a new one being started. Pinning the store to memory and using a
    fresh product id per test keeps them independent.
    """

    def setUp(self):
        command = mock.patch.object(job_store, "_command", return_value=None)
        command.start()
        self.addCleanup(command.stop)

        audit = mock.patch.object(notify_jobs.audit, "record")
        self.audit = audit.start()
        self.addCleanup(audit.stop)

        job_store._memory.clear()
        self.addCleanup(job_store._memory.clear)

    def start(self, deliver, entity_id=None):
        return notify_jobs.start(
            "notify-test", "Product delivery", deliver,
            entity_type="fia",
            entity_id=entity_id or f"uuid-{next(_ids)}",
            entity_label="FIA-1",
            user="a@b.test",
        )


class Delivery(JobTestCase):
    def test_the_caller_is_not_held_by_a_slow_delivery(self):
        started = time.time()
        job = self.start(lambda log: (time.sleep(1), (True, "sent via email"))[1])
        self.assertLess(time.time() - started, 0.5)
        self.assertIn(job["status"], ("queued", "running"))

    def test_a_successful_delivery_completes_and_is_audited(self):
        job = self.start(lambda log: (log("2 recipient(s)."), (True, "sent via email"))[1])
        finished = _wait_for_finish(job["id"])
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["message"], "sent via email")
        self.assertIn("2 recipient(s).", [row["message"] for row in finished["log"]])
        self.assertEqual(self.audit.call_count, 1)

    def test_a_channel_that_could_not_be_reached_fails_the_job(self):
        job = self.start(lambda log: (False, "could not reach mattermost"))
        finished = _wait_for_finish(job["id"])
        self.assertEqual(finished["status"], "failed")
        self.assertEqual(finished["error"], "could not reach mattermost")

    def test_an_exception_is_reported_rather_than_lost(self):
        def explode(log):
            raise RuntimeError("SMTP timed out")

        job = self.start(explode)
        finished = _wait_for_finish(job["id"])
        self.assertEqual(finished["status"], "failed")
        self.assertIn("SMTP timed out", finished["message"])
        self.assertIn("SMTP timed out", self.audit.call_args.kwargs["details"])

    def test_a_broken_audit_write_does_not_lose_the_job_result(self):
        self.audit.side_effect = RuntimeError("db gone")
        job = self.start(lambda log: (True, "sent via email"))
        finished = _wait_for_finish(job["id"])
        self.assertEqual(finished["status"], "completed")


class DoubleSubmit(JobTestCase):
    """Delivery is instant to start now, so Publish is easy to double-click."""

    def test_a_second_click_joins_the_running_job(self):
        delivered = []

        def slow(log):
            time.sleep(0.4)
            delivered.append(1)
            return True, "sent via email"

        first = self.start(slow, entity_id="same-product")
        second = self.start(slow, entity_id="same-product")
        self.assertEqual(first["id"], second["id"])
        time.sleep(0.8)
        self.assertEqual(len(delivered), 1)

    def test_a_different_product_is_unaffected(self):
        first = self.start(lambda log: (time.sleep(0.3), (True, "ok"))[1], entity_id="product-a")
        other = self.start(lambda log: (True, "ok"), entity_id="product-b")
        self.assertNotEqual(first["id"], other["id"])

    def test_resending_after_the_first_finished_starts_a_new_job(self):
        first = self.start(lambda log: (True, "ok"), entity_id="product-c")
        _wait_for_finish(first["id"])
        again = self.start(lambda log: (True, "ok"), entity_id="product-c")
        self.assertNotEqual(first["id"], again["id"])


class AuditTrail(JobTestCase):
    def test_the_permanent_record_keeps_the_per_channel_detail(self):
        """The job log expires with the job; the audit entry is what remains, so
        it has to carry which Flowintel case was created and which channel failed."""
        def deliver(log):
            log("publish: 3 eligible recipient(s).")
            log("Channels: sent via email; could not reach mattermost")
            log("Flowintel case 4711 created on prod.")
            return False, "sent via email; could not reach mattermost"

        job = self.start(deliver)
        _wait_for_finish(job["id"])
        details = self.audit.call_args.kwargs["details"]
        self.assertIn("4711", details)
        self.assertIn("could not reach mattermost", details)


class PreviewDelivery(JobTestCase):
    def test_the_outcome_wording_comes_from_the_shared_helper(self):
        summary = {"recipients": 3, "sent_types": ["email"],
                   "failed_types": ["mattermost"], "skipped_types": []}
        job = notify_jobs.start_preview(
            "notify-pir", "PIR-1 notification", lambda: summary,
            entity_type="pir", entity_id="pir-1", entity_label="PIR-1", user="a@b.test",
        )
        finished = _wait_for_finish(job["id"])
        self.assertEqual(finished["status"], "failed")
        self.assertIn("sent via email", finished["message"])
        self.assertIn("could not reach mattermost", finished["message"])


if __name__ == "__main__":
    unittest.main()
