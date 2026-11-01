"""One analyser run at a time, from the schedule or from any dashboard.

cron runs the analyser in its own process and the dashboard in a thread of the
web app, and both write workflow states and products for the same events. The
lock is a row in the database both share. A second run asking for it is told
who has it, and does not start: from the dashboard it is refused with that
answer, and the page holds its Start buttons while the lock is taken. A holder
that stopped refreshing it, because its process died, loses it once it has gone
quiet for an hour. A run refreshes it from a thread of its own while it goes,
so one waiting on a model call that takes longer than that keeps it. A run that
finds it lost the lock all the same stops at its next step rather than write
beside the new holder. Releasing a lock someone else took over changes nothing.
A run started from the dashboard can read back a number of hours again, between
1 and 168.

The database is temporary, the run itself is stubbed.

    python -m unittest tests.test_analyser_lock
"""

import os
import tempfile
import threading
import unittest
from unittest import mock

from flask import Flask

import config
from analyser import run_lock
from core import db
from webapp.routes import dashboard

NOW = 1_800_000_000


class LockTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")),
                        mock.patch.object(run_lock.time, "time", side_effect=lambda: self.now)):
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        self.now = NOW


class Lock(LockTest):
    def test_a_second_run_is_told_who_has_it(self):
        token, holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org", job_id="job-1")
        self.assertTrue(token)
        self.assertIsNone(holder)
        token2, holder = run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
        self.assertIsNone(token2)
        self.assertEqual((holder["label"], holder["started_by"], holder["job_id"]),
                         ("Vulnerability advisory", "a@example.org", "job-1"))

    def test_it_is_free_again_once_released(self):
        token, _holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        run_lock.release(token)
        self.assertIsNone(run_lock.holder())
        self.assertTrue(run_lock.acquire("analyser", "Scheduled analyser run", "schedule")[0])

    def test_a_holder_that_went_quiet_loses_it(self):
        run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        self.now = NOW + run_lock.QUIET_AFTER_SECONDS + 1
        self.assertIsNone(run_lock.holder())
        token, holder = run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
        self.assertTrue(token)
        self.assertIsNone(holder)

    def test_a_run_that_lost_it_stops_at_its_next_step(self):
        """A model call outlasted the window, and a second run started beside it."""
        from webapp import analyser_pipeline

        token, _holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        self.now = NOW + run_lock.QUIET_AFTER_SECONDS + 1
        run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
        self.assertFalse(run_lock.refresh(token))
        reached = []

        def handler(reading, progress=None):
            analyser_pipeline._emit(progress, "collect-events", "in_progress")
            reached.append("past it")
            return {"message": "done"}
        with mock.patch.dict(analyser_pipeline.__dict__, run_vea_action=handler), \
             mock.patch.object(analyser_pipeline.job_store, "get_job", return_value={"action": "vea"}), \
             mock.patch.object(analyser_pipeline.job_store, "set_step"), \
             mock.patch.object(analyser_pipeline.job_store, "update_job"), \
             mock.patch.object(analyser_pipeline.job_store, "append_log"), \
             mock.patch.object(analyser_pipeline.audit, "record"), \
             mock.patch.object(analyser_pipeline.Reading, "commit") as commit, \
             self.assertLogs("webapp.analyser_pipeline", level="ERROR"):
            self.assertIsNone(analyser_pipeline.run_action("job-1", "a@example.org", lock_token=token))
        self.assertEqual(reached, [])
        commit.assert_not_called()

    def test_one_that_keeps_refreshing_it_keeps_it(self):
        token, _holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        self.now = NOW + run_lock.QUIET_AFTER_SECONDS - 60
        run_lock.refresh(token)
        self.now = NOW + run_lock.QUIET_AFTER_SECONDS + 60
        self.assertIsNone(run_lock.acquire("analyser", "Scheduled analyser run", "schedule")[0])

    def test_a_run_waiting_on_a_long_model_call_keeps_it(self):
        """The model call outlasts the quiet hour, with no step reported in
        between: the run's own thread keeps the lock fresh."""
        token, _holder = run_lock.acquire("flash-intel", "Flash intel alert", "a@example.org")
        refresh, refreshed = run_lock.refresh, threading.Event()

        def counted(held):
            still = refresh(held)
            refreshed.set()
            return still
        with mock.patch.object(run_lock, "REFRESH_EVERY_SECONDS", 0.01), \
             mock.patch.object(run_lock, "refresh", counted), \
             run_lock.kept_fresh(token):
            self.now = NOW + run_lock.QUIET_AFTER_SECONDS + 60
            # Twice: the second refresh began after the clock moved on.
            for _refresh in range(2):
                refreshed.clear()
                self.assertTrue(refreshed.wait(2))
            self.assertIsNone(run_lock.acquire("analyser", "Scheduled analyser run", "schedule")[0])
        self.assertEqual(run_lock.holder()["token"], token)

    def test_the_thread_keeping_it_fresh_ends_with_the_run(self):
        token, _holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        before = threading.active_count()
        with mock.patch.object(run_lock, "REFRESH_EVERY_SECONDS", 0.01), run_lock.kept_fresh(token):
            self.assertEqual(threading.active_count(), before + 1)
        self.assertEqual(threading.active_count(), before)

    def test_releasing_a_lock_taken_over_changes_nothing(self):
        stale, _holder = run_lock.acquire("vea", "Vulnerability advisory", "a@example.org")
        self.now = NOW + run_lock.QUIET_AFTER_SECONDS + 1
        token, _holder = run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
        run_lock.release(stale)
        run_lock.refresh(stale)
        self.assertEqual(run_lock.holder()["token"], token)

    def test_it_says_what_is_running_who_started_it_and_when(self):
        self.assertEqual(run_lock.describe({"label": "Daily briefing", "started_by": "a@example.org",
                                            "started_at": 1761771600}),
                         "Daily briefing, started at 21:00 UTC by a@example.org")


class Dashboard(LockTest):
    def setUp(self):
        super().setUp()
        app = Flask(__name__)
        app.register_blueprint(dashboard.bp)
        self.client = app.test_client()
        for patcher in (mock.patch.object(dashboard.misp_session, "current_user_email", return_value="a@example.org"),
                        mock.patch.object(dashboard.job_store, "create_job", return_value={"id": "job-2"}),
                        mock.patch.object(dashboard.job_store, "forget_job")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def start(self, action="vea", **body):
        with mock.patch.object(dashboard.threading, "Thread") as thread:
            answer = self.client.post("/pipeline/run", json={"action": action, **body})
        return answer, thread

    def test_a_run_started_takes_the_lock_and_gives_it_back_when_done(self):
        answer, thread = self.start()
        self.assertEqual(answer.status_code, 200)
        holder = run_lock.holder()
        self.assertEqual((holder["action"], holder["started_by"], holder["job_id"]), ("vea", "a@example.org", "job-2"))
        target, args = thread.call_args.kwargs["target"], thread.call_args.kwargs["args"]
        with mock.patch.object(dashboard.analyser_pipeline, "run_action", side_effect=RuntimeError("MISP down")):
            with self.assertRaises(RuntimeError):
                target(*args)
        self.assertIsNone(run_lock.holder())

    def test_one_started_while_another_runs_is_refused_with_who_has_it(self):
        run_lock.acquire("analyser", "Scheduled analyser run", "schedule")
        answer, thread = self.start()
        self.assertEqual(answer.status_code, 409)
        body = answer.get_json()
        self.assertIn("Scheduled analyser run", body["error"])
        self.assertIn("by schedule", body["busy"]["message"])
        thread.assert_not_called()
        dashboard.job_store.forget_job.assert_called_once_with("job-2")

    def test_a_rescan_reads_back_as_far_as_it_is_asked(self):
        answer, thread = self.start(rescan_hours=24)
        self.assertEqual(answer.status_code, 200)
        target, args = thread.call_args.kwargs["target"], thread.call_args.kwargs["args"]
        with mock.patch.object(dashboard.analyser_pipeline, "run_action") as run:
            target(*args)
        self.assertEqual(run.call_args.kwargs["rescan_hours"], 24)

    def test_a_rescan_out_of_range_is_refused_before_anything_starts(self):
        for hours in (0, 500, "24", True):
            with self.subTest(hours=hours):
                answer, thread = self.start(rescan_hours=hours)
                self.assertEqual(answer.status_code, 400)
                thread.assert_not_called()
        self.assertIsNone(run_lock.holder())

    def test_the_page_can_ask_whether_the_analyser_is_free(self):
        self.assertIsNone(self.client.get("/pipeline/lock").get_json()["busy"])
        run_lock.acquire("daily-briefing", "Daily briefing", "a@example.org", job_id="job-1")
        busy = self.client.get("/pipeline/lock").get_json()["busy"]
        self.assertEqual((busy["action"], busy["job_id"]), ("daily-briefing", "job-1"))


if __name__ == "__main__":
    unittest.main()
