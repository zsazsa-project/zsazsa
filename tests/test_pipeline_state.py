"""The analyser watermark, and runs nothing ever closed.

Two things that look like display details and are not. The watermark decides
which scraper events the next analyser run will see, so anything that moves it
without processing those events drops them for good. And a run row is only
closed by the process that opened it, so the page reading them has to allow for
one that never came back. Before each summary it writes, a run says which one it
is on, so a slow run looks alive and one that died shows how far it got. The end
of a run prunes the logs, the audit log too unless its retention is 0.

    python -m unittest tests.test_pipeline_state
"""

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import config
from analyser import reader
from core import db
from webapp import analyser_pipeline, audit
from webapp.routes import dashboard
from webapp.routes.dashboard import _pipeline_status
from webapp.routes.pipeline import _mark_interrupted_runs


class Watermark(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(json.dumps({"analyser_last_run": 1000}))
        handle.close()
        self.state = handle.name
        self.addCleanup(os.unlink, self.state)
        patcher = mock.patch.object(config, "STATE_FILE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)
        # _pipeline_status also counts pending events on the scraper MISP, which
        # is a live call and nothing to do with the timestamps tested here.
        misp = mock.patch.object(dashboard.misp_store, "_scraper_misp")
        misp.start()
        self.addCleanup(misp.stop)

    def stored(self):
        with open(self.state) as f:
            return json.load(f)

    def test_a_dashboard_action_does_not_move_the_watermark(self):
        """It reads today's incomplete events, not the analyser's queue, so
        advancing the watermark would skip whatever came in between."""
        reader.save_last_action(2000)
        self.assertEqual(reader.load_last_run(), 1000)
        self.assertEqual(reader.load_last_action(), 2000)

    def test_an_analyser_run_moves_the_watermark_only(self):
        reader.save_last_action(2000)
        reader.save_last_run(3000)
        self.assertEqual(self.stored(), {"analyser_last_run": 3000, "pipeline_last_action": 2000})

    def test_freshness_follows_whichever_ran_last(self):
        now = int(time.time())
        reader.save_last_run(now - 7200)
        self.assertEqual(_pipeline_status()["minutes_since"], 120)
        reader.save_last_action(now - 300)
        self.assertEqual(_pipeline_status()["minutes_since"], 5)

    def test_no_state_yet(self):
        with mock.patch.object(config, "STATE_FILE", "/nonexistent/state.json"):
            status = _pipeline_status()
        self.assertIsNone(status["minutes_since"])
        self.assertTrue(status["stale"])

    def test_a_failed_write_leaves_the_previous_state_alone(self):
        """The analyser and the web app write this file from separate
        processes, so a half-written one is a state both of them can lose."""
        reader.save_last_action(2000)
        with mock.patch("core.atomic_write.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                reader.save_last_run(3000)

        self.assertEqual(self.stored(), {"analyser_last_run": 1000, "pipeline_last_action": 2000})


class InterruptedRuns(unittest.TestCase):
    def _run(self, minutes_ago, status="running", finished=None):
        # started_at comes from SQLite's "now", which is UTC.
        started = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
        return {"status": status, "started_at": started.isoformat(), "finished_at": finished}

    def test_a_run_that_never_finished_is_marked(self):
        rows = _mark_interrupted_runs([self._run(45)])
        self.assertTrue(rows[0]["interrupted"])

    def test_a_run_still_going_is_left_alone(self):
        rows = _mark_interrupted_runs([self._run(5)])
        self.assertFalse(rows[0]["interrupted"])

    def test_utc_is_not_compared_against_local_time(self):
        """A machine ahead of UTC would otherwise mark every fresh run as
        interrupted the moment it started."""
        with mock.patch.dict(os.environ, {"TZ": "Australia/Sydney"}):
            time.tzset()
            self.addCleanup(time.tzset)
            rows = _mark_interrupted_runs([self._run(1)])
        self.assertFalse(rows[0]["interrupted"])

    def test_finished_and_unparsable_rows_are_untouched(self):
        rows = _mark_interrupted_runs([
            self._run(600, status="completed", finished="2026-08-05T10:00:00"),
            {"status": "running", "started_at": "not a date", "finished_at": None},
            {"status": "running", "finished_at": None},
        ])
        for row in rows:
            self.assertNotIn("interrupted", row)



class SummaryProgress(unittest.TestCase):
    def test_each_missing_summary_is_announced_before_it_is_written(self):
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[]) for c in "abc"]
        reports = {"a" * 36: [SimpleNamespace(name="Article", content="An article")],
                   "b" * 36: [SimpleNamespace(name="Article", content="An article"),
                              SimpleNamespace(name="[AI-Summary] Event b", content="Done before")],
                   "c" * 36: [SimpleNamespace(name="Article", content="An article")]}
        said = []
        pipeline = analyser_pipeline
        with mock.patch.object(pipeline, "_refresh_scraper_cache"), \
             mock.patch.object(pipeline, "_incomplete_scraper_events", return_value=(None, events)), \
             mock.patch.object(pipeline, "read_event_reports", side_effect=lambda misp, e: reports[e.uuid]), \
             mock.patch.object(pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary",
                               side_effect=lambda misp, e, r, g: said.append(f"ensure: {e.info}") or ("", e.info != "Event b")):
            pipeline._common_candidate_events(
                progress=lambda step, state, message="": said.append(message) if step == "generate-summaries" else None)
        self.assertEqual(said[:7], ["2 of 3 event(s) need an AI summary.",
                                    "AI summary 1 of 2: Event a", "ensure: Event a",
                                    "ensure: Event b",
                                    "AI summary 2 of 2: Event c", "ensure: Event c",
                                    "AI summary pass complete: created 2 new summary report(s)."])



class LogRetention(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db"))
        patcher.start()
        self.addCleanup(patcher.stop)
        db.init_db()
        audit.init()

    def entries_after_pruning(self, days):
        now = datetime.now(timezone.utc)
        ages = {"today": timedelta(0), "a day inside": timedelta(days=364),
                "an hour past": timedelta(days=365, hours=1), "long gone": timedelta(days=500)}
        with db.row_connection() as conn:
            for label, age in ages.items():
                conn.execute("INSERT INTO audit_log (timestamp, user, action, entity_type, details)"
                             " VALUES (?, 'a@example.org', 'notify', 'fia', ?)",
                             ((now - age).strftime("%Y-%m-%dT%H:%M:%S"), label))
        with mock.patch.object(config, "AUDIT_LOG_RETENTION_DAYS", days, create=True):
            db._prune_logs()
        with db.row_connection() as conn:
            return [r["details"] for r in conn.execute("SELECT details FROM audit_log ORDER BY id")]

    def test_entries_past_the_retention_go_to_the_hour(self):
        """The timestamps have a T where datetime() has a space, which kept a
        whole day of entries past their retention."""
        self.assertEqual(self.entries_after_pruning(365), ["today", "a day inside"])

    def test_a_database_without_an_audit_log_still_has_the_rest_pruned(self):
        with db.row_connection() as conn:
            conn.execute("DROP TABLE audit_log")
            conn.execute("INSERT INTO pipeline_run_log (action, started_at) VALUES ('vea', '2020-01-01T00:00:00')")
        with self.assertLogs("core.db", level="WARNING"):
            db._prune_logs()
        with db.row_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM pipeline_run_log").fetchone()[0], 0)

    def test_0_keeps_the_audit_log_for_good(self):
        self.assertEqual(self.entries_after_pruning(0), ["today", "a day inside", "an hour past", "long gone"])


if __name__ == "__main__":
    unittest.main()
