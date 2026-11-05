"""When the analyser last ran, and runs nothing ever closed.

Two things that look like display details and are not. The dashboard says when
the analyser last completed a run, scheduled or started there, from the
watermarks those runs move (analyser.sources, whose own tests pin what moves
them). And a run row is only closed by the process that opened it, so the page
reading them has to allow for one that never came back. Before each summary it
writes, a run says which one it is on, so a slow run looks alive and one that
died shows how far it got. The end of a run prunes the logs, the audit log too
unless its retention is 0. The day of the last briefing is kept in the state
file, which is written whole or not at all.

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
from analyser import reader, sources
from core import db
from webapp import analyser_pipeline, audit
from webapp.routes import dashboard
from webapp.routes.dashboard import _pipeline_status
from webapp.routes.pipeline import _mark_interrupted_runs


class LastRun(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db"))
        patcher.start()
        self.addCleanup(patcher.stop)
        db.init_db()
        # _pipeline_status also counts pending events on the scraper MISP, which
        # is a live call and nothing to do with the timestamps tested here.
        misp = mock.patch.object(dashboard.misp_store, "_scraper_misp")
        misp.start()
        self.addCleanup(misp.stop)

    def test_freshness_follows_whichever_ran_last(self):
        now = int(time.time())
        sources._save_watermark("focus-points", "scraper", now - 7300, {}, now - 7200)
        self.assertEqual(_pipeline_status()["minutes_since"], 120)
        sources._save_watermark("vea", "partner", now - 400, {}, now - 300)
        self.assertEqual(_pipeline_status()["minutes_since"], 5)

    def test_no_run_yet(self):
        status = _pipeline_status()
        self.assertIsNone(status["minutes_since"])
        self.assertTrue(status["stale"])


class BriefingDay(unittest.TestCase):
    def test_a_failed_write_leaves_the_previous_state_alone(self):
        """The analyser writes this file and the web app reads it, from separate
        processes, so a half-written one is a state both of them can lose."""
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(json.dumps({"analyser_last_briefing": "2026-10-30"}))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with mock.patch.object(config, "STATE_FILE", handle.name), \
             mock.patch("core.atomic_write.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                reader.save_last_briefing("2026-10-31")
            self.assertEqual(reader.load_last_briefing(), "2026-10-30")


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
    def setUp(self):
        # Nothing is flagged for follow-up, and this install's cache is left unread.
        self.enterContext(mock.patch.object(analyser_pipeline.collection_cache, "get_flagged_uuids", return_value=set()))

    def test_each_missing_summary_is_announced_before_it_is_written(self):
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[]) for c in "abc"]
        reports = {"a" * 36: [SimpleNamespace(name="Article", content="An article")],
                   "b" * 36: [SimpleNamespace(name="Article", content="An article"),
                              SimpleNamespace(name="[AI-Summary] Event b", content="Done before")],
                   "c" * 36: [SimpleNamespace(name="Article", content="An article")]}
        said = []
        pipeline = analyser_pipeline
        reading = mock.create_autospec(sources.Reading, instance=True)
        scraper = sources.Source("scraper", "scraper", "MISP scraper", None, True)
        reading.read.return_value = [(e, scraper) for e in events]
        reading.counts, reading.errors = {"MISP scraper": 3}, []
        with mock.patch.object(pipeline, "read_event_reports", side_effect=lambda misp, e: reports[e.uuid]), \
             mock.patch.object(pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(pipeline, "_ensure_ai_summary",
                               side_effect=lambda source, e, r, g, p: said.append(f"ensure: {e.info}") or ("", e.info != "Event b")):
            pipeline._common_candidate_events(
                reading,
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
