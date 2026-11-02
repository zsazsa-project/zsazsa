"""The Pipeline page's Overview and the activity filters: the outcomes per day
and by reason, what "Needs a look" lists and in what order, and the counts
beside each filter choice, each counted under the other filters.

The database is temporary; MISP is not asked.

    python -m unittest tests.test_pipeline_overview
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flask import Flask

import config
from core import db as core_db
from webapp.routes import pipeline


def _log(outcome, detail="", feed="Feed", ago="-0 days", n=1):
    with core_db.row_connection() as db:
        for _ in range(n):
            db.execute("INSERT INTO event_log (event_uuid, event_info, source_feed, outcome, detail, processed_at)"
                       " VALUES ('u', 'An event', ?, ?, ?, datetime('now', ?))", (feed, outcome, detail, ago))


class _TempLog(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")))
        core_db.init_db()


class Overview(_TempLog):
    def setUp(self):
        super().setUp()
        _log("product_created", "vea; CVEs: CVE-2026-1", n=2)
        _log("not_relevant", "no PIR/GIR match", n=3)
        _log("not_relevant", "excluded by title filter")
        _log("http_error", "HTTP 403")
        _log("error", "No alert could be drafted", ago="-3 days")
        _log("not_relevant", "no PIR/GIR match", ago="-40 days")
        self.overview = pipeline._overview()

    def test_each_day_of_the_last_two_weeks_by_outcome(self):
        days = self.overview["days"]
        self.assertEqual(len(days), 14)
        self.assertEqual(days[-1]["date"], datetime.now(timezone.utc).date().isoformat())
        self.assertEqual({k: days[-1][k] for k in ("made", "declined", "problem", "total")},
                         {"made": 2, "declined": 4, "problem": 1, "total": 7})
        self.assertEqual(days[-4]["problem"], 1)
        self.assertEqual(sum(d["total"] for d in days), 8)

    def test_the_first_day_names_its_month(self):
        first = datetime.now(timezone.utc).date() - timedelta(days=13)
        self.assertEqual(self.overview["days"][0]["label"], f"{first.day} {first.strftime('%b')}")

    def test_the_last_30_days_by_the_reason_the_activity_gives(self):
        self.assertEqual((self.overview["made"], self.overview["declined"], self.overview["problem"]), (2, 4, 2))
        self.assertEqual([(r["label"], r["n"]) for r in self.overview["reasons"]["declined"]],
                         [("No requirement match", 3), ("Excluded by title", 1)])

    def test_a_reason_links_to_the_outcome_the_activity_filters_on(self):
        """A declined reason comes from the detail, which the filter cannot
        narrow to; the other outcomes each have their own entries."""
        self.assertEqual({r["outcome"] for r in self.overview["reasons"]["declined"]}, {""})
        self.assertEqual({r["label"]: r["outcome"] for r in self.overview["reasons"]["problem"]},
                         {"Article not fetched": "http_error", "Error": "error"})


class RunHistory(_TempLog):
    def test_older_runs_are_there_to_ask_for(self):
        """Only the newest twenty were shown, a few hours of an hourly schedule,
        and nothing led to the ones before."""
        for action in ("vea", "flash-intel", "daily-briefing"):
            core_db.log_pipeline_run_end(core_db.log_pipeline_run_start(action, "schedule"), "completed")
        runs, older = pipeline._run_history(2)
        self.assertEqual(([r["action"] for r in runs], older), (["daily-briefing", "flash-intel"], True))
        self.assertFalse(pipeline._run_history(3)[1])


class ProblemsOfTheWeek(_TempLog):
    def test_counted_as_the_activity_it_opens_filters_them(self):
        """Counted by calendar day, the entry could say more problems than the
        activity it opens showed."""
        _log("http_error", ago="-167 hours")
        _log("no_content", ago="-169 hours")
        _log("not_relevant", "no CVE found", ago="-1 hours")
        self.assertEqual(pipeline._pipeline_stats()["problems_7d"], 1)


class Attention(unittest.TestCase):
    OK = {"ok": True, "configured": True}

    def source(self, label, **state):
        row = {"label": label, "kind": "misp", "ok": True, "error": "", "manual": False, "refresh_error": "",
               "refresh_overdue": False, "refresh_age": "4m ago", "limit_reached": False}
        return {**row, **state}

    def logged_run(self, action, minutes_ago, status, **extra):
        # As the run log stores it.
        started = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")
        return {"action": action, "label": pipeline._RUN_ACTIONS.get(action, action),
                "started_at": started, "status": status, "result": None, **extra}

    def attention(self, sources=(), mailboxes=(), runs=(), servers=(), problems=0, scraper=None):
        return pipeline._attention(scraper or self.OK, self.OK, list(sources), list(mailboxes), list(runs),
                                   {"servers": list(servers)}, problems)

    def test_nothing_down_lists_nothing(self):
        self.assertEqual(self.attention(sources=[self.source("CIRCL")]), [])

    def test_what_is_down_comes_first(self):
        found = self.attention(
            sources=[self.source("Partner", limit_reached=True),
                     self.source("CIRCL", ok=False, error="Connection timed out")],
            mailboxes=[{"name": "vendor-alerts", "enabled": True, "status": "failed", "message": "LOGIN failed"}],
            servers=[{"label": "CIRCL", "error": "403"}], problems=3)
        self.assertEqual([(i["level"], i["title"]) for i in found], [
            ("danger", "CIRCL is unreachable"),
            ("danger", "Mailbox vendor-alerts failed its last poll"),
            ("warning", "3 problems in the last 7 days"),
            ("info", "Partner filled its limit on the last refresh"),
            ("info", "The indicator counts of CIRCL could not be read"),
        ])

    def test_the_problems_open_the_activity_filtered_to_them(self):
        [item] = self.attention(problems=1)
        self.assertEqual((item["tab"], item["outcome"], item["period"]), ("activity", "problems", "7d"))

    def test_a_failed_run_until_a_later_run_of_its_action(self):
        runs = [self.logged_run("analyser", 10, "completed"), self.logged_run("analyser", 70, "failed"),
                self.logged_run("flash-intel", 30, "failed", result={"message": "429 rate limit"}),
                self.logged_run("vea", 50, "running", interrupted=True)]
        found = self.attention(runs=runs)
        self.assertEqual([i["title"].split(" at ")[0] for i in found], ["Flash intel alert failed", "Vulnerability advisory was interrupted"])
        self.assertEqual(found[0]["text"], "429 rate limit")
        self.assertEqual(found[0]["title"], f"Flash intel alert failed at {runs[2]['started_at'][:16].replace('T', ' ')}")

    def test_a_failure_older_than_a_week_is_left_out(self):
        self.assertEqual(self.attention(runs=[self.logged_run("vea", 8 * 24 * 60, "failed")]), [])

    def test_the_scraper_is_listed_once(self):
        down = {"ok": False, "configured": True, "error": "refused"}
        found = self.attention(scraper=down, sources=[self.source("MISP scraper", kind="scraper", ok=False, error="refused")])
        self.assertEqual([i["title"] for i in found], ["MISP scraper is unreachable"])
        self.assertEqual([i["title"] for i in self.attention(scraper=down)], ["The scraper MISP is unreachable"])

    def test_a_manual_source_is_never_down(self):
        self.assertEqual(self.attention(sources=[self.source("Manual", manual=True, ok=True)]), [])


class Facets(_TempLog):
    def setUp(self):
        super().setUp()
        _log("product_created", feed="A", n=2)
        _log("http_error", feed="A", ago="-10 days")
        _log("not_relevant", "no CVE found", feed="B")

    def counts(self, facet, **args):
        return {c["label"]: c["n"] for c in pipeline._activity_facets(args)[facet]}

    def test_the_outcomes_are_counted_under_the_other_filters(self):
        self.assertEqual(self.counts("outcome", source="A"),
                         {"All outcomes": 3, "Product made": 2, "Any problem": 1, "Article not fetched": 1})

    def test_the_feeds_are_counted_whatever_feed_is_chosen(self):
        self.assertEqual(self.counts("source", source="A"), {"All feeds": 4, "A": 3, "B": 1})

    def test_the_periods(self):
        self.assertEqual(self.counts("period", source="A"),
                         {"Any time": 3, "Today": 2, "Last 48 hours": 2, "Last 7 days": 2, "Last 30 days": 3})

    def test_the_choice_made_is_kept_when_nothing_has_it(self):
        self.assertEqual(self.counts("outcome", source="A", outcome="not_relevant")["Declined"], 0)
        self.assertEqual(self.counts("source", source="C", period="today")["C"], 0)

    def test_any_problem_is_a_choice_of_its_own(self):
        choices = pipeline._activity_facets({"problems": "1"})["outcome"]
        self.assertEqual([(c["value"], c.get("sub", False)) for c in choices if c["value"] in ("problems", "http_error")],
                         [("problems", False), ("http_error", True)])

    def test_the_first_page_has_them_and_the_next_not(self):
        app = Flask(__name__)
        app.register_blueprint(pipeline.bp)
        with mock.patch.object(pipeline, "scraper_enabled", return_value=False):
            first = app.test_client().get("/pipeline/activity").get_json()
            more = app.test_client().get("/pipeline/activity?offset=50").get_json()
        self.assertIn("facets", first)
        self.assertNotIn("facets", more)


class PurgeReturnsToTheActivity(unittest.TestCase):
    def test_the_redirect_opens_the_activity_tab(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(pipeline.bp)
        with mock.patch.object(pipeline, "scraper_enabled", return_value=False):
            reply = app.test_client().post("/pipeline/purge-orphaned")
        self.assertEqual(reply.status_code, 302)
        self.assertTrue(reply.headers["Location"].endswith("/pipeline#activity"))


if __name__ == "__main__":
    unittest.main()
