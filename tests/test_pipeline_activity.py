"""The Pipeline activity: each entry links to its event in the MISP it was read
from, has an icon for what became of it, and an event of another source is not
hidden as orphaned for not being on the scraper. A row has the source Data
collection lists its event under, for its Push and Review by hand, and the
reply the scores Push sets.

The database is temporary, and MISP and the collection cache are patched.

    python -m unittest tests.test_pipeline_activity
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask

import config
from analyser.sources import Source
from core import db as core_db
from webapp import analyser_pipeline, collection_cache, misp_store, product_log
from webapp.routes import pipeline

SCRAPED, MANUAL, PARTNER, OLD = ("1" * 36, "2" * 36, "3" * 36, "4" * 36)
SERVERS = [{"id": "circl", "label": "CIRCL", "url": "https://misp.circl.example/"}]


class Activity(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
                      mock.patch.object(config, "MISP_URL", "https://scraper.example"),
                      mock.patch.object(config, "MISP_WEBAPP_URL", "https://webapp.example"),
                      mock.patch.object(config, "MISP_SERVERS", SERVERS, create=True),
                      mock.patch.object(pipeline, "scraper_enabled", return_value=True)):
            self.enterContext(patch)
        core_db.init_db()
        self.on_scraper = self.enterContext(
            mock.patch.object(misp_store, "scraper_existing_uuids", return_value={SCRAPED, OLD}))
        self.cache = self.enterContext(mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]))

    def page(self):
        return {row["event_uuid"]: row for row in pipeline._activity_page({}, 0, 50)["rows"]}

    def test_an_entry_links_to_the_misp_its_event_was_read_from(self):
        for uuid, source in ((SCRAPED, "scraper"), (MANUAL, "webapp"), (PARTNER, "circl")):
            core_db.log_event(uuid, "An event", "Feed", "not_relevant", "no CVE found", source_id=source)
        rows = self.page()
        self.assertEqual(rows[SCRAPED]["misp_url"], f"https://scraper.example/events/view/{SCRAPED}")
        self.assertEqual(rows[MANUAL]["misp_url"], f"https://webapp.example/events/view/{MANUAL}")
        self.assertEqual(rows[PARTNER]["misp_url"], f"https://misp.circl.example/events/view/{PARTNER}")

    def test_an_entry_from_before_the_source_was_kept_goes_by_the_collection_cache(self):
        core_db.log_event(OLD, "An event", "Feed", "not_relevant", "no PIR/GIR match")
        core_db.log_event(SCRAPED, "Gone from the cache", "Feed", "not_relevant", "no PIR/GIR match")
        self.cache.return_value = [{"uuid": OLD, "source_id": "scraper"}]
        rows = self.page()
        self.assertEqual(rows[OLD]["misp_url"], f"https://scraper.example/events/view/{OLD}")
        self.assertEqual(rows[SCRAPED]["misp_url"], "")

    def test_an_event_of_another_source_is_not_taken_for_an_orphan(self):
        """Only the scraper is asked whether an event still exists, and the
        manual entries and the other servers' events were hidden as orphaned."""
        core_db.log_event(MANUAL, "A manual entry", "Feed", "product_created", "vea", source_id="webapp")
        core_db.log_event(PARTNER, "A partner's event", "Feed", "not_relevant", "no CVE found", source_id="circl")
        core_db.log_event("5" * 36, "Deleted from the scraper", "Feed", "not_relevant", "", source_id="scraper")
        self.assertEqual(set(self.page()), {MANUAL, PARTNER})
        self.on_scraper.assert_called_once_with(["5" * 36])

    def test_purge_orphaned_keeps_the_history_of_the_other_sources(self):
        """Every logged event was looked for on the scraper, and the manual
        entries' and the other servers' history went with the purge."""
        for uuid, source in ((SCRAPED, "scraper"), ("5" * 36, "scraper"), (MANUAL, "webapp"), (PARTNER, "circl")):
            core_db.log_event(uuid, "An event", "Feed", "not_relevant", "", source_id=source)
        core_db.log_event("6" * 36, "From before the source was kept", "Feed", "not_relevant", "")
        self.assertEqual(pipeline._purge_orphaned_rows(), (2, 3))
        self.assertEqual(set(self.on_scraper.call_args.args[0]), {SCRAPED, "5" * 36, "6" * 36})
        with core_db.row_connection() as db:
            left = {r[0] for r in db.execute("SELECT event_uuid FROM event_log")}
        self.assertEqual(left, {SCRAPED, MANUAL, PARTNER})

    def test_an_older_entry_of_another_server_is_not_taken_for_an_orphan(self):
        """Logged before the source was kept, a partner server's event was
        looked for on the scraper, hidden, and purged."""
        core_db.log_event(PARTNER, "A partner's event", "Feed", "not_relevant", "no CVE found")
        self.cache.return_value = [{"uuid": PARTNER, "source_id": "circl"}]
        self.assertEqual(self.page()[PARTNER]["misp_url"], f"https://misp.circl.example/events/view/{PARTNER}")
        self.assertEqual(pipeline._purge_orphaned_rows(), (0, 0))
        self.on_scraper.assert_called_once_with([])

    def test_a_decision_links_to_the_activity_only_when_it_has_entries(self):
        core_db.log_event(SCRAPED, "An event", "Feed", "not_relevant", "no CVE found", source_id="scraper")
        self.assertEqual(pipeline._logged({SCRAPED, MANUAL}), {SCRAPED})

    def test_a_product_s_source_is_the_one_it_was_picked_from(self):
        """An event synced to two servers is cached under both, and the log
        took whichever row came last."""
        self.cache.return_value = [{"uuid": PARTNER, "source_id": "scraper", "info": "Synced", "tags": []},
                                   {"uuid": PARTNER, "source_id": "circl", "info": "Synced", "tags": []}]
        self.on_scraper.return_value = {PARTNER}
        product_log.log_product_sources([PARTNER], "flash-intel", {PARTNER: "scraper"})
        self.assertEqual(self.page()[PARTNER]["misp_url"], f"https://scraper.example/events/view/{PARTNER}")

    def test_a_row_names_the_source_its_buttons_act_on(self):
        core_db.log_event(MANUAL, "A manual entry", "Feed", "not_relevant", "no CVE found", source_id="webapp")
        core_db.log_event(OLD, "Gone from the cache", "Feed", "not_relevant", "no CVE found", source_id="scraper")
        self.cache.return_value = [{"uuid": MANUAL, "source_id": "manual-slack"}]
        rows = self.page()
        self.assertEqual(rows[MANUAL]["collection_source"], "manual-slack")
        self.assertEqual(rows[OLD]["collection_source"], "")

    def test_the_reply_has_the_scores_push_sets(self):
        app = Flask(__name__)
        app.register_blueprint(pipeline.bp)
        with mock.patch.object(config, "ANALYSER_PUSH_BRIEFING", "moderate", create=True):
            reply = app.test_client().get("/pipeline/activity").get_json()
        self.assertEqual(reply["push"], {"briefing": "moderate", "alert": "very-high"})

    def test_each_outcome_has_an_icon(self):
        for outcome, detail, label in (
                ("product_created", "vea; CVEs: CVE-2026-1", "Product made"),
                ("not_relevant", "excluded by title filter", "Excluded by title"),
                ("not_relevant", "The same story as FIA-00012.", "Told before"),
                ("not_relevant", "An analyst scored its relevance low", "Analyst score"),
                ("not_relevant", "Its timeliness score is under the limit for the alerts", "Under a limit"),
                ("not_relevant", "no CVE found", "No CVE to advise on"),
                ("not_relevant", "No CVE to advise on: CVE-2026-1 out of scope", "No CVE to advise on"),
                ("not_relevant", "no PIR/GIR match", "No requirement match"),
                ("not_relevant", "A recap of the week, not threat information.", "Not relevant"),
                ("http_error", None, "Article not fetched"),
                ("error", "No alert could be drafted", "Error")):
            with self.subTest(detail or outcome):
                self.assertEqual(pipeline._outcome_icon(outcome, detail)[1], label)

    def test_the_analyser_logs_the_source_it_read_the_event_from(self):
        event = SimpleNamespace(uuid=PARTNER, info="A partner's event", tags=[])
        analyser_pipeline._log(event, Source("circl", "misp", "CIRCL", None, False), "not_relevant", "no CVE found")
        self.assertEqual(self.page()[PARTNER]["misp_url"], f"https://misp.circl.example/events/view/{PARTNER}")


if __name__ == "__main__":
    unittest.main()
