"""The statistics, scope statistics, pipeline and audit log pages: what each
number counts.

A product went out when MISP published it, or, for the profiles and feeds zsazsa
publishes without publishing the event, when it last changed. Products are named
after their type whatever tag value the settings give it, every page of them is
read, a rejected one is left out, and a stakeholder is covered by an active PIR
they own. Indicator health counts every enabled server once, from a cache. Scope values are
counted once per record, whatever their case. The pipeline never purges history
on an answer MISP refused, and the audit log says when it shows only part of
itself. A day chosen on its chart narrows the who, what and on what, not the
figures that say they cover the last 90 days.

MISP is an autospec of PyMISP or the store is patched; the databases are
temporary.

    python -m unittest tests.test_statistics
"""

import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask, url_for
from pymisp import MISPEvent, PyMISP

import config
from core import db as core_db
from webapp import collection_cache, create_app, misp_store
from webapp.routes import pipeline, stats

PIR = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
DAY = 86400


def _product(published=None, changed=1, tag='zsazsa:ctiproduct="flash-intel"', linked_pir="",
             state="approved", object_name="zsazsa-flash-intel"):
    """A product event, published and last changed that many days ago, whose
    object records ``state`` (None for an object without one)."""
    now = time.time()
    event = MISPEvent()
    event.from_dict(info="[zsazsa:fia] An alert", date="2026-10-01",
                    timestamp=str(int(now - changed * DAY)),
                    publish_timestamp=str(int(now - published * DAY)) if published is not None else "0",
                    published=published is not None)
    event.add_tag(tag)
    if object_name:
        obj = misp_store._build_obj(object_name)
        relation = "status" if object_name == "zsazsa-threat-actor-profile" else "review-state"
        if state:
            obj.add_attribute(relation, value=state, type="text")
        if linked_pir:
            obj.add_attribute("linked-pir-uuid", value=linked_pir, type="text")
        event.add_object(obj)
    return event


def _pir(uuid=PIR, pir_id="PIR-001", status="Active", owner_uuid="", intel_level=()):
    return SimpleNamespace(uuid=uuid, pir_id=pir_id, status=status, owner_uuid=owner_uuid,
                           intel_level=list(intel_level), collection_sources=[], focus_points=[])


def _metrics(products, pirs=(), stakeholders=(), misp=None):
    if misp is None:
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = products
    with mock.patch.object(misp_store, "_misp", return_value=misp), \
         mock.patch.object(misp_store, "list_rfis", return_value=[]):
        return stats._program_metrics(list(pirs), [], list(stakeholders))


class ProgramHealth(unittest.TestCase):
    def test_recent_products_are_counted(self):
        """PyMISP hands the timestamps over as datetimes, which int() refused,
        so every product read as dateless and both counts stayed at 0."""
        products = [_product(published=2), _product(published=20), _product(published=100),
                    _product(changed=10, tag='zsazsa:ctiproduct="threat-actor-profile"',
                             object_name="zsazsa-threat-actor-profile", state="Published")]
        metrics = _metrics(products)["products"]
        self.assertEqual((metrics["last_7d"], metrics["last_30d"]), (1, 3))

    def test_pir_coverage_counts_a_product_from_the_last_90_days(self):
        other = "0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7"
        pirs = [_pir(), _pir(other, "PIR-002")]
        coverage = _metrics([_product(published=10, linked_pir=PIR), _product(published=100, linked_pir=other)],
                            pirs)["pir_coverage"]
        self.assertEqual((coverage["covered"], coverage["uncovered"]), (1, 1))

    def test_products_are_named_after_their_type_whatever_the_tag(self):
        """The maturity signals looked the counts up under the built-in tag values."""
        with mock.patch.object(config, "TAG_FLASH_INTEL", 'zsazsa:ctiproduct="fia"', create=True):
            program = _metrics([_product(published=1, tag='zsazsa:ctiproduct="fia"')])
            threat = stats._maturity_signals(program, [], [], 0, [])[2]
        self.assertEqual(program["products"]["by_type"], {"Flash intel alert": 1})
        self.assertIn("1 flash intel alerts", threat["observed"])

    def test_every_page_of_products_is_read(self):
        """Only the first 500 were, so the totals stopped there."""
        pages = {1: [_product(published=1) for _ in range(500)], 2: [_product(published=1)]}
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.side_effect = lambda page=1, **kw: pages.get(page, [])
        metrics = _metrics([], misp=misp)
        self.assertEqual(metrics["products"]["total"], 501)

    def test_a_draft_has_not_gone_out(self):
        """It was dated by its last edit, so one edited yesterday counted as a
        product of the last 7 days and covered the PIR it was linked to."""
        program = _metrics([_product(changed=1, state="draft", linked_pir=PIR)], [_pir()])
        self.assertEqual(program["products"]["last_7d"], 0)
        self.assertEqual(program["pir_coverage"]["covered"], 0)

    def test_a_rejected_product_is_left_out_and_the_rest_not_out_yet_are_named(self):
        """A rejected product never went out, and the analyser leaves many. One
        waiting for review has not gone out either; it counted as out."""
        products = [_product(published=1), _product(state="rejected"), _product(state="pending-review"),
                    _product(state="draft", tag='zsazsa:ctiproduct="threat-actor-profile"',
                             object_name="zsazsa-threat-actor-profile"),
                    _product(tag='zsazsa:ctiproduct="indicator-feed"', object_name="zsazsa-indicator-feed",
                             state=None),
                    _product(object_name="")]
        metrics = _metrics(products)["products"]
        self.assertEqual(metrics["total"], 5)
        self.assertEqual(metrics["not_out"], 3)
        self.assertEqual(metrics["by_type"], {"Flash intel alert": 3, "Threat actor profile": 1,
                                              "Indicator feed": 1})
        self.assertEqual(metrics["not_out_by_type"], {"Flash intel alert": 2, "Threat actor profile": 1})

    def test_a_pir_counts_under_each_of_its_intel_levels(self):
        """Only the first one counted, so the statistics page and the PIR list
        gave different numbers for the same PIRs."""
        pirs = [_pir(intel_level=["Strategic", "Operational"]), _pir(pir_id="PIR-002")]
        self.assertEqual(_metrics([], pirs)["intel_levels"]["pir"],
                         {"Strategic": 1, "Operational": 1, "Unspecified": 1})

    def test_a_stakeholder_is_covered_by_an_active_pir_they_own(self):
        pirs = [_pir(owner_uuid="ada"), _pir(pir_id="PIR-002", status="Pending", owner_uuid="bob")]
        stakeholders = [SimpleNamespace(uuid="ada"), SimpleNamespace(uuid="bob")]
        coverage = _metrics([], pirs, stakeholders)["stakeholder_coverage"]
        self.assertEqual((coverage["with_pir"], coverage["without_pir"]), (1, 1))

    def test_a_program_held_back_by_coverage_says_why(self):
        """Three active PIRs and every product linked, but none in the last 90
        days: CTI1, with no gap to explain it."""
        pirs = [_pir(f"{i}" * 36, f"PIR-00{i}") for i in range(1, 4)]
        program = _metrics([_product(published=100, linked_pir="1" * 36)], pirs)
        signal = stats._maturity_signals(program, pirs, [], 1, [])[0]
        self.assertEqual(signal["level"], "CTI1")
        self.assertIn("No active PIR had a product in the last 90 days", signal["gaps"])


class ScopeStats(unittest.TestCase):
    def categories(self, pirs=(), fias=()):
        empty = {name: mock.Mock(return_value=[]) for name in
                 ("list_girs", "list_threat_actor_profiles", "list_briefings")}
        with mock.patch.multiple(misp_store, list_pirs=mock.Mock(return_value=list(pirs)),
                                 list_fias=mock.Mock(return_value=list(fias)), **empty):
            return {c["attr"]: c for c in misp_store.scope_stats()}

    def test_threat_actors_are_counted(self):
        pir = SimpleNamespace(uuid="p", pir_id="PIR-001", question="q", threat_actors=["Lazarus Group"])
        actors = self.categories([pir])["threat_actors"]
        self.assertEqual([i["value"] for i in actors["items"]], ["Lazarus Group"])

    def test_a_value_is_one_value_whatever_its_case_and_counts_once_per_record(self):
        pir = SimpleNamespace(uuid="p", pir_id="PIR-001", question="q", geographic_scope=["Belgium", "belgium"])
        alert = SimpleNamespace(uuid="f", fia_id="FIA-00001", title="t", geographic_scope=["BELGIUM"])
        geography = self.categories([pir], [alert])["geographic_scope"]
        self.assertEqual([(i["value"], i["count"]) for i in geography["items"]], [("Belgium", 2)])
        self.assertEqual([e["kind"] for e in geography["items"][0]["entries"]], ["pir", "fia"])


class IndicatorHealth(unittest.TestCase):
    """The pane counts indicators on every server zsazsa reads, from a cache the
    worker fills, as MISP's statistics take a while on a large instance."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db")),
                        mock.patch.object(config, "MISP_WEBAPP_URL", "https://misp.example.org"),
                        mock.patch.object(config, "MISP_WEBAPP_KEY", "wk"),
                        mock.patch.object(config, "MISP_URL", "https://scraper.example.org/"),
                        mock.patch.object(config, "MISP_KEY", "sk"),
                        mock.patch.object(config, "MISP_SERVERS", [
                            {"id": "partner", "label": "Partner", "url": "https://partner.example.org", "api_key": "k"},
                            {"id": "off", "url": "https://off.example.org", "api_key": "k", "enabled": False},
                            {"id": "nokey", "url": "https://nokey.example.org"},
                            {"id": "again", "url": "https://scraper.example.org", "api_key": "k"},
                        ])):
            patcher.start()
            self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def test_every_enabled_server_is_counted_once(self):
        """The scraper is often the store itself, and counting it twice doubles it."""
        ids = [misp_store._server_id(s) for s in misp_store.indicator_stat_servers()]
        self.assertEqual(ids, [misp_store.WEBAPP_STORE_ID, "scraper", "partner"])

    def refresh(self, answers):
        def connect(url, *args, **kwargs):
            misp = mock.create_autospec(PyMISP, instance=True)
            answer = answers[url.rstrip("/")]
            if isinstance(answer, Exception):
                misp.attributes_statistics.side_effect = answer
            else:
                misp.attributes_statistics.return_value = answer
            return misp
        with mock.patch.object(collection_cache, "PyMISP", side_effect=connect):
            collection_cache.refresh_indicator_stats()
        return {s["id"]: s for s in pipeline._indicator_stats()["servers"]}

    def test_the_counts_are_kept_per_server(self):
        servers = self.refresh({"https://misp.example.org": {"ip-dst": "4", "comment": "6"},
                                "https://scraper.example.org": {"domain": "2"},
                                "https://partner.example.org": {"ip-dst": "1", "sha256": "0"}})
        self.assertEqual(servers["zsazsa-store"]["by_type"], {"ip-dst": 4})
        self.assertEqual(servers["zsazsa-store"]["all_total"], 10)
        self.assertEqual(servers["partner"]["by_type"], {"ip-dst": 1})

    def test_a_server_that_fails_keeps_the_counts_it_last_gave(self):
        ok = {"https://misp.example.org": {"ip-dst": "4"}, "https://scraper.example.org": {"domain": "2"},
              "https://partner.example.org": {"ip-dst": "1"}}
        self.refresh(ok)
        servers = self.refresh({**ok, "https://partner.example.org": ConnectionError("timed out")})
        self.assertEqual(servers["partner"]["by_type"], {"ip-dst": 1})
        self.assertIn("timed out", servers["partner"]["error"])
        self.assertEqual(servers["scraper"]["error"], "")

    def test_the_servers_keep_their_order_after_one_fails(self):
        """A good refresh replaced its row and went to the back, behind the one that failed."""
        ok = {"https://misp.example.org": {}, "https://scraper.example.org": {}, "https://partner.example.org": {}}
        self.refresh(ok)
        self.refresh({**ok, "https://partner.example.org": ConnectionError("timed out")})
        self.assertEqual([s["id"] for s in pipeline._indicator_stats()["servers"]],
                         [misp_store.WEBAPP_STORE_ID, "scraper", "partner"])

    def test_a_server_no_longer_configured_drops_out(self):
        self.refresh({"https://misp.example.org": {}, "https://scraper.example.org": {},
                      "https://partner.example.org": {}})
        with mock.patch.object(config, "MISP_SERVERS", []):
            servers = self.refresh({"https://misp.example.org": {}, "https://scraper.example.org": {}})
        self.assertEqual(sorted(servers), ["scraper", "zsazsa-store"])

    def test_the_refresh_button_runs_a_job(self):
        app = Flask(__name__)
        app.register_blueprint(pipeline.bp)
        self.addCleanup(pipeline.job_store._memory.clear)
        with mock.patch.object(pipeline.job_store, "_command", return_value=None), \
             mock.patch.object(collection_cache, "refresh_indicator_stats") as refresh:
            reply = app.test_client().post("/pipeline/indicator-stats/refresh")
            job_id = reply.get_json()["job_id"]
            for thread in threading.enumerate():
                if thread.name == pipeline.job_store.thread_name(job_id):
                    thread.join(5)
            self.assertEqual(pipeline.job_store.get_job(job_id)["status"], "completed")
        refresh.assert_called_once()


class _TempDatabase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        core_db.init_db()


class Purge(_TempDatabase):
    def rows(self):
        with core_db.row_connection() as db:
            return db.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]

    def test_nothing_is_purged_on_an_answer_misp_refused(self):
        """A refused search read as "these events are gone", and their history
        was deleted."""
        with core_db.row_connection() as db:
            db.executemany("INSERT INTO event_log (event_uuid, outcome) VALUES (?, 'not_relevant')",
                           [(PIR,), ("0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7",)])
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = {"errors": (500, {"message": "Internal error"})}
        with mock.patch.object(misp_store, "_scraper_misp", return_value=misp), \
             self.assertRaises(RuntimeError):
            pipeline._purge_orphaned_rows()
        self.assertEqual(self.rows(), 2)


class SourceCounts(unittest.TestCase):
    def test_a_tag_no_event_has_is_left_out(self):
        """The panel scales its bars by the busiest source, and a busiest source
        of 0 failed the page."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.tags_statistics.return_value = {"tags": {"scraper:data-collection-source:A": "3",
                                                      "scraper:data-collection-source:B": "0"}}
        with mock.patch.object(misp_store, "scraper_enabled", return_value=True), \
             mock.patch.object(misp_store, "_scraper_misp", return_value=misp):
            self.assertEqual(misp_store.data_collection_source_counts(), [{"source_feed": "A", "n": 3}])


class _App(_TempDatabase):
    def setUp(self):
        super().setUp()
        for patcher in (
            mock.patch.object(config, "LOG_FILE", str(Path(config.DB_FILE).with_name("test.log")), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def soup(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")


class AuditLog(_App):
    def page(self, query=""):
        return self.soup(f"/logs{query}").get_text(" ", strip=True)

    def write(self, n):
        with core_db.row_connection() as db:
            db.executemany("INSERT INTO audit_log (timestamp, user, action, entity_type) VALUES (?, ?, ?, ?)",
                           [("2026-10-18T10:00:00", "analyst@example.org", "update", "pir")] * n)

    def test_a_filter_that_matches_nothing_says_so(self):
        self.write(1)
        self.assertIn("No entries match these filters.", self.page("?action=delete"))

    def test_a_cut_off_list_says_so(self):
        self.write(201)
        self.assertIn("The newest 200 entries are shown.", self.page())

    def test_a_short_list_does_not(self):
        self.write(3)
        self.assertNotIn("The newest 200", self.page())

    def write_on(self, days_ago, n, user="analyst@example.org", action="update"):
        day = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")
        with core_db.row_connection() as db:
            db.executemany("INSERT INTO audit_log (timestamp, user, action, entity_type) VALUES (?, ?, ?, ?)",
                           [(f"{day}T10:00:00", user, action, "pir")] * n)
        return day

    def test_the_busiest_day_stands_out_and_opens_its_entries(self):
        self.write_on(1, 2)
        busy = self.write_on(5, 7)
        page = self.soup("/logs")
        self.assertIn("The busiest day was", page.get_text(" ", strip=True))
        tile = page.select_one("a.stats-count[href*='day=']")
        self.assertIn(f"day={busy}", tile["href"])
        self.assertEqual(page.select_one(".day-chart-col.peak .day-chart-mark").get_text(strip=True), "7")
        on_that_day = self.soup(f"/logs?day={busy}")
        self.assertEqual(len(on_that_day.select(".logs-table tbody tr:not(.logs-day)")), 7)

    def test_the_figures_follow_the_user_filter(self):
        self.write_on(1, 2, user="one@example.org")
        self.write_on(2, 5, user="other@example.org")
        text = self.page("?user=one@example.org")
        self.assertIn("The busiest day was", text)
        self.assertIn("with 2 entries", text)

    def breakdown(self, query=""):
        """The who, what and on what under the chart, as {name: count}."""
        rows = self.soup(f"/logs{query}").select("a.chart-row")
        return {row.select_one(".name").get_text(strip=True): int(row.select_one(".chart-pill").get_text(strip=True))
                for row in rows}

    def test_a_day_narrows_the_who_what_and_on_what(self):
        """Only the entries followed the day; these went on counting the 90 days."""
        day = self.write_on(1, 2, user="one@example.org", action="create")
        self.write_on(2, 5, user="other@example.org", action="delete")
        self.assertEqual(self.breakdown(), {"other@example.org": 5, "one@example.org": 2,
                                            "delete": 5, "create": 2, "pir": 7})
        self.assertEqual(self.breakdown(f"?day={day}"), {"one@example.org": 2, "create": 2, "pir": 2})

    def test_a_day_keeps_the_other_filters(self):
        day = self.write_on(1, 2, user="one@example.org", action="create")
        self.write_on(1, 3, user="other@example.org", action="create")
        self.assertEqual(self.breakdown(f"?day={day}&user=other@example.org"),
                         {"other@example.org": 3, "create": 3, "pir": 3})

    def test_a_filter_chosen_under_the_chart_stays_on_the_day(self):
        day = self.write_on(1, 2)
        link = self.soup(f"/logs?day={day}").select_one("a.chart-row")
        self.assertIn(f"day={day}", link["href"])

    def test_the_page_says_which_day_they_are_of(self):
        day = self.write_on(1, 2)
        page = self.soup(f"/logs?day={day}")
        self.assertIn("Who, what and on what for", page.get_text(" ", strip=True))
        self.assertNotIn("Who, what and on what for", self.page())

    def test_the_most_active_user_stays_that_of_the_chart(self):
        """Its tile says the last 90 days, whatever the day chosen."""
        day = self.write_on(1, 2, user="one@example.org")
        self.write_on(2, 5, user="other@example.org")
        tile = self.soup(f"/logs?day={day}").select("a.stats-count")[-1].get_text(" ", strip=True)
        self.assertIn("other@example.org", tile)

    def test_a_day_without_entries_says_so(self):
        self.write_on(1, 2)
        empty = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")
        self.assertIn("None on this day.", self.page(f"?day={empty}"))

    def test_a_day_before_the_chart_has_its_who_what_and_on_what(self):
        old = self.write_on(120, 3)
        self.assertEqual(self.breakdown(f"?day={old}"), {"analyst@example.org": 3, "update": 3, "pir": 3})

    def test_an_empty_log(self):
        text = self.page()
        self.assertIn("No log entries yet.", text)
        self.assertIn("Nothing in the last 90 days", text)
        self.assertNotIn("The busiest day was", text)

    def test_a_day_before_the_chart_has_no_count(self):
        """Its heading counted only the entries shown, which a cut-off list
        made too few."""
        old = self.write_on(120, 3)
        heading = self.soup(f"/logs?day={old}").select_one(".logs-day th").get_text(" ", strip=True)
        self.assertNotIn("entries", heading)
        self.write_on(1, 2)
        self.assertIn("2 entries", self.soup("/logs").select_one(".logs-day th").get_text(" ", strip=True))

    def test_a_day_that_is_no_date_is_ignored(self):
        self.write_on(1, 2)
        self.assertNotIn("No entries match", self.page("?day=yesterday"))

    def test_older_entries_are_there_to_ask_for(self):
        """The newest 200 were all there was; a day's filter was the only way back."""
        self.write(201)
        self.assertIn("limit=400", self.soup("/logs").select_one(".card-footer a")["href"])
        self.assertIsNone(self.soup("/logs?limit=400").select_one(".card-footer a"))


class StatisticsPage(_App):
    """Every figure the page showed before it had charts is still on it."""

    PROGRAM = {
        "rfis": {"total": 7, "by_status": {"Acknowledged": 2, "Closed": 4, "In Progress": 1}, "open": 3, "overdue": 3,
                 "feedback_collected": 1, "feedback_met": 1, "feedback_on_time": 1,
                 "pct_feedback_collected": 14.3, "pct_on_time": 100.0},
        "products": {"total": 32, "not_out": 8, "by_type": {"Flash intel alert": 8, "Daily threat briefing": 9},
                     "not_out_by_type": {"Daily threat briefing": 5}, "with_pir_link": 6, "with_feedback": 5,
                     "last_30d": 5, "last_7d": 2, "pct_with_pir_link": 18.8, "pct_with_feedback": 15.6},
        "intel_levels": {"pir": Counter({"Operational": 5, "Strategic": 2}), "gir": Counter()},
        "stakeholder_coverage": {"with_pir": 2, "without_pir": 8, "pct_covered": 20.0},
        "pir_coverage": {"covered": 0, "uncovered": 2, "pct": 0.0},
        "collection_gaps": {"pirs_with_sources": 1, "pirs_without_sources": 1,
                            "girs_with_sources": 0, "girs_without_sources": 0},
    }

    def setUp(self):
        super().setUp()
        pirs = [_pir(), _pir(uuid="p" * 36, pir_id="PIR-002", status="Pending")]
        rows = [{"actor_type": "State-Nexus Actors", "daily_briefings": 1, "flash_intel_alerts": 4,
                 "threat_actor_profiles": 2, "total": 7}]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs), \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[SimpleNamespace(uuid="s")] * 10), \
             mock.patch.object(stats, "_program_metrics", return_value=self.PROGRAM), \
             mock.patch.object(misp_store, "product_counts_by_threat_actor_type", return_value=rows), \
             mock.patch.object(pipeline, "_source_health", return_value=[]):
            self.page = self.soup("/stats")
        self.text = self.page.get_text(" ", strip=True)

    def test_the_counts_and_the_warnings(self):
        for shown in ("1 / 2 Active / total PIRs", "0 / 0 Active / total GIRs", "10 Stakeholders",
                      "1 Active requirements without scope items",
                      "1 active PIR has no scope items.",
                      "Collection gap: 1 active PIR has no collection sources mapped."):
            self.assertIn(shown, self.text)

    def test_the_counts_link_to_their_lists(self):
        with self.client.application.test_request_context():
            expected = {"Active / total PIRs": url_for("requirements.pir_list"),
                        "Active / total GIRs": url_for("requirements.gir_list"),
                        "Stakeholders": url_for("stakeholders.list"),
                        "Open RFIs": url_for("rfi.rfi_list")}
        links = {a.select_one(".label, .name").get_text(): a["href"]
                 for a in self.page.select("a.stats-count, a.stats-metric")}
        self.assertEqual(links, expected)

    def test_the_program_health_figures(self):
        for shown in ("Open RFIs 3 3 overdue 7 total RFIs",
                      "RFI feedback collected 14.3% 1 of 7", "RFI on-time delivery 100.0% of feedback received",
                      "RFIs by status Acknowledged 2 Closed 4 In Progress 1",
                      "Products linked to a PIR 18.8% 6 of 32 products", "Products with feedback 15.6% 5 of 32 products",
                      "PIR coverage (last 90 days) 0.0% 0 of 2 active PIRs with a product",
                      "Products (7 / 30 days) 2 / 5", "32 total products (8 not out yet)",
                      "Stakeholder coverage 20.0% 2 stakeholders owning an active PIR",
                      "PIRs by intel level Operational 5 Strategic 2", "GIRs by intel level -"):
            self.assertIn(shown, self.text)

    def test_products_by_type_link_to_their_list_busiest_first(self):
        links = [(a.get_text(" ", strip=True), a["href"]) for a in self.page.select("a.stats-type")]
        self.assertEqual(links, [("Daily threat briefing 9 (5 not out yet)", "/products/?type=Daily+threat+briefing"),
                                 ("Flash intel alert 8", "/products/?type=Flash+intel+alert")])

    def test_the_actor_types_maturity_and_the_rest(self):
        self.assertIn("State-Nexus Actors 1 4 2 7", self.text)
        self.assertIn("published briefings, alerts and profiles", self.text)
        program = self.page.find(string="Program").find_parent(class_="stats-signal")
        self.assertEqual([s.get_text() for s in program.select(".stats-steps > .on")], ["CTI0", "CTI1"])
        for shown in ("Observable maturity signals (CTI-CMM indicative)", "Fewer than 3 active PIRs (currently 1)",
                      "PIRs with scope items 0 / 1", "GIRs with scope items 0 / 0", "PIRs with an owner -",
                      "Stakeholders with products -", "PIRs as Markdown", "Stakeholders as Markdown"):
            self.assertIn(shown, self.text)


class ScopePage(_App):
    def setUp(self):
        super().setUp()
        pir = {"kind": "pir", "label": "PIR-001 Wipers", "uuid": PIR}
        alert = {"kind": "fia", "label": "FIA-00001 Grid", "uuid": "f" * 36}
        categories = [
            {"label": "Geographic scope", "attr": "geographic_scope", "total": 3, "distinct": 2,
             "items": [{"value": "Belgium", "count": 2, "entries": [pir, alert]},
                       {"value": "Europe", "count": 1, "entries": [pir]}]},
            {"label": "Campaign", "attr": "campaign", "total": 0, "distinct": 0, "items": []},
        ]
        with mock.patch.object(misp_store, "scope_stats", return_value=categories):
            self.page = self.soup("/stats/scope")
        self.text = self.page.get_text(" ", strip=True)

    def test_every_value_its_count_and_its_records(self):
        geography = self.page.select_one("#scope-geographic_scope")
        self.assertIn("2 distinct · 3 total", geography.get_text(" ", strip=True))
        rows = [r.get_text(" ", strip=True) for r in geography.select(".scope-row")]
        self.assertEqual(rows, ["1 Belgium 2", "2 Europe 1"])
        records = [(a.find_previous_sibling().get_text(), a["href"]) for a in geography.select(".scope-entries a")]
        self.assertEqual(records[:2], [("PIR", f"/pirs/{PIR}"), ("Alert", f"/products/flash-intel/{'f' * 36}")])

    def test_bars_are_split_by_record_type(self):
        belgium = self.page.select_one("#scope-geographic_scope .chart-bar")
        self.assertEqual([s["title"] for s in belgium.find_all("span")], ["PIR: 1", "Alert: 1"])

    def test_the_page_totals_and_an_empty_category(self):
        self.assertIn("3 scope values counted 2 distinct values 1 / 2 categories in use", self.text)
        self.assertIn("PIRs 1", self.text)
        self.assertIn("Flash intel alerts 1", self.text)
        self.assertIn("Campaign No scope items recorded. 0 distinct · 0 total", self.text)


if __name__ == "__main__":
    unittest.main()
