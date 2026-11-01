"""The dashboard panes below the counts: active PIRs and GIRs, products by threat
actor type, throughput by collection source and events per configured source,
and what loading them asks of MISP. Above them, the products waiting for a
review or still a draft, per kind, which the scheduled analyser's alerts would
otherwise wait unseen in.

Each pane still shows everything it did before it had charts: the rows, their
numbers and links, and an empty state. The requirement panes add the mix of
priorities or review cycles. A load reads the alerts once for the two panes
that use them and the advisories once for the two that use those, counts
stakeholders from their metadata, and has MISP count the pending scraper events.

The fragment the dashboard loads is rendered with stand-in data, MISP is an
autospec of PyMISP, and the database and log are temporary.

    python -m unittest tests.test_dashboard_panes
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import render_template, url_for
from pymisp import PyMISP

import config
from webapp import collection_cache, create_app, misp_store
from webapp.models import MOSCOW_PRIORITIES, REVIEW_CYCLES
from webapp.routes import dashboard
from webapp.utils import ordered_counts


def _pir(n, priority, status="Active"):
    return SimpleNamespace(id=f"pir-{n}", pir_id=f"PIR-00{n}", question=f"Question {n}", priority=priority, status=status)


class Panes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(collection_cache, "start_worker")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = create_app()

    def render(self, **data):
        context = dict(setup_needed=False, stakeholder_count=1, pir_count=1, gir_count=1, rfi_count=1,
                       active_pirs=[], active_girs=[], actor_type_products=[], throughput_by_source=[],
                       configured_sources=[])
        context.update(data)
        # The route counts these from the same lists.
        context["priority_counts"] = ordered_counts((p.priority for p in context["active_pirs"]), MOSCOW_PRIORITIES)
        context["cycle_counts"] = ordered_counts((g.review_cycle for g in context["active_girs"]), REVIEW_CYCLES)
        with self.app.test_request_context("/"):
            page = BeautifulSoup(render_template("_dashboard_content.html", **context), "html.parser")
            self.urls = {"pir": url_for("requirements.pir_detail", id="pir-1"), "stats": url_for("stats.index")}
        return page

    def pane(self, page, title):
        return page.find(string=title).find_parent(class_="card")

    def text(self, element):
        return element.get_text(" ", strip=True)

    def test_the_counts_open_their_lists(self):
        page = self.render(stakeholder_count=4, pir_count=3, gir_count=2, rfi_count=5)
        with self.app.test_request_context("/"):
            lists = [url_for(e) for e in ("stakeholders.list", "requirements.pir_list", "requirements.gir_list",
                                          "rfi.rfi_list")]
        cards = page.select(".stat-card")
        self.assertEqual([self.text(c) for c in cards],
                         ["4 Stakeholders", "3 Priority Intelligence Requirements",
                          "2 General Intelligence Requirements", "5 Requests for Information"])
        self.assertEqual([c.select_one("a.stat-label")["href"] for c in cards], lists)

    def test_active_pirs_with_their_priority_mix(self):
        pirs = [_pir(1, "Must have"), _pir(2, "Should have", "In Development"), _pir(3, "Should have")]
        pane = self.pane(self.render(active_pirs=pirs), "Active PIRs")
        self.assertIn("3 active", self.text(pane))
        self.assertIn("Priority Must have 1 Should have 2", self.text(pane))
        self.assertEqual([s["title"] for s in pane.select(".chart-segbar > span")], ["Must have: 1", "Should have: 2"])
        first = pane.select_one(".req-item")
        self.assertEqual(self.text(first), "PIR-001 Question 1 Must have Active")
        self.assertEqual(first.a["href"], self.urls["pir"])

    def test_active_girs_with_their_review_cycles(self):
        girs = [SimpleNamespace(id="gir-1", gir_id="GIR-001", topic="Ransomware", status="Active", review_cycle="Monthly")]
        pane = self.pane(self.render(active_girs=girs), "Active GIRs")
        self.assertIn("1 active", self.text(pane))
        self.assertIn("Review cycle Monthly 1", self.text(pane))
        self.assertIn("GIR-001 Ransomware Active Monthly", self.text(pane))

    def test_products_by_threat_actor_type(self):
        rows = [{"actor_type": "Unspecified", "daily_briefings": 3, "flash_intel_alerts": 5, "threat_actor_profiles": 1, "total": 9},
                {"actor_type": "State-Nexus Actors", "daily_briefings": 1, "flash_intel_alerts": 0, "threat_actor_profiles": 0, "total": 1}]
        pane = self.pane(self.render(actor_type_products=rows), "Products by threat actor type")
        self.assertIn("Daily briefings Flash intel Threat actor profiles", self.text(pane))
        self.assertEqual([self.text(r) for r in pane.select(".chart-row")], ["1 Unspecified 9", "2 State-Nexus Actors 1"])
        self.assertEqual([s["title"] for s in pane.select(".chart-row")[0].select(".chart-bar > span")],
                         ["3 daily briefing(s)", "5 flash intel alert(s)", "1 threat actor profile(s)"])
        self.assertEqual(pane.find("a", string="Stats")["href"], self.urls["stats"])

    def test_throughput_and_configured_sources(self):
        page = self.render(throughput_by_source=[{"source_feed": "Security.NL", "n": 274}, {"source_feed": "", "n": 3}],
                           configured_sources=[{"label": "MISP scraper", "events": 260}, {"label": "ISAC-MISP", "events": 0}])
        self.assertEqual([self.text(r) for r in self.pane(page, "Throughput by collection source").select(".chart-row")],
                         ["1 Security.NL 274", "2 Unknown 3"])
        self.assertEqual([self.text(r) for r in self.pane(page, "By configured source").select(".chart-row")],
                         ["1 MISP scraper 260", "2 ISAC-MISP 0"])

    def test_each_pane_says_when_it_has_nothing(self):
        page = self.render(configured_sources=[{"label": "MISP scraper", "events": 0}])
        for title, empty in (("Active PIRs", "No active PIRs yet."), ("Active GIRs", "No active GIRs yet."),
                             ("Products by threat actor type", "No products published yet."),
                             ("Throughput by collection source", "No events processed yet."),
                             ("By configured source", "No events cached yet.")):
            self.assertIn(empty, self.text(self.pane(page, title)), title)

    def test_each_kind_links_to_its_list_and_each_count_to_its_state(self):
        rows = [SimpleNamespace(kind="briefing", review=0, drafts=5, total=5),
                SimpleNamespace(kind="flash-intel", review=2, drafts=1, total=3),
                SimpleNamespace(kind="threat-actor-profile", review=0, drafts=1, total=1),
                SimpleNamespace(kind="threat-landscape", review=1, drafts=0, total=1)]
        pane = self.render(to_review=rows).select_one("#products-to-review")
        self.assertIn("To review 3 Draft 7", self.text(pane.select_one(".chart-legend")))
        rows = pane.select(".chart-row")
        self.assertEqual([" ".join(r.get_text().split()) for r in rows],
                         ["Daily briefings · 5 drafts 5", "Flash intel alerts · 2 to review, 1 draft 3",
                          "Threat actor profiles · 1 draft 1", "Threat landscapes · 1 to review 1"])
        with self.app.test_request_context("/"):
            self.assertEqual([[(self.text(a), a["href"]) for a in r.select("a")] for r in rows], [
                [("Daily briefings", url_for("daily_briefing.list_briefings")),
                 ("5 drafts", url_for("daily_briefing.list_briefings", state="draft"))],
                [("Flash intel alerts", url_for("flash_intel.review")),
                 ("2 to review", url_for("flash_intel.review", state="pending-review")),
                 ("1 draft", url_for("flash_intel.review", state="draft"))],
                [("Threat actor profiles", url_for("threat_actor_profile.review")),
                 ("1 draft", url_for("threat_actor_profile.review", state="Draft"))],
                # Its list has no state filter.
                [("Threat landscapes", url_for("threat_landscape.review"))],
            ])
        self.assertEqual([s["title"] for s in rows[1].select(".chart-bar > span")], ["2 to review", "1 draft"])

    def test_nothing_is_shown_when_nothing_waits(self):
        self.assertIsNone(self.render(to_review=[]).select_one("#products-to-review"))


class Loading(unittest.TestCase):
    """What one load of the panes asks of MISP."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def load(self, veas):
        alert = SimpleNamespace(uuid="f" * 36, fia_id="FIA-00001", title="Grid", review_state="approved",
                                actor_types=["State-Nexus Actors"], feedback_deadline=None, published=True)
        status = {"last_run": None, "stale": True, "minutes_since": None, "pending": None,
                  "total_24h": 0, "processed_24h": {}}
        empty = {name: mock.Mock(return_value=[]) for name in (
            "list_pirs", "list_girs", "list_pending_newsletters", "list_briefings",
            "list_threat_actor_profiles", "list_tlrs", "list_ders", "data_collection_source_counts")}
        with mock.patch.multiple(misp_store, **empty), \
             mock.patch.object(misp_store, "list_fias", return_value=[alert]) as self.list_fias, \
             mock.patch.object(misp_store, "list_veas", veas), \
             mock.patch.object(misp_store, "list_stakeholders") as self.list_stakeholders, \
             mock.patch.object(misp_store, "count_records", return_value=10) as self.count_records, \
             mock.patch.object(misp_store, "_misp", return_value=mock.create_autospec(PyMISP, instance=True)), \
             mock.patch.object(collection_cache, "cached_event_counts", return_value=[]), \
             mock.patch.object(dashboard, "_pipeline_status", return_value=status):
            return self.client.get("/dashboard/widgets").get_json()["html"]

    def test_the_alerts_are_read_once_for_both_panes_and_stakeholders_and_rfis_only_counted(self):
        """Both panes searched MISP for every alert, and every stakeholder was
        loaded whole to show how many there are."""
        veas = mock.Mock(return_value=[])
        html = self.load(veas)
        self.list_fias.assert_called_once_with()
        veas.assert_called_once_with()
        self.assertIn("State-Nexus Actors", html)
        self.list_stakeholders.assert_not_called()
        self.assertEqual([c.args for c in self.count_records.call_args_list],
                         [(config.TAG_STAKEHOLDER,), (config.TAG_RFI,)])

    def test_the_alerts_still_show_when_the_advisories_fail(self):
        with self.assertLogs("webapp.routes.dashboard", level="ERROR"):
            html = self.load(mock.Mock(side_effect=RuntimeError("MISP refused")))
        self.assertIn("State-Nexus Actors", html)


class CountProductsToReview(unittest.TestCase):
    def states(self, *states, field="review_state"):
        return [SimpleNamespace(**{field: s}) for s in states]

    def test_review_and_drafts_are_counted_per_kind_in_menu_order(self):
        lists = dict(
            list_briefings=self.states("draft", "published"),
            list_tlrs=self.states("internal-review", "stakeholder-review", "approved", "draft"),
            list_veas=self.states("approved", "rejected"),
            list_threat_actor_profiles=self.states("Draft", "Published", field="status"),
            list_ders=self.states("pending-review"),
        )
        alerts = self.states("pending-review", "pending-review", "draft", "approved")
        with mock.patch.multiple(misp_store, **{name: mock.Mock(return_value=v) for name, v in lists.items()}):
            counts = misp_store.products_to_review(fias=alerts)
        self.assertEqual([(c.kind, c.review, c.drafts, c.total) for c in counts],
                         [("briefing", 0, 1, 1), ("threat-landscape", 2, 1, 3), ("flash-intel", 2, 1, 3),
                          ("threat-actor-profile", 0, 1, 1), ("detection-eng", 1, 0, 1)])


class PendingScraperEvents(unittest.TestCase):
    """MISP counts the events that have both the scraper marker and the
    incomplete state. Read from the newest few hundred marked events and
    sorted here, the older pending ones were never counted. Of those, the ones
    with a relevance verdict are not waiting for the analyser any more."""

    def pending(self, answer, judged=(), read=True):
        """``read`` whether Settings > Analyser has the analyser read the scraper."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = answer
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True), \
             mock.patch.object(dashboard.event_state, "judged", return_value=set(judged)), \
             mock.patch.object(dashboard, "last_completed_at", return_value=None), \
             mock.patch.object(dashboard, "scraper_enabled", return_value=True), \
             mock.patch.object(config, "ANALYSER_READ_SCRAPER", read, create=True), \
             mock.patch.object(misp_store, "_scraper_misp", return_value=misp):
            return dashboard._pipeline_status()["pending"], misp

    def test_misp_is_asked_for_the_pending_ones_and_counts_them_all(self):
        count, misp = self.pending([{"Event": {"id": str(n)}} for n in range(3)])
        self.assertEqual(count, 3)
        misp.build_complex_query.assert_called_once_with(
            and_parameters=[config.SCRAPER_MARKER_TAG, 'workflow:state="incomplete"'])
        self.assertEqual(misp.search.call_args.kwargs["tags"], misp.build_complex_query.return_value)

    def test_an_event_with_a_verdict_is_not_waiting_for_the_analyser(self):
        """It stays open until the briefing closes it, but has been judged."""
        count, _misp = self.pending([{"Event": {"id": str(n), "uuid": f"{n}" * 36}} for n in range(3)],
                                    judged={"1" * 36})
        self.assertEqual(count, 2)

    def test_none_is_counted_when_the_analyser_does_not_read_the_scraper(self):
        """None of them would ever be judged, and the count would only grow."""
        count, misp = self.pending([{"Event": {"id": "1"}}], read=False)
        self.assertIsNone(count)
        misp.search.assert_not_called()

    def test_a_refused_search_shows_no_count_rather_than_none_pending(self):
        with self.assertLogs(dashboard.logger, "WARNING"):
            count, _misp = self.pending({"errors": "denied"})
        self.assertIsNone(count)


class CountRecords(unittest.TestCase):
    def test_a_count_reads_metadata_and_survives_a_refusal(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [SimpleNamespace(uuid="a"), SimpleNamespace(uuid="b")]
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            self.assertEqual(misp_store.count_records(config.TAG_STAKEHOLDER), 2)
            self.assertTrue(misp.search.call_args.kwargs["metadata"])
            misp.search.return_value = {"errors": "denied"}
            self.assertEqual(misp_store.count_records(config.TAG_STAKEHOLDER), 0)


if __name__ == "__main__":
    unittest.main()
