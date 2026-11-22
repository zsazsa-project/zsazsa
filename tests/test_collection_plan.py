"""The collection plan page: what each requirement's planned sources delivered.

Per active PIR and GIR it shows the sources the requirement names, each with
the events it brought that match the requirement, or as silent when it brought
none; a mailbox cannot be traced and says so. It lists the sources that brought
events without being named, the events per month over the last six months, the
last event, flagged when it is over 30 days old, and the open RFIs linked to
it. Open RFIs linked to no active requirement are listed apart. MISP and the cache are
patched out; the database and log are temporary.

    python -m unittest tests.test_collection_plan
"""

import tempfile
import unittest
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, collection_plan, create_app, matching, misp_store

TODAY = date(2026, 11, 20)
SERVERS = [{"id": "misp-intern", "label": "MISP intern", "url": "https://misp.example"}]
PIR = SimpleNamespace(uuid="pir-1", pir_id="PIR-003", question="Who targets the grid?",
                      collection_sources=["misp-scraper", "MISP intern", "ISAC feed", "Gmail/IT-ISAC"])
GIR = SimpleNamespace(uuid="gir-1", gir_id="GIR-002", topic="Phishing against our brand", collection_sources=[])
EVENTS = [{"uuid": "e1", "source_id": "scraper", "date": "2026-11-10"},
          {"uuid": "e2", "source_id": "scraper", "date": "2026-09-03"},
          {"uuid": "e3", "source_id": "manual-newsletter", "date": "2026-10-01"},
          {"uuid": "e4", "source_id": "scraper", "date": "2026-04-30"},
          {"uuid": "e5", "source_id": "scraper", "date": "2026-08-15"}]
MATCHED = {"e1": [{"uuid": "pir-1"}], "e2": [{"uuid": "pir-1"}], "e3": [{"uuid": "pir-1"}], "e4": [{"uuid": "pir-1"}],
           "e5": [{"uuid": "gir-1"}]}
RFIS = [SimpleNamespace(uuid="r1", rfi_id="RFI-007", question="Is the grid at risk?", status="In Progress",
                        linked_pir_uuid="pir-1", linked_gir_uuid=""),
        SimpleNamespace(uuid="r2", rfi_id="RFI-008", question="What about water?", status="New",
                        linked_pir_uuid="", linked_gir_uuid=""),
        SimpleNamespace(uuid="r3", rfi_id="RFI-001", question="Old one", status="Closed",
                        linked_pir_uuid="", linked_gir_uuid=""),
        SimpleNamespace(uuid="r4", rfi_id="RFI-009", question="Still the dams?", status="Acknowledged",
                        linked_pir_uuid="pir-retired", linked_gir_uuid="")]


def _patches():
    return (mock.patch.object(config, "MISP_SERVERS", SERVERS, create=True),
            mock.patch.object(matching, "get_requirements", return_value=([PIR], [GIR])),
            mock.patch.object(matching, "match_events", return_value=MATCHED),
            mock.patch.object(collection_cache, "get_events", return_value=EVENTS),
            mock.patch.object(collection_cache, "cached_source_ids", return_value=["scraper", "manual-newsletter"]),
            mock.patch.object(collection_cache, "_build_sources", return_value=[{"id": "scraper", "label": "MISP scraper"}]),
            mock.patch.object(misp_store, "list_rfis", return_value=RFIS))


class Plan(unittest.TestCase):
    def setUp(self):
        for patcher in _patches():
            patcher.start()
            self.addCleanup(patcher.stop)
        self.data = collection_plan.plan(TODAY)
        self.rows = {r["id"]: r for r in self.data["rows"]}

    def test_the_months_are_the_last_six(self):
        self.assertEqual(self.data["months"], ["2026-06", "2026-07", "2026-08", "2026-09", "2026-10", "2026-11"])
        self.assertEqual(collection_plan._months(date(2026, 2, 5))[0], "2025-09")

    def test_a_planned_source_is_found_by_the_name_the_requirement_gives_it(self):
        with mock.patch.object(config, "MISP_SERVERS", SERVERS, create=True):
            self.assertEqual([collection_plan._planned_source_id(n) for n in PIR.collection_sources],
                             ["scraper", "misp-intern", "manual-isac-feed", None])

    def test_each_planned_source_with_what_it_delivered(self):
        pir = self.rows["PIR-003"]
        self.assertEqual([(p["name"], p["traced"], p["events"]) for p in pir["planned"]],
                         [("misp-scraper", True, 2), ("MISP intern", True, 0), ("ISAC feed", True, 0),
                          ("Gmail/IT-ISAC", False, 0)])
        self.assertEqual(pir["unplanned"], [("newsletter", 1)])
        self.assertEqual(self.data["silent_sources"], 2)

    def test_the_months_and_the_last_event(self):
        pir = self.rows["PIR-003"]
        self.assertEqual(dict(pir["months"]), {"2026-06": 0, "2026-07": 0, "2026-08": 0, "2026-09": 1, "2026-10": 1,
                                               "2026-11": 1})
        self.assertEqual((pir["events"], pir["last"], pir["quiet"]), (3, "2026-11-10", False), "April is too old")
        gir = self.rows["GIR-002"]
        self.assertEqual((gir["last"], gir["quiet"]), ("2026-08-15", True))
        self.assertEqual(self.data["rows"][0]["id"], "GIR-002", "the quiet ones first")
        self.assertEqual(self.data["quiet"], 1)

    def test_the_open_rfis_of_a_requirement_and_those_of_none(self):
        self.assertEqual([r.rfi_id for r in self.rows["PIR-003"]["rfis"]], ["RFI-007"])
        self.assertEqual([r.rfi_id for r in self.data["unlinked_rfis"]], ["RFI-008", "RFI-009"],
                         "RFI-009 is linked to a PIR that is no longer active")

    def test_how_far_back_each_source_goes(self):
        self.assertEqual(self.data["windows"], [("MISP scraper", "2026-08-15"), ("newsletter", "2026-10-01")])

    def test_rfis_that_cannot_be_read_leave_the_plan(self):
        with mock.patch.object(misp_store, "list_rfis", side_effect=RuntimeError("down")), \
             self.assertLogs("webapp.collection_plan", level="WARNING"):
            data = collection_plan.plan(TODAY)
        self.assertEqual((len(data["rows"]), data["unlinked_rfis"]), (2, []))


class Page(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker"), *_patches()):
            patcher.start()
            self.addCleanup(patcher.stop)
        reply = create_app().test_client().get("/stats/collection-plan")
        self.assertEqual(reply.status_code, 200)
        self.page = BeautifulSoup(reply.data, "html.parser")

    def test_it_shows_each_requirement_with_its_plan(self):
        rows = {r.select_one("a").get_text(): r for r in self.page.select("table.plan-table tbody tr")}
        pir = rows["PIR-003"]
        self.assertEqual(pir.select_one("a")["href"], "/pirs/pir-1")
        self.assertEqual([s.get_text(" ", strip=True) for s in pir.select(".plan-source.silent")], ["MISP intern 0", "ISAC feed 0"])
        self.assertEqual(pir.select_one(".plan-source.delivered").get_text(" ", strip=True), "misp-scraper 2")
        self.assertTrue(pir.select_one(".plan-source.untraced"))
        self.assertIn("RFI-007", pir.get_text())
        self.assertIn("2026-11: 1", pir.select_one(".plan-months")["aria-label"])
        self.assertEqual(rows["GIR-002"].select_one(".badge").get_text(), "2026-08-15")

    def test_the_unlinked_rfis_and_the_menu(self):
        card = self.page.find(string=lambda s: "Open RFIs no active PIR or GIR covers" in s).find_parent(class_="card")
        self.assertIn("RFI-008", card.get_text())
        self.assertTrue(self.page.select_one('a[href="/stats/collection-plan"]'))


if __name__ == "__main__":
    unittest.main()
