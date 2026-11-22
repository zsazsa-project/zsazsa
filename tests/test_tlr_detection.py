"""The detection coverage of a threat landscape report, its tactical annex.

The most frequent ATT&CK techniques of the report's incidents, each counted
once per incident, are set against the detection engineering requests for
them: covered by an active detection or one found through Rulezet, in progress
while a request is pending, in development or in test, or a gap. A rejected or
retired request does not count, and one shared more strictly than the report is
left out. On the report page a gap offers a new request for its technique,
prefilled from its incidents; the PDF has the annex too. MISP and the cache are patched out; the
database and log are temporary.

    python -m unittest tests.test_tlr_detection
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _entry(n, **fields):
    data = {"event_uuid": f"ev-{n}", "event_info": f"Event {n}", "event_date": f"2026-08-0{n}", "source_id": "scraper",
            **fields}
    return misp_store._tlr_entry_obj(data)


def _report(entries=(), **fields):
    data = {"tlr_id": "TLR-00007", "title": "Q3", "tlp": "amber", **fields}
    return misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj(data)] + list(entries),
                                              published=False, date=None))


def _der(n, technique, **fields):
    data = dict(uuid=f"der-{n}", der_id=f"DER-0000{n}", technique=technique, status="Pending", review_state="approved",
                tlp="amber", existing_coverage=[])
    data.update(fields)
    return SimpleNamespace(**data)


ENTRIES = [_entry(1, techniques=["Phishing - T1566", "T1566"], incident="ev-1"),
           _entry(2, techniques=["T1566"], incident="ev-1"),
           _entry(3, techniques=["T1566", "T1190"], source_id="misp-intern"),
           _entry(4, techniques=["T1486"]),
           _entry(5, techniques=["T1078"], excluded=True)]


class Coverage(unittest.TestCase):
    def coverage(self, ders, report=None):
        with mock.patch.object(misp_store, "list_ders", return_value=ders):
            return {r["technique"]: r for r in threat_landscape._detection_coverage(report or _report(ENTRIES))}

    def test_the_techniques_of_the_incidents_the_most_frequent_first(self):
        rows = self.coverage([])
        self.assertEqual(list(rows), ["T1566", "T1190", "T1486"], "a left-out event's technique is not one")
        phishing = rows["T1566"]
        self.assertEqual((phishing["incidents"], phishing["name"], phishing["state"]), (2, "Phishing - T1566", "gap"))
        self.assertEqual(phishing["events"], ["ev-3|misp-intern", "ev-1|scraper"])

    def test_what_the_requests_come_to(self):
        rows = self.coverage([_der(1, ["Phishing - T1566"], status="Active"),
                              _der(2, ["T1190"], status="In Dev"),
                              _der(3, ["T1486"], existing_coverage=["Sigma rule from Rulezet"])])
        self.assertEqual({t: r["state"] for t, r in rows.items()},
                         {"T1566": "covered", "T1190": "in progress", "T1486": "covered"})
        self.assertEqual([d.der_id for d in rows["T1566"]["requests"]], ["DER-00001"])

    def test_a_rejected_retired_or_stricter_request_does_not_count(self):
        rows = self.coverage([_der(1, ["T1566"], status="Active", review_state="rejected"),
                              _der(2, ["T1566"], status="Retired"),
                              _der(3, ["T1566"], status="Active", tlp="red")])
        self.assertEqual((rows["T1566"]["state"], rows["T1566"]["requests"]), ("gap", []))

    def test_requests_that_cannot_be_read_leave_every_technique_a_gap(self):
        with mock.patch.object(misp_store, "list_ders", side_effect=RuntimeError("down")), \
             self.assertLogs("webapp.routes.threat_landscape", level="WARNING"):
            rows = threat_landscape._detection_coverage(_report(ENTRIES))
        self.assertEqual({r["state"] for r in rows}, {"gap"})

    def test_without_techniques_there_is_no_annex(self):
        with mock.patch.object(misp_store, "list_ders") as ders:
            self.assertEqual(threat_landscape._detection_coverage(_report([_entry(1)])), [])
        ders.assert_not_called()


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(misp_store, "list_veas", return_value=[]),
            mock.patch.object(misp_store, "list_ders", return_value=[_der(1, ["T1190"], status="In Test")]),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        self.report = _report(ENTRIES)

    def get(self, path):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]):
            return self.client.get(path)

    def test_a_gap_offers_a_request_from_its_incidents(self):
        page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}").data, "html.parser")
        rows = {r.td.get_text(): r for r in page.select("table.tlr-detection tbody tr")}
        form = rows["Phishing - T1566"].select_one("form")
        self.assertEqual(form["action"], "/products/detection-eng/new")
        self.assertEqual(form.select_one("[name=prefill_only]")["value"], "1")
        self.assertEqual(form.select_one("[name=technique]")["value"], "Phishing - T1566")
        self.assertEqual([i["value"] for i in form.select("[name=source]")], ["ev-3|misp-intern", "ev-1|scraper"])
        self.assertIsNone(rows["T1190"].select_one("form"), "in progress already")
        self.assertEqual(rows["T1190"].select_one("a")["href"], "/products/detection-eng/der-1")

    def test_the_pdf_has_the_annex(self):
        with mock.patch("weasyprint.HTML") as html:
            html.return_value.write_pdf.return_value = b"%PDF"
            self.get(f"/products/threat-landscape/{UUID}/pdf")
        page = BeautifulSoup(html.call_args.kwargs["string"], "html.parser")
        heading = next(h for h in page.select(".section-heading") if h.get_text() == "Annex: detection coverage")
        box = heading.find_next_sibling(class_="section-box")
        self.assertIn("2 of the 3 have no detection yet", " ".join(box.get_text(" ").split()))
        self.assertIsNone(box.select_one("form"))


if __name__ == "__main__":
    unittest.main()
