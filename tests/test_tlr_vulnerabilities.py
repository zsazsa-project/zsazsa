"""The vulnerabilities of a threat landscape report, and the threat type for them.

A report lists the CVEs its incidents name, counted once per incident, and
those of the vulnerability advisories made in its period, each with how far it
is exploited and whether it is in a product the organisation runs: as the
analyser found it, or as the asset inventory has the affected product. An
advisory shared more strictly than the report is left out, as is a rejected
one, and the section is empty without CVEs. The report page links each to its
advisory; the PDF and the mail list them too. "Vulnerability exploitation" is a
threat type besides ENISA's prime threats. MISP and the cache are patched out;
the database and log are temporary.

    python -m unittest tests.test_tlr_vulnerabilities
"""

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from core import asset_inventory
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _entry(n, **fields):
    data = {key: "" for key in misp_store.TLR_ENTRY_FIELDS}
    data.update({key: [] for key in misp_store.TLR_ENTRY_LISTS})
    data.update(uuid=f"obj-{n}", event_uuid=f"ev-{n}", event_info=f"Event {n}", event_date="2026-08-01", excluded=False)
    data.update(fields)
    return SimpleNamespace(**data)


def _vea(cve, made="2026-08-10", **fields):
    data = dict(uuid=f"vea-{cve}", vea_id=f"VEA-{cve[-4:]}", cve_id=cve, tlp="amber", review_state="approved",
                created_at=datetime.fromisoformat(made), affected_product="Fortinet FortiOS", cvss="9.8", cwe="CWE-787",
                exposure="", observed_exploitation="", cisa_kev="", exploit_availability="")
    data.update(fields)
    return SimpleNamespace(**data)


def _report(entries, **fields):
    data = dict(uuid=UUID, tlr_id="TLR-00007", title="Q3", tlp="amber", period_start="2026-07-01",
                period_end="2026-09-30", entries=list(entries))
    data.update(fields)
    return SimpleNamespace(**data)


class Section(unittest.TestCase):
    def section(self, report, veas=(), cves=None, inventory=False):
        cached = [{"uuid": e.event_uuid, "vulnerability_ids": (cves or {}).get(e.event_uuid, [])} for e in report.entries]
        with mock.patch.object(collection_cache, "get_events_by_uuids", return_value=cached), \
             mock.patch.object(misp_store, "list_veas", return_value=list(veas)), \
             mock.patch.object(asset_inventory, "enabled", return_value=inventory):
            return threat_landscape._vulnerabilities(report)

    def test_the_cves_of_the_incidents_and_of_the_advisories_of_the_period(self):
        report = _report([_entry(1, incident="g"), _entry(2, incident="g"), _entry(3)])
        veas = [_vea("CVE-2026-0001", exposure="In the asset inventory: Fortinet FortiOS 7.2", observed_exploitation="Yes"),
                _vea("CVE-2026-0002", cvss="5.3", cisa_kev="Yes", affected_product="Ivanti EPMM", cwe="CWE-22"),
                _vea("CVE-2026-0003", made="2026-06-30"),
                _vea("CVE-2026-0004", review_state="rejected"),
                _vea("CVE-2026-0005", tlp="red")]
        v = self.section(report, veas, {"ev-1": ["cve-2026-0009"], "ev-2": ["CVE-2026-0009", "CVE-2026-0001"],
                                        "ev-3": ["CVE-2026-0009"]})
        self.assertEqual([r["cve"] for r in v["rows"]], ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0009"],
                         "ours first, then exploited, then the rest")
        first = v["rows"][0]
        self.assertEqual((first["ours"], first["exploitation"], first["incidents"], first["vea"].vea_id),
                         (True, "Active", 1, "VEA-0001"))
        self.assertEqual(v["rows"][2]["incidents"], 2, "the two events of one incident count once")
        self.assertEqual((v["cves"], v["advisories"], v["exploited"], v["ours"]), (3, 2, 2, 1))
        self.assertEqual(v["products"], [("Fortinet FortiOS", 1, None), ("Ivanti EPMM", 1, None)])

    def test_the_asset_inventory_finds_a_product_the_analyser_did_not_check(self):
        with mock.patch.object(asset_inventory, "find", return_value=("Ivanti", "EPMM", "12")) as find:
            v = self.section(_report([_entry(1)]), [_vea("CVE-2026-0002", affected_product="Ivanti EPMM")], inventory=True)
        self.assertTrue(v["rows"][0]["ours"])
        find.assert_called_once_with("", "Ivanti EPMM")

    def test_an_inventory_that_cannot_be_read_keeps_what_the_analyser_found(self):
        veas = [_vea("CVE-2026-0001", exposure="In the asset inventory: X"), _vea("CVE-2026-0002")]
        with mock.patch.object(asset_inventory, "find", side_effect=asset_inventory.InventoryError("gone")), \
             self.assertLogs("webapp.routes.threat_landscape", level="WARNING"):
            v = self.section(_report([_entry(1)]), veas, inventory=True)
        self.assertEqual({r["cve"]: r["ours"] for r in v["rows"]}, {"CVE-2026-0001": True, "CVE-2026-0002": False})

    def test_advisories_that_cannot_be_read_leave_the_cves_of_the_incidents(self):
        report = _report([_entry(1)])
        with mock.patch.object(collection_cache, "get_events_by_uuids",
                               return_value=[{"uuid": "ev-1", "vulnerability_ids": ["CVE-2026-0009"]}]), \
             mock.patch.object(misp_store, "list_veas", side_effect=RuntimeError("MISP down")), \
             self.assertLogs("webapp.routes.threat_landscape", level="WARNING"):
            v = threat_landscape._vulnerabilities(report)
        self.assertEqual([r["cve"] for r in v["rows"]], ["CVE-2026-0009"])

    def test_without_cves_there_is_no_section(self):
        self.assertEqual(self.section(_report([_entry(1)])), {})

    def test_without_a_period_the_dates_of_the_events_are_its_period(self):
        report = _report([_entry(1, event_date="2026-08-01"), _entry(2, event_date="2026-08-20")], period_start="",
                         period_end="")
        v = self.section(report, [_vea("CVE-2026-0001", made="2026-08-15"), _vea("CVE-2026-0002", made="2026-08-25")])
        self.assertEqual([r["cve"] for r in v["rows"]], ["CVE-2026-0001"])

    def test_the_mail_lists_them(self):
        tlr = misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj({"title": "Q3"})],
                                                 published=False, date=None))
        v = self.section(_report([_entry(1)]), [_vea("CVE-2026-0001", observed_exploitation="Yes",
                                                      exposure="In the asset inventory: X")])
        text = misp_store.render_tlr_markdown(tlr, vulnerabilities=v)
        self.assertIn("1 CVE in the period, 1 of them exploited, 1 in products the organisation runs; 1 vulnerability advisory.", text)
        self.assertIn("- **CVE-2026-0001**: Fortinet FortiOS, CVSS 9.8, Active, in our assets, VEA-0001", text)


class ThreatType(unittest.TestCase):
    def test_it_is_one_of_the_default_threat_types(self):
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", [], create=True):
            types = misp_store.tlr_threat_types()
        self.assertEqual(types, misp_store.ENISA_THREAT_TYPES + ["Vulnerability exploitation"])

    def test_an_advisory_says_how_far_it_is_exploited(self):
        self.assertEqual(misp_store.vea_exploitation(_vea("C", observed_exploitation="Yes, in the wild")), "Active")
        self.assertEqual(misp_store.vea_exploitation(_vea("C", cisa_kev="Yes")), "KEV listed")
        self.assertEqual(misp_store.vea_exploitation(_vea("C", exploit_availability="PoC")), "PoC")
        self.assertEqual(misp_store.vea_exploitation(_vea("C")), "Unknown")


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(collection_cache, "get_events_by_uuids",
                              return_value=[{"uuid": "ev-1", "vulnerability_ids": ["CVE-2026-0009"]}]),
            mock.patch.object(misp_store, "list_veas", return_value=[_vea("CVE-2026-0001", observed_exploitation="Yes")]),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        data = {"tlr_id": "TLR-00007", "title": "Q3", "tlp": "amber", "period_start": "2026-07-01",
                "period_end": "2026-09-30"}
        self.report = misp_store._tlr_ns(SimpleNamespace(
            uuid=UUID, objects=[misp_store._tlr_obj(data), misp_store._tlr_entry_obj({"event_uuid": "ev-1",
                                                                                     "event_date": "2026-08-01"})],
            published=False, date=None))

    def get(self, path):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]):
            return self.client.get(path)

    def test_the_report_page_links_each_cve_to_its_advisory(self):
        page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}").data, "html.parser")
        table = page.select_one("table.tlr-vulnerabilities")
        self.assertEqual(table.select_one("a")["href"], "/products/vea/vea-CVE-2026-0001")
        self.assertEqual([r.td.get_text(strip=True) for r in table.select("tbody tr")], ["CVE-2026-0001", "CVE-2026-0009"])
        self.assertIn("2 CVEs in the period, 1 of them exploited", table.find_previous("p").get_text(" ", strip=True))

    def test_the_pdf_lists_them(self):
        with mock.patch("weasyprint.HTML") as html:
            html.return_value.write_pdf.return_value = b"%PDF"
            self.get(f"/products/threat-landscape/{UUID}/pdf")
        page = BeautifulSoup(html.call_args.kwargs["string"], "html.parser")
        heading = next(h for h in page.select(".section-heading") if h.get_text() == "Vulnerabilities")
        self.assertIn("CVE-2026-0001", heading.find_next_sibling(class_="section-box").get_text())


if __name__ == "__main__":
    unittest.main()
