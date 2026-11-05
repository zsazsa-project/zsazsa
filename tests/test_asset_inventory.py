"""The asset inventory a vulnerability advisory is checked against.

With it on, the analyser only makes an advisory for a CVE in a product of the
inventory, a CSV file of "Supplier","Product","Version" rows read again after a
set number of minutes. A CVE record and an inventory spell names differently,
so case, punctuation, company forms, initials and a product name that starts
with its supplier's do not stand in the way of a match; another edition or
another supplier does. A CVE whose record names no product cannot be checked,
so it makes a draft that says so, unless another CVE of the event is in the
inventory; one whose lookup failed waits for the next run instead. A file that cannot be read fails the run rather than letting every
advisory through or none.

The CSV files are temporary, and MISP, the CVE lookup and the model are stubbed.

    python -m unittest tests.test_asset_inventory
"""

import contextlib
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import config
from core import asset_inventory, vuln_lookup
from analyser import sources
from webapp import analyser_pipeline

INVENTORY = '''"Supplier","Product","Version"
"Microsoft Corporation","Exchange Server 2019","15.2"
"Palo Alto Networks","PAN-OS","11.1"
"Fortinet","FortiOS",""
"Hewlett Packard Enterprise","Aruba, Instant On","3.0"
'''


class Inventory(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8-sig")
        handle.write(INVENTORY)
        handle.close()
        self.path = handle.name
        self.addCleanup(os.unlink, self.path)
        patcher = mock.patch.multiple(config, create=True, ASSET_INVENTORY_FILE=self.path,
                                      ASSET_INVENTORY_REFRESH_MINUTES=60)
        patcher.start()
        self.addCleanup(patcher.stop)
        asset_inventory._cache.update(path=None, read_at=0.0, assets=[])

    def found(self, vendor, product):
        asset = asset_inventory.find(vendor, product)
        return asset and asset.product


class Reading(Inventory):
    def test_quoted_values_a_header_and_a_spreadsheet_bom(self):
        self.assertEqual(asset_inventory.read(self.path), [
            asset_inventory.Asset("Microsoft Corporation", "Exchange Server 2019", "15.2"),
            asset_inventory.Asset("Palo Alto Networks", "PAN-OS", "11.1"),
            asset_inventory.Asset("Fortinet", "FortiOS", ""),
            asset_inventory.Asset("Hewlett Packard Enterprise", "Aruba, Instant On", "3.0"),
        ])

    def test_a_missing_file_says_so(self):
        with self.assertRaises(asset_inventory.InventoryError):
            asset_inventory.read(self.path + ".gone")

    def test_it_is_read_again_after_the_refresh_interval(self):
        self.assertEqual(len(asset_inventory.assets()), 4)
        with open(self.path, "w") as handle:
            handle.write('"Cisco","IOS XE","17.9"\n')
        self.assertEqual(len(asset_inventory.assets()), 4)
        asset_inventory._cache["read_at"] -= 61 * 60
        self.assertEqual([a.product for a in asset_inventory.assets()], ["IOS XE"])


class Matching(Inventory):
    def test_suppliers_are_matched_loosely(self):
        self.assertEqual(self.found("Microsoft", "Exchange Server 2019"), "Exchange Server 2019")
        self.assertEqual(self.found("paloaltonetworks", "PAN-OS"), "PAN-OS")
        self.assertEqual(self.found("HPE", "Aruba Instant On"), "Aruba, Instant On")
        self.assertEqual(self.found("Fortinet, Inc.", "FortiOS"), "FortiOS")

    def test_products_are_matched_loosely(self):
        self.assertEqual(self.found("Palo Alto Networks", "PANOS"), "PAN-OS")
        self.assertEqual(self.found("Microsoft", "Microsoft Exchange Server 2019 Cumulative Update 14"),
                         "Exchange Server 2019")
        self.assertEqual(self.found("Fortinet", "fortios-6.4"), "FortiOS")
        self.assertEqual(self.found("Palo Alto Networks", "PAN OS 11"), "PAN-OS")

    def test_names_as_real_cve_records_spell_them(self):
        """From vulnerability.circl.lu: CVE-2026-109618 and CVE-2021-44228."""
        with open(self.path, "a") as handle:
            handle.write('"The PHP Group","PHP","8.3"\n"Apache","Log4j","2.17.1"\n')
        self.assertEqual(self.found("PHP Group", "PHP"), "PHP")
        self.assertEqual(self.found("Apache Software Foundation", "Apache Log4j2"), "Log4j")

    def test_another_edition_or_supplier_is_not_a_match(self):
        self.assertIsNone(self.found("Microsoft", "Exchange Server 2016"))
        self.assertIsNone(self.found("Microsoft", "Exchange Server 201"))
        self.assertIsNone(self.found("Micro Focus", "Exchange Server 2019"))
        self.assertIsNone(self.found("Fortinet", "FortiWeb"))


class CveRecord(unittest.TestCase):
    def test_the_affected_vendor_and_product_are_kept_apart(self):
        record = {"containers": {"cna": {"affected": [
            {"vendor": "Fortinet", "product": "FortiOS"}, {"vendor": "n/a", "product": "n/a"}]}}}
        parsed = vuln_lookup._parse(record)
        self.assertEqual((parsed["products"], parsed["affected"]), (["Fortinet FortiOS"], [("Fortinet", "FortiOS")]))

    def test_a_vendor_given_as_n_a_is_no_vendor(self):
        """Matched as a supplier it would rule out every asset."""
        record = {"containers": {"cna": {"affected": [{"vendor": "n/a", "product": "FortiOS"}]}}}
        self.assertEqual(vuln_lookup._parse(record)["affected"], [("", "FortiOS")])


class AdvisoryRun(Inventory):
    RECORDS = {"CVE-2026-0001": {"affected": [("Ivanti", "Connect Secure")], "products": ["Ivanti Connect Secure"]},
               "CVE-2026-0002": {"affected": [("Fortinet", "FortiOS")], "products": ["Fortinet FortiOS"]},
               "CVE-2026-0003": {"title": "A flaw"}}

    def run_vea(self, cves_by_title, enabled=True):
        events = [SimpleNamespace(uuid=f"{i}" * 36, info=title, tags=[], id=i)
                  for i, title in enumerate(cves_by_title, start=1)]
        self.created, self.logged = [], []
        patches = [
            mock.patch.object(config, "ASSET_INVENTORY_ENABLED", enabled, create=True),
            mock.patch.object(analyser_pipeline.collection_cache, "event_cves",
                              side_effect=lambda e: cves_by_title[e.info]),
            mock.patch.object(analyser_pipeline, "lookup_cve", side_effect=lambda cve: self.RECORDS.get(cve, {})),
            mock.patch.object(analyser_pipeline.llm, "draft_vea_sections", return_value={}),
            mock.patch.object(analyser_pipeline.misp_store, "create_vea",
                              side_effect=lambda data: self.created.append(data) or ("u" * 36, "VEA-00001")),
            mock.patch.object(analyser_pipeline.misp_store, "list_veas", return_value=[]),
            mock.patch.object(analyser_pipeline.misp_store, "vea_source_uuids", return_value=set()),
            mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="Vulnerability management"),
            mock.patch.object(analyser_pipeline, "_log",
                              side_effect=lambda e, source, outcome, detail=None: self.logged.append((e.info, detail))),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            scraper = sources.Source("scraper", "scraper", "MISP scraper", None, True)
            self.candidates = stack.enter_context(mock.patch.object(
                analyser_pipeline, "_common_candidate_events",
                return_value=SimpleNamespace(sources={e.uuid: scraper for e in events}, events=events, excluded=[],
                                             summaries={}, reports={e.uuid: [] for e in events},
                                             stats={"event_decisions": []})))
            stack.enter_context(mock.patch.object(analyser_pipeline, "_scope_terms", return_value=[]))
            stack.enter_context(mock.patch.object(analyser_pipeline.event_state, "save_outcome"))
            return analyser_pipeline.run_vea_action(mock.create_autospec(sources.Reading, instance=True))

    def test_only_a_cve_in_a_product_we_run_makes_an_advisory(self):
        result = self.run_vea({"Ivanti bug": ["CVE-2026-0001"], "Two bugs": ["CVE-2026-0001", "CVE-2026-0002"]})
        # The scheduled run checks these for an alert as well.
        self.assertEqual((result["created"], result["source_event_uuids"]), (1, ["2" * 36]))
        self.assertEqual(self.created[0]["audience"], "Vulnerability management")
        self.assertEqual([(v["title"], v["cve_id"].split("\n"), v["affected_product"], v["exposure"])
                          for v in self.created],
                         [("Two bugs", ["CVE-2026-0002"], "Fortinet FortiOS",
                           "In the asset inventory: Fortinet FortiOS")])
        self.assertIn(("Ivanti bug", "No CVE to advise on: CVE-2026-0001 out of scope"), self.logged)

    def test_a_record_without_products_makes_a_draft_that_says_so(self):
        """A reserved CVE, which names no product yet; one whose lookup failed
        waits for the next run (tests.test_analyser_drafts). The title is not
        guessed from: "Head office breached" would be taken for Microsoft Office."""
        self.run_vea({"Head office breached": ["CVE-2026-0003"]})
        self.assertEqual([(v["cve_id"], v["exposure"]) for v in self.created], [(
            "CVE-2026-0003", analyser_pipeline._NOT_CHECKED)])

    def test_a_cve_in_the_inventory_comes_before_one_that_cannot_be_checked(self):
        self.run_vea({"Two bugs": ["CVE-2026-0003", "CVE-2026-0002"]})
        self.assertEqual([v["exposure"] for v in self.created], ["In the asset inventory: Fortinet FortiOS"])

    def test_a_file_that_cannot_be_read_fails_the_run_before_any_summary(self):
        with mock.patch.object(config, "ASSET_INVENTORY_FILE", self.path + ".gone"), \
             self.assertRaises(asset_inventory.InventoryError):
            self.run_vea({"Two bugs": ["CVE-2026-0002"]})
        self.candidates.assert_not_called()
        self.assertEqual(self.created, [])

    def test_switched_off_every_cve_makes_one_as_before(self):
        self.run_vea({"Ivanti bug": ["CVE-2026-0001"]}, enabled=False)
        self.assertEqual([(v["title"], v["exposure"]) for v in self.created], [("Ivanti bug", "")])


if __name__ == "__main__":
    unittest.main()
