"""What hit the organisation itself, in a threat landscape report.

A manual collection source can be the organisation's own: its incidents and
the detections of its SOC. The flag is stored with the source, kept when the
source is switched off and on, and set on its form. An incident of a report is
the organisation's own when one of its events comes from such a source: the
ranking counts them per threat, the report page, the PDF and the mail list them under
"What hit us", the dataset marks the events, and the methodology says how many
there are. MISP and the cache are patched out; the database and log are
temporary.

    python -m unittest tests.test_tlr_own
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import PyMISP
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import collection_sources, threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
SOC = "manual-soc-detections"
INTERNAL = {SOC: "SOC detections"}


def _entry(n, **fields):
    data = {"event_uuid": f"ev-{n}", "event_info": f"Event {n}", "event_date": f"2026-08-0{n}", "source_id": "scraper",
            **fields}
    return misp_store._tlr_entry_obj(data)


def _report(entries=(), **fields):
    data = {"tlr_id": "TLR-00007", "title": "Q3", "tlp": "amber", **fields}
    return misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj(data)] + list(entries),
                                              published=False, date=None))


ENTRIES = [_entry(1, source_id=SOC, threat_type="Ransomware", relevance="medium", impact="Two days of outage"),
           _entry(2, threat_type="Ransomware", incident="ev-2"), _entry(3, source_id=SOC, incident="ev-2"),
           _entry(4, threat_type="Malware"), _entry(5, source_id=SOC, threat_type="Malware", excluded=True)]


class Source(unittest.TestCase):
    def test_the_flag_is_stored_and_read_back(self):
        obj = misp_store._collection_source_obj({"name": "SOC detections", "internal": True})
        event = SimpleNamespace(uuid="u", objects=[obj], tags=[])
        self.assertTrue(misp_store._collection_source_ns(event).internal)
        plain = SimpleNamespace(uuid="u", objects=[misp_store._collection_source_obj({"name": "Feed"})], tags=[])
        self.assertFalse(misp_store._collection_source_ns(plain).internal)

    def test_switching_a_source_off_keeps_it_our_own(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        stored = misp_store._collection_source_obj({"name": "SOC detections", "internal": True})
        event = SimpleNamespace(uuid="u", id=1, objects=[stored], tags=[])
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_sync_object_attributes") as sync:
            misp_store.toggle_collection_source("u", False)
        new = sync.call_args.args[3]
        self.assertEqual(misp_store._obj_attr(new, "internal"), "true")
        self.assertEqual(misp_store._obj_attr(new, "enabled"), "false")

    def test_the_form_sets_it(self):
        self.assertTrue(collection_sources._form_data(MultiDict({"name": "SOC", "internal": "on"}))["internal"])
        self.assertFalse(collection_sources._form_data(MultiDict({"name": "SOC"}))["internal"])

    def test_the_own_sources_are_named_by_their_id(self):
        sources = [SimpleNamespace(name="SOC detections", internal=True), SimpleNamespace(name="ISAC feed", internal=False)]
        with mock.patch.object(misp_store, "list_collection_sources", return_value=sources):
            self.assertEqual(threat_landscape._internal_sources(), {"manual-soc-detections": "SOC detections"})


class Report(unittest.TestCase):
    def test_an_incident_one_of_whose_events_is_ours_is_ours(self):
        own = threat_landscape._own_incidents(_report(ENTRIES), INTERNAL)
        self.assertEqual([i.event_uuid for i in own], ["ev-2", "ev-1"], "the newest first, and a left-out event is not one")
        self.assertEqual(own[1].impact, "Two days of outage")

    def test_the_ranking_counts_them(self):
        rows = {r["name"]: r for r in threat_landscape._threat_ranking(_report(ENTRIES), None, INTERNAL)}
        self.assertEqual((rows["Ransomware"]["incidents"], rows["Ransomware"]["ours"]), (2, 2))
        self.assertEqual(rows["Malware"]["ours"], 0)

    def test_the_methodology_and_the_mail_say_so(self):
        report = _report(ENTRIES)
        with mock.patch.object(collection_cache, "_build_sources", return_value=[]), \
             mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]):
            text = threat_landscape._methodology_draft(report, None, [], INTERNAL)
        self.assertIn("2 of the events hit the organisation itself, from its own records: SOC detections.", text)
        mail = misp_store.render_tlr_markdown(report, own=threat_landscape._own_incidents(report, INTERNAL))
        self.assertIn("## What hit us\n\n2 of the events hit the organisation itself.", mail)
        self.assertIn("- 2026-08-01: **Event 1** (Ransomware, medium relevance). Two days of outage", mail)

    def test_without_own_sources_nothing_is_ours(self):
        self.assertEqual(threat_landscape._own_incidents(_report(ENTRIES), {}), [])


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
            mock.patch.object(misp_store, "list_collection_sources",
                              return_value=[SimpleNamespace(name="SOC detections", internal=True)]),
            mock.patch.object(misp_store, "list_veas", return_value=[]),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=[]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=[]),
            mock.patch.object(misp_store, "galaxy_threat_actors", return_value=[]),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        self.report = _report(ENTRIES)

    def get(self, path):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]):
            reply = self.client.get(path)
        self.assertEqual(reply.status_code, 200)
        return BeautifulSoup(reply.data, "html.parser")

    def test_the_report_page_lists_what_hit_us(self):
        page = self.get(f"/products/threat-landscape/{UUID}")
        card = next(c for c in page.select(".card") if c.select_one(".card-header")
                    and c.select_one(".card-header").get_text(strip=True) == "What hit us")
        self.assertIn("from its own records: SOC detections", " ".join(card.get_text(" ").split()))
        self.assertEqual([r.select("td")[1].get_text() for r in card.select("tbody tr")], ["Event 2", "Event 1"])

    def test_the_dataset_marks_our_events(self):
        page = self.get(f"/products/threat-landscape/{UUID}/entries")
        marked = [row["data-entry-row"] for row in page.select("tr[data-entry-row]") if row.select_one(".tlr-ours")]
        self.assertEqual(len(marked), 3)
        figures = {k.select_one("span").get_text(strip=True): k.b.get_text() for k in page.select(".record-hero .record-kpi")}
        self.assertEqual(figures["of our own"], "2")


if __name__ == "__main__":
    unittest.main()
