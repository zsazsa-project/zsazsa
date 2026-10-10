"""The dataset of a threat landscape report: its entries, the queue they come from, the counts.

Each source event in a report is a zsazsa-tlr-entry object on the report's own
event, holding the report's assessment of it. Building a report from the queue
fills the entries in from the event's tags, and an event a report holds leaves
the queue. The triage page saves only the entries that changed, refuses a
published report, and counts over the entries left in the analysis. MISP is
patched out.

    python -m unittest tests.test_tlr_entries
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import PyMISP
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _cached(uuid, tags=(), source_id="scraper", date="2026-09-01"):
    return {"uuid": uuid, "info": f"Event {uuid}", "date": date, "tags": list(tags),
            "source_id": source_id, "galaxy_names": [], "vulnerability_ids": []}


def _entry(event_uuid, **fields):
    data = {key: "" for key in misp_store.TLR_ENTRY_FIELDS}
    data.update({key: [] for key in misp_store.TLR_ENTRY_LISTS})
    data.update(event_uuid=event_uuid, excluded=False, uuid=f"obj-{event_uuid}")
    data.update(fields)
    return SimpleNamespace(**data)


def _report(entries=(), review_state="draft"):
    return SimpleNamespace(uuid=UUID, tlr_id="TLR-00007", title="Q3", review_state=review_state,
                           entries=list(entries))


def _client():
    app = Flask(__name__, template_folder="../webapp/templates")
    app.secret_key = "test"
    app.config["TESTING"] = True
    app.register_blueprint(threat_landscape.bp)
    return app.test_client()


class EntryObject(unittest.TestCase):
    def test_an_entry_survives_the_round_trip(self):
        entry = {"event_uuid": "e1", "relevance": "high", "source_reliability": "B",
                 "threat_type": "Ransomware", "sectors": ["Energy", "Health"],
                 "techniques": ["T1566"], "excluded": True, "note": "Duplicate"}
        stored = misp_store._tlr_entry(misp_store._tlr_entry_obj(entry))
        for key, value in entry.items():
            self.assertEqual(stored[key], value, key)
        self.assertEqual(stored["threat_actors"], [])

    def test_the_template_declares_every_field(self):
        relations = {a.object_relation for a in misp_store._tlr_entry_obj(
            {key: "x" for key in misp_store.TLR_ENTRY_FIELDS}
            | {key: ["x"] for key in misp_store.TLR_ENTRY_LISTS} | {"excluded": True}).attributes}
        template = misp_store._build_obj("zsazsa-tlr-entry")._definition["attributes"]
        self.assertEqual(relations - set(template), set())


class StoreWrites(unittest.TestCase):
    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        objs = []
        for event_uuid, relevance in (("e1", "high"), ("e2", "")):
            obj = misp_store._tlr_entry_obj({"event_uuid": event_uuid, "relevance": relevance})
            obj.uuid = f"obj-{event_uuid}"
            objs.append(obj)
        event = SimpleNamespace(objects=objs, id=1, uuid=UUID)
        for patcher in (mock.patch.object(misp_store, "_misp", return_value=self.misp),
                        mock.patch.object(misp_store, "_tlr_event", return_value=event)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_adding_skips_an_event_the_report_holds(self):
        with mock.patch.object(misp_store, "_check"):
            added = misp_store.add_tlr_entries(UUID, [{"event_uuid": "e1"}, {"event_uuid": "e3"},
                                                      {"event_uuid": "e3"}])
        self.assertEqual(added, 1)
        self.assertEqual(self.misp.add_object.call_count, 1)

    def test_only_the_entries_that_changed_are_written(self):
        with mock.patch.object(misp_store, "_update_object") as update:
            misp_store.update_tlr_entries(UUID, {"obj-e1": {"relevance": "high"},
                                                 "obj-e2": {"relevance": "low"}})
        update.assert_called_once()
        self.assertEqual(update.call_args.args[1].uuid, "obj-e2")


class UsedIn(unittest.TestCase):
    def test_a_report_holding_the_event_is_listed(self):
        report = _report([_entry("e1")])
        report.created_at = None
        with mock.patch.object(misp_store, "list_briefings", return_value=[]), \
             mock.patch.object(misp_store, "list_fias", return_value=[]), \
             mock.patch.object(misp_store, "list_veas", return_value=[]), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[report]):
            self.assertEqual([p["uuid"] for p in misp_store.find_products_using_source("e1")], [UUID])
            self.assertEqual(misp_store.find_products_using_source("e2"), [])


class Queue(unittest.TestCase):
    def test_an_event_a_report_holds_leaves_the_queue(self):
        events = [_cached("e1"), _cached("e2")]
        with mock.patch.object(threat_landscape.collection_cache, "get_events", return_value=events), \
             mock.patch.object(threat_landscape.collection_cache, "source_ids", return_value=["scraper"]):
            queued = threat_landscape._queued_events([_report([_entry("e1")])])
        self.assertEqual([ev["uuid"] for ev in queued], ["e2"])

    def test_the_filters_narrow_the_queue(self):
        queued = [_cached("e1", ['misp-galaxy:sector="Energy"'], date="2026-07-01"),
                  _cached("e2", ['misp-galaxy:sector="Health"'], date="2026-09-01")]
        for ev in queued:
            ev["context"] = misp_store.context_from_tags(ev["tags"])
        kept = threat_landscape._filter_queue
        self.assertEqual([e["uuid"] for e in kept(queued, {"sector": "Energy"})], ["e1"])
        self.assertEqual([e["uuid"] for e in kept(queued, {"since": "2026-08-01"})], ["e2"])
        self.assertEqual(len(kept(queued, {})), 2)


class Build(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        self.queued = [
            _cached("e1", ['misp-galaxy:sector="Energy"', 'misp-galaxy:threat-actor="APT29"',
                           'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
                           'admiralty-scale:source-reliability="b"',
                           'admiralty-scale:information-credibility="2"']),
            _cached("e2", source_id="manual-isac"),
        ]
        self.tlrs = [_report()]
        sources = [SimpleNamespace(name="isac", source_reliability="C")]
        for patcher in (
            mock.patch.object(threat_landscape.misp_store, "list_tlrs", return_value=self.tlrs),
            mock.patch.object(threat_landscape.misp_store, "list_collection_sources", return_value=sources),
            mock.patch.object(threat_landscape, "_queued_events", return_value=self.queued),
            mock.patch.object(threat_landscape.audit, "record"),
            mock.patch.object(threat_landscape.product_log, "log_product_sources"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, **form):
        def create(data):
            data["tlr_id"] = "TLR-00008"
            return "new-uuid"
        with mock.patch.object(threat_landscape.misp_store, "create_tlr", side_effect=create) as create_tlr, \
             mock.patch.object(threat_landscape.misp_store, "add_tlr_entries", return_value=2) as add:
            reply = self.client.post("/products/threat-landscape/build", data=form)
        return reply, create_tlr, add

    def test_a_new_report_takes_the_events_filled_in_from_their_tags(self):
        reply, create_tlr, add = self.post(event=["e1", "e2"], title="Q3 2026")
        self.assertTrue(reply.location.endswith("/products/threat-landscape/new-uuid/entries"))
        self.assertEqual(create_tlr.call_args.args[0]["title"], "Q3 2026")
        first, second = add.call_args.args[1]
        self.assertEqual(first["sectors"], ["Energy"])
        self.assertEqual(first["threat_actors"], ["APT29"])
        self.assertEqual(first["techniques"], ["Phishing - T1566"])
        self.assertEqual((first["source_reliability"], first["information_credibility"]), ("B", "2"))
        self.assertEqual(second["source_reliability"], "C", "the manual source's rating fills in")

    def test_events_can_go_to_an_existing_draft(self):
        _reply, create_tlr, add = self.post(event=["e1"], target=UUID)
        create_tlr.assert_not_called()
        self.assertEqual(add.call_args.args[0], UUID)

    def test_a_published_report_takes_no_events(self):
        self.tlrs[0].review_state = "published"
        _reply, _create, add = self.post(event=["e1"], target=UUID)
        add.assert_not_called()

    def test_a_new_report_needs_a_title(self):
        _reply, create_tlr, add = self.post(event=["e1"])
        create_tlr.assert_not_called()
        add.assert_not_called()

    def test_an_event_no_longer_queued_is_ignored(self):
        _reply, create_tlr, add = self.post(event=["gone"], title="Q3")
        create_tlr.assert_not_called()
        add.assert_not_called()


class Triage(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        patcher = mock.patch.object(threat_landscape.audit, "record")
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, report, **form):
        with mock.patch.object(threat_landscape.misp_store, "get_tlr", return_value=report), \
             mock.patch.object(threat_landscape.misp_store, "update_tlr_entries") as update:
            self.client.post(f"/products/threat-landscape/{UUID}/entries", data=form)
        return update

    def test_the_triage_is_saved_per_entry(self):
        update = self.post(_report([_entry("e1"), _entry("e2")]),
                           **{"relevance-obj-e1": "high", "threat_type-obj-e1": "Ransomware",
                              "relevance-obj-e2": "", "excluded-obj-e2": "on", "note-obj-e2": " Duplicate "})
        changes = update.call_args.args[1]
        self.assertEqual(changes["obj-e1"]["relevance"], "high")
        self.assertEqual(changes["obj-e1"]["threat_type"], "Ransomware")
        self.assertFalse(changes["obj-e1"]["excluded"])
        self.assertTrue(changes["obj-e2"]["excluded"])
        self.assertEqual(changes["obj-e2"]["note"], "Duplicate")

    def test_the_classification_is_saved_and_can_be_emptied(self):
        form = MultiDict([("relevance-obj-e1", ""), ("sectors-obj-e1", "Energy"), ("sectors-obj-e1", "Health"),
                          ("techniques-obj-e1", "Phishing - T1566")])
        update = self.post(_report([_entry("e1", threat_actors=["APT29"])]), **form.to_dict(flat=False))
        saved = update.call_args.args[1]["obj-e1"]
        self.assertEqual(saved["sectors"], ["Energy", "Health"])
        self.assertEqual(saved["techniques"], ["Phishing - T1566"])
        self.assertEqual(saved["threat_actors"], [], "an actor removed in the picker is removed")

    def test_an_entry_added_after_the_page_loaded_is_left_alone(self):
        update = self.post(_report([_entry("e1"), _entry("e2", relevance="high")]),
                           **{"relevance-obj-e1": "low"})
        self.assertEqual(list(update.call_args.args[1]), ["obj-e1"])

    def test_a_published_report_is_not_changed(self):
        update = self.post(_report([_entry("e1")], review_state="published"), **{"relevance-obj-e1": "low"})
        update.assert_not_called()


class Statistics(unittest.TestCase):
    def test_counts_cover_only_the_events_in_the_analysis(self):
        stats = dict(threat_landscape._statistics([
            _entry("e1", threat_type="Ransomware", sectors=["Energy", "Health"], event_date="2026-09-03"),
            _entry("e2", threat_type="Ransomware", sectors=["Energy"], event_date="2026-07-10"),
            _entry("e3", threat_type="Malware", sectors=["Energy"], excluded=True),
            _entry("e4", event_date="2026-08-01"),
        ]))
        self.assertEqual(stats["Threat type"], [("Ransomware", 2, None), ("Not classified", 1, None)])
        self.assertEqual(stats["Sector"], [("Energy", 2, None), ("Health", 1, None)])
        self.assertEqual(stats["Month"], [("2026-07", 1, None), ("2026-08", 1, None), ("2026-09", 1, None)])
        self.assertNotIn("Threat actor", stats)

    def test_each_count_stands_beside_the_previous_reports(self):
        previous = SimpleNamespace(entries=[_entry("p1", threat_type="Ransomware"), _entry("p2", threat_type="Malware")])
        stats = dict(threat_landscape._statistics([_entry("e1", threat_type="Ransomware"),
                                                   _entry("e2", threat_type="Phishing")], previous))
        self.assertEqual(stats["Threat type"], [("Ransomware", 1, 1), ("Phishing", 1, 0)])

    def test_the_previous_report_is_the_one_numbered_before(self):
        reports = [SimpleNamespace(tlr_id=n) for n in ("TLR-00003", "TLR-00005", "TLR-00009")]
        self.assertEqual(threat_landscape._previous_report(reports[2], reports).tlr_id, "TLR-00005")
        self.assertIsNone(threat_landscape._previous_report(reports[0], reports))


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=["Energy", "Health"]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=["Belgium"]),
            mock.patch.object(misp_store, "galaxy_threat_actors", return_value=["APT29"]),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=["Phishing - T1566"]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        self.report = _report([_entry("e1", event_info="Grid attack", threat_type="Ransomware",
                                      sectors=["Energy"], event_date="2026-09-01"),
                               _entry("e2", excluded=True)])
        self.report.__dict__.update(
            reporting_period="2026 Q3", tlp="amber", author="", creator="", approved_by="", created_at=None,
            audience="", misp_url="", top_threats="", trending_actors="", key_incidents="",
            recommendations="", outlook="", purpose="", audience_level="", period_start="", period_end="",
            methodology="", scope_sectors=[], scope_geography=[], linked_pir_uuids=[], threat_sections=[], review_log=[], corrections=[],
            **{key: "" for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES})

    def page(self, path, tlrs=None, queued=()):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=tlrs or [self.report]), \
             mock.patch.object(threat_landscape, "_queued_events", return_value=list(queued)):
            reply = self.client.get(path)
        self.assertEqual(reply.status_code, 200)
        return BeautifulSoup(reply.data, "html.parser")

    def test_the_queue_offers_its_events_and_the_drafts_to_add_them_to(self):
        page = self.page("/products/threat-landscape/",
                         queued=[_cached("e9", ['misp-galaxy:sector="Energy"'])])
        self.assertEqual([box["value"] for box in page.select("input.tlr-pick")], ["e9"])
        targets = [o["value"] for o in page.select("select[name=target] option")]
        self.assertEqual(targets, ["", UUID])
        self.assertIn("Energy", [o.get_text() for o in page.select("select[name=sector] option")])

    def test_the_dataset_page_shows_triage_and_counts(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertTrue(page.select_one("select[name='relevance-obj-e1']"))
        self.assertTrue(page.select_one("input[name='excluded-obj-e2'][checked]"))
        self.assertIn("Ransomware", page.find(string="Threat type").find_next("table").get_text())
        self.assertIn("Save triage", [b.get_text(strip=True) for b in page.select("button")])

    def test_each_row_carries_its_classification_for_the_picker(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        cell = page.select_one('.entry-classification[data-entry="obj-e1"]')
        self.assertEqual([i["value"] for i in cell.select("input[name='sectors-obj-e1']")], ["Energy"])
        self.assertTrue(cell.select_one(".classification-edit"))
        self.assertEqual([b["value"] for b in page.select("#classification-modal #gms-classification-sectors input")],
                         ["Energy", "Health"])

    def test_a_published_dataset_is_read_only(self):
        self.report.review_state = "published"
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertTrue(page.select_one("fieldset[disabled]"))
        self.assertNotIn("Save triage", [b.get_text(strip=True) for b in page.select("button")])
        self.assertIsNone(page.select_one("#classification-modal"))

    def test_the_report_page_links_its_dataset(self):
        page = self.page(f"/products/threat-landscape/{UUID}")
        self.assertTrue(page.select_one(f'a[href="/products/threat-landscape/{UUID}/entries"]'))
        self.assertIn("Events 1 in the analysis, 1 left out", page.get_text(" ", strip=True))

    def test_edit_sits_in_the_actions_card_as_on_the_other_products(self):
        page = self.page(f"/products/threat-landscape/{UUID}")
        [link] = page.select(f'a[href="/products/threat-landscape/{UUID}/edit"]')
        self.assertEqual(link.find_parent(class_="card").select_one(".card-header").get_text(strip=True), "Actions")

    def test_the_list_offers_the_usual_row_actions(self):
        page = self.page("/products/threat-landscape/")
        row = page.select_one(".req-id-badge").find_parent("tr")
        self.assertTrue(row.select_one(".preview-toggle-btn"))
        self.assertEqual(row.select_one(".feedback-btn")["data-action"], f"/products/threat-landscape/{UUID}/feedback")
        self.assertTrue(row.select_one('a[title="Edit"]'))
        self.assertTrue(page.select_one(f"#tlr-preview-{UUID}"))

    def test_the_wizard_shows_the_dataset_and_takes_threat_assessments(self):
        self.report.threat_sections = [{"threat_type": "Ransomware", "title": "Grid", "findings": "Up"}]
        page = self.page(f"/products/threat-landscape/{UUID}/edit")
        self.assertIn("Grid attack", page.get_text())
        self.assertEqual([i["value"] for i in page.select("#tlr-sections input[name=section_title]")], ["Grid"])
        self.assertIn("Events in the dataset: 1", page.select_one("#tlr-sections .tlr-section-count").get_text())
        self.assertTrue(page.select_one("#tlr-section-template"))
        self.assertTrue(page.select_one("textarea[name=purpose]"))

    def test_a_new_report_starts_from_the_feedback_on_the_last_one(self):
        self.report.review_state = "published"
        feedback = [SimpleNamespace(name="feedback: CISO", content="More on **supply chain**, please.")]
        with mock.patch.object(misp_store, "list_product_feedback", return_value=feedback):
            page = self.page("/products/threat-landscape/new")
        note = page.find(string=lambda t: t and "the last report" in t).find_parent(class_="alert")
        self.assertIn("TLR-00007", note.get_text())
        self.assertEqual(note.strong.get_text(), "supply chain")

    def test_the_picker_asks_the_incident_questions(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual([d["data-question"] for d in page.select("#classification-modal [data-question]")],
                         ["affected_assets", "impact", "motivation", "mitigation"])
        self.assertTrue(page.select_one("input[name='impact-obj-e1']"))

    def test_editing_drafts_from_the_entries(self):
        page = self.page(f"/products/threat-landscape/{UUID}/edit")
        self.assertEqual(page.select_one("#tlr-draft-btn")["data-tlr"], UUID)


class DraftTrends(unittest.TestCase):
    def test_editing_drafts_from_the_reports_own_entries(self):
        report = _report([_entry("e1"), _entry("e2", excluded=True)])
        with mock.patch.object(threat_landscape.misp_store, "get_tlr", return_value=report), \
             mock.patch.object(threat_landscape.collection_cache, "get_events_by_uuids",
                               return_value=[_cached("e1")]) as rows, \
             mock.patch.object(threat_landscape, "_queued_events") as queue, \
             mock.patch("analyser.llm.draft_landscape_trends", return_value={"outlook": "x"}) as llm:
            _client().post("/products/threat-landscape/draft-trends", data={"tlr": UUID})
        rows.assert_called_once_with(["e1"])
        queue.assert_not_called()
        self.assertEqual([ev["title"] for ev in llm.call_args.args[1]], ["Event e1"])


if __name__ == "__main__":
    unittest.main()
