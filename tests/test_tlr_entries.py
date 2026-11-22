"""The dataset of a threat landscape report: its entries, the queue they come from, the counts.

Each source event in a report is a zsazsa-tlr-entry object on the report's own
event, holding the report's assessment of it. Building a report from the queue
fills the entries in from the event's tags, and an event a report holds leaves
the queue. The triage page saves only the entries that changed, refuses a
published report, and counts over the entries left in the analysis. The page
opens with a banner summing the dataset up (outside the scope, without a threat
type, PIR gaps), always posts a relevance for each row, and gives each count
its change since the previous published report. MISP is patched out.

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
    data.update(event_uuid=event_uuid, excluded=False, no_classification=False, uuid=f"obj-{event_uuid}")
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
        with mock.patch.object(threat_landscape.collection_cache, "get_events", return_value=[]) as get, \
             mock.patch.object(threat_landscape.collection_cache, "source_ids", return_value=["scraper"]):
            threat_landscape._queued_events([_report([_entry("e1")])])
        self.assertEqual(get.call_args.kwargs["exclude"], {"e1"})

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

    def test_none_relevant_is_saved_and_can_be_undone(self):
        update = self.post(_report([_entry("e1"), _entry("e2", no_classification=True)]),
                           **{"relevance-obj-e1": "", "no_classification-obj-e1": "1", "relevance-obj-e2": ""})
        changes = update.call_args.args[1]
        self.assertEqual((changes["obj-e1"]["no_classification"], changes["obj-e2"]["no_classification"]), (True, False))

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

    def test_the_previous_report_is_the_last_one_published_before(self):
        reports = [SimpleNamespace(tlr_id=n, review_state=s) for n, s in (
            ("TLR-00003", "published"), ("TLR-00005", "published"), ("TLR-00007", "internal-review"),
            ("TLR-00009", "draft"), ("TLR-00011", "published"))]
        self.assertEqual(threat_landscape._previous_report(reports, before=reports[3]).tlr_id, "TLR-00005",
                         "a report still in review is no baseline")
        self.assertIsNone(threat_landscape._previous_report(reports, before=reports[0]))
        self.assertEqual(threat_landscape._previous_report(reports).tlr_id, "TLR-00011")


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
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=["Energy", "Health"]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=["Belgium"]),
            mock.patch.object(misp_store, "galaxy_threat_actors", return_value=["APT29"]),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=["Phishing - T1566"]),
            mock.patch.object(misp_store, "list_veas", return_value=[]),
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
            executive_summary="", key_judgements=[], ai_drafted=[], threat_ranking=[], hidden_figures=[],
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
        remove = page.select_one("#tlr-remove-btn")
        self.assertEqual(remove["formaction"], "/products/threat-landscape/remove-from-queue")
        self.assertTrue(remove.has_attr("disabled"))
        self.assertTrue(remove.has_attr("data-submit-confirm"))
        self.assertIsNotNone(remove.select_one(".fa-arrow-rotate-left"))
        self.assertIs(remove.find_previous_sibling("button"), page.select_one("#tlr-build-btn"))
        self.assertEqual(remove.select_one("#tlr-remove-count").get_text(), "0")
        footer = page.select_one("#tlr-build-form .card-footer")
        self.assertIn("d-flex", footer["class"])
        self.assertNotIn("col-12", remove.parent["class"])
        self.assertIn("width:10rem", page.select_one("#tlr-build-target").parent["style"])

    def test_a_full_queue_says_more_events_are_waiting(self):
        queued = [_cached(f"e{i}") for i in range(3)]
        with mock.patch.object(threat_landscape, "QUEUE_SIZE", 2):
            page = self.page("/products/threat-landscape/", queued=queued)
            self.assertEqual(len(page.select("input.tlr-pick")), 2)
            self.assertIn("More events are waiting than the 2 newest shown here", page.get_text(" ", strip=True))
            page = self.page("/products/threat-landscape/", queued=queued[:2])
            self.assertNotIn("More events are waiting", page.get_text())

    def test_the_dataset_page_shows_triage_and_counts(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        # One relevance is always ticked, "-" when none is set: the route saves only the rows that post it.
        ticked = page.select("input[name='relevance-obj-e1'][checked]")
        self.assertEqual([r["value"] for r in ticked], [""])
        self.assertEqual([r["value"] for r in page.select("input[name='relevance-obj-e1']")], ["", "high", "medium", "low"])
        self.assertTrue(page.select_one("input[name='excluded-obj-e2'][checked]"))
        card = self.stat_card(page, "Threat type")
        self.assertIn("Ransomware", card.get_text())
        saves = [b for b in page.select("button") if b.get_text(strip=True) == "Save triage"]
        self.assertEqual([b.get("form") for b in saves], ["triage-form", None])
        self.assertEqual(page.select_one("form#triage-form")["method"], "post")

    def test_each_row_says_where_it_stands_and_marks_what_is_missing(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        row = page.select_one('tr[data-entry-row="obj-e1"]')
        self.assertIn("is-todo", row["class"])
        self.assertEqual(row.select_one("[data-state]").get_text(" ", strip=True),
                         "To do: relevance, source reliability, information credibility")
        self.assertIn("not-set", row.select_one(".dataset-relevance")["class"])
        self.assertIn("not-set", row.select_one("[data-field=credibility]")["class"])
        self.assertNotIn("not-set", row.select_one("[data-field=threat_type]")["class"])
        self.assertNotIn("not-set", row.select_one(".dataset-chips")["class"], "it has a sector")
        out = page.select_one('tr[data-entry-row="obj-e2"]')
        self.assertIn("is-left-out", out["class"])
        self.assertEqual(out.select_one(".dataset-chips .dataset-none").get_text(), "None yet")
        self.assertNotIn("not-set", out.select_one(".dataset-chips")["class"], "a left-out event lacks nothing")
        self.assertIn("1 of 2 events triaged", " ".join(page.select_one(".dataset-progress").get_text(" ").split()))

    def test_a_triaged_event_opens_folded_with_an_arrow_to_open_it(self):
        self.report.entries[0].__dict__.update(relevance="high", source_reliability="B", information_credibility="2")
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        row = page.select_one('tr[data-entry-row="obj-e1"]')
        self.assertIn("is-done", row["class"])
        self.assertIn("is-collapsed", row["class"])
        arrow = row.select_one(".dataset-head [data-fold]")
        self.assertEqual((arrow.name, arrow["role"], arrow["aria-expanded"]), ("span", "button", "false"),
                         "not a button, which the fieldset of a locked report would disable")
        self.assertEqual(arrow.find_next_sibling("a")["class"], ["entry-title"])
        self.assertNotIn("is-collapsed", page.select_one('tr[data-entry-row="obj-e2"]')["class"], "left out, not triaged")

    def test_an_event_still_to_triage_is_open(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertNotIn("is-collapsed", page.select_one('tr[data-entry-row="obj-e1"]')["class"])

    def test_the_columns_and_what_sits_under_the_title(self):
        self.report.entries[0].note = "From the ISAC call"
        self.report.entries[0].source_reliability, self.report.entries[0].information_credibility = "B", "2"
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual([th.get_text(strip=True) for th in page.select(".dataset-table thead th")],
                         ["", "Left out", "Story", "Relevance and Admiralty", "Threat type", "Classification"])
        row = page.select_one('tr[data-entry-row="obj-e1"]')
        story = row.select_one(".c-story")
        self.assertEqual(story.select_one("[data-note-text]").get_text(), "From the ISAC call")
        self.assertEqual(story.select_one("input[name=note-obj-e1]")["value"], "From the ISAC call")
        self.assertTrue(story.select_one("[data-note-add]").has_attr("hidden"))
        self.assertEqual(row.select_one("[data-grade]").get_text(" ", strip=True), "B2 : usually reliable, probably true")
        self.assertIn("excluded-obj-e1", [i["name"] for i in row.select(".c-out input")])
        title = story.select_one(".entry-title")
        self.assertEqual(title["data-preview"], "/collection/e1/preview")
        self.assertTrue(page.select_one("#entry-preview"), "the story opens beside the table")

    def test_an_answered_question_is_a_classification(self):
        self.report.entries[0].sectors = []
        self.report.entries[0].affected_assets = "The billing portal"
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        row = page.select_one('tr[data-entry-row="obj-e1"]')
        chips = row.select_one(".dataset-chips")
        self.assertEqual([c.get_text(strip=True) for c in chips.select(".dataset-chip")], ["Affected assets"])
        self.assertIsNone(chips.select_one(".dataset-none"), "not None yet beside what is there")
        self.assertNotIn("not-set", chips["class"])
        self.assertNotIn("classification", row.select_one("[data-state]").get_text())

    def test_none_relevant_shows_and_ends_the_classification(self):
        self.report.entries[0].sectors = []
        self.report.entries[0].no_classification = True
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        row = page.select_one('tr[data-entry-row="obj-e1"]')
        chips = row.select_one(".dataset-chips")
        self.assertEqual([c.get_text(strip=True) for c in chips.select(".dataset-chip")], ["None relevant"])
        self.assertIsNone(chips.select_one(".dataset-none"))
        self.assertEqual(row.select_one("input[name=no_classification-obj-e1]")["value"], "1")
        self.assertNotIn("classification", row.select_one("[data-state]").get_text())
        self.assertIsNone(page.select_one("input[name=no_classification-obj-e2]"), "only where it was chosen")
        self.assertIn("None relevant", page.select_one("#classification-modal .modal-footer").get_text())

    def test_half_an_admiralty_rating_says_which_half(self):
        self.report.entries[0].source_reliability = "C"
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual(page.select_one('tr[data-entry-row="obj-e1"] [data-grade]').get_text(" ", strip=True),
                         "C? : fairly reliable, information not rated")

    def test_the_top_bar_leads_to_the_queue_and_back_to_the_report(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        [queue] = page.select('a[href="/products/threat-landscape/#queue"]')
        self.assertEqual(queue.get_text(" ", strip=True), "Threat landscape queue")
        self.assertIsNone(queue.find_parent(class_="record-hero"), "in the top bar, and only there")
        back = queue.find_next_sibling("a")
        self.assertEqual((back["href"], back.get_text(" ", strip=True)), (f"/products/threat-landscape/{UUID}", "Back to report"))

    def test_every_threat_type_list_is_in_alphabetical_order(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        for select in (page.select_one("select[name=threat_type-obj-e1]"), page.select_one('select[data-bulk="threat_type"]')):
            names = [o["value"] for o in select.select("option") if o["value"]]
            self.assertEqual(names, sorted(misp_store.tlr_threat_types(), key=str.casefold))

    def statistics(self, report=True, **form):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        form["csrf_token"] = "tok"
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report if report else None), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]), \
             mock.patch.object(misp_store, "update_tlr_entries") as update:
            reply = self.client.post(f"/products/threat-landscape/{UUID}/entries/statistics", data=form)
        update.assert_not_called()
        return reply

    def test_the_statistics_follow_the_triage_before_it_is_saved(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual(page.select_one("#dataset-stats")["data-src"], f"/products/threat-landscape/{UUID}/entries/statistics")
        reply = self.statistics(**{"relevance-obj-e1": "high", "threat_type-obj-e1": "Malware", "sectors-obj-e1": ["Water", "Energy"],
                                   "relevance-obj-e2": "", "threat_type-obj-e2": "Phishing", "excluded-obj-e2": "on"})
        self.assertEqual(reply.status_code, 200)
        stats = BeautifulSoup(reply.data, "html.parser")
        self.assertIn("Malware", self.stat_card(stats, "Threat type").get_text())
        self.assertNotIn("Ransomware", self.stat_card(stats, "Threat type").get_text(), "as posted, not as saved")
        self.assertNotIn("Phishing", stats.get_text(), "a left-out event is not counted")
        self.assertIn("Water", self.stat_card(stats, "Sector").get_text())
        self.assertIsNone(stats.select_one(".record-hero"), "only the statistics")
        self.assertEqual((self.report.entries[0].threat_type, self.report.entries[0].sectors), ("Ransomware", ["Energy"]),
                         "the report itself is untouched")

    def test_a_row_the_form_does_not_post_counts_as_saved(self):
        stats = BeautifulSoup(self.statistics().data, "html.parser")
        self.assertIn("Ransomware", self.stat_card(stats, "Threat type").get_text())

    def test_the_statistics_of_no_report_are_not_found(self):
        self.assertEqual(self.statistics(report=False).status_code, 404)

    @staticmethod
    def stat_card(page, heading):
        return next(c for c in page.select(".chart-card") if c.select_one(".card-header").get_text(strip=True) == heading)

    def test_the_banner_sums_up_the_dataset(self):
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        figures = {k.select_one("span").get_text(strip=True): k.b.get_text() for k in page.select(".record-hero .record-kpi")}
        self.assertEqual(figures, {"event in the analysis": "1", "left out": "1", "outside the scope": "0",
                                   "without a threat type": "0"})
        panel = page.select_one(".dataset-panel").get_text(" ", strip=True)
        self.assertIn("To do 1", panel)
        self.assertIn("Left out 1", panel)
        self.assertIn("Ransomware 1", panel)
        self.assertIn("Q3", page.select_one(".record-hero h1").get_text())

    def test_a_relevance_not_in_the_list_is_kept(self):
        self.report.entries[0].relevance = "critical"
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual([r["value"] for r in page.select("input[name='relevance-obj-e1'][checked]")], ["critical"])

    def test_the_events_outside_the_scope_can_be_shown_and_left_out(self):
        self.report.scope_sectors = ["Health"]
        page = self.page(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual(len(page.select("tr[data-outside-scope]")), 1)
        self.assertIn("Leave out the 1 outside the scope", page.select_one("#exclude-outside-scope").get_text(" ", strip=True))
        self.assertTrue(page.select_one("#filter-outside"))
        outside = page.select_one('.record-kpi[data-show="outside"]')
        self.assertEqual((outside.b.get_text(), "warn" in outside["class"]), ("1", True))

    def test_each_count_has_its_change_since_the_previous_report(self):
        previous = _report([_entry("p1", threat_type="Ransomware"), _entry("p2", threat_type="Ransomware")],
                           review_state="published")
        previous.uuid, previous.tlr_id = "prev-uuid", "TLR-00006"
        page = self.page(f"/products/threat-landscape/{UUID}/entries", tlrs=[self.report, previous])
        card = self.stat_card(page, "Threat type")
        delta = card.select_one(".dataset-delta")
        self.assertEqual((delta.get_text(), delta["title"], delta["class"]), ("-1", "2 in TLR-00006", ["dataset-delta", "down"]))
        self.assertIn("TLR-00006", page.select_one(".record-facts").get_text())

    def test_a_pir_gap_is_counted_and_shown(self):
        pir = SimpleNamespace(uuid="pir-uuid", pir_id="PIR-003", question="Who targets energy?")
        with mock.patch.object(threat_landscape, "_pir_coverage",
                               return_value=[(pir, [("Sector", "Energy", 1), ("Sector", "Health", 0)])]):
            page = self.page(f"/products/threat-landscape/{UUID}/entries")
        gaps = page.select_one('.record-kpi[href="#pir-coverage"]')
        self.assertEqual((gaps.b.get_text(), gaps.span.get_text()), ("1", "PIR gap"))
        coverage = page.select_one("#pir-coverage")
        self.assertEqual([g.find_previous_sibling(class_="term").get_text() for g in coverage.select(".dataset-gap")], ["Health"])
        self.assertIn("1 of 2 covered", coverage.get_text())

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

    def test_edit_sits_in_the_banner_as_on_the_other_products(self):
        page = self.page(f"/products/threat-landscape/{UUID}")
        [link] = page.select(f'a[href="/products/threat-landscape/{UUID}/edit"]')
        self.assertIsNotNone(link.find_parent(class_="hero-actions"))

    def test_the_list_offers_the_usual_row_actions(self):
        page = self.page("/products/threat-landscape/")
        row = page.select_one(".req-id-badge").find_parent("tr")
        data = row.select_one(f'a[href="/products/threat-landscape/{UUID}/entries"]')
        self.assertEqual((data.get_text(strip=True), data["title"]), ("", "Data: triage and statistics"),
                         "an icon, as the other row actions, named on hover")
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

    def test_the_threat_types_are_those_of_settings_and_one_removed_stays(self):
        self.report.threat_sections = [{"threat_type": "Ransomware", "title": "Grid", "findings": "Up"}]
        with mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", ["Insider threat", "Malware"], create=True):
            entries = self.page(f"/products/threat-landscape/{UUID}/entries")
            wizard = self.page(f"/products/threat-landscape/{UUID}/edit")
        kept = [("", False), ("Ransomware", True), ("Insider threat", False), ("Malware", False)]
        offered = [("", False), ("Insider threat", False), ("Malware", False)]
        self.assertEqual(self.options(entries, "select[name='threat_type-obj-e1']"), kept)
        self.assertEqual(self.options(entries, "select[data-bulk=threat_type]"), offered)
        self.assertEqual(self.options(wizard, "#tlr-sections select[name=section_threat_type]"), kept)
        # What a template holds is not part of the page, as for the browser: it is
        # read as the fragment a new section is cloned from.
        section = BeautifulSoup(wizard.select_one("#tlr-section-template").decode_contents(), "html.parser")
        self.assertEqual(self.options(section, "select"), offered)

    @staticmethod
    def options(page, select):
        return [(o["value"], o.has_attr("selected")) for o in page.select_one(select).select("option")]

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

    def test_an_audience_typed_before_the_boxes_survives_an_edit(self):
        """The audience was free text once; a save must not drop what it said."""
        self.report.audience = "SOC, Board of directors"
        page = self.page(f"/products/threat-landscape/{UUID}/edit")
        ticked = [box["value"] for box in page.select("input[name=audience][checked]")]
        self.assertEqual(ticked, ["SOC", "Board of directors"])


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

    def test_a_story_of_a_deleted_threat_report_is_drafted_as_an_event(self):
        gone = _cached("s1", tags=[misp_store.report_tag("9" * 8 + "-0000-4000-8000-000000000009")])
        with mock.patch.object(threat_landscape, "_queued_events", return_value=[gone, _cached("e1")]), \
             mock.patch.object(threat_landscape.misp_store, "list_tlrs", return_value=[]), \
             mock.patch.object(threat_landscape.misp_store, "list_report_documents", return_value=[]), \
             mock.patch("analyser.llm.draft_landscape_trends", return_value={"outlook": "x"}) as llm:
            _client().post("/products/threat-landscape/draft-trends", data={})
        self.assertEqual([ev["title"] for ev in llm.call_args.args[1]], ["Event s1", "Event e1"])
        self.assertEqual(llm.call_args.args[2], [])

    def test_the_stories_of_a_threat_report_that_cannot_be_read_are_drafted_as_events(self):
        report = SimpleNamespace(uuid="9" * 8 + "-0000-4000-8000-000000000009", title="R", provider="P", published="")
        story = _cached("s1", tags=[misp_store.report_tag(report.uuid)])
        with mock.patch.object(threat_landscape, "_queued_events", return_value=[story]), \
             mock.patch.object(threat_landscape.misp_store, "list_tlrs", return_value=[]), \
             mock.patch.object(threat_landscape.misp_store, "list_report_documents", return_value=[report]), \
             mock.patch.object(threat_landscape.misp_store, "report_manifest", side_effect=RuntimeError("gone")), \
             mock.patch("analyser.llm.draft_landscape_trends", return_value={"outlook": "x"}) as llm:
            _client().post("/products/threat-landscape/draft-trends", data={})
        self.assertEqual(([ev["title"] for ev in llm.call_args.args[1]], llm.call_args.args[2]), (["Event s1"], []))


if __name__ == "__main__":
    unittest.main()
