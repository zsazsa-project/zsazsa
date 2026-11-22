"""The incidents of a threat landscape report's dataset.

Several sources report one incident, and each report is an event of its own in
the dataset. An analyst groups those events as one incident, and every count of
the report counts it once: the statistics, the banner, the PIR coverage, the
ATT&CK layer, the annex and the methodology, and the trend draft reads it once.
An incident has the earliest date of its events, their highest relevance and
every value any of them names. The dataset proposes the events that may report
one incident, as the analyser shortlists the same story, within a week of each
other; the analyst groups them or sets them apart, which is saved with the
triage. The triage table lists the duplicates together under one header and
judges them together: an event is triaged once it, with its duplicates, has a
relevance, both halves of its Admiralty rating, a threat type and a
classification, or is left out. MISP and the cache are patched out; the
database and log are temporary.

    python -m unittest tests.test_tlr_incidents
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
ALONE = misp_store.TLR_INCIDENT_ALONE


def _entry(n, **fields):
    data = {key: "" for key in misp_store.TLR_ENTRY_FIELDS}
    data.update({key: [] for key in misp_store.TLR_ENTRY_LISTS})
    data.update(uuid=f"obj-{n}", event_uuid=f"ev-{n}", event_info=f"Event {n}", event_date="2026-08-01",
                source_id="scraper", excluded=False, no_classification=False)
    data.update(fields)
    return SimpleNamespace(**data)


def _report(entries, **fields):
    data = dict(uuid=UUID, tlr_id="TLR-00007", title="Q3", review_state="draft", entries=list(entries),
                scope_sectors=[], scope_geography=[], linked_pir_uuids=[], period_start="", period_end="",
                reporting_period="2026 Q3", ai_drafted=[])
    data.update(fields)
    return SimpleNamespace(**data)


# Three outlets on one ransomware attack, grouped; one of them left out; and two events on their own.
GROUPED = [
    _entry(1, event_date="2026-08-03", relevance="medium", threat_type="", sectors=["Energy"], incident="ev-2"),
    _entry(2, event_date="2026-08-02", relevance="low", threat_type="Ransomware", sectors=["Energy", "Water"],
           threat_actors=["Akira"], incident="ev-2"),
    _entry(3, event_date="2026-08-04", relevance="high", sectors=["Health"], incident="ev-2", excluded=True),
    _entry(4, threat_type="Ransomware", relevance="high", incident=ALONE),
    _entry(5, threat_type="Malware"),
]


class Merge(unittest.TestCase):
    def test_the_events_of_an_incident_count_once(self):
        incidents = {i.event_uuid: i for i in misp_store.tlr_incidents(GROUPED)}
        self.assertEqual(set(incidents), {"ev-2", "ev-4", "ev-5"})
        akira = incidents["ev-2"]
        self.assertEqual((akira.events, akira.event_date, akira.event_info), (2, "2026-08-02", "Event 2"))
        self.assertEqual((akira.relevance, akira.threat_type), ("medium", "Ransomware"))
        self.assertEqual((akira.sectors, akira.threat_actors), (["Energy", "Water"], ["Akira"]),
                         "a left-out event adds nothing")

    def test_the_statistics_count_incidents(self):
        stats = dict(threat_landscape._statistics(GROUPED))
        self.assertEqual(stats["Threat type"], [("Ransomware", 2, None), ("Malware", 1, None)])
        self.assertEqual(dict((v, n) for v, n, _b in stats["Sector"]), {"Energy": 1, "Water": 1})

    def test_the_annex_and_the_banner_say_how_many_incidents(self):
        report = _report(GROUPED)
        self.assertEqual(dict(misp_store.tlr_annex(report))["Duplicates"], "counted once, so the events count as 3")
        summary = threat_landscape._dataset_summary(report, set(), [])
        self.assertEqual((summary["used"], summary["incidents"]), (4, 3))
        self.assertEqual(summary["threat_types"], [("Ransomware", 2), ("Malware", 1)])
        self.assertNotIn("Duplicates", dict(misp_store.tlr_annex(_report(GROUPED[3:]))))

    def test_the_pir_coverage_counts_an_incident_once(self):
        pir = SimpleNamespace(uuid="p", pir_id="PIR-1", question="q", sectors=["Energy"], out_of_scope=[])
        [(_pir, items)] = threat_landscape._pir_coverage(_report(GROUPED), [pir])
        self.assertEqual(items, [("Sector", "Energy", 1)])

    def test_the_table_lists_duplicates_together_where_the_first_is(self):
        entries = [_entry(9, incident="ev-2")] + GROUPED + [_entry(6, incident="ev-6")]
        blocks = [(n, [e.uuid for e in members]) for n, members in threat_landscape._triage_blocks(entries)]
        self.assertEqual(blocks, [(1, ["obj-9", "obj-1", "obj-2", "obj-3"]), (0, ["obj-4"]), (0, ["obj-5"]), (0, ["obj-6"])],
                         "a set of one is no set, and an event marked as standing alone is on its own")


class Triage(unittest.TestCase):
    def test_what_each_event_lacks_judged_with_its_duplicates(self):
        lacking = threat_landscape._still_to_do(GROUPED)
        both = ["source reliability", "information credibility"]
        self.assertEqual((lacking["obj-1"], lacking["obj-2"]), (both, both), "the threat type of one is enough for both")
        self.assertEqual(lacking["obj-3"], [], "a left-out event lacks nothing")
        self.assertEqual(lacking["obj-4"], both + ["classification"])
        self.assertEqual(lacking["obj-5"], ["relevance"] + both + ["classification"])

    def test_a_classification_is_part_of_it(self):
        rated = dict(relevance="high", source_reliability="B", information_credibility="2", threat_type="Malware")
        lacking = threat_landscape._still_to_do([_entry(1, **rated), _entry(2, techniques=["T1566"], **rated),
                                                 _entry(3, affected_assets="The billing portal", **rated)])
        self.assertEqual(lacking, {"obj-1": ["classification"], "obj-2": [], "obj-3": []},
                         "what the classification picker asks counts too")
        grouped = [_entry(4, incident="ev-4", **rated), _entry(5, incident="ev-4", mitigation="Patch the VPN")]
        self.assertEqual(threat_landscape._still_to_do(grouped), {"obj-4": [], "obj-5": []}, "a duplicate lends its answer")

    def test_none_relevant_ends_the_classification(self):
        rated = dict(relevance="high", source_reliability="B", information_credibility="2", threat_type="Malware")
        self.assertEqual(threat_landscape._still_to_do([_entry(1, no_classification=True, **rated)]), {"obj-1": []})

    def test_none_relevant_is_stored_with_the_entry(self):
        stored = misp_store._tlr_entry(misp_store._tlr_entry_obj({"event_uuid": "ev-1", "no_classification": True}))
        self.assertTrue(stored["no_classification"])
        self.assertFalse(misp_store._tlr_entry(misp_store._tlr_entry_obj({"event_uuid": "ev-1"}))["no_classification"],
                         "an entry saved before has none")

    def test_the_banner_counts_the_triaged(self):
        rated = dict(relevance="high", source_reliability="B", information_credibility="2", threat_type="Malware",
                     sectors=["Energy"])
        report = _report(GROUPED + [_entry(6, **rated)])
        self.assertEqual(threat_landscape._dataset_summary(report, set(), [])["triage"], {"done": 1, "todo": 4, "out": 1})


class Proposals(unittest.TestCase):
    def propose(self, entries, cves=None):
        cached = [{"uuid": e.event_uuid, "vulnerability_ids": (cves or {}).get(e.event_uuid, []), "tags": []}
                  for e in entries]
        with mock.patch.object(collection_cache, "get_events_by_uuids", return_value=cached):
            return [[e.uuid for e in group] for group in threat_landscape._incident_proposals(_report(entries))]

    def test_events_with_most_of_a_title_in_common_within_a_week(self):
        entries = [_entry(1, event_info="Akira ransomware hits Belgian energy contractor", event_date="2026-08-05"),
                   _entry(2, event_info="Belgian energy contractor hit by Akira ransomware", event_date="2026-08-02"),
                   _entry(3, event_info="Phishing wave against banks", event_date="2026-08-03")]
        self.assertEqual(self.propose(entries), [["obj-2", "obj-1"]])

    def test_a_week_apart_is_not_proposed(self):
        entries = [_entry(1, event_info="Akira ransomware hits Belgian energy contractor", event_date="2026-08-09"),
                   _entry(2, event_info="Belgian energy contractor hit by Akira ransomware", event_date="2026-08-02")]
        self.assertEqual(self.propose(entries), [])

    def test_a_shared_cve_is_enough(self):
        entries = [_entry(1, event_info="Edge appliance exploited", event_date="2026-08-03"),
                   _entry(2, event_info="Patch now", event_date="2026-08-04")]
        self.assertEqual(self.propose(entries, {"ev-1": ["CVE-2026-1234"], "ev-2": ["cve-2026-1234"]}),
                         [["obj-1", "obj-2"]])

    def test_the_stories_of_an_imported_report_are_not_proposed(self):
        """They share the report's date and often an actor or words of their titles."""
        title = "Akira ransomware hits Belgian energy contractor"
        entries = [_entry(1, event_info=title), _entry(2, event_info=title), _entry(3, event_info=title)]
        tags = {"ev-1": [misp_store.report_tag("rep")], "ev-2": [misp_store.report_tag("rep")], "ev-3": []}
        cached = [{"uuid": e.event_uuid, "vulnerability_ids": [], "tags": tags[e.event_uuid]} for e in entries]
        entries.append(_entry(4, event_info=title))
        cached.append({"uuid": "ev-4", "vulnerability_ids": [], "tags": []})
        with mock.patch.object(collection_cache, "get_events_by_uuids", return_value=cached):
            groups = [[e.uuid for e in g] for g in threat_landscape._incident_proposals(_report(entries))]
        self.assertEqual(groups, [["obj-3", "obj-4"]], "a story is a part of its report, not news of an incident")

    def test_an_event_whose_date_cannot_be_read_is_not_proposed(self):
        title = "Akira ransomware hits Belgian energy contractor"
        entries = [_entry(1, event_info=title, event_date="2026-8-1"), _entry(2, event_info=title),
                   _entry(3, event_info=title, event_date="2026-08-02")]
        self.assertEqual(self.propose(entries), [["obj-2", "obj-3"]])

    def test_grouped_alone_and_left_out_events_are_not_proposed(self):
        title = "Akira ransomware hits Belgian energy contractor"
        entries = [_entry(1, event_info=title), _entry(2, event_info=title, incident=ALONE),
                   _entry(3, event_info=title, incident="ev-9"), _entry(4, event_info=title, excluded=True)]
        self.assertEqual(self.propose(entries), [])


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
            mock.patch.object(threat_landscape.audit, "record"),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=["Energy"]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=["Belgium"]),
            mock.patch.object(misp_store, "galaxy_threat_actors", return_value=["Akira"]),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        title = "Akira ransomware hits Belgian energy contractor"
        self.report = _report(GROUPED + [_entry(6, event_info=title, event_date="2026-08-10"),
                                         _entry(7, event_info=title, event_date="2026-08-11")],
                              tlp="amber", reporting_period="2026 Q3")
        self.report.__dict__.update({key: "" for key, _l, _i in misp_store.TLR_ACTOR_CATEGORIES})

    def page(self):
        cached = [{"uuid": e.event_uuid, "vulnerability_ids": []} for e in self.report.entries]
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]), \
             mock.patch.object(collection_cache, "get_events_by_uuids", return_value=cached):
            reply = self.client.get(f"/products/threat-landscape/{UUID}/entries")
        self.assertEqual(reply.status_code, 200)
        return BeautifulSoup(reply.data, "html.parser")

    def test_the_dataset_shows_duplicates_together_and_suggests_more(self):
        page = self.page()
        body = page.select_one(".dataset-table tbody")
        rows = [tr.get("data-entry-row") or "group:" + tr["data-group"] for tr in body.find_all("tr", recursive=False)]
        self.assertEqual(rows[:4], ["group:ev-2", "obj-1", "obj-2", "obj-3"])
        head = " ".join(body.select_one("tr.dataset-group").get_text(" ").split())
        self.assertIn("Duplicates 1 3 events report the same story and count once.", head)
        self.assertIn("To do: source reliability, information credibility", head)
        row = page.select_one('tr[data-entry-row="obj-1"]')
        self.assertEqual(row.select_one("[data-state]").get_text(" ", strip=True),
                         "To do with its duplicates: source reliability, information credibility")
        self.assertEqual(page.select_one('tr[data-entry-row="obj-3"] [data-state]').get_text(" ", strip=True),
                         "Left out, counts as triaged")
        self.assertEqual(row.select_one("input[name=incident-obj-1]")["value"], "ev-2")
        self.assertEqual((row.select_one("[data-pick]").has_attr("hidden"), row.select_one("[data-undup]").has_attr("hidden")),
                         (True, False), "in a set: it can leave it, not join another")
        alone = page.select_one('tr[data-entry-row="obj-5"]')
        self.assertEqual((alone.select_one("[data-pick]").has_attr("hidden"), "is-dup" in alone["class"]), (False, False))
        self.assertEqual(alone.select_one("[data-pick]").get_text(strip=True), "Same story as…")
        [proposal] = page.select("#incident-proposals [data-proposal]")
        self.assertEqual(proposal["data-proposal"], "obj-6 obj-7")
        figures = {k.select_one("span").get_text(strip=True): k.b.get_text() for k in page.select(".record-hero .record-kpi")}
        self.assertEqual((figures["events in the analysis"], figures["without duplicates"]), ("6", "5"))
        self.assertEqual(page.select_one('[data-bulk-incident="join"]').get_text(strip=True), "Mark as duplicates")

    def test_the_table_says_how_to_mark_duplicates_and_what_it_suggests(self):
        strip = self.page().select_one("#dataset-duplicates")
        self.assertIn("Use Same story as… under an event", " ".join(strip.get_text(" ").split()))
        suggested = strip.select_one("#incident-proposals")
        self.assertEqual([b.get_text(strip=True) for b in suggested.select("button")], ["Duplicates", "Not duplicates"])
        self.assertNotIn("incident", strip.get_text().lower())
        self.assertNotIn("No suggested duplicates", strip.get_text())

    def test_without_suggestions_it_says_so(self):
        self.report.entries = GROUPED
        strip = self.page().select_one("#dataset-duplicates")
        self.assertIsNone(strip.select_one("#incident-proposals"))
        self.assertIn("No suggested duplicates right now.", strip.get_text())

    def test_the_triage_saves_the_incidents_it_may(self):
        form = {"csrf_token": "tok"}
        for e in self.report.entries:
            form[f"relevance-{e.uuid}"] = ""
        form.update({"incident-obj-6": "ev-6", "incident-obj-7": "ev-6", "incident-obj-5": ALONE,
                     "incident-obj-4": "elsewhere"})
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "update_tlr_entries") as update:
            self.client.post(f"/products/threat-landscape/{UUID}/entries", data=form)
        saved = {uuid: fields["incident"] for uuid, fields in update.call_args.args[1].items()}
        self.assertEqual((saved["obj-6"], saved["obj-7"], saved["obj-5"]), ("ev-6", "ev-6", ALONE))
        self.assertEqual(saved["obj-4"], ALONE, "an incident outside the report keeps the one it had")
        self.assertEqual(saved["obj-1"], "ev-2", "a row that posts no incident keeps its own")

    def test_a_locked_report_proposes_nothing(self):
        self.report.review_state = "published"
        page = self.page()
        self.assertIsNone(page.select_one("#incident-proposals"))
        self.assertIsNone(page.select_one("#dataset-duplicates"))
        self.assertEqual([tr["data-group"] for tr in page.select(".dataset-table tr.dataset-group")], ["ev-2"], "its sets still show")


class Elsewhere(unittest.TestCase):
    def test_the_trend_draft_reads_an_incident_once_with_how_many_report_it(self):
        report = _report(GROUPED)
        cached = [{"uuid": u, "info": u, "date": "2026-08-01", "tags": [], "galaxy_names": [], "vulnerability_ids": [],
                   "source_id": "scraper"} for u in ("ev-2", "ev-4", "ev-5")]
        flask_app = Flask(__name__)
        flask_app.register_blueprint(threat_landscape.bp)
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch.object(collection_cache, "get_events_by_uuids", return_value=cached) as read, \
             mock.patch("analyser.llm.draft_landscape_trends", return_value={"outlook": "x"}) as llm:
            flask_app.test_client().post("/products/threat-landscape/draft-trends", data={"tlr": UUID})
        self.assertEqual(sorted(read.call_args.args[0]), ["ev-2", "ev-4", "ev-5"])
        events = {e["title"]: e for e in llm.call_args.args[1]}
        self.assertEqual(events["ev-2"]["reported_by"], 2)
        self.assertNotIn("reported_by", events["ev-5"])

    def test_the_navigator_layer_scores_incidents(self):
        report = _report([_entry(1, techniques=["T1486"], incident="g"), _entry(2, techniques=["T1486"], incident="g"),
                          _entry(3, techniques=["T1486"])], tlp="amber")
        flask_app = Flask(__name__)
        flask_app.register_blueprint(threat_landscape.bp)
        with mock.patch.object(misp_store, "get_tlr", return_value=report):
            layer = flask_app.test_client().get(f"/products/threat-landscape/{UUID}/navigator.json").get_json()
        self.assertEqual(layer["techniques"][0]["score"], 2)

    def test_the_methodology_says_the_events_are_grouped(self):
        with mock.patch.object(collection_cache, "_build_sources", return_value=[]), \
             mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]):
            text = threat_landscape._methodology_draft(_report(GROUPED), None, [])
        self.assertIn("Limitations: events that report the same thing count once: analysts marked the duplicates, "
                      "so the 4 events count as 3.", text)


if __name__ == "__main__":
    unittest.main()
