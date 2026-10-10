"""The direction, scope and threat assessments of a threat landscape report.

A report records why it is written, for whom, the period and scope it covers,
the PIRs it answers, a methodology note and any number of threat assessments.
Its dataset marks the events outside the scope and shows how well they cover
each linked PIR. Publishing keeps all of it, and a published report can be
neither edited nor deleted. MISP is patched out.

    python -m unittest tests.test_tlr_direction
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask, render_template
from pymisp import PyMISP
from werkzeug.datastructures import MultiDict

from webapp import create_app, matching, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _entry(**fields):
    data = {"event_info": "", "threat_type": "", "excluded": False, "sectors": [],
            "geographic_scope": [], "threat_actors": [], "techniques": []}
    data.update(fields)
    return SimpleNamespace(**data)


def _pir(**scope):
    data = {"uuid": "pir-1", "pir_id": "PIR-001", "question": "Who targets our grid?", "out_of_scope": []}
    data.update(scope)
    return SimpleNamespace(**data)


class StoredReport(unittest.TestCase):
    def test_direction_and_sections_survive_the_round_trip(self):
        data = {"tlr_id": "TLR-00009", "purpose": "Budget planning", "audience_level": "Strategic",
                "period_start": "2026-07-01", "period_end": "2026-09-30", "methodology": "Collected from ISACs.",
                "scope_sectors": ["Energy"], "scope_geography": ["Belgium"], "linked_pir_uuids": ["pir-1"],
                "threat_sections": [{"threat_type": "Ransomware", "title": "Grid", "findings": "Up",
                                     "confidence": "moderate", "alternative_hypotheses": "", "recommendations": ""}]}
        event = SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj(data)], published=False, date=None)
        tlr = misp_store._tlr_ns(event)
        for key, value in data.items():
            self.assertEqual(getattr(tlr, key), value, key)

    def test_a_report_from_before_has_empty_direction(self):
        event = SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj({"title": "Old"})], published=False, date=None)
        tlr = misp_store._tlr_ns(event)
        self.assertEqual((tlr.purpose, tlr.scope_sectors, tlr.threat_sections), ("", [], []))

    def test_publishing_keeps_every_field(self):
        stored = misp_store._tlr_obj({"tlr_id": "TLR-00009", "purpose": "Budget planning",
                                      "threat_sections": [{"title": "Grid"}], "scope_sectors": ["Energy"]})
        stored.id = 7
        event = SimpleNamespace(uuid=UUID, id=1, objects=[stored], tags=[], published=False, date=None)
        misp = mock.create_autospec(PyMISP, instance=True)
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_check"), \
             mock.patch.object(misp_store.misp_session, "current_user_email", return_value="pub@example.org"):
            misp_store.publish_tlr(UUID)
        published = {a.object_relation: a.value for a in misp.update_object.call_args.args[0].attributes}
        self.assertEqual(published["purpose"], "Budget planning")
        self.assertEqual(published["scope-sectors"], '["Energy"]')
        self.assertIn("Grid", published["threat-sections"])
        self.assertEqual(published["review-state"], "published")


class WizardForm(unittest.TestCase):
    def test_the_direction_and_sections_are_read(self):
        form = MultiDict([
            ("purpose", " Budget planning "), ("audience_level", "Strategic"),
            ("scope_sectors", "Energy"), ("scope_sectors", "Health"), ("linked_pir_uuids", "pir-1"),
            *[(f"section_{key}", value) for key, value in zip(misp_store.TLR_SECTION_FIELDS,
                                                               ("Ransomware", "Grid", "Up", "moderate", "", "", ""))],
            *[(f"section_{key}", value) for key, value in zip(misp_store.TLR_SECTION_FIELDS,
                                                               ("Malware", "", "", "low", "", "", ""))],
        ])
        data = threat_landscape._form_data(form)
        self.assertEqual(data["purpose"], "Budget planning")
        self.assertEqual(data["scope_sectors"], ["Energy", "Health"])
        self.assertEqual(data["linked_pir_uuids"], ["pir-1"])
        self.assertEqual([s["title"] for s in data["threat_sections"]], ["Grid"], "an empty section is dropped")
        self.assertEqual(data["threat_sections"][0]["confidence"], "moderate")

    def test_scope_typed_one_per_line_is_split(self):
        data = threat_landscape._form_data(MultiDict({"scope_geography": "Belgium\r\n\r\nFrance\n"}))
        self.assertEqual(data["scope_geography"], ["Belgium", "France"])


class Scope(unittest.TestCase):
    def report(self, sectors=(), geography=()):
        return SimpleNamespace(scope_sectors=list(sectors), scope_geography=list(geography))

    def test_a_report_for_the_whole_organisation_takes_everything(self):
        self.assertFalse(threat_landscape._outside_scope(self.report(), _entry(sectors=["Health"])))

    def test_an_event_naming_other_sectors_only_is_outside(self):
        report = self.report(sectors=["Energy"])
        self.assertTrue(threat_landscape._outside_scope(report, _entry(sectors=["Health"])))
        self.assertFalse(threat_landscape._outside_scope(report, _entry(sectors=["Health", "energy"])))

    def test_an_event_without_a_sector_is_not_held_against_it(self):
        self.assertFalse(threat_landscape._outside_scope(self.report(sectors=["Energy"]), _entry()))

    def test_geography_counts_too(self):
        report = self.report(geography=["Belgium"])
        self.assertTrue(threat_landscape._outside_scope(report, _entry(geographic_scope=["France"])))


class PirCoverage(unittest.TestCase):
    def test_each_scope_item_is_counted_and_a_gap_shows_as_zero(self):
        events = [{"info": "", "galaxy_names": ["Energy", "APT29"], "tags": []},
                  {"info": "", "galaxy_names": ["Energy"], "tags": []}]
        items = matching.coverage(events, _pir(sectors=["Energy", "Health"], threat_actors=["APT29"]))
        self.assertEqual(items, [("Sector", "Energy", 2), ("Sector", "Health", 0), ("Threat actor", "APT29", 1)])

    def test_the_triaged_classification_is_what_counts(self):
        report = SimpleNamespace(entries=[
            _entry(event_info="Grid outage", sectors=["Energy"], threat_type="Ransomware"),
            _entry(event_info="Left out", sectors=["Health"], excluded=True),
        ])
        [(pir, items)] = threat_landscape._pir_coverage(report, [_pir(sectors=["Energy", "Health"],
                                                                      threat_types=["Ransomware"])])
        self.assertEqual(items, [("Sector", "Energy", 1), ("Sector", "Health", 0), ("Threat type", "Ransomware", 1)])


def _report(**fields):
    data = {key: "" for key in misp_store.TLR_DIRECTION_FIELDS}
    data.update({key: [] for key in misp_store.TLR_DIRECTION_LISTS})
    data.update({key: "" for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES})
    data.update(uuid=UUID, tlr_id="TLR-00009", title="Q3", reporting_period="2026 Q3", tlp="amber", author="",
                audience="", top_threats="", trending_actors="", key_incidents="", recommendations="",
                outlook="", threat_sections=[], review_log=[], corrections=[], entries=[], review_state="draft", creator="", approved_by="",
                created_at=None, misp_url="")
    data.update(fields)
    return SimpleNamespace(**data)


class Markdown(unittest.TestCase):
    def test_the_markdown_carries_direction_assessments_and_methodology(self):
        md = misp_store.render_tlr_markdown(_report(
            purpose="Budget planning", audience_level="Strategic", scope_sectors=["Energy"],
            period_start="2026-07-01", period_end="2026-09-30", methodology="From **ISAC** feeds.",
            threat_sections=[{"threat_type": "Ransomware", "title": "Grid", "confidence": "moderate",
                              "findings": "- Up by half", "alternative_hypotheses": "", "recommendations": "Patch"}]))
        self.assertIn("**Scope:** Energy", md)
        self.assertIn("**Period:** 2026-07-01 to 2026-09-30", md)
        self.assertIn("## Purpose\n\nBudget planning", md)
        self.assertIn("## Grid\n\n**Threat type:** Ransomware | **Confidence:** Moderate", md)
        self.assertIn("### Findings\n\n- Up by half", md)
        self.assertNotIn("Alternative hypotheses", md)
        self.assertIn("## Methodology and limitations\n\nFrom **ISAC** feeds.", md)

    def test_a_report_without_scope_covers_the_whole_organisation(self):
        self.assertIn("**Scope:** the whole organisation", misp_store.render_tlr_markdown(_report()))


class RenderedPage(unittest.TestCase):
    def test_every_text_field_is_handed_to_the_markdown_renderer(self):
        report = _report(purpose="**Why**", top_threats="- one", key_incidents="x", recommendations="y",
                         outlook="z", methodology="m", trending_actors="t", actors_cybercrime="c",
                         threat_sections=[{"findings": "f", "key_drivers": "k", "alternative_hypotheses": "a",
                                           "recommendations": "r"}],
                         corrections=[{"date": "2026-10-01", "text": "fix"}])
        app = create_app()
        with app.test_request_context():
            page = render_template("threat_landscape/detail.html", tlr=report, feedback=[], linked_pirs=[],
                                   annex=[], next_states=[], locked=False, can_publish=False,
                                   **threat_landscape._report_context())
        soup = BeautifulSoup(page, "html.parser")
        rendered = [el["data-md"] for el in soup.select(".report-md-body")]
        self.assertEqual(sorted(rendered), sorted(["**Why**", "- one", "f", "k", "a", "r", "t", "c", "x", "y", "z", "m", "fix"]))
        self.assertIn("marked.min.js", page)
        self.assertIn("purify.min.js", page)


class PublishedReport(unittest.TestCase):
    def test_it_cannot_be_deleted(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_landscape.bp)
        report = SimpleNamespace(uuid=UUID, tlr_id="TLR-00009", review_state="published")
        with mock.patch.object(threat_landscape.misp_store, "get_tlr", return_value=report), \
             mock.patch.object(threat_landscape.misp_store, "delete_tlr") as delete:
            app.test_client().post(f"/products/threat-landscape/{UUID}/delete")
        delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
