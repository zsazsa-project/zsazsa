"""Scope items filled from the threat-actor galaxy, and the profile export.

"Complete profile with MISP galaxy data" used to fill only the narrative fields,
leaving the analyst to work the scope out from the victimology note by hand.

    python -m unittest tests.test_tap_galaxy_scope
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import misp_store
from webapp.routes import export, threat_actor_profile


class MatchScopeItems(unittest.TestCase):
    """The scope fields only take what their galaxy offers, so a galaxy value
    that names nothing in the pick-list is left out rather than typed in."""

    SECTORS = ["Government, Administration", "Military", "Finance", "Education"]

    def test_a_value_that_names_an_item_exactly(self):
        self.assertEqual(misp_store._match_scope_items(["Military"], self.SECTORS), ["Military"])

    def test_cfr_names_a_sector_by_its_first_word(self):
        # The galaxy says "Government"; the sector galaxy spells it out.
        self.assertEqual(misp_store._match_scope_items(["Government"], self.SECTORS),
                         ["Government, Administration"])

    def test_matching_ignores_case_and_padding(self):
        self.assertEqual(misp_store._match_scope_items(["  military "], self.SECTORS), ["Military"])

    def test_a_value_with_no_item_is_dropped(self):
        # NATO and the like are recorded as victims but are not countries.
        self.assertEqual(misp_store._match_scope_items(["NATO", "Military"], self.SECTORS),
                         ["Military"])

    def test_the_same_item_is_only_named_once(self):
        self.assertEqual(misp_store._match_scope_items(["Government", "Government"], self.SECTORS),
                         ["Government, Administration"])


class GalaxyEnrichmentScope(unittest.TestCase):
    def test_victims_and_target_categories_become_scope_items(self):
        meta = {
            "capabilities": [], "mode_of_operation": [], "synonyms": [], "refs": [],
            "victimology": [], "suspected_origin": [], "motivation": [], "sponsorship": [],
            "victims": ["Belgium", "NATO"], "target_categories": ["Government"],
        }
        with mock.patch.object(misp_store, "threat_actor_galaxy_meta", return_value=meta), \
             mock.patch.object(misp_store, "galaxy_geography", return_value=["Belgium", "France"]), \
             mock.patch.object(misp_store, "galaxy_sectors",
                               return_value=["Government, Administration", "Military"]):
            data = misp_store.galaxy_enrichment(["APT28"])
        self.assertEqual(data["geographic_scope"], ["Belgium"])
        self.assertEqual(data["sectors"], ["Government, Administration"])

    def test_an_actor_the_galaxy_knows_nothing_about_adds_no_scope(self):
        with mock.patch.object(misp_store, "threat_actor_galaxy_meta", return_value={}):
            data = misp_store.galaxy_enrichment(["Made up"])
        self.assertEqual(data["geographic_scope"], [])
        self.assertEqual(data["sectors"], [])


class EnrichEndpoint(unittest.TestCase):
    """What the page is told after the enrich button runs."""

    def _post(self, enrichment):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_actor_profile.bp)
        with mock.patch.object(misp_store, "galaxy_enrichment", return_value=enrichment):
            with app.test_request_context():
                pass
            client = app.test_client()
            with client.session_transaction() as session:
                session["_csrf_token"] = "tok"
            return client.post("/products/threat-actor-profile/galaxy-enrich",
                               data={"threat_actors": "APT28"},
                               headers={"X-CSRF-Token": "tok"}).get_json()

    def _enrichment(self, **over):
        data = dict(capabilities="", mode_of_operation="", synonyms="", refs=[],
                    suspected_origin="", motivation="", sponsorship="",
                    geographic_scope=[], sectors=[], victimology=[])
        data.update(over)
        return data

    def test_the_actors_that_will_produce_a_note_are_named(self):
        """The note is written server-side on save, so the page is told who it
        will be about rather than being handed the text."""
        body = self._post(self._enrichment(victimology=[("ALLANITE", "Electric utilities")]))
        self.assertEqual(body["victimology_actors"], ["ALLANITE"])

    def test_an_actor_with_no_victimology_names_nobody(self):
        # Saying "victimology is added as a note" for an actor that has none
        # promises something that will not happen.
        self.assertEqual(self._post(self._enrichment())["victimology_actors"], [])

    def test_the_scope_items_come_back_for_the_page_to_tick(self):
        body = self._post(self._enrichment(geographic_scope=["Belgium"], sectors=["Military"]))
        self.assertEqual(body["geographic_scope"], ["Belgium"])
        self.assertEqual(body["sectors"], ["Military"])


class ProfileExport(unittest.TestCase):
    """The Markdown export of the profiles, as the PIR and GIR lists offer."""

    def _tap(self, **over):
        fields = dict(
            tap_id="TAP-001", title="Sample actor", summary="A summary.", status="Published",
            tlp="amber", published_at=None, author="analyst", audience="SOC", review_date=None,
            threat_actors=["APT28"], actor_types=["State-sponsored"], synonyms="Fancy Bear",
            suspected_origin="RU", motivation="Espionage", sponsorship="",
            capabilities="Custom malware", mode_of_operation="Spearphishing",
            mitre_attack_techniques=["Phishing - T1566"], infrastructure="Rented VPS",
            geographic_scope=["Belgium"], sectors=["Military"], threat_types=["APT"],
            time_frame="Past 12 months", technology=["Windows"], vendor=["Microsoft"],
            attribution_rationale="", assessment_confidence="High", origin_confidence="",
            source_reliability="B", source_credibility="2", rec_prevention="Patch",
            rec_detection="", rec_response="", external_references=["https://example.org/a"],
            misp_url="https://misp.example/events/view/1",
        )
        fields.update(over)
        return SimpleNamespace(**fields)

    def _markdown(self, taps):
        with mock.patch.object(misp_store, "list_threat_actor_profiles", return_value=taps):
            return export._taps_markdown()

    def test_the_document_groups_the_fields_by_diamond_corner(self):
        """The export cannot draw the Diamond, so it says which corner each
        group of fields belongs to, as the profile page shows them."""
        md = self._markdown([self._tap()])
        for heading in ("### Actor (Diamond: Adversary)", "### Capability (Diamond: Capability)",
                        "### Infrastructure (Diamond: Infrastructure)", "### Victim (Diamond: Victim)"):
            self.assertIn(heading, md)

    def test_it_carries_the_profile_content(self):
        md = self._markdown([self._tap()])
        self.assertIn("## TAP-001: Sample actor", md)
        self.assertIn("A summary.", md)
        self.assertIn("- Threat actors: APT28", md)
        self.assertIn("- Geographic scope: Belgium", md)
        self.assertIn("- MITRE ATT&CK techniques: Phishing - T1566", md)
        self.assertIn("- https://example.org/a", md)
        self.assertIn("https://misp.example/events/view/1", md)

    def test_empty_fields_are_left_out_rather_than_printed_blank(self):
        md = self._markdown([self._tap(sponsorship="", rec_detection="")])
        self.assertNotIn("Sponsorship:", md)
        self.assertNotIn("Detection:", md)

    def test_a_section_with_nothing_in_it_is_not_headed(self):
        md = self._markdown([self._tap(rec_prevention="", rec_detection="", rec_response="")])
        self.assertNotIn("### Recommendations", md)

    def test_a_profile_with_nothing_filled_in_gets_no_section_headings(self):
        """Every section is headed only when it has something under it, the
        Actor one included: a heading with nothing after it reads as data lost
        rather than data absent."""
        empty = {f: "" for f in ("summary", "synonyms", "suspected_origin", "motivation",
                                 "sponsorship", "capabilities", "mode_of_operation",
                                 "infrastructure", "time_frame", "attribution_rationale",
                                 "assessment_confidence", "origin_confidence",
                                 "source_reliability", "source_credibility",
                                 "rec_prevention", "rec_detection", "rec_response")}
        empty.update({f: [] for f in ("threat_actors", "actor_types", "mitre_attack_techniques",
                                      "geographic_scope", "sectors", "threat_types",
                                      "technology", "vendor", "external_references")})
        md = self._markdown([self._tap(**empty)])
        self.assertNotIn("###", md)
        self.assertIn("## TAP-001: Sample actor", md)

    def test_an_untitled_profile_still_gets_a_heading(self):
        self.assertIn("## TAP-001: (untitled)", self._markdown([self._tap(title="")]))

    def test_no_profiles_still_produces_a_document(self):
        md = self._markdown([])
        self.assertIn("# Threat actor profiles", md)


if __name__ == "__main__":
    unittest.main()
