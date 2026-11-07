"""The TLP of a daily briefing on its form: every level survives a save, and a
story that is added takes the briefing up to the TLP of its source event.

The form offered clear, green and amber only, so a briefing the analyser had
raised to amber+strict or red opened with clear selected and was saved as clear.

    python -m unittest tests.test_briefing_tlp
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import PyMISP

import config
from webapp import audit, collection_cache, create_app, job_store, misp_store

UUID = "11111111-2222-3333-4444-555555555555"
SOURCE = "aaaaaaaa-2222-3333-4444-555555555555"


def _briefing(tlp):
    return SimpleNamespace(
        uuid=UUID, date="2026-11-06", title="Briefing", author="analyser", tlp=tlp,
        escalations="", notes="", detection_rules="", summary="", summary_stale=False,
        review_state=misp_store.BRIEFING_REVIEW_DRAFT, stories=[], also_seen=[], geographic_scope=[],
        sectors=[], threat_actors=[], mitre_attack_techniques=[], threat_types=[], technology=[],
        vendor=[], incident=[], campaign=[], created_at=None,
    )


def _resolved(*tags):
    """What resolve_source_event gives for an event with these tags."""
    event = SimpleNamespace(uuid=SOURCE, info="A story", tags=[SimpleNamespace(name=tag) for tag in tags])
    return event, mock.create_autospec(PyMISP, instance=True), "scraper"


class StrictestTlp(unittest.TestCase):
    def test_it_is_the_most_restrictive_level(self):
        for levels, expected in ((["clear"], "clear"),
                                 (["clear", "amber"], "amber"),
                                 (["amber+strict", "amber", "green"], "amber+strict"),
                                 (["red", "amber+strict"], "red")):
            with self.subTest(levels=levels):
                self.assertEqual(misp_store.strictest_tlp(levels), expected)

    def test_a_value_that_is_no_level_counts_as_red(self):
        self.assertEqual(misp_store.strictest_tlp(["clear", "secret"]), "red")


class BriefingForm(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch("webapp._setup_file_logging"),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(job_store, "by_entity", return_value={}),
            mock.patch.object(audit, "record"),
            mock.patch.object(misp_store, "galaxy_geography", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=[]),
            mock.patch.object(misp_store, "galaxy_threat_actors", return_value=[]),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]),
            mock.patch.object(misp_store, "extract_story_context", return_value={}),
            mock.patch.object(misp_store, "extract_source_url", return_value=""),
        ):
            self.enterContext(patch)
        app = create_app()
        app.testing = True
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"

    def selected(self, response):
        """The TLP the form would post."""
        chosen = BeautifulSoup(response.data, "html.parser").select("select[name=tlp] option[selected]")
        self.assertEqual(len(chosen), 1, "with none selected the browser posts the first one, clear")
        return chosen[0]["value"]

    def add_story(self, briefing_tlp, *tags):
        with mock.patch.object(misp_store, "get_briefing", return_value=_briefing(briefing_tlp)), \
             mock.patch.object(misp_store, "resolve_source_event", return_value=_resolved(*tags)):
            return self.client.post(f"/briefing/{UUID}/add-stories",
                                    data={"csrf_token": "test-token", "selected_events": f"{SOURCE}|scraper"})

    def test_every_level_opens_selected_on_the_edit_form(self):
        for level in misp_store.FIA_TLP_LEVELS:
            with self.subTest(level=level), \
                 mock.patch.object(misp_store, "get_briefing", return_value=_briefing(level)):
                self.assertEqual(self.selected(self.client.get(f"/briefing/{UUID}/edit")), level)

    def test_the_badge_of_amber_strict_has_the_class_the_stylesheet_knows(self):
        with mock.patch.object(misp_store, "get_briefing", return_value=_briefing("amber+strict")):
            page = BeautifulSoup(self.client.get(f"/briefing/{UUID}/edit").data, "html.parser")
        self.assertIn("tlp-amber-strict", page.select_one("#shell-tlp")["class"])

    def test_an_added_story_raises_the_briefing_to_its_source_event(self):
        response = self.add_story("clear", "tlp:amber")
        self.assertEqual(self.selected(response), "amber")
        self.assertIn("went up to TLP:AMBER", response.get_data(as_text=True))

    def test_an_added_story_never_lowers_the_briefing(self):
        response = self.add_story("red", "tlp:green")
        self.assertEqual(self.selected(response), "red")
        self.assertNotIn("went up to", response.get_data(as_text=True))

    def test_a_story_without_a_tlp_leaves_the_briefing_as_it_is(self):
        self.assertEqual(self.selected(self.add_story("green")), "green")

    def test_a_briefing_composed_from_an_event_starts_at_its_tlp(self):
        with mock.patch.object(misp_store, "resolve_source_event", return_value=_resolved("tlp:amber+strict")):
            response = self.client.get("/briefing/compose", query_string={"source": f"{SOURCE}|scraper"})
        self.assertEqual(self.selected(response), "amber+strict")

    def test_a_briefing_composed_from_a_selection_starts_at_their_tlp(self):
        with mock.patch.object(misp_store, "resolve_source_event", return_value=_resolved("tlp:red")):
            response = self.client.post("/briefing/compose", data={
                "csrf_token": "test-token", "selected_events": f"{SOURCE}|scraper"})
        self.assertEqual(self.selected(response), "red")


if __name__ == "__main__":
    unittest.main()
