"""The actor categories of a threat landscape report are stored, rendered and shown.

    python -m unittest tests.test_tlr_actor_categories
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import render_template
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape


def _report(**fields):
    base = dict(
        uuid="u", tlr_id="TLR-00001", title="Q3", reporting_period="2026 Q3", tlp="amber",
        review_state="draft", author="", audience="", created_at=None, top_threats="", trending_actors="",
        key_incidents="", recommendations="", outlook="",
        actors_nation_state="", actors_cybercrime="", actors_hacker_for_hire="",
        actors_hacktivists="", purpose="", audience_level="", period_start="", period_end="", methodology="",
        scope_sectors=[], scope_geography=[], linked_pir_uuids=[], threat_sections=[], review_log=[], corrections=[], entries=[],
        executive_summary="", key_judgements=[], ai_drafted=[], threat_ranking=[], hidden_figures=[])
    base.update(fields)
    return SimpleNamespace(**base)


class ActorCategories(unittest.TestCase):
    def test_object_carries_the_categories(self):
        obj = misp_store._tlr_obj({"actors_nation_state": "APT29", "actors_hacktivists": "KillNet"})
        values = {a.object_relation: a.value for a in obj.attributes}
        self.assertEqual(values["actors-nation-state"], "APT29")
        self.assertEqual(values["actors-hacktivists"], "KillNet")
        self.assertNotIn("actors-cybercrime", values)

    def test_form_reads_the_categories(self):
        data = threat_landscape._form_data(MultiDict({"actors_cybercrime": " LockBit "}))
        self.assertEqual(data["actors_cybercrime"], "LockBit")
        self.assertEqual(data["actors_hacker_for_hire"], "")

    def test_markdown_lists_only_filled_categories(self):
        md = misp_store.render_tlr_markdown(_report(actors_nation_state="APT29"))
        self.assertIn("## Trending threat actors", md)
        self.assertIn("### Nation state\n\nAPT29", md)
        self.assertNotIn("### Cybercrime", md)

    def test_wizard_offers_a_three_line_box_per_category(self):
        # Not this install's database, log or collection cache worker.
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(collection_cache, "start_worker"), \
             create_app().test_request_context():
            page = render_template(
                "threat_landscape/wizard.html", tlr=_report(actors_cybercrime="LockBit"),
                tlp_levels=misp_store.TLR_TLP_LEVELS, is_edit=True, queued=[], audiences=[],
                actor_categories=misp_store.TLR_ACTOR_CATEGORIES, intel_levels=[], threat_types=[],
                estimative_confidence=[], pirs=[], sector_items=[], geo_items=[], type_counts={})
        soup = BeautifulSoup(page, "html.parser")
        boxes = [soup.find("textarea", id=key) for key, _l, _i in misp_store.TLR_ACTOR_CATEGORIES]
        self.assertEqual([(b["name"], b["rows"]) for b in boxes],
                         [(key, "3") for key, _l, _i in misp_store.TLR_ACTOR_CATEGORIES])
        self.assertEqual(boxes[1].text, "LockBit")


if __name__ == "__main__":
    unittest.main()
