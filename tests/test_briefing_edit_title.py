"""The heading of a briefing's edit page: its title, as on the briefing itself,
and its date when it has none.

    python -m unittest tests.test_briefing_edit_title
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import job_store
from webapp.routes import daily_briefing as briefing_routes


def _briefing(title):
    return SimpleNamespace(
        uuid="b" * 36, date="2026-10-28", title=title, author="analyser", tlp="clear",
        escalations="", notes="", detection_rules="", summary="", summary_stale=False,
        review_state="draft", stories=[], geographic_scope=[], sectors=[], threat_actors=[],
        mitre_attack_techniques=[], threat_types=[], technology=[], vendor=[], incident=[],
        campaign=[], created_at=None,
    )


class EditHeading(unittest.TestCase):
    def heading(self, title):
        app = Flask(__name__)
        app.register_blueprint(briefing_routes.bp)
        briefing = _briefing(title)
        # The form asks whether a drafting job is running, which is a read of
        # the Redis the app uses, and fills its scope pickers from the galaxies
        # on MISP.
        store = briefing_routes.misp_store
        with mock.patch.object(job_store, "_command", return_value=None), \
             mock.patch.object(store, "galaxy_geography", return_value=[]), \
             mock.patch.object(store, "galaxy_sectors", return_value=[]), \
             mock.patch.object(store, "galaxy_threat_actors", return_value=[]), \
             mock.patch.object(store, "galaxy_mitre_attack_patterns", return_value=[]), \
             mock.patch.object(store, "get_briefing", return_value=briefing), \
             mock.patch.object(briefing_routes, "render_template", return_value="") as render:
            app.test_client().get(f"/briefing/{briefing.uuid}/edit")
        kwargs = render.call_args.kwargs
        return kwargs["page_title_text"], kwargs["browser_title"]

    def test_it_is_the_title_of_the_briefing(self):
        self.assertEqual(self.heading("Daily threat briefing for 28 October 2026"),
                         ("Edit Daily threat briefing for 28 October 2026",) * 2)

    def test_a_briefing_without_a_title_is_named_by_its_date(self):
        self.assertEqual(self.heading(""), ("Edit briefing 2026-10-28",) * 2)


if __name__ == "__main__":
    unittest.main()
