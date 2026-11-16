"""The daily briefing list, page and form in the layout of the stakeholder,
PIR, GIR and RFI pages.

The list opens on the compact banner with its figures and breakdowns, has the
drop-downs in the filter card, and groups the table by review state with a
date leaf per row. A briefing's page has the record banner with its buttons at
the bottom left, its TLP and its delivery, and the stories and their contents
under it. The form has numbered sections, the TLP as choices and an "As it
will appear" card with Save, and the AI actions in a card of their own. A
story from a MISP event opens that event on Data collection in a new tab.

MISP is patched; the database and log are temporary.

    python -m unittest tests.test_briefing_pages
"""

import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(__file__))

import test_briefing_rejection  # noqa: E402
from test_briefing_rejection import UUID, _event  # noqa: E402

from webapp import audit, misp_store  # noqa: E402


def _briefing(state="draft", **fields):
    briefing = misp_store._briefing_ns(_event(state))
    for name, value in fields.items():
        setattr(briefing, name, value)
    return briefing


class BriefingPages(unittest.TestCase):
    # The app, database and patches of the rejection route tests, not their tests.
    setUp = test_briefing_rejection.BriefingRejectionRoutes.setUp

    def page(self, path, **patches):
        with mock.patch.multiple(misp_store, list_product_feedback=mock.Mock(return_value=[]),
                                 list_stakeholders=mock.Mock(return_value=[]), **patches), \
             mock.patch.object(audit, "latest_notify_status", return_value=None):
            response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")

    def test_the_list_banner_and_filters(self):
        briefings = [_briefing("draft"), _briefing("published", published_at=datetime(2026, 10, 24, 17, 14))]
        briefings[1].uuid = "published-briefing"
        page = self.page("/briefing/", list_briefings=mock.Mock(return_value=briefings))
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-compact", hero["class"])
        kpis = hero.select_one(".record-kpis").get_text(" ", strip=True)
        for shown in ("2 briefings", "1 draft waiting for approval", "1 published", "0 rejected", "24-10 last published"):
            self.assertIn(shown, kpis)
        self.assertEqual([a.get_text(strip=True) for a in hero.select(".hero-actions .btn")],
                         ["New briefing", "How a daily briefing is made"])
        self.assertEqual(hero.select_one('[data-bs-target="#product-flow"]')["aria-controls"], "product-flow")
        self.assertIsNotNone(page.select_one("#product-flow"))
        filters = page.select_one("form.record-filters")
        self.assertEqual([s["name"] for s in filters.select("select")], ["state", "tlp"])

    def test_the_list_groups_the_rows_by_state(self):
        briefings = [_briefing("published"), _briefing("draft"), _briefing("rejected")]
        for n, briefing in enumerate(briefings):
            briefing.uuid = f"briefing-{n}"
        page = self.page("/briefing/", list_briefings=mock.Mock(return_value=briefings))
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Draft", "Published", "Rejected"])
        leaf = page.select_one("#briefing-row-briefing-1 .date-leaf")
        self.assertEqual((leaf.b.get_text(), leaf.span.get_text(), leaf["class"]), ("Oct", "27", ["date-leaf", "draft"]))
        self.assertEqual(page.select_one("#briefing-row-briefing-0 .date-leaf")["class"], ["date-leaf"])

    def test_a_published_briefing_page(self):
        briefing = _briefing("published", approved_by="admin@example.org", author="analyser")
        page = self.page(f"/briefing/{UUID}", get_briefing=mock.Mock(return_value=briefing))
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-detail", hero["class"])
        self.assertEqual([c["class"][0] for c in hero.select_one(".hero-body").find_all(recursive=False)],
                         ["hero-main", "hero-actions"])
        actions = [b.get_text(strip=True) for b in hero.select(".hero-actions .btn")]
        self.assertEqual(actions, ["Resend", "Recipients", "PDF", "MISP event history", "Edit", "Delete"])
        self.assertTrue(all(b.has_attr("disabled") for b in hero.select(".hero-actions button")
                            if b.get_text(strip=True) in ("Edit", "Delete")))
        self.assertIn("TLP:CLEAR", hero.select_one(".hero-tlp").get_text())
        legs = [leg.get_text(" ", strip=True) for leg in hero.select(".delivery .leg")]
        self.assertEqual(legs[1], "Approved admin@example.org")
        self.assertEqual([a["href"] for a in page.select(".briefing-toc a")], ["#briefing-summary-card", "#story-1"])
        self.assertIsNotNone(page.select_one("article#story-1"))
        self.assertIsNone(page.select_one(f'form[action="/zsazsa/briefing/{UUID}/publish"]'))

    def test_a_draft_page_offers_the_review_and_the_edit(self):
        page = self.page(f"/briefing/{UUID}", get_briefing=mock.Mock(return_value=_briefing("draft")))
        hero = page.select_one("section.record-hero")
        self.assertEqual(hero.select_one(".hero-actions .btn-hero").get_text(strip=True), "Edit")
        self.assertIsNotNone(hero.select_one(f'.hero-actions form[action="/zsazsa/briefing/{UUID}/delete"]'))
        self.assertIn("waiting", hero.select_one(".delivery").get_text())
        self.assertIsNotNone(page.select_one(f'form[action="/zsazsa/briefing/{UUID}/reject"]'))

    def test_the_form(self):
        galaxies = {name: mock.Mock(return_value=[]) for name in
                    ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        page = self.page(f"/briefing/{UUID}/edit", get_briefing=mock.Mock(return_value=_briefing("draft")), **galaxies)
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         ["#step-details", "#step-summary", "#step-stories", "#step-scope", "#step-notes"])
        for step in ("details", "summary", "stories", "scope", "notes"):
            self.assertIsNotNone(page.select_one(f".form-step#step-{step}"), step)
        self.assertEqual([r["value"] for r in page.select("input[name=tlp]")], misp_store.FIA_TLP_LEVELS)
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertEqual(card.select_one(".card-header").get_text(strip=True), "As it will appear")
        self.assertEqual(card.select_one("#preview-title").get_text(strip=True), "Daily briefing")
        self.assertEqual(card.select_one("button[type=submit]").get_text(strip=True), "Save changes")
        ai = page.select_one(".ai-actions")
        self.assertEqual([b.get("id") or b["class"][-1] for b in ai.select("button")],
                         ["btn-draft-everything", "btn-draft-all", "btn-use-all-summaries", "btn-draft-summary",
                          "btn-check-overlap", "btn-auto-delete-excluded"])
        self.assertEqual([b["value"] for b in ai.select("button[name=ai_draft]")], ["stories+summary", "stories"])
        self.assertIsNotNone(page.select_one("#step-stories #rail-stories"))
        self.assertIsNone(page.select_one(".wb-shell"))


    def test_a_story_technique_is_ticked_by_its_galaxy_name(self):
        """A story keeps a technique by its id; the pick-list showed "T1059"
        ticked on its own, without the name the galaxy gives it."""
        galaxies = {name: mock.Mock(return_value=[]) for name in ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors")}
        galaxies["galaxy_mitre_attack_patterns"] = mock.Mock(
            return_value=["Command and Scripting Interpreter - T1059", "Valid Accounts - T1078"])
        briefing = _briefing("draft", stories=[{"title": "Story", "content": "x", "techniques": ["T1059", "T1078"]}])
        # The page names techniques from a cache; this list must not stay in it.
        with mock.patch.dict(misp_store._mitre_name_cache, clear=True), \
             mock.patch.object(misp_store, "_mitre_name_ts", 0.0):
            page = self.page(f"/briefing/{UUID}/edit", get_briefing=mock.Mock(return_value=briefing), **galaxies)
        self.assertEqual(sorted(i["value"] for i in page.select('#gms-briefing-mitre-attack input:checked')),
                         ["Command and Scripting Interpreter - T1059", "Valid Accounts - T1078"])
        self.assertIsNone(page.select_one('#gms-briefing-mitre-attack input[value="T1059"]'))

    def test_a_story_jumps_to_its_event_on_data_collection(self):
        """Next to its AI and MISP buttons, in a new tab: the form may have
        unsaved changes. A story written by hand has no event to jump to."""
        galaxies = {name: mock.Mock(return_value=[]) for name in
                    ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        event_uuid = "001f09ac-c17e-433c-ad70-81a480a6b7de"
        briefing = _briefing("draft", stories=[{"title": "From MISP", "content": "x", "source_event_uuid": event_uuid},
                                               {"title": "By hand", "content": "y"}])
        page = self.page(f"/briefing/{UUID}/edit", get_briefing=mock.Mock(return_value=briefing), **galaxies)
        first, second = page.select(".story-card")
        link = first.select_one(".card-header a.btn-story-collection")
        self.assertEqual(link["href"], f"/zsazsa/collection/?event={event_uuid}")
        self.assertEqual(link["target"], "_blank")
        self.assertEqual(" ".join(link.get_text().split()), "Jump to story in data collection")
        self.assertIsNotNone(link.find_previous_sibling(class_="btn-include-attributes"))
        self.assertIsNone(second.select_one(".btn-story-collection"))
        # A story added on the page gets it too.
        self.assertIn("/collection/?event=${encodeURIComponent(sourceUuid)}", str(page))

    def test_data_collection_shows_the_linked_event_on_its_own(self):
        """By its title, in the search box, with the other filters cleared; the
        parameter comes off again so a reload keeps the analyst's filters."""
        script = (Path(misp_store.__file__).parent / "templates" / "data_collection" / "_list_js.html").read_text()
        linked = script.split("function showLinkedEvent() {", 1)[1].split("\n  }\n", 1)[0]
        for line in ("params.get('event')", "params.delete('event')", "history.replaceState(",
                     "clearAllFilters();", "state.q = title;", "searchInput.value = title;", "applyAll();",
                     "That event is not on Data collection."):
            self.assertIn(line, linked)
        self.assertIn("showLinkedEvent();\n    _saveFilterState();", script)


if __name__ == "__main__":
    unittest.main()
