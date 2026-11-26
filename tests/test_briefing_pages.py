"""The daily briefing list, page and form in the layout of the stakeholder,
PIR, GIR and RFI pages.

The list opens on the compact banner with its figures and breakdowns, has the
drop-downs in the filter card, and groups the table by review state with a
date leaf per row that opens the briefing. A briefing's page has the record
banner with its buttons at the bottom left, its TLP and its delivery, and the stories and their contents
under it. The form has numbered sections, the TLP as choices and an "As it
will appear" card with Save, and the AI actions in a card of their own. A
story from a MISP event opens that event on Data collection in a new tab. A
briefing's page folds its source events away and reads them from MISP on the
first Show; its page and form queue the stories' articles for the threat
landscape, all of them or one story's, of those saved on the briefing.

MISP is patched; the database and log are temporary.

    python -m unittest tests.test_briefing_pages
"""

import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(__file__))

import test_briefing_rejection  # noqa: E402
from test_briefing_rejection import UUID, _event  # noqa: E402

from webapp import audit, misp_store  # noqa: E402
from webapp.models import TLP_LEVELS  # noqa: E402
from webapp.routes import data_collection  # noqa: E402

EVENT_A = "0c1d6a8e-61b4-4f0b-9a55-1f4f1d2f0a01"
EVENT_B = "5e2f9b3c-0d7a-4c41-8e66-2a5b3c4d0b02"


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
        # The leaf is the link, without the date written out beside it.
        link = leaf.parent
        self.assertEqual((link.name, link["href"]), ("a", "/zsazsa/briefing/briefing-1"))
        self.assertEqual((link["title"], link["aria-label"]), ("2026-10-27", "Daily briefing 2026-10-27"))
        self.assertEqual(link.find_parent("td").get_text(" ", strip=True), "Oct 27")

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
        self.assertEqual([r["value"] for r in page.select("input[name=tlp]")], TLP_LEVELS)
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
        self.assertEqual(" ".join(link.get_text().split()), "Story in data coll.")
        self.assertIsNotNone(link.find_previous_sibling(class_="btn-include-attributes"))
        self.assertIsNone(second.select_one(".btn-story-collection"))
        # A story added on the page gets it too.
        self.assertIn("/collection/?event=${encodeURIComponent(sourceUuid)}", str(page))

    def test_data_collection_shows_the_linked_event_on_its_own(self):
        """By its title, in the search box, with the other filters cleared; the
        parameter comes off again so a reload keeps the analyst's filters."""
        script = (Path(misp_store.__file__).parent / "templates" / "data_collection" / "_list_js.html").read_text()
        linked = script.split("function showLinkedEvent() {", 1)[1].split("\n  }\n", 1)[0]
        for line in ("takeParam('event')", "clearAllFilters();", "state.q = title;", "searchInput.value = title;",
                     "applyAll();", "That event is not on Data collection."):
            self.assertIn(line, linked)
        take = script.split("function takeParam(name) {", 1)[1].split("\n  }\n", 1)[0]
        self.assertIn("params.delete(name);", take)
        self.assertIn("history.replaceState(", take)
        self.assertIn("showLinkedEvent();\n    _saveFilterState();", script)

    def with_stories(self):
        stories = [SimpleNamespace(title="One", content="x", source_event_uuid=EVENT_A, source_id="scraper"),
                   SimpleNamespace(title="Two", content="y", source_event_uuid=EVENT_B, source_id="partner"),
                   SimpleNamespace(title="Again", content="z", source_event_uuid=EVENT_A, source_id="scraper"),
                   SimpleNamespace(title="By hand", content="w")]
        return _briefing("draft", stories=stories)

    def test_a_briefing_page_folds_its_source_events_away_until_asked(self):
        """Read from MISP on the first Show only: a briefing has many."""
        with mock.patch.object(misp_store, "fetch_source_events") as fetched:
            page = self.page(f"/briefing/{UUID}", get_briefing=mock.Mock(return_value=self.with_stories()))
        fetched.assert_not_called()
        header = page.select_one("#source-events-header")
        self.assertEqual(header.find("span").get_text(strip=True), "Source events (2)")
        body = page.select_one("#source-events-accordion")
        self.assertEqual(body["data-src"], f"/zsazsa/briefing/{UUID}/source-events")
        self.assertEqual(body.get_text(strip=True), "")
        cards = [h.get_text(" ", strip=True) for h in page.select(".col-lg-8 > .card > .card-header")]
        self.assertEqual(cards[:2], ["Source events (2) Show", "Briefing summary Out of date"])

    def test_the_source_events_are_read_when_asked(self):
        events = [{"uuid": EVENT_A, "info": "Article A", "date": "", "orgc": "", "source_label": "", "tags": [],
                   "attributes": [], "objects": [], "reports": [{"name": "R", "date": "",
                               "content": "Full text <img src=x onerror=alert(1)>"}]}]
        with mock.patch.object(misp_store, "get_briefing", return_value=self.with_stories()), \
             mock.patch.object(misp_store, "fetch_source_events", return_value=events) as fetched:
            reply = self.client.get(f"/briefing/{UUID}/source-events", headers=self.headers)
        self.assertEqual(fetched.call_args.args[:2], ([EVENT_A, EVENT_B], {EVENT_A: "scraper", EVENT_B: "partner"}))
        fragment = BeautifulSoup(reply.data, "html.parser")
        body = fragment.select_one(".report-md-body")
        # An article is someone else's text: md escapes it before rendering.
        self.assertEqual(body.get_text(strip=True), "Full text <img src=x onerror=alert(1)>")
        self.assertIsNone(body.select_one("img"))
        self.assertIn("1 source event could not be read from MISP.", fragment.get_text())
        self.assertIsNone(fragment.select_one(".add-fact-btn"))

    def test_a_briefing_page_queues_its_articles_all_or_per_story(self):
        page = self.page(f"/briefing/{UUID}", get_briefing=mock.Mock(return_value=self.with_stories()))
        url = f"/zsazsa/briefing/{UUID}/queue-for-tlr"
        hero = page.select_one("section.record-hero .hero-actions > [data-tlr-url]")
        self.assertEqual(" ".join(hero.get_text().split()), "Queue 2 articles for threat landscape")
        self.assertEqual((hero["data-tlr-url"], hero.get("data-tlr-uuid")), (url, None))
        per_story = page.select("article.briefing-story [data-tlr-url]")
        self.assertEqual([b["data-tlr-uuid"] for b in per_story], [EVENT_A, EVENT_B, EVENT_A])
        self.assertEqual({" ".join(b.get_text().split()) for b in per_story}, {"Queue 1 article for threat landscape"})
        self.assertIsNone(page.select_one("article#story-4 [data-tlr-url]"))

    def test_a_story_s_buttons_keep_to_one_line(self):
        """Six of them took two lines. Where the pane is too narrow for their
        labels, the lesser ones keep their icon and tooltip, then the reports
        and the queue keep only their count; Draft with AI keeps its label."""
        galaxies = {name: mock.Mock(return_value=[]) for name in
                    ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        stories = self.with_stories()
        stories.stories[0].report_count = 2
        page = self.page(f"/briefing/{UUID}/edit", get_briefing=mock.Mock(return_value=stories), **galaxies)
        header = page.select_one(".story-card .card-header")
        tiers = {" ".join(b.get_text().split()): [c for c in b["class"] if c.startswith("wb-t")]
                 for b in header.select(".btn")}
        self.assertEqual(tiers, {"Draft with AI": [], "MISP reports (2)": ["wb-t3"], "Include attributes": ["wb-t2"],
                                 "Story in data coll.": ["wb-t2"], "Queue 1 article for threat landscape": ["wb-t3"],
                                 "": []})
        for button in header.select(".wb-t2"):
            self.assertTrue(button["title"])
        queue = header.select_one("[data-tlr-url]")
        self.assertEqual(" ".join(t.get_text() for t in queue.find_all(string=True, recursive=False)).split(), ["1"])
        css = page.find("style").get_text()
        self.assertIn(".wb-editor .story-card > .card-header > div { flex-wrap: nowrap; }", css)
        self.assertIn("container-type: inline-size", css)
        self.assertIn("@container (max-width: 680px) { .story-card .wb-t3 :is(.wb-lbl, .tlr-lbl) { display: none; } }", css)

    def test_the_form_queues_a_story_s_article(self):
        galaxies = {name: mock.Mock(return_value=[]) for name in
                    ("galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        page = self.page(f"/briefing/{UUID}/edit", get_briefing=mock.Mock(return_value=self.with_stories()), **galaxies)
        buttons = [card.select_one(".card-header [data-tlr-url]") for card in page.select(".story-card")]
        self.assertEqual([b and b["data-tlr-uuid"] for b in buttons], [EVENT_A, EVENT_B, EVENT_A, None])

    def queue(self, body):
        with mock.patch.object(misp_store, "get_briefing", return_value=self.with_stories()), \
             mock.patch.object(data_collection, "queue_events_for_tlr", return_value={"ok": True}) as queued:
            reply = self.client.post(f"/briefing/{UUID}/queue-for-tlr", json=body,
                                     headers={**self.headers, "X-CSRF-Token": "test-token"})
        return reply, queued

    def test_the_route_queues_the_articles_saved_on_the_briefing(self):
        reply, queued = self.queue({})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(queued.call_args.args[0], [(EVENT_A, "scraper"), (EVENT_B, "partner")])
        self.assertFalse(queued.call_args.kwargs["collected_only"])
        _, queued = self.queue({"uuid": EVENT_B})
        self.assertEqual(queued.call_args.args[0], [(EVENT_B, "partner")])

    def test_but_not_one_the_briefing_does_not_hold(self):
        reply, queued = self.queue({"uuid": "00000000-0000-4000-8000-000000000009"})
        self.assertEqual(reply.status_code, 400)
        self.assertIn("Save it first", reply.get_json()["error"])
        queued.assert_not_called()

    def test_nor_a_uuid_that_is_no_text(self):
        for body in ({"uuid": 5}, {"uuid": ["x"]}):
            with self.subTest(body):
                reply, queued = self.queue(body)
                self.assertEqual(reply.status_code, 400)
                queued.assert_not_called()

    def test_a_body_that_is_no_object_queues_them_all(self):
        reply, queued = self.queue(["x"])
        self.assertEqual(queued.call_args.args[0], [(EVENT_A, "scraper"), (EVENT_B, "partner")])

    def test_an_unknown_briefing_or_one_without_articles_is_refused(self):
        for briefing, status in ((None, 404), (_briefing("draft", stories=[SimpleNamespace(title="By hand")]), 400)):
            with self.subTest(status), \
                 mock.patch.object(misp_store, "get_briefing", return_value=briefing), \
                 mock.patch.object(data_collection, "queue_events_for_tlr") as queued:
                reply = self.client.post(f"/briefing/{UUID}/queue-for-tlr", json={},
                                         headers={**self.headers, "X-CSRF-Token": "test-token"})
                self.assertEqual(reply.status_code, status)
                queued.assert_not_called()


if __name__ == "__main__":
    unittest.main()
