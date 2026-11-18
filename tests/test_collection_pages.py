"""The manual entry form, the newsletter import and a newsletter under review,
in the layout of the record pages.

The manual entry has numbered sections, the source as tiles, the TLP and the
Admiralty ratings as choices, and an "As it will appear" card with Create
event. Build with AI on the Summary line outlines the summary and the scope it
fills. A link with ?tag= opens the list on the events with that tag, and says
why when the list is empty. The import picks the newsletter from tiles and
says how many already wait in the mailbox. A newsletter under review is a record with its articles
to tick, each with its site, and a card that sends the ticked ones; one from
the queue says when it came in and which one waits after it.

MISP is patched; the database and log are temporary.

    python -m unittest tests.test_collection_pages
"""

import datetime
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_store, newsletter_parsers
from webapp.routes import data_collection

_ARTICLES = [
    {"title": "Ivanti exploited", "primary_url": "https://www.thehackernews.com/a", "section": "News",
     "priority_key": "critical", "priority_label": "Critical", "intro": "", "related_urls": []},
    {"title": "OT agents", "primary_url": "https://securityweek.com/b", "section": "News",
     "priority_key": "", "priority_label": "", "intro": "Booz Allen", "related_urls": []},
]


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.multiple(misp_store, galaxy_geography=mock.Mock(return_value=["Belgium"]),
                                galaxy_sectors=mock.Mock(return_value=["Energy"]),
                                galaxy_threat_actors=mock.Mock(return_value=[]),
                                galaxy_mitre_attack_patterns=mock.Mock(return_value=[])),
        ):
            self.enterContext(patch)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")


class ManualEntry(Pages):
    def form(self):
        sources = [mock.Mock(enabled=True), mock.Mock(enabled=True)]
        sources[0].name, sources[1].name = "ISAC Mattermost", "Newsletter"
        with mock.patch.object(misp_store, "list_collection_sources", return_value=sources):
            return self.page("/collection/manual/new")

    def test_the_form_has_its_sections_and_the_card_with_create_event(self):
        page = self.form()
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         ["#step-source", "#step-article", "#step-scope", "#step-references"])
        self.assertEqual([i["value"] for i in page.select('#step-source input[name="source"]')],
                         ["ISAC Mattermost", "Newsletter"])
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertIsNotNone(card.select_one("#create-event-btn"))
        self.assertIsNotNone(card.select_one('input[name="summary_job"]'))

    def test_tlp_and_the_admiralty_ratings_are_choices(self):
        page = self.form()
        self.assertEqual(page.select_one('input[name="tlp"]:checked')["value"], "green")
        self.assertEqual([i["value"] for i in page.select('input[name="source_reliability"]')], list("ABCDEF"))
        self.assertEqual([i["value"] for i in page.select('input[name="information_credibility"]')], list("123456"))
        self.assertEqual(page.select_one('label[for="source_reliability-B"]')["title"], "Usually reliable")

    def test_the_scripts_it_needs_are_there(self):
        page = self.form()
        for hook in ("btn-fetch-url", "btn-llm-summary", "md-tab-edit", "md-tab-preview", "md-tab-split",
                     "description", "summary", "ref-add", "admiralty-preview"):
            self.assertIsNotNone(page.find(id=hook), hook)

    def test_build_with_ai_outlines_the_summary_and_the_scope(self):
        page = self.form()
        button = page.select_one("#btn-llm-summary")
        self.assertEqual(" ".join(button.get_text().split()), "Build with AI")
        targets = [t.strip() for t in button["data-ai-targets"].split(",")]
        self.assertEqual(targets, ["#summary", "#step-scope"])
        self.assertEqual([a["data-ai-targets"] for a in page.select("#ai-fills a")], targets)
        for target in targets:
            self.assertIsNotNone(page.select_one(target), target)
        self.assertIn("window.zsazsaAiTargets = function(el, on)", str(page))

    def test_a_saved_entry_keeps_the_ratings_picked(self):
        sources = [mock.Mock(enabled=True)]
        sources[0].name = "ISAC Mattermost"
        with mock.patch.object(misp_store, "list_collection_sources", return_value=sources), \
             mock.patch.object(misp_store, "create_manual_collection_event", return_value="u1") as create, \
             mock.patch.object(data_collection, "_cache_manual_event"), \
             mock.patch.object(data_collection.audit, "record"):
            with self.client.session_transaction() as session:
                session["_csrf_token"] = "tok"
            self.client.post("/collection/manual/new", data={
                "csrf_token": "tok", "source": "ISAC Mattermost", "title": "Web shells", "tlp": "amber",
                "source_reliability": "B", "information_credibility": "2"})
        data = create.call_args[0][0]
        self.assertEqual((data["tlp"], data["source_reliability"], data["information_credibility"]), ("amber", "B", "2"))


class LinkedTag(unittest.TestCase):
    def test_a_link_with_a_tag_opens_the_list_on_that_tag_alone(self):
        """As a feed on the pipeline page links here: the parameter comes off
        again, and the list says so when no event it holds has the tag, or
        when all of them are set aside and so hidden."""
        script = (Path(misp_store.__file__).parent / "templates" / "data_collection" / "_list_js.html").read_text()
        linked = script.split("function showLinkedTag() {", 1)[1].split("\n  }\n", 1)[0]
        for line in ("takeParam('tag')", "window.zsazsaRestoreFilterState({include: [tag]});",
                     "No event on Data collection has the tag ", "are all set aside",
                     "tags.indexOf(REJECTED_TAG) !== -1 || tags.indexOf(DISMISSED_TAG) !== -1"):
            self.assertIn(line, linked)
        self.assertIn("showLinkedTag();\n    showLinkedEvent();", script)


class NewsletterImport(Pages):
    def test_the_newsletter_is_picked_from_tiles(self):
        with mock.patch.object(misp_store, "list_pending_newsletters",
                               return_value=[{"uuid": "a", "info": "x", "date": "2026-10-01"}]):
            page = self.page("/collection/newsletter/new")
        self.assertEqual([i["value"] for i in page.select('input[name="source"]')], newsletter_parsers.available_sources())
        self.assertIsNotNone(page.select_one('textarea[name="raw"][required]'))
        self.assertIn("1 newsletter the IMAP collector archived is waiting for review", " ".join(page.get_text().split()))

    def test_without_any_waiting_the_mailbox_card_stays_away(self):
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=[]):
            page = self.page("/collection/newsletter/new")
        self.assertNotIn("Already in the mailbox", page.get_text())


class NewsletterReview(Pages):
    def review(self, articles=_ARTICLES):
        today = datetime.date.today()
        item = {"uuid": "u1", "feed": "IT-ISAC Open Source News", "parser": "IT-ISAC Open Source News", "raw_email": "body"}
        queue = [{"uuid": "u1", "info": "[IT-ISAC] News 14", "date": (today - datetime.timedelta(days=31)).isoformat()},
                 {"uuid": "u2", "info": "[IT-ISAC] News 13", "date": (today - datetime.timedelta(days=32)).isoformat()}]
        parsed = {"articles": [dict(a) for a in articles], "report_title": "Open Source News", "tlp": "clear"}
        with mock.patch.object(misp_store, "get_newsletter_for_review", return_value=item), \
             mock.patch.object(misp_store, "list_pending_newsletters", return_value=queue), \
             mock.patch.object(newsletter_parsers, "parse", return_value=parsed):
            return self.page("/collection/newsletter/pending/u1")

    def test_a_newsletter_from_the_queue_is_a_record(self):
        hero = self.review().select_one("section.record-hero")
        self.assertEqual(hero.select_one("h1").get_text(strip=True), "News 14")
        self.assertIn("waiting 31 days", hero.select_one(".eyebrow").get_text(" ", strip=True))
        self.assertIn("TLP:CLEAR", hero.select_one(".hero-tlp").get_text())
        self.assertIsNotNone(hero.select_one('form[action="/collection/newsletter/pending/u1/ignore"]'))
        self.assertEqual(hero.select_one('button[form="review-form"]')["type"], "submit")

    def test_each_article_names_its_site_and_the_graded_ones_are_ticked(self):
        page = self.review()
        self.assertEqual([a["data-site"] for a in page.select("label.article")], ["thehackernews.com", "securityweek.com"])
        self.assertEqual([b["value"] for b in page.select('input[name="selected"]:checked')], ["0"])
        self.assertEqual([i["value"] for i in page.select(".site-filter input")], ["securityweek.com", "thehackernews.com"])

    def test_an_article_address_that_is_not_a_web_page_is_not_a_link(self):
        """The mail decides what an article's address is."""
        odd = dict(_ARTICLES[1], primary_url="javascript:alert(1)")
        page = self.review([_ARTICLES[0], odd])
        self.assertEqual([a["href"] for a in page.select("label.article .meta a")], ["https://www.thehackernews.com/a"])
        self.assertIn("javascript:alert(1)", page.select("label.article .meta")[1].get_text())

    def test_the_next_one_waiting_is_offered(self):
        header = next(h for h in self.review().select(".card-header") if "next one" in h.get_text())
        link = header.find_parent("div", class_="card").select_one("a")
        self.assertEqual(link["href"], "/collection/newsletter/pending/u2")


if __name__ == "__main__":
    unittest.main()
