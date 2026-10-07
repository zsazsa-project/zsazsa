"""The review queue: what it counts, how it sorts, and ignoring an entry.

The page is the only way an analyst sees what the IMAP collector archived, so a
newsletter dropping off it silently means nobody reviews that mail.

    python -m unittest tests.test_newsletter_pending_page
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import data_collection

_PENDING = [
    {"uuid": "u1", "info": "Zebra weekly", "date": "2026-01-05"},
    {"uuid": "u2", "info": "apple digest", "date": "2026-03-09", "empty": True},
    {"uuid": "u3", "info": "Middle report", "date": "2026-02-02"},
]


class PendingQueue(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(collection_cache, "start_worker"),
            # Off, or a developer who runs single sign-on gets a 302 per request.
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(misp_store, "list_pending_newsletters",
                              side_effect=lambda: list(_PENDING)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = create_app().test_client()

    def _page(self, query=""):
        return BeautifulSoup(self.client.get("/collection/newsletter/pending" + query).data,
                             "html.parser")

    def _titles(self, query=""):
        links = self._page(query).select("tbody tr td:first-child a")
        return [a.get_text(strip=True) for a in links]

    def test_the_queue_says_how_many_are_waiting(self):
        self.assertIn("3 sources", self._page().get_text())

    def test_one_waiting_is_not_called_sources(self):
        with mock.patch.object(misp_store, "list_pending_newsletters",
                               return_value=[dict(_PENDING[0])]):
            self.assertIn("1 source", self._page().get_text())

    def test_without_a_sort_the_order_it_arrives_in_is_kept(self):
        # list_pending_newsletters already hands them over newest first.
        self.assertEqual(self._titles(), ["Zebra weekly", "apple digest", "Middle report"])

    def test_sorting_by_title_ignores_case(self):
        self.assertEqual(self._titles("?sort=title&dir=asc"),
                         ["apple digest", "Middle report", "Zebra weekly"])
        self.assertEqual(self._titles("?sort=title&dir=desc"),
                         ["Zebra weekly", "Middle report", "apple digest"])

    def test_sorting_by_date(self):
        self.assertEqual(self._titles("?sort=date&dir=asc"),
                         ["Zebra weekly", "Middle report", "apple digest"])

    def test_an_unknown_sort_key_leaves_the_order_alone(self):
        self.assertEqual(self._titles("?sort=nonsense&dir=asc"), self._titles())

    def test_a_newsletter_with_no_articles_is_marked_as_such(self):
        # Otherwise the only sign is an empty review page, which reads as a bug
        # in the page rather than as a mail the parser made nothing of.
        rows = self._page().select("tbody tr")
        badges = [[b.get_text(strip=True) for b in row.select("span.badge")] for row in rows]
        self.assertEqual(badges, [[], ["no articles"], []])

    def test_both_columns_offer_a_sort(self):
        self.assertEqual([a.get_text(strip=True) for a in self._page().select("thead th a")],
                         ["Title", "Date"])

    def test_each_row_can_be_ignored(self):
        forms = self._page().select("tbody tr form")
        self.assertEqual([f["action"] for f in forms],
                         [f"/collection/newsletter/pending/{n['uuid']}/ignore" for n in _PENDING])
        self.assertTrue(all(f.select_one('input[name="csrf_token"]') for f in forms))

    def test_the_subject_stays_out_of_the_confirmation(self):
        """A mail subject carries quotes often enough to have broken out of the
        old onsubmit string, so the confirmation names no subject."""
        form = self._page().select_one("tbody tr form")
        self.assertNotIn("Zebra weekly", form["data-submit-confirm"])

    def _ignore(self, uuid="u1", data=None, **over):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        form = {"csrf_token": "tok"}
        form.update(data or {})
        return self.client.post(f"/collection/newsletter/pending/{uuid}/ignore",
                                data=form, **over)

    def test_ignoring_untags_the_event_and_returns_to_the_queue(self):
        with mock.patch.object(misp_store, "ignore_newsletter") as ignore, \
             mock.patch.object(data_collection.audit, "record") as record:
            response = self._ignore()
        ignore.assert_called_once_with("u1")
        self.assertEqual(record.call_args.args[:2], ("ignore", "newsletter-import"))
        self.assertEqual(record.call_args.kwargs["entity_label"], "Zebra weekly")
        self.assertEqual(response.headers["Location"], "/collection/newsletter/pending")

    def test_the_subject_it_records_comes_from_misp_not_from_the_post(self):
        """Nothing the browser sends decides what the audit trail says: no other
        route in the application takes its label from the form either."""
        with mock.patch.object(misp_store, "ignore_newsletter"), \
             mock.patch.object(data_collection.audit, "record") as record:
            self._ignore(data={"label": "something else"})
        self.assertEqual(record.call_args.kwargs["entity_label"], "Zebra weekly")

    def test_a_newsletter_the_queue_no_longer_lists_falls_back_to_its_uuid(self):
        with mock.patch.object(misp_store, "ignore_newsletter"), \
             mock.patch.object(data_collection.audit, "record") as record:
            self._ignore(uuid="gone")
        self.assertEqual(record.call_args.kwargs["entity_label"], "gone")

    def test_a_refused_ignore_says_so_instead_of_looking_done(self):
        with mock.patch.object(misp_store, "ignore_newsletter",
                               side_effect=RuntimeError("Tag is locked")):
            page = self._ignore(follow_redirects=True).data.decode()
        self.assertIn("Could not ignore Zebra weekly", page)

    def test_a_mail_with_no_articles_says_so_instead_of_an_empty_form(self):
        # The review page is the parse, so a mail it recognises nothing in would
        # otherwise be a form with no rows and a send button that does nothing.
        item = {"uuid": "u1", "feed": "ETDA", "parser": "ETDA CTI Robot",
                "raw_email": "Subject: nothing this parser recognises\n"}
        with mock.patch.object(misp_store, "get_newsletter_for_review", return_value=item):
            page = BeautifulSoup(self.client.get("/collection/newsletter/pending/u1").data,
                                 "html.parser")
        self.assertIn("No articles were found in this e-mail", page.get_text())
        self.assertEqual(page.select('input[name="selected"]'), [])

    def test_review_from_the_queue_offers_the_way_back_to_it(self):
        # Reached from the queue rather than from the paste box, so "Paste
        # another" would send the analyst somewhere they have not been.
        item = {"uuid": "u1", "feed": "ETDA", "parser": "ETDA CTI Robot", "raw_email": "body"}
        with mock.patch.object(misp_store, "get_newsletter_for_review", return_value=item):
            page = BeautifulSoup(self.client.get("/collection/newsletter/pending/u1").data,
                                 "html.parser")
        links = {a.get_text(strip=True): a["href"] for a in page.select("a.btn")}
        self.assertEqual(links.get("Back to email sources"), "/collection/newsletter/pending")
        self.assertEqual(links.get("Cancel"), "/collection/newsletter/pending")
        self.assertNotIn("Paste another", links)

    def test_an_empty_queue_says_so(self):
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=[]):
            text = self._page().get_text()
        self.assertIn("0 sources", text)
        self.assertIn("No email sources are waiting for review", text)


if __name__ == "__main__":
    unittest.main()
