"""The review queue: what it counts, how it sorts and groups, and ignoring an
entry or the ones of a newsletter that have waited too long.

The page is the only way an analyst sees what the IMAP collector archived, so a
newsletter dropping off it silently means nobody reviews that mail.

    python -m unittest tests.test_newsletter_pending_page
"""

import datetime
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
        links = self._page(query).select("tbody tr:not(.lane-head) a.title")
        return [a.get_text(strip=True) for a in links]

    def figures(self, page):
        return page.select_one("section.record-hero .record-kpis").get_text(" ", strip=True)

    def test_the_queue_says_how_many_are_waiting(self):
        self.assertIn("3 waiting for review", self.figures(self._page()))

    def test_one_newsletter_is_not_called_newsletters(self):
        with mock.patch.object(misp_store, "list_pending_newsletters",
                               return_value=[dict(_PENDING[0])]):
            figures = self.figures(self._page())
        self.assertIn("1 waiting for review", figures)
        self.assertIn("1 newsletter ", figures + " ")

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
        rows = self._page().select("tbody tr:not(.lane-head)")
        badges = [[b.get_text(strip=True) for b in row.select("span.badge")] for row in rows]
        self.assertEqual(badges, [[], ["no articles"], []])

    def test_both_columns_offer_a_sort(self):
        self.assertEqual([a.get_text(strip=True) for a in self._page().select("thead th a")],
                         ["Received", "Title"])

    def test_each_row_can_be_ignored(self):
        forms = self._page().select("tbody tr:not(.lane-head) form")
        self.assertEqual([f["action"] for f in forms],
                         [f"/collection/newsletter/pending/{n['uuid']}/ignore" for n in _PENDING])
        self.assertTrue(all(f.select_one('input[name="csrf_token"]') for f in forms))

    def test_the_subject_stays_out_of_the_confirmation(self):
        """A mail subject has quotes in it often enough to have broken out of the
        old onsubmit string, so the confirmation names no subject."""
        for form in self._page().select("form[data-submit-confirm]"):
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
        self.assertIn("No email sources are waiting for review", text)

    def test_the_queue_is_grouped_by_newsletter(self):
        """By the parser it was archived with, else by the list named in its subject."""
        pending = [{"uuid": "a", "info": "[zsazsa:newsletter] [IT-ISAC] Open Source News", "date": "2026-10-14"},
                   {"uuid": "b", "info": "[zsazsa:newsletter] [FIRST] ETDA of 12 October", "date": "2026-10-14",
                    "parser": "ETDA CTI Robot"},
                   {"uuid": "c", "info": "[zsazsa:newsletter] [IT-ISAC] Open Source News", "date": "2026-10-15"}]
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending):
            page = self._page()
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["IT-ISAC", "ETDA CTI Robot"])
        self.assertEqual([a.get_text() for a in page.select("a.title")],
                         ["Open Source News", "Open Source News", "ETDA of 12 October"])

    def test_the_queue_filters_on_newsletter_and_month(self):
        pending = [{"uuid": "a", "info": "[IT-ISAC] News", "date": "2026-10-14"},
                   {"uuid": "b", "info": "[FIRST] ETDA", "date": "2026-09-14", "parser": "ETDA CTI Robot"}]
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending):
            self.assertEqual(self._titles("?newsletter=ETDA+CTI+Robot"), ["ETDA"])
            self.assertEqual(self._titles("?month=2026-10"), ["News"])

    def test_how_long_each_has_waited(self):
        today = datetime.date.today()
        pending = [{"uuid": "a", "info": "News", "date": (today - datetime.timedelta(days=40)).isoformat()}]
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending):
            wait = self._page().select_one("tbody .wait")
        self.assertEqual(wait.get_text(strip=True), "40 days")
        self.assertIn("old", wait["class"])

    def test_ignoring_together_says_which_could_not_be(self):
        old = (datetime.date.today() - datetime.timedelta(days=90)).isoformat()
        pending = [{"uuid": "a", "info": "[IT-ISAC] One", "date": old}, {"uuid": "b", "info": "[IT-ISAC] Two", "date": old}]
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending), \
             mock.patch.object(misp_store, "ignore_newsletter", side_effect=[None, RuntimeError("Tag is locked")]), \
             mock.patch.object(data_collection.audit, "record") as record, \
             self.assertLogs("webapp.routes.data_collection", level="ERROR"):
            page = self.client.post("/collection/newsletter/pending/ignore-stale", follow_redirects=True,
                                    data={"csrf_token": "tok", "newsletter": "IT-ISAC"}).data.decode()
        self.assertEqual(record.call_count, 1)
        self.assertIn("1 of 2 IT-ISAC newsletters were taken out of the queue", page)

    def test_the_ones_of_a_newsletter_waiting_too_long_are_ignored_together(self):
        today = datetime.date.today()
        old = (today - datetime.timedelta(days=90)).isoformat()
        pending = [{"uuid": "a", "info": "[IT-ISAC] Old", "date": old},
                   {"uuid": "b", "info": "[IT-ISAC] New", "date": today.isoformat()},
                   {"uuid": "c", "info": "[FIRST] Old too", "date": old, "parser": "ETDA CTI Robot"}]
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending), \
             mock.patch.object(misp_store, "ignore_newsletter") as ignore, \
             mock.patch.object(data_collection.audit, "record") as record:
            reply = self.client.post("/collection/newsletter/pending/ignore-stale",
                                     data={"csrf_token": "tok", "newsletter": "IT-ISAC"})
        self.assertEqual(reply.status_code, 302)
        ignore.assert_called_once_with("a")
        self.assertEqual(record.call_args.kwargs["entity_id"], "a")

    def test_the_button_counts_what_it_takes_out_whatever_the_filter(self):
        """It takes out every one of the newsletter's that waited too long, so
        a month filter must not make it count fewer than it ignores."""
        today = datetime.date.today()
        pending = [{"uuid": "a", "info": "[IT-ISAC] One", "date": (today - datetime.timedelta(days=90)).isoformat()},
                   {"uuid": "b", "info": "[IT-ISAC] Two", "date": (today - datetime.timedelta(days=200)).isoformat()}]
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending):
            button = self._page(f"?month={pending[0]['date'][:7]}").select_one("form.lane-hint button")
        self.assertEqual(button.get_text(strip=True), "Ignore the 2 older than 60 days")

    def test_the_last_part_of_the_bar_is_what_the_button_takes_out(self):
        today = datetime.date.today()
        pending = [{"uuid": str(days), "info": "[IT-ISAC] News", "date": (today - datetime.timedelta(days=days)).isoformat()}
                   for days in (60, 61)]
        with mock.patch.object(misp_store, "list_pending_newsletters", return_value=pending):
            page = self._page()
        bar = page.select("section.record-hero .list-stats > div")[-1].select_one(".chart-legend")
        self.assertEqual(bar.get_text(" ", strip=True), "30 to 60 days 1 over 60 days 1")
        self.assertIn("Ignore the 1 older", page.select_one("form.lane-hint button").get_text())

    def test_ignoring_a_newsletter_with_nothing_old_ignores_nothing(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        with mock.patch.object(misp_store, "ignore_newsletter") as ignore:
            page = self.client.post("/collection/newsletter/pending/ignore-stale", follow_redirects=True,
                                    data={"csrf_token": "tok", "newsletter": ""}).data.decode()
        ignore.assert_not_called()
        self.assertIn("No such newsletters have waited longer than 60 days.", page)


if __name__ == "__main__":
    unittest.main()
