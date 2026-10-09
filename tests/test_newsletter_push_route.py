"""Tests for the push step of the newsletter importer.

The review screen posts back the newsletter it was parsed with in a hidden
field, and that name is what the archived event is attributed to and what the
scraper is told the articles came from. It has to be one we actually parse.

    python -m unittest tests.test_newsletter_push_route
"""

import unittest
from unittest import mock

from flask import Flask

from webapp.routes import data_collection


class Push(unittest.TestCase):
    def setUp(self):
        # The links count as public without a DNS lookup.
        patcher = mock.patch.object(data_collection.newsletter_ingest, "is_safe_public_url", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def post(self, source):
        return self.client.post("/collection/newsletter/new", data={
            "action": "push", "source": source, "raw": "the e-mail",
            "selected": "0", "url-0": "https://example.org/article", "title-0": "A story",
        })

    def test_an_unknown_newsletter_is_neither_archived_nor_pushed(self):
        with mock.patch.object(data_collection.misp_store, "create_newsletter_event") as archive, \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles") as publish:
            response = self.post("Made Up Newsletter")
        self.assertEqual(response.status_code, 302)
        archive.assert_not_called()
        publish.assert_not_called()

    def test_a_registered_newsletter_is_archived_and_pushed(self):
        counts = {"published": 1, "failed": 0, "no_subscriber": 0, "refused": 0}
        with mock.patch.object(data_collection.misp_store, "create_newsletter_event") as archive, \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles",
                               return_value=counts) as publish, \
             mock.patch.object(data_collection.audit, "record"):
            self.post("IT-ISAC Open Source News")
        self.assertEqual(archive.call_args.args[0], "IT-ISAC Open Source News")
        self.assertEqual(publish.call_args.args[1],
                         [{"url": "https://example.org/article", "title": "A story",
                           "section": "", "priority": ""}])

    def test_links_that_were_all_refused_are_not_blamed_on_redis(self):
        counts = {"published": 0, "failed": 0, "no_subscriber": 0, "refused": 1}
        with mock.patch.object(data_collection.misp_store, "create_newsletter_event"), \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles", return_value=counts), \
             mock.patch.object(data_collection.audit, "record"):
            response = self.post("IT-ISAC Open Source News")
            with self.client.session_transaction() as session:
                messages = [m for _cat, m in session.get("_flashes", [])]
        self.assertEqual(response.status_code, 302)
        self.assertTrue(any("only given public web addresses" in m for m in messages), messages)
        self.assertFalse(any("Redis" in m for m in messages), messages)

    def test_a_redis_failure_is_not_hidden_by_a_refused_link(self):
        counts = {"published": 0, "failed": 1, "no_subscriber": 0, "refused": 1}
        with mock.patch.object(data_collection.misp_store, "create_newsletter_event"), \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles", return_value=counts), \
             mock.patch.object(data_collection.audit, "record"):
            self.post("IT-ISAC Open Source News")
            with self.client.session_transaction() as session:
                messages = [m for _cat, m in session.get("_flashes", [])]
        self.assertTrue(any("Redis" in m for m in messages), messages)
        self.assertTrue(any("only given public web addresses" in m for m in messages), messages)

    def test_pending_review_reports_redis_and_refusal_together(self):
        counts = {"published": 0, "failed": 1, "no_subscriber": 0, "refused": 1}
        item = {"uuid": "u1", "feed": "IT-ISAC Open Source News"}
        with mock.patch.object(data_collection.misp_store, "get_newsletter_for_review", return_value=item), \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles", return_value=counts), \
             mock.patch.object(data_collection.misp_store, "finalize_newsletter"), \
             mock.patch.object(data_collection.audit, "record"):
            self.client.post("/collection/newsletter/pending/u1", data={
                "selected": "0", "url-0": "https://example.org/article", "title-0": "Story",
            })
            with self.client.session_transaction() as session:
                messages = [m for _cat, m in session.get("_flashes", [])]
        self.assertTrue(any("Redis" in m for m in messages), messages)
        self.assertTrue(any("only given public web addresses" in m for m in messages), messages)


if __name__ == "__main__":
    unittest.main()
