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
        counts = {"published": 1, "failed": 0, "no_subscriber": 0}
        with mock.patch.object(data_collection.misp_store, "create_newsletter_event") as archive, \
             mock.patch.object(data_collection.newsletter_ingest, "publish_articles",
                               return_value=counts) as publish, \
             mock.patch.object(data_collection.audit, "record"):
            self.post("IT-ISAC Open Source News")
        self.assertEqual(archive.call_args.args[0], "IT-ISAC Open Source News")
        self.assertEqual(publish.call_args.args[1],
                         [{"url": "https://example.org/article", "title": "A story",
                           "section": "", "priority": ""}])


if __name__ == "__main__":
    unittest.main()
