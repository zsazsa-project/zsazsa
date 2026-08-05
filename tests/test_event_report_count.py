"""Tests for /api/event-report-count.

The briefing form asks for this once per story whose source event the collection
cache does not hold, so it has to answer the same number the cache would: live
reports only, and a plain zero when the event is gone.

    python -m unittest tests.test_event_report_count
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp.routes import api


def _report(name, deleted=False):
    return SimpleNamespace(name=name, content="content", deleted=deleted)


class EventReportCount(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()

    def post(self, **body):
        return self.client.post("/api/event-report-count", json=body)

    def test_counts_live_reports_only(self):
        event = SimpleNamespace(uuid="u", info="Event",
                                event_reports=[_report("Article"),
                                               _report("[AI-Summary] Event"),
                                               _report("Removed", deleted=True)])
        with mock.patch.object(api.misp_store, "resolve_source_event",
                               return_value=(event, None, "misp-intern")):
            reply = self.post(event_uuid="u", source_id="misp-intern")
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json(), {"count": 2, "error": None})

    def test_event_without_reports(self):
        event = SimpleNamespace(uuid="u", info="Event", event_reports=[])
        with mock.patch.object(api.misp_store, "resolve_source_event",
                               return_value=(event, None, "")):
            reply = self.post(event_uuid="u")
        self.assertEqual(reply.get_json()["count"], 0)

    def test_unknown_event(self):
        with mock.patch.object(api.misp_store, "resolve_source_event",
                               return_value=(None, None, "")):
            reply = self.post(event_uuid="u")
        self.assertEqual(reply.status_code, 404)
        self.assertEqual(reply.get_json()["count"], 0)

    def test_uuid_is_required(self):
        reply = self.post()
        self.assertEqual(reply.status_code, 400)


if __name__ == "__main__":
    unittest.main()
