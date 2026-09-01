"""SSRF guard tests for Flowintel outbound requests and notification pings.

Covers the shared `core.net_safety.is_safe_public_url` guard applied to:
  - every `core.flowintel_client` function that issues an HTTP request,
  - `webapp.routes.config_page.ping_notification_channel` (webhook test), and
  - `webapp.routes.config_page.test_flowintel_connection`.

    python -m unittest tests.test_flowintel_ssrf
"""

import unittest
from unittest import mock

from flask import Flask

from core import flowintel_client
from webapp.routes import config_page

_PRIVATE_URLS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:6379/",
    "http://localhost/",
    "http://10.0.0.5/",
    "http://192.168.1.10/",
    "http://169.254.169.254/latest/meta-data/",
]


class FlowintelClientRejectsPrivateUrls(unittest.TestCase):
    """Every direct-request function must reject a private/loopback URL before
    calling requests.* at all."""

    def setUp(self):
        patcher = mock.patch.object(flowintel_client, "requests")
        self.requests = patcher.start()
        self.addCleanup(patcher.stop)

    def test_test_connection(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.test_connection(url, "key")
            self.assertFalse(result["ok"], url)
        self.requests.get.assert_not_called()

    def test_get_case_templates(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.get_case_templates(url, "key")
            self.assertFalse(result["ok"], url)
        self.requests.get.assert_not_called()

    def test_create_case_from_template(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.create_case_from_template(url, "key", "1", "title")
            self.assertFalse(result["ok"], url)
        self.requests.post.assert_not_called()

    def test_append_case_note(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.append_case_note(url, "key", "1", "note")
            self.assertFalse(result["ok"], url)
        self.requests.post.assert_not_called()

    def test_find_task_by_title(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.find_task_by_title(url, "key", "1", "title")
            self.assertFalse(result["ok"], url)
        self.requests.get.assert_not_called()

    def test_get_case_template_tasks(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.get_case_template_tasks(url, "key", "1")
            self.assertFalse(result["ok"], url)
        self.requests.get.assert_not_called()

    def test_add_case_tags(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.add_case_tags(url, "key", "1", ["tlp:amber"])
            self.assertFalse(result["ok"], url)
        self.requests.post.assert_not_called()

    def test_add_task_note(self):
        for url in _PRIVATE_URLS:
            result = flowintel_client.add_task_note(url, "key", "1", "note")
            self.assertFalse(result["ok"], url)
        self.requests.post.assert_not_called()

    def test_add_vulnerability_object_delegates_the_guard(self):
        """add_vulnerability_object funnels through _create_misp_object, so it
        is protected transitively without its own check."""
        for url in _PRIVATE_URLS:
            result = flowintel_client.add_vulnerability_object(url, "key", "1", cve_ids=["CVE-2024-0001"])
            self.assertFalse(result["ok"], url)
        self.requests.post.assert_not_called()

    def test_create_case_from_product_delegates_the_guard(self):
        instance = {
            "id": "test", "name": "Test", "url": "http://169.254.169.254/", "api_key": "key",
            "case_templates": {"Flash intel alert": {"enabled": True, "template_id": "1"}},
        }
        result = flowintel_client.create_case_from_product(instance, "Flash intel alert", "title")
        self.assertFalse(result["ok"])
        self.requests.post.assert_not_called()


class PingNotificationChannelRejectsPrivateUrls(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        patcher = mock.patch.object(config_page, "requests")
        self.requests = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_private_webhook_url_is_rejected_before_posting(self):
        channels = [{"id": "chan1", "type": "mattermost", "url": "http://169.254.169.254/latest/meta-data/"}]
        with mock.patch.object(config_page, "_read_notification_channels", return_value=channels):
            resp = self.client.post("/config/ping-notification-channel", json={"channel_id": "chan1"})
        self.assertEqual(resp.get_json()["ok"], False)
        self.requests.post.assert_not_called()


class FlowintelConnectionRouteRejectsPrivateUrls(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        patcher = mock.patch.object(flowintel_client, "requests")
        self.requests = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_private_instance_url_is_rejected_before_connecting(self):
        resp = self.client.post(
            "/config/test-flowintel-connection",
            json={"url": "http://127.0.0.1/", "api_key": "key"},
        )
        self.assertEqual(resp.get_json()["ok"], False)
        self.requests.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
