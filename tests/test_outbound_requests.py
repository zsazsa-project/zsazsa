"""What zsazsa sends to a MISP server from a settings page (GHSA-24wh-h52p-fcgg).

The settings pages connect to MISP servers an admin enters, which are internal
by design, so their addresses are not filtered. Two things still are: a failed
connection test answers with a fixed message, never the server's own response,
which could be any host the URL redirects to; and an organisation lookup keeps
the TLS verification stored for that server, never switching it off.

    python -m unittest tests.test_outbound_requests
"""

import unittest
from unittest import mock

import requests
from flask import Flask
from pymisp.exceptions import PyMISPError

import config
from webapp import misp_store
from webapp.routes import config_page

MARKER = "secret-from-an-internal-service"


class ConnectionTest(unittest.TestCase):
    def failure(self, exc):
        with mock.patch.object(misp_store, "PyMISP", side_effect=exc):
            return misp_store._test_connection("https://misp.example.org", "key", True)

    def test_the_servers_response_is_never_passed_on(self):
        with self.assertLogs(misp_store.logger, level="WARNING") as captured:
            result = self.failure(PyMISPError(f"Unable to connect to MISP: <html>{MARKER}</html>"))
        self.assertFalse(result["ok"])
        self.assertNotIn(MARKER, result["error"])
        self.assertNotIn(MARKER, " ".join(captured.output))

    def test_the_kind_of_failure_is_still_named(self):
        cases = {
            requests.exceptions.SSLError(MARKER): "TLS certificate",
            requests.exceptions.ConnectTimeout(MARKER): "did not answer in time",
            requests.exceptions.ConnectionError(MARKER): "Could not connect",
        }
        for exc, expected in cases.items():
            with self.subTest(exc=type(exc).__name__):
                error = self.failure(exc)["error"]
                self.assertIn(expected, error)
                self.assertNotIn(MARKER, error)


class OrganisationLookup(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()
        servers = [{"url": "https://partner.example.org", "api_key": "pk", "verify_tls": False}]
        for patcher in (
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
            mock.patch.multiple(config, create=True, MISP_SERVERS=servers,
                                MISP_WEBAPP_URL="https://misp.example.org", MISP_WEBAPP_KEY="wk",
                                MISP_WEBAPP_VERIFYCERT=True, MISP_URL="", MISP_KEY=""),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def verify_used_for(self, url):
        with mock.patch("pymisp.PyMISP") as pymisp:
            org = mock.Mock()
            org.name = "Example Organisation"
            pymisp.return_value.get_organisation.return_value = org
            response = self.client.post(
                "/config/sources/lookup-org",
                json={"uuid": "o" * 36, "misp_url": url, "misp_key": "k"},
            )
        self.assertEqual(response.get_json(), {"name": "Example Organisation", "error": None})
        return pymisp.call_args_list[0].args[2]

    def test_an_unknown_url_is_contacted_with_verification_on(self):
        self.assertIs(self.verify_used_for("https://unknown.example.org"), True)

    def test_a_configured_server_keeps_its_own_setting(self):
        self.assertIs(self.verify_used_for("https://partner.example.org/"), False)
        self.assertIs(self.verify_used_for("https://misp.example.org"), True)


if __name__ == "__main__":
    unittest.main()
