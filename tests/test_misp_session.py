"""Tests for how the MISP session cookie name is resolved.

The name is looked up from MISP when it is not in the config, and that lookup
sits in front of every request. An unreachable MISP must therefore be asked
again only now and then, not once per request.

    python -m unittest tests.test_misp_session
"""

import unittest
from unittest import mock

from flask import Flask, g

from webapp import misp_session


class CookieName(unittest.TestCase):
    def setUp(self):
        misp_session._cookie_name_cache.update({"value": "", "retry_after": 0.0})
        self.addCleanup(misp_session._cookie_name_cache.update,
                        {"value": "", "retry_after": 0.0})

    def _derive(self, result):
        patcher = mock.patch.object(misp_session, "derive_cookie_name",
                                    return_value=result)
        derive = patcher.start()
        self.addCleanup(patcher.stop)
        return derive

    def test_configured_name_is_used_without_asking_misp(self):
        derive = self._derive("MISP-from-server")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME",
                               "MISP-from-config"):
            self.assertEqual(misp_session._session_cookie_name(), "MISP-from-config")
        derive.assert_not_called()

    def test_derived_name_is_asked_once_and_kept(self):
        derive = self._derive("MISP-from-server")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            first = misp_session._session_cookie_name()
            second = misp_session._session_cookie_name()
        self.assertEqual([first, second], ["MISP-from-server"] * 2)
        self.assertEqual(derive.call_count, 1)

    def test_unreachable_misp_is_not_asked_again_until_the_window_passes(self):
        derive = self._derive("")
        with mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            self.assertEqual(misp_session._session_cookie_name(), "")
            misp_session._session_cookie_name()
            self.assertEqual(derive.call_count, 1)

            misp_session._cookie_name_cache["retry_after"] = 0.0
            misp_session._session_cookie_name()
            self.assertEqual(derive.call_count, 2)


class HostingInstance(unittest.TestCase):
    """Single sign-on belongs to the MISP zsazsa is served behind, which is the
    one it stores its data in. The misp-scraper instance is only polled, and is
    often a different server, so reading it sent analysts to a login page that
    was not theirs and looked for a session cookie that was never sent."""

    def setUp(self):
        self.split = [
            mock.patch.object(misp_session.config, "MISP_URL", "https://scraper.test"),
            mock.patch.object(misp_session.config, "MISP_KEY", "scraper-key"),
            mock.patch.object(misp_session.config, "MISP_WEBAPP_URL", "https://misp.test"),
            mock.patch.object(misp_session.config, "MISP_WEBAPP_KEY", "webapp-key"),
        ]
        for patcher in self.split:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_login_redirect_points_at_the_hosting_misp(self):
        app = Flask(__name__)
        with app.test_request_context("/"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            self.assertEqual(misp_session.login_redirect_url(),
                             "https://misp.test/users/login")

    def test_no_redirect_when_the_request_already_has_a_user(self):
        app = Flask(__name__)
        with app.test_request_context("/"), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            g.misp_user = {"email": "analyst@misp.test"}
            self.assertIsNone(misp_session.login_redirect_url())

    def test_cookie_name_is_derived_from_the_hosting_misp(self):
        with mock.patch("pymisp.PyMISP") as PyMISP:
            PyMISP.return_value.misp_instance_version = {"uuid": "abc"}
            self.assertEqual(misp_session.derive_cookie_name(), "MISP-abc")
        url, key = PyMISP.call_args.args[0], PyMISP.call_args.args[1]
        self.assertEqual((url, key), ("https://misp.test", "webapp-key"))


if __name__ == "__main__":
    unittest.main()
