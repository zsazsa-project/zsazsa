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


class Diagnosis(unittest.TestCase):
    """The two setups that break single sign-on, MISP naming its cookie something
    other than MISP-<uuid> and PHP not keeping sessions in Redis, are
    indistinguishable from the outside. The check has to tell them apart."""

    def setUp(self):
        patcher = mock.patch.object(misp_session, "_session_cookie_name",
                                    return_value="MISP-abc")
        patcher.start()
        self.addCleanup(patcher.stop)

    def diagnose(self, cookies, redis=None):
        redis = redis if redis is not None else mock.DEFAULT
        with mock.patch.object(misp_session, "_redis_get", redis), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            return misp_session.diagnose(cookies)

    def failed(self, result):
        return [c["label"] for c in result["checks"] if not c["ok"]]

    def detail(self, result, label):
        return next(c["detail"] for c in result["checks"] if c["label"] == label)

    def test_a_different_cookie_name_is_named_and_explained(self):
        result = self.diagnose({"CAKEPHP": "abc"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["Cookie sent by your browser"])
        self.assertIn("CAKEPHP", self.detail(result, "Cookie sent by your browser"))
        self.assertIn("MISP_SESSION_COOKIE_NAME", result["hint"])

    def test_nothing_writing_sessions_points_at_the_php_setting(self):
        with mock.patch.object(misp_session, "_holds_php_sessions", return_value=False):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("session.save_handler", result["hint"])

    def test_other_sessions_present_means_this_one_expired_not_misconfigured(self):
        """PHP writing sessions here and this cookie having none behind it look the
        same from one failed lookup, and want opposite fixes."""
        with mock.patch.object(misp_session, "_holds_php_sessions", return_value=True):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=None))
        self.assertEqual(self.failed(result), ["MISP session"])
        self.assertIn("does hold PHP sessions", self.detail(result, "MISP session"))
        self.assertIn("Log in to MISP again", result["hint"])
        self.assertNotIn("session.save_handler", result["hint"])

    def test_unreachable_redis_is_reported_as_such(self):
        # Redis being down fails the connection, which is what the check opens.
        with mock.patch.object(misp_session, "_redis_connect",
                               side_effect=OSError("connection refused")), \
             mock.patch.object(misp_session.config, "MISP_SESSION_COOKIE_NAME", ""):
            result = misp_session.diagnose({"MISP-abc": "sid"})
        self.assertEqual(self.failed(result), ["Session Redis"])
        self.assertIn("connection refused", self.detail(result, "Session Redis"))

    def test_a_working_setup_reports_the_user_and_no_hint(self):
        with mock.patch.object(misp_session, "get_misp_user",
                               return_value={"email": "analyst@misp.test"}):
            result = self.diagnose({"MISP-abc": "sid"}, redis=mock.Mock(return_value=b"x"))
        self.assertEqual(self.failed(result), [])
        self.assertIn("analyst@misp.test", self.detail(result, "MISP session"))
        self.assertEqual(result["hint"], "")

    def test_the_session_id_is_never_reported_back(self):
        """The cookie value is a live session. Naming it on a settings page would
        hand it to anyone who can read the response."""
        result = self.diagnose({"MISP-abc": "s3cr3t-session-id"},
                               redis=mock.Mock(return_value=None))
        self.assertNotIn("s3cr3t-session-id", repr(result))


class MissLogging(unittest.TestCase):
    def setUp(self):
        misp_session._warned_misses.clear()
        self.addCleanup(misp_session._warned_misses.clear)

    def load(self, cookies, sso_on=True):
        app = Flask(__name__)
        with app.test_request_context("/", headers={"Cookie": cookies}), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", sso_on), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
             mock.patch.object(misp_session, "get_misp_user", return_value=None), \
             self.assertLogs("webapp.misp_session", level="WARNING") as logs:
            misp_session.load_request_user()
            misp_session.load_request_user()
        return logs.output

    def test_a_missing_cookie_is_reported_once_with_what_was_sent(self):
        output = self.load("CAKEPHP=abc")
        self.assertEqual(len(output), 1, "warned on every request instead of once")
        self.assertIn("CAKEPHP", output[0])

    def test_nothing_is_logged_when_single_sign_on_is_off(self):
        app = Flask(__name__)
        with app.test_request_context("/", headers={"Cookie": "CAKEPHP=abc"}), \
             mock.patch.object(misp_session.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(misp_session, "_session_cookie_name", return_value="MISP-abc"), \
             mock.patch.object(misp_session, "get_misp_user", return_value=None):
            with self.assertNoLogs("webapp.misp_session", level="WARNING"):
                misp_session.load_request_user()


if __name__ == "__main__":
    unittest.main()
