"""The /api/rulezet-* routes the "Search Rulezet" buttons and the Detection
engineering request validation call.

Anything can be posted to these, not only what the forms send, so a malformed
body has to come back as a 400 with a reason rather than a 500, and only IDs of
the right shape are forwarded to Rulezet. The Rulezet client itself is patched
out; tests/test_rulezet_lookup.py covers it.

    python -m unittest tests.test_rulezet_api
"""

import unittest
from unittest import mock

from flask import Flask

from webapp import rate_limit
from webapp.routes import api


def _client():
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(api.bp, url_prefix="/api")
    return app.test_client()


class _Base(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        # The limiter is per process and these tests post far more than 20
        # times a minute from the same address.
        rate_limit._WINDOWS.clear()
        self.addCleanup(rate_limit._WINDOWS.clear)
        p = mock.patch.object(api.config, "RULEZET_URL", "https://rulezet.test", create=True)
        p.start()
        self.addCleanup(p.stop)


class NotConfigured(_Base):
    def test_every_route_says_so_and_asks_nothing(self):
        with mock.patch.object(api.config, "RULEZET_URL", ""), \
             mock.patch.object(api, "search_rules_by_cve") as by_cve, \
             mock.patch.object(api, "search_rules_by_attack") as by_attack, \
             mock.patch.object(api, "validate_rule") as validate:
            for path, body in (("/api/rulezet-lookup", {"cve_ids": ["CVE-2021-44228"]}),
                               ("/api/rulezet-attack-lookup", {"technique_ids": ["T1190"]}),
                               ("/api/rulezet-validate", {"format": "sigma", "content": "x"})):
                with self.subTest(path=path):
                    reply = self.client.post(path, json=body).get_json()
                    self.assertFalse(reply["ok"])
                    self.assertIn("not configured", reply["error"])
        by_cve.assert_not_called()
        by_attack.assert_not_called()
        validate.assert_not_called()


class MalformedBodies(_Base):
    def test_a_body_that_is_not_a_json_object_is_a_400(self):
        for path in ("/api/rulezet-lookup", "/api/rulezet-attack-lookup",
                     "/api/rulezet-validate", "/api/cve-lookup"):
            for data in ("not json", "[1, 2]"):
                with self.subTest(path=path, data=data):
                    reply = self.client.post(path, data=data, content_type="application/json")
                    self.assertEqual(reply.status_code, 400)

    def test_ids_that_are_not_a_list_of_strings_are_a_400_not_a_500(self):
        """A bare string used to be iterated a character at a time, and a
        number in the list reached .strip()."""
        for path, key in (("/api/rulezet-lookup", "cve_ids"),
                          ("/api/rulezet-attack-lookup", "technique_ids"),
                          ("/api/cve-lookup", "cve_ids")):
            for ids in ("CVE-2021-44228", ["CVE-2021-44228", 3], [None], {"a": "b"}, 7):
                with self.subTest(path=path, ids=ids):
                    reply = self.client.post(path, json={key: ids})
                    self.assertEqual(reply.status_code, 400)
                    self.assertIn("list of strings", reply.get_json()["error"])

    def test_a_format_or_content_that_is_not_a_string_is_a_400(self):
        for body in ({"format": ["sigma"], "content": "x"}, {"format": "sigma", "content": 3}):
            with self.subTest(body=body):
                self.assertEqual(self.client.post("/api/rulezet-validate", json=body).status_code, 400)


class CveLookup(_Base):
    def _lookup(self, ids):
        with mock.patch.object(api, "search_rules_by_cve", return_value=[]) as search:
            reply = self.client.post("/api/rulezet-lookup", json={"cve_ids": ids})
        return reply, search

    def test_only_cve_ids_are_forwarded_normalised(self):
        _reply, search = self._lookup([" cve-2021-44228 ", "not-a-cve", ""])
        search.assert_called_once_with(["CVE-2021-44228"])

    def test_at_most_ten_are_forwarded(self):
        _reply, search = self._lookup([f"CVE-2024-{n:04d}" for n in range(15)])
        self.assertEqual(len(search.call_args[0][0]), 10)

    def test_no_valid_id_asks_rulezet_nothing(self):
        reply, search = self._lookup(["T1190"])
        self.assertFalse(reply.get_json()["ok"])
        search.assert_not_called()


class AttackLookup(_Base):
    def _lookup(self, ids):
        with mock.patch.object(api, "search_rules_by_attack", return_value=[]) as search:
            reply = self.client.post("/api/rulezet-attack-lookup", json={"technique_ids": ids})
        return reply, search

    def test_only_whole_technique_ids_are_forwarded(self):
        _reply, search = self._lookup(["t1190", "T1566.001", "T1566.1", "T12345",
                                       "xT1190", "T1190 ; drop", "CVE-2021-44228"])
        search.assert_called_once_with(["T1190", "T1566.001"])

    def test_at_most_twenty_are_forwarded(self):
        _reply, search = self._lookup([f"T{1000 + n}" for n in range(30)])
        self.assertEqual(len(search.call_args[0][0]), 20)

    def test_no_valid_id_asks_rulezet_nothing(self):
        reply, search = self._lookup(["phishing"])
        self.assertFalse(reply.get_json()["ok"])
        search.assert_not_called()


class Validate(_Base):
    def _validate(self, result, body=None):
        with mock.patch.object(api, "validate_rule", return_value=result) as validate:
            reply = self.client.post("/api/rulezet-validate",
                                     json=body or {"format": "sigma", "content": "title: x"})
        return reply.get_json(), validate

    def test_a_verdict_is_passed_through(self):
        reply, _ = self._validate({"valid": True, "errors": [], "warnings": ["w"]})
        self.assertEqual(reply, {"ok": True, "valid": True, "errors": [], "warnings": ["w"]})

    def test_rulezets_error_is_passed_through(self):
        reply, _ = self._validate({"error": "Unknown format"})
        self.assertEqual(reply, {"ok": False, "error": "Unknown format"})

    def test_unreachable_says_so(self):
        reply, _ = self._validate(None)
        self.assertEqual(reply, {"ok": False, "error": "Rulezet is unreachable."})

    def test_a_missing_format_or_content_asks_rulezet_nothing(self):
        for body in ({"format": "", "content": "x"}, {"format": "sigma", "content": "  "}):
            with self.subTest(body=body):
                reply, validate = self._validate(None, body)
                self.assertFalse(reply["ok"])
                validate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
