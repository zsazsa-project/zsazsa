"""The Rulezet client in core.rulezet_lookup.

Rulezet is optional enrichment, so what matters is that nothing it answers can
break a form: an empty RULEZET_URL makes no request at all, and a Rulezet that
is down, slow or answers with something unexpected is an empty result rather
than an exception. No network access: requests is patched throughout.

    python -m unittest tests.test_rulezet_lookup
"""

import unittest
from unittest import mock

import requests

from core import rulezet_lookup


def _response(status=200, json_data=None, text_only=False):
    """A requests.Response stand-in. text_only: the body is not JSON (an HTML
    error page from a proxy), so .json() raises like the real one does."""
    r = mock.Mock(status_code=status)
    if text_only:
        r.json.side_effect = ValueError("Expecting value")
    else:
        r.json.return_value = json_data
    return r


_ITEM = {"id": 7, "uuid": "u-7", "title": "Log4Shell JNDI lookup", "format": "sigma",
         "cve_id": '["CVE-2021-44228"]', "matched_techniques": ["T1190"],
         "to_string": "title: x", "detail_url": "https://rulezet.org/rule/detail_rule/7"}


_DETAIL = {"id": 740025, "title": "know_attacker_arp_poison.execve.detection",
           "format": "kunai", "license": "GPL-3.0", "cve_id": "[]",
           "source": "https://github.com/digisquad-repo/kunai-rules",
           "original_uuid": "know_attacker_arp_poison.execve.detection",
           "to_string": "name: arp poison\n", "user": {"first_name": "Benjamin",
                                                       "last_name": "Collas"}}


class GetRule(unittest.TestCase):
    """get_rule() reads one rule back for a product that only stored its link."""

    def setUp(self):
        for p in (mock.patch.object(rulezet_lookup._cfg, "RULEZET_URL",
                                    "https://rulezet.test/", create=True),
                  mock.patch.object(rulezet_lookup, "logger")):
            p.start()
            self.addCleanup(p.stop)

    def test_a_rule_comes_back_in_the_shape_the_viewer_expects(self):
        with mock.patch.object(requests, "get",
                               return_value=_response(json_data=_DETAIL)) as get:
            rule = rulezet_lookup.get_rule("740025")
        self.assertEqual(get.call_args.args[0],
                         "https://rulezet.test/api/rule/public/detail/740025")
        self.assertEqual(rule["title"], "know_attacker_arp_poison.execve.detection")
        self.assertEqual(rule["content"], "name: arp poison\n")
        self.assertEqual(rule["author"], "Benjamin Collas")
        self.assertEqual(rule["url"], "https://rulezet.test/rule/detail_rule/740025")

    def test_the_fields_the_detail_endpoint_does_not_carry_are_left_empty(self):
        """The viewer skips an empty field, so they simply do not show rather
        than appearing with a made-up value."""
        with mock.patch.object(requests, "get", return_value=_response(json_data=_DETAIL)):
            rule = rulezet_lookup.get_rule("740025")
        self.assertEqual(rule["uuid"], "")
        self.assertEqual(rule["last_modif"], "")
        self.assertIsNone(rule["quality_score"])
        self.assertEqual(rule["matched_techniques"], [])

    def test_a_record_whose_name_fields_are_not_strings_is_still_a_rule(self):
        """Rulezet is a community instance and a record can carry anything. A
        number where a name belongs used to raise a TypeError out of the module
        and reach the analyst as a bare 500 instead of a rule."""
        for user in ({"first_name": 87, "last_name": "Collas"},
                     {"first_name": "B", "last_name": ["a"]},
                     {"first_name": None, "last_name": None},
                     "not a dict",
                     None):
            with mock.patch.object(requests, "get",
                                   return_value=_response(json_data=dict(_DETAIL, user=user))):
                rule = rulezet_lookup.get_rule("740025")
            self.assertIsInstance(rule, dict)
            self.assertIsInstance(rule["author"], str)

    def test_an_author_on_the_record_survives_an_account_with_no_name(self):
        """The submitting account is the usual attribution, but a record that
        names its author kept it in the search results and lost it here."""
        for user in (None, {}, {"first_name": "", "last_name": ""}):
            item = dict(_DETAIL, author="Florian Roth", user=user)
            with mock.patch.object(requests, "get", return_value=_response(json_data=item)):
                self.assertEqual(rulezet_lookup.get_rule("740025")["author"], "Florian Roth")

    def test_an_id_that_is_not_a_number_asks_rulezet_nothing(self):
        """The id goes into the path of the URL called on the Rulezet side."""
        with mock.patch.object(requests, "get") as get:
            for bad in ("", "  ", "7/../../admin", "abc", None):
                self.assertIsNone(rulezet_lookup.get_rule(bad))
            get.assert_not_called()

    def test_anything_other_than_a_rule_is_none_rather_than_an_exception(self):
        for reply in (_response(status=404),
                      _response(status=500),
                      _response(text_only=True),
                      _response(json_data=[]),
                      _response(json_data={"detail": "gone"})):
            with mock.patch.object(requests, "get", return_value=reply):
                self.assertIsNone(rulezet_lookup.get_rule("740025"))

    def test_an_unreachable_rulezet_is_none(self):
        with mock.patch.object(requests, "get",
                               side_effect=requests.RequestException("boom")):
            self.assertIsNone(rulezet_lookup.get_rule("740025"))

    def test_without_a_url_configured_nothing_is_asked(self):
        with mock.patch.object(rulezet_lookup._cfg, "RULEZET_URL", ""), \
             mock.patch.object(requests, "get") as get:
            self.assertIsNone(rulezet_lookup.get_rule("740025"))
            get.assert_not_called()


class Configured(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(rulezet_lookup._cfg, "RULEZET_URL", "https://rulezet.test/", create=True),
                  mock.patch.object(rulezet_lookup, "logger")):
            self.logger = p.start()
            self.addCleanup(p.stop)

    def _search(self, response):
        with mock.patch.object(rulezet_lookup.requests, "get", return_value=response) as get:
            return rulezet_lookup.search_rules_by_cve(["CVE-2021-44228"]), get

    def test_a_rule_is_returned_with_its_url_rebuilt_from_the_configured_base(self):
        rules, get = self._search(_response(json_data={"results": [_ITEM]}))
        self.assertEqual(get.call_args[0][0],
                         "https://rulezet.test/api/rule/public/search_rules_by_cve")
        self.assertEqual(rules[0]["url"], "https://rulezet.test/rule/detail_rule/7")
        self.assertEqual(rules[0]["cve_ids"], ["CVE-2021-44228"])
        self.assertEqual(rules[0]["matched_techniques"], ["T1190"])

    def test_the_rule_id_is_quoted_into_the_url(self):
        rules, _ = self._search(_response(json_data={"results": [dict(_ITEM, id="../admin?x=1")]}))
        self.assertEqual(rules[0]["url"], "https://rulezet.test/rule/detail_rule/..%2Fadmin%3Fx%3D1")

    def test_a_non_200_is_no_rules_and_its_status_is_logged(self):
        self.assertEqual(self._search(_response(status=502, text_only=True))[0], [])
        self.assertIn(502, self.logger.warning.call_args[0])

    def test_a_timeout_is_no_rules(self):
        with mock.patch.object(rulezet_lookup.requests, "get", side_effect=requests.Timeout("slow")):
            self.assertEqual(rulezet_lookup.search_rules_by_attack(["T1190"]), [])

    def test_a_body_that_is_not_json_is_no_rules(self):
        self.assertEqual(self._search(_response(text_only=True))[0], [])

    def test_json_that_is_not_an_object_is_no_rules(self):
        for body in ([], ["a", "b"], "results", 3, {"results": "nope"}):
            with self.subTest(body=body):
                self.assertEqual(self._search(_response(json_data=body))[0], [])

    def test_results_that_are_not_objects_are_skipped(self):
        rules, _ = self._search(_response(json_data={"results": ["x", 3, _ITEM]}))
        self.assertEqual([r["id"] for r in rules], [7])

    def test_match_lists_of_the_wrong_type_are_dropped(self):
        rules, _ = self._search(_response(json_data={"results": [
            dict(_ITEM, cve_id={"a": 1}, matched_techniques="T1190")]}))
        self.assertEqual(rules[0]["cve_ids"], [])
        self.assertEqual(rules[0]["matched_techniques"], ["T1190"])


class Validate(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(rulezet_lookup._cfg, "RULEZET_URL", "https://rulezet.test", create=True),
                  mock.patch.object(rulezet_lookup, "logger")):
            p.start()
            self.addCleanup(p.stop)

    def _validate(self, response):
        with mock.patch.object(rulezet_lookup.requests, "post", return_value=response):
            return rulezet_lookup.validate_rule("sigma", "title: x")

    def test_a_verdict_comes_back_as_is(self):
        self.assertEqual(
            self._validate(_response(json_data={"valid": False, "errors": ["bad"], "warnings": []})),
            {"valid": False, "errors": ["bad"], "warnings": []},
        )

    def test_a_4xx_carries_rulezets_own_error(self):
        self.assertEqual(self._validate(_response(status=400, json_data={"error": "Unknown format"})),
                         {"error": "Unknown format"})

    def test_an_html_5xx_is_an_error_not_unreachable(self):
        """None would tell the analyst Rulezet is unreachable, which sends them
        to the configuration when the instance is up and failing."""
        self.assertEqual(self._validate(_response(status=503, text_only=True)),
                         {"error": "Rulezet returned HTTP 503"})

    def test_a_200_without_a_verdict_is_an_error(self):
        self.assertIn("error", self._validate(_response(json_data=["valid"])))

    def test_unreachable_is_none(self):
        with mock.patch.object(rulezet_lookup.requests, "post",
                               side_effect=requests.ConnectionError("refused")):
            self.assertIsNone(rulezet_lookup.validate_rule("sigma", "title: x"))


class NotConfigured(unittest.TestCase):
    def test_nothing_is_requested(self):
        with mock.patch.object(rulezet_lookup._cfg, "RULEZET_URL", "", create=True), \
             mock.patch.object(rulezet_lookup.requests, "get") as get, \
             mock.patch.object(rulezet_lookup.requests, "post") as post:
            self.assertEqual(rulezet_lookup.search_rules_by_cve(["CVE-2021-44228"]), [])
            self.assertEqual(rulezet_lookup.search_rules_by_attack(["T1190"]), [])
            self.assertIsNone(rulezet_lookup.validate_rule("sigma", "title: x"))
        get.assert_not_called()
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
