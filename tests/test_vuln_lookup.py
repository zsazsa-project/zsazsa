"""What reaches the CIRCL vulnerability API, and what is turned away first.

The CVE ID goes into the URL path, so a value that is not one steers the
request somewhere else on that host. The route that feeds this only checks that
the string starts with "CVE-", so the check belongs here, where both callers
pass through.

The same pattern pulls CVE IDs out of event titles elsewhere. It has to keep
doing both jobs: matching inside a sentence, and matching a whole string and
nothing more.

    python -m unittest tests.test_vuln_lookup
"""

import unittest
from unittest import mock

from core import vuln_lookup
from core.vuln_lookup import CVE_RE


class Rejected(unittest.TestCase):
    """Nothing malformed should reach requests.get at all."""

    def fetch(self, cve_id):
        with mock.patch.object(vuln_lookup.requests, "get") as get:
            result = vuln_lookup.fetch_cve_info(cve_id)
        return result, get

    def test_a_traversal_never_becomes_a_request(self):
        for cve_id in ("CVE-../../admin", "CVE-2024-1234/../../x", "CVE-2024-1234/.."):
            result, get = self.fetch(cve_id)
            self.assertEqual(result, {}, cve_id)
            get.assert_not_called()

    def test_url_punctuation_is_not_part_of_a_cve_id(self):
        for cve_id in ("CVE-2024-1234?x=1", "CVE-2024-1234#frag", "CVE-2024-1234%0d%0aX:%20y"):
            result, get = self.fetch(cve_id)
            self.assertEqual(result, {}, cve_id)
            get.assert_not_called()

    def test_a_short_or_absent_id_is_turned_away(self):
        for cve_id in ("", None, "CVE-", "CVE-24-1", "CVE-2024-123", "not a cve"):
            result, get = self.fetch(cve_id)
            self.assertEqual(result, {}, repr(cve_id))
            get.assert_not_called()


class Accepted(unittest.TestCase):
    """And nothing legitimate should be turned away by the check."""

    def url_for(self, cve_id):
        with mock.patch.object(vuln_lookup.requests, "get") as get:
            get.return_value = mock.Mock(status_code=200, json=lambda: {})
            vuln_lookup.fetch_cve_info(cve_id)
        return get.call_args[0][0]

    def test_an_ordinary_id_is_looked_up(self):
        self.assertEqual(self.url_for("CVE-2024-1234"),
                         "https://vulnerability.circl.lu/api/cve/CVE-2024-1234")

    def test_case_and_surrounding_space_are_tidied_rather_than_refused(self):
        for cve_id in ("cve-2024-1234", "  CVE-2024-1234  ", "Cve-2024-1234"):
            self.assertEqual(self.url_for(cve_id),
                             "https://vulnerability.circl.lu/api/cve/CVE-2024-1234", cve_id)

    def test_the_oldest_and_the_longest_ids_are_both_fine(self):
        """Four digits from 1999, and sequence numbers that outgrew four."""
        self.assertIn("CVE-1999-0001", self.url_for("CVE-1999-0001"))
        self.assertIn("CVE-2024-123456789", self.url_for("CVE-2024-123456789"))

    def test_a_failed_lookup_still_reads_as_no_enrichment(self):
        with mock.patch.object(vuln_lookup.requests, "get",
                               side_effect=RuntimeError("circl is down")):
            self.assertEqual(vuln_lookup.fetch_cve_info("CVE-2024-1234"), {})

    def test_a_lookup_that_could_not_be_made_is_told_from_an_unknown_cve(self):
        """The advisories declined a CVE as below the severity asked for when
        the database was only down."""
        for answer, expected in ((mock.Mock(status_code=404), {}), (mock.Mock(status_code=503), None),
                                 (RuntimeError("circl is down"), None)):
            with self.subTest(answer=answer), \
                 mock.patch.object(vuln_lookup.requests, "get",
                                   **({"side_effect": answer} if isinstance(answer, Exception)
                                      else {"return_value": answer})):
                self.assertEqual(vuln_lookup.lookup_cve("CVE-2024-1234"), expected)


class ThePatternDoesBothJobs(unittest.TestCase):
    """collection_cache and the advisory wizard pull IDs out of event titles
    with this same pattern, so narrowing it for the URL check would quietly
    stop those finding anything."""

    def test_it_still_finds_ids_inside_a_sentence(self):
        found = CVE_RE.findall("Patch for CVE-2024-1234 and cve-1999-0001 is out")
        self.assertEqual([m.upper() for m in found], ["CVE-2024-1234", "CVE-1999-0001"])

    def test_it_matches_a_whole_string_and_nothing_more(self):
        self.assertTrue(CVE_RE.fullmatch("CVE-2024-1234"))
        self.assertFalse(CVE_RE.fullmatch("CVE-2024-1234 and more"))


if __name__ == "__main__":
    unittest.main()
