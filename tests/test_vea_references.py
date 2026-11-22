"""The reference links a vulnerability advisory is seeded with.

A MISP vulnerability attribute holds whatever was typed into it, and that is
not always a CVE ID: GHSA and vendor identifiers arrive the same way. The
advisory keeps all of them in its cve_id field, because dropping one would lose
what the analyst is writing about, but only a real CVE gets a link built for it.
Anything else either has no page there or has no business in a URL.

    python -m unittest tests.test_vea_references
"""

import unittest
from unittest import mock

from webapp.routes import vea

CIRCL = "https://vulnerability.circl.lu/vuln/"


def _event(*values, info="An event title with no CVE in it"):
    return {
        "uuid": "e1", "info": info, "source_url": "https://misp.example",
        "source_label": "scraper", "objects": [],
        "attributes": [{"type": "vulnerability", "value": v} for v in values],
    }


def _seed(event):
    with mock.patch.object(vea.collection_cache, "get_events_by_uuids", return_value=[]), \
         mock.patch.object(vea.misp_store, "source_event_urls", return_value=[]):
        return vea._build_seed_from_sources(["e1"], [("e1", "scraper")], [event])


class ReferenceLinks(unittest.TestCase):
    def links(self, seed):
        return [r for r in seed.references if r.startswith(CIRCL)]

    def test_a_cve_gets_a_link(self):
        self.assertEqual(self.links(_seed(_event("CVE-2024-1234"))),
                         [CIRCL + "CVE-2024-1234"])

    def test_an_identifier_that_is_not_a_cve_gets_none(self):
        for value in ("GHSA-abcd-1234-efgh", "VU#123456", "../../admin",
                      "CVE-2024-1234/../../x"):
            self.assertEqual(self.links(_seed(_event(value))), [], value)

    def test_the_cve_id_field_still_holds_all_of_them(self):
        """Filtering the links must not filter what the advisory is about."""
        seed = _seed(_event("CVE-2024-1234", "GHSA-abcd-1234-efgh"))
        self.assertEqual(seed.cve_id, "CVE-2024-1234, GHSA-abcd-1234-efgh")
        self.assertEqual(self.links(seed), [CIRCL + "CVE-2024-1234"])

    def test_an_id_read_out_of_the_title_is_linked_too(self):
        seed = _seed(_event(info="Fixes CVE-2024-1234 today"))
        self.assertEqual(self.links(seed), [CIRCL + "CVE-2024-1234"])


if __name__ == "__main__":
    unittest.main()
