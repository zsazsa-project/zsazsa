"""Tests for indicator-feed text de-duplication and count refinement.

Covers:
- `_values_text` de-duplicates values (first-seen order) so .txt/public text
  exports don't repeat a value seen on multiple attributes/servers.
- `count_indicators` applies the same local tag include/exclude AND/exclude
  refinement as the result rows, and `capped` reflects raw per-server
  truncation regardless of that refinement.

    python -m unittest tests.test_indicator_feed_dedup_count
"""

import unittest

from webapp import misp_store
from webapp.routes import indicator_feed


class ValuesTextDedup(unittest.TestCase):
    def test_deduplicates_preserving_first_seen_order(self):
        rows = [
            {"value": "1.2.3.4"},
            {"value": "evil.example"},
            {"value": "1.2.3.4"},
            {"value": "8.8.8.8"},
            {"value": "evil.example"},
        ]
        self.assertEqual(
            indicator_feed._values_text(rows),
            "1.2.3.4\nevil.example\n8.8.8.8",
        )

    def test_empty_rows(self):
        self.assertEqual(indicator_feed._values_text([]), "")


class FakeClient:
    def __init__(self, attrs):
        self._attrs = attrs

    def search(self, **kwargs):
        return {"Attribute": self._attrs}


class CountIndicators(unittest.TestCase):
    def setUp(self):
        self._orig = misp_store._indicator_feed_clients

    def tearDown(self):
        misp_store._indicator_feed_clients = self._orig

    def _patch(self, clients):
        misp_store._indicator_feed_clients = lambda server_ids=None: clients

    def test_no_tag_filter_counts_all_attributes(self):
        attrs = [{"id": "1", "value": "a"}, {"id": "2", "value": "b"}]
        self._patch([("s1", "Server 1", "https://misp1", FakeClient(attrs))])
        total, capped = misp_store.count_indicators({})
        self.assertEqual(total, 2)
        self.assertFalse(capped)

    def test_tags_include_applies_and_semantics_locally(self):
        attrs = [
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}, {"name": "actor:x"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:red"}]},
        ]
        self._patch([("s1", "Server 1", "https://misp1", FakeClient(attrs))])
        total, capped = misp_store.count_indicators(
            {"tags_include": ["tlp:red", "actor:x"]}
        )
        self.assertEqual(total, 1)
        self.assertFalse(capped)

    def test_tags_exclude_removes_matches_locally(self):
        attrs = [
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:green"}]},
        ]
        self._patch([("s1", "Server 1", "https://misp1", FakeClient(attrs))])
        total, capped = misp_store.count_indicators({"tags_exclude": ["tlp:red"]})
        self.assertEqual(total, 1)
        self.assertFalse(capped)

    def test_capped_reflects_raw_per_server_truncation(self):
        attrs = [{"id": str(i), "value": str(i)} for i in range(3)]
        self._patch([("s1", "Server 1", "https://misp1", FakeClient(attrs))])
        total, capped = misp_store.count_indicators({}, cap=3)
        self.assertEqual(total, 3)
        self.assertTrue(capped)

    def test_capped_true_if_any_server_hits_cap_even_with_others_below(self):
        capped_attrs = [{"id": str(i), "value": str(i)} for i in range(3)]
        small_attrs = [{"id": "9", "value": "x"}]
        self._patch([
            ("s1", "Server 1", "https://misp1", FakeClient(capped_attrs)),
            ("s2", "Server 2", "https://misp2", FakeClient(small_attrs)),
        ])
        total, capped = misp_store.count_indicators({}, cap=3)
        self.assertEqual(total, 4)
        self.assertTrue(capped)


if __name__ == "__main__":
    unittest.main()
