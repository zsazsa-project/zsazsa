"""Indicator-feed value de-duplication and the result count.

The plain-text export lists each value once; the CSV keeps a row per attribute
with its event/server context. count_indicators has to end up at the same total
as the table, which means applying the same local tag refinement.

    python -m unittest tests.test_indicator_feed_dedup_count
"""

import unittest
from unittest import mock

from webapp import misp_store
from webapp.routes import indicator_feed


class ValuesText(unittest.TestCase):
    def test_a_value_seen_on_several_attributes_is_listed_once(self):
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

    def test_no_rows_is_an_empty_export(self):
        self.assertEqual(indicator_feed._values_text([]), "")

    def test_the_csv_export_keeps_the_duplicates(self):
        rows = [
            {"value": "1.2.3.4", "server_label": "One"},
            {"value": "1.2.3.4", "server_label": "Two"},
        ]
        self.assertEqual(indicator_feed._csv_bytes(rows).count(b"1.2.3.4"), 2)


class FakeClient:
    """A MISP server returning one page of attributes, recording the query."""

    def __init__(self, attrs):
        self._attrs = attrs
        self.kwargs = None

    def search(self, **kwargs):
        self.kwargs = kwargs
        return {"Attribute": self._attrs}


class CountIndicators(unittest.TestCase):
    def _servers(self, *clients):
        servers = [(f"s{i}", f"Server {i}", f"https://misp{i}", c)
                   for i, c in enumerate(clients, start=1)]
        patcher = mock.patch.object(misp_store, "_indicator_feed_clients", return_value=servers)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_attribute_counts_when_no_tag_filter_is_set(self):
        self._servers(FakeClient([{"id": "1", "value": "a"}, {"id": "2", "value": "b"}]))
        self.assertEqual(misp_store.count_indicators({}), (2, False))

    def test_the_totals_of_all_servers_are_added_up(self):
        self._servers(FakeClient([{"id": "1", "value": "a"}]),
                      FakeClient([{"id": "2", "value": "b"}, {"id": "3", "value": "c"}]))
        self.assertEqual(misp_store.count_indicators({}), (3, False))

    def test_an_included_tag_has_to_be_on_every_counted_attribute(self):
        # MISP would OR these; the table ANDs them, so the count must too.
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}, {"name": "actor:x"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:red"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red", "actor:x"]}), (1, False))

    def test_a_tag_on_the_event_counts_as_a_tag_on_the_attribute(self):
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Event": {"Tag": [{"name": "tlp:red"}]}},
            {"id": "2", "value": "b", "Event": {"Tag": [{"name": "tlp:green"}]}},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red"]}), (1, False))

    def test_an_excluded_tag_drops_the_attribute(self):
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:green"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_exclude": ["tlp:red"]}), (1, False))

    def test_the_event_context_is_only_fetched_when_tags_are_filtered(self):
        plain = FakeClient([{"id": "1", "value": "a"}])
        self._servers(plain)
        misp_store.count_indicators({})
        self.assertNotIn("include_context", plain.kwargs)

        tagged = FakeClient([{"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]}])
        self._servers(tagged)
        misp_store.count_indicators({"tags_include": ["tlp:red"]})
        self.assertTrue(tagged.kwargs["include_context"])

    def test_a_server_filling_the_cap_marks_the_total_as_incomplete(self):
        self._servers(FakeClient([{"id": str(i), "value": str(i)} for i in range(3)]),
                      FakeClient([{"id": "9", "value": "x"}]))
        self.assertEqual(misp_store.count_indicators({}, cap=3), (4, True))

    def test_the_cap_is_measured_before_the_tag_refinement(self):
        # Only one attribute survives the filter, but the fetch still hit the
        # cap, so the analyst has to be told the total may be higher.
        self._servers(FakeClient([
            {"id": "1", "value": "a", "Tag": [{"name": "tlp:red"}]},
            {"id": "2", "value": "b", "Tag": [{"name": "tlp:green"}]},
        ]))
        self.assertEqual(misp_store.count_indicators({"tags_include": ["tlp:red"]}, cap=2), (1, True))

    def test_a_server_that_cannot_be_reached_is_skipped(self):
        broken = mock.Mock()
        broken.search.side_effect = ConnectionError("down")
        self._servers(broken, FakeClient([{"id": "1", "value": "a"}]))
        self.assertEqual(misp_store.count_indicators({}), (1, False))


if __name__ == "__main__":
    unittest.main()
