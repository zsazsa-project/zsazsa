"""Tests for the collection cache query behaviour.

Pins the C-1 fix: a selective tag filter must not silently drop matching events
that happen to be older than the result cap. Uses a throwaway SQLite file.

    python -m unittest tests.test_collection_cache
"""

import os
import tempfile
import time
import unittest
from unittest import mock

from webapp import collection_cache


def _row(uuid, date, tags, source_id="src"):
    return {
        "source_id": source_id,
        "uuid": uuid,
        "event_id": uuid,
        "info": f"event {uuid}",
        "date": date,
        "tags": tags,
        "galaxy_names": [],
    }


class GetEvents(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._orig_db = collection_cache._DB_FILE
        collection_cache._DB_FILE = self._tmp.name
        collection_cache.init_db()

    def tearDown(self):
        collection_cache._DB_FILE = self._orig_db
        os.unlink(self._tmp.name)

    def test_filter_finds_old_matching_event_beyond_the_cap(self):
        # 20 recent events without the tag, plus one tagged event that is the
        # oldest of all. With the old `limit * 3` pre-cap and a small limit the
        # tagged event would be sliced off before filtering.
        for i in range(20):
            collection_cache.insert_event(_row(f"new-{i:02d}", f"2024-02-{i + 1:02d}", ["other"]))
        collection_cache.insert_event(_row("old-tagged", "2023-01-01", ["zsazsa:queue"]))

        matches = collection_cache.get_events(["src"], ["zsazsa:queue"], limit=5)
        self.assertEqual([m["uuid"] for m in matches], ["old-tagged"])

    def test_unfiltered_respects_limit_and_date_order(self):
        for i in range(10):
            collection_cache.insert_event(_row(f"e-{i:02d}", f"2024-03-{i + 1:02d}", ["x"]))
        events = collection_cache.get_events(["src"], [], limit=3)
        self.assertEqual(len(events), 3)
        # Newest first.
        self.assertEqual([e["uuid"] for e in events], ["e-09", "e-08", "e-07"])

    def test_requires_all_tag_filters(self):
        collection_cache.insert_event(_row("both", "2024-01-02", ["a", "b"]))
        collection_cache.insert_event(_row("only-a", "2024-01-01", ["a"]))
        matches = collection_cache.get_events(["src"], ["a", "b"], limit=10)
        self.assertEqual([m["uuid"] for m in matches], ["both"])

    def test_no_source_ids_returns_empty(self):
        self.assertEqual(collection_cache.get_events([], ["a"], limit=5), [])

    def test_init_db_is_idempotent(self):
        # W-5: re-running migrations must swallow only "duplicate column" errors,
        # so a second init on an already-migrated DB does not raise.
        collection_cache.init_db()
        collection_cache.init_db()

    def test_source_status_event_count_is_live_not_persisted(self):
        # N-3: source_status no longer stores event_count; get_source_status must
        # report the actual current row count for the source.
        for i in range(3):
            collection_cache.insert_event(_row(f"s-{i}", f"2024-04-0{i + 1}", ["x"]))
        with collection_cache._db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO source_status (source_id, last_fetch, error) VALUES (?, ?, ?)",
                ("src", 123.0, None),
            )
        status = collection_cache.get_source_status()
        self.assertEqual(status["src"]["event_count"], 3)

    def test_a_refresh_keeps_events_cached_while_it_ran(self):
        # A manual entry is written to the cache by the request that creates it.
        # When a refresh for that source is already in flight, its search ran
        # before the event existed, so the replace must not take the row with it.
        collection_cache.insert_event(_row("stale", "2024-01-01", [], source_id="manual-x"))
        time.sleep(0.01)

        class _Misp:
            def search(self, **kwargs):
                collection_cache.insert_event(
                    _row("entered-meanwhile", "2024-06-01", [], source_id="manual-x"))
                return []

        src = {"id": "manual-x", "kind": "manual", "url": "u", "api_key": "k", "source_tag": ""}
        with mock.patch.object(collection_cache, "PyMISP", lambda *a, **k: _Misp()):
            collection_cache.refresh_source(src)

        cached = [e["uuid"] for e in collection_cache.get_events(["manual-x"], [], limit=10)]
        self.assertEqual(cached, ["entered-meanwhile"])

    def test_source_status_reports_last_run_counts(self):
        # The pipeline page reads these to show what the last import fetched,
        # which is separate from how many rows are currently cached.
        collection_cache.insert_event(_row("s-0", "2024-05-01", ["x"]))
        with collection_cache._db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO source_status"
                " (source_id, last_fetch, error, last_duration_s, last_event_count, last_new_count)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("src", 123.0, None, 4.2, 87, 3),
            )
        st = collection_cache.get_source_status()["src"]
        self.assertEqual((st["last_event_count"], st["last_new_count"], st["last_duration_s"]),
                         (87, 3, 4.2))
        self.assertEqual(st["event_count"], 1)


if __name__ == "__main__":
    unittest.main()
