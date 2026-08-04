"""A manually entered event must be visible on the collection page at once.

_cache_manual_event writes the new event straight into the collection cache, so
it no longer waits for the next background sweep. It must also stay quiet when
MISP cannot be reached: the event is already stored by then, and an exception
here would make the entry look like it failed.

    python -m unittest tests.test_manual_entry_cache
"""

import os
import tempfile
import unittest
from unittest import mock

from webapp import collection_cache
from webapp.routes import data_collection


class _Tag:
    def __init__(self, name):
        self.name = name


class _Event:
    """The parts of a MISPEvent that _extract_row reads."""

    uuid = "u-1"
    id = "42"
    info = "Manually entered item"
    date = "2026-08-04"
    org = None
    orgc = None
    attribute_count = 0
    Object = []
    attributes = []
    event_reports = []
    tags = [_Tag('zsazsa:source="newsletter"')]


class _Misp:
    def get_event(self, uuid, pythonify=True):
        return _Event()


class ManualEntryCache(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._orig_db = collection_cache._DB_FILE
        collection_cache._DB_FILE = self._tmp.name
        collection_cache.init_db()

    def tearDown(self):
        collection_cache._DB_FILE = self._orig_db
        os.unlink(self._tmp.name)

    def test_new_event_is_cached_under_its_source(self):
        with mock.patch.object(data_collection.misp_store, "_misp", return_value=_Misp()):
            data_collection._cache_manual_event("u-1", "Newsletter")

        cached = collection_cache.get_events(["manual-newsletter"], [], limit=10)
        self.assertEqual([e["uuid"] for e in cached], ["u-1"])

    def test_unreachable_misp_falls_back_to_the_worker(self):
        with mock.patch.object(data_collection.misp_store, "_misp",
                               side_effect=RuntimeError("MISP down")), \
             mock.patch.object(collection_cache, "trigger_refresh") as trigger:
            data_collection._cache_manual_event("u-2", "Newsletter")

        trigger.assert_called_once()


if __name__ == "__main__":
    unittest.main()
