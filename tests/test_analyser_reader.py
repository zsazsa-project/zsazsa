"""The analyser reads every scraper event changed since its watermark, and
every manual entry with a report.

The run moves the watermark to the moment it started, so whatever the search
did not return is never asked for again. That makes two things load-bearing:
every page of the search is read, not only the first, and a search that fails
stops the run instead of reading as "nothing new".

    python -m unittest tests.test_analyser_reader
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

import config
from analyser import reader

INCOMPLETE = 'workflow:state="incomplete"'
COMPLETE = 'workflow:state="complete"'


def _event(n, state=INCOMPLETE):
    return SimpleNamespace(uuid=f"e{n}", tags=[SimpleNamespace(name=config.SCRAPER_MARKER_TAG),
                                               SimpleNamespace(name=state)])


class _PagedMISP:
    def __init__(self, events, fail_on_page=None):
        self.events, self.fail_on_page, self.pages = events, fail_on_page, []

    def search(self, limit=None, page=None, **kw):
        self.pages.append(page)
        if page == self.fail_on_page:
            return {"errors": (500, "Internal error")}
        start = (page - 1) * limit
        return self.events[start:start + limit]


class EveryPageIsRead(unittest.TestCase):
    def read(self, misp, limit=2):
        with mock.patch.object(reader, "load_last_run", return_value=None), \
             mock.patch.object(config, "MISP_SCRAPER_LIMIT", limit, create=True):
            return reader.get_new_scraper_events(misp)

    def test_an_event_past_the_first_page_is_returned(self):
        misp = _PagedMISP([_event(1), _event(2), _event(3)])
        self.assertEqual([e.uuid for e in self.read(misp)], ["e1", "e2", "e3"])
        self.assertEqual(misp.pages, [1, 2])

    def test_complete_events_filling_a_page_do_not_hide_an_incomplete_one(self):
        misp = _PagedMISP([_event(1, COMPLETE), _event(2, COMPLETE), _event(3)])
        self.assertEqual([e.uuid for e in self.read(misp)], ["e3"])

    def test_a_full_last_page_costs_one_empty_request(self):
        misp = _PagedMISP([_event(1), _event(2)])
        self.assertEqual(len(self.read(misp)), 2)
        self.assertEqual(misp.pages, [1, 2])

    def test_a_failed_search_raises_instead_of_reading_as_empty(self):
        for page in (1, 2):
            with self.subTest(failing_page=page):
                misp = _PagedMISP([_event(1), _event(2), _event(3)], fail_on_page=page)
                with self.assertRaises(RuntimeError):
                    self.read(misp)

class ManualEntries(unittest.TestCase):
    """Manual collection entries are read too, from the webapp MISP, when they
    have a report for the model to read."""

    def test_only_an_incomplete_entry_with_a_report_is_read(self):
        def entry(n, state=INCOMPLETE, reports=("Report",)):
            return SimpleNamespace(uuid=f"m{n}", tags=[SimpleNamespace(name=state)], event_reports=list(reports))
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [entry(1), entry(2, reports=()), entry(3, COMPLETE)]
        with mock.patch.object(reader, "load_last_run", return_value=None):
            read = reader.get_new_manual_entries(misp)
        self.assertEqual([e.uuid for e in read], ["m1"])
        self.assertEqual(misp.search.call_args.kwargs["tags"], [reader.TAG_MANUAL_ENTRY])

    def test_an_entry_whose_report_was_deleted_is_left_for_the_analyst(self):
        """MISP keeps a deleted report on the event. Read, the entry would be
        rejected for having nothing to summarise."""
        deleted = SimpleNamespace(name="Report", deleted=True)
        entry = SimpleNamespace(uuid="m1", tags=[SimpleNamespace(name=INCOMPLETE)], event_reports=[deleted])
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [entry]
        with mock.patch.object(reader, "load_last_run", return_value=None):
            self.assertEqual(reader.get_new_manual_entries(misp), [])


if __name__ == "__main__":
    unittest.main()
