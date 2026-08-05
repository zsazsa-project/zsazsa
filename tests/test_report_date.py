"""Tests for the date shown next to a MISP event report title.

PyMISP hands the timestamp over as a UTC datetime, but a report that has not
been through the API yet still carries the raw epoch value, and an instance
that sends something unusable must leave the page standing.

    python -m unittest tests.test_report_date
"""

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from webapp import misp_store


class ReportDate(unittest.TestCase):
    def test_datetime_timestamp(self):
        report = SimpleNamespace(timestamp=datetime(2026, 3, 14, 9, 30, tzinfo=timezone.utc))
        self.assertEqual(misp_store.report_date(report), "2026-03-14")

    def test_epoch_timestamp(self):
        report = SimpleNamespace(timestamp=1773480600)
        self.assertEqual(misp_store.report_date(report), "2026-03-14")

    def test_epoch_as_string(self):
        report = SimpleNamespace(timestamp="1773480600")
        self.assertEqual(misp_store.report_date(report), "2026-03-14")

    def test_no_usable_timestamp(self):
        for ts in [None, "", "not a timestamp"]:
            self.assertEqual(misp_store.report_date(SimpleNamespace(timestamp=ts)), "", ts)
        self.assertEqual(misp_store.report_date(SimpleNamespace()), "")


if __name__ == "__main__":
    unittest.main()
