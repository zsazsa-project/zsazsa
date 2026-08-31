"""Tests for the audit log: the notify-status badge every product page shows,
and the shape of the timestamp each entry is written with.

    python -m unittest tests.test_audit_notify_status
"""

import unittest
from unittest import mock

from webapp import audit


class LatestNotifyStatus(unittest.TestCase):
    def _status(self, details):
        row = {"details": details, "timestamp": "2026-06-22T00:00:00"}
        with mock.patch.object(audit, "latest_event", return_value=row):
            return audit.latest_notify_status("fia", "x")

    def test_delivered(self):
        self.assertEqual(self._status("publish notification; result=ok")["tone"], "success")
        self.assertEqual(self._status("publish notification; result=ok")["label"], "Delivered")

    def test_failed(self):
        self.assertEqual(self._status("publish notification; result=failed")["label"], "Failed")

    def test_skipped(self):
        self.assertEqual(self._status("skipped types: email")["label"], "Skipped")

    def test_unknown(self):
        self.assertEqual(self._status("queued for later")["label"], "Unknown")

    def test_none_when_no_event(self):
        with mock.patch.object(audit, "latest_event", return_value=None):
            self.assertIsNone(audit.latest_notify_status("fia", "x"))


class Timestamp(unittest.TestCase):
    """The timestamp is a text column that existing rows already fill, and the
    log is ordered and read as text, so an entry written today has to look like
    the ones written before it: UTC, seconds, and no offset suffix."""

    def written(self):
        rows = []
        db = mock.MagicMock()
        db.execute.side_effect = lambda _sql, args=None: rows.append(args)
        with mock.patch.object(audit, "_conn") as conn, \
             mock.patch.object(audit.misp_session, "current_user_email", return_value="a@b.c"):
            conn.return_value.__enter__.return_value = db
            audit.record("create", "pir", entity_id="u", entity_label="PIR-001")
        return rows[0][0]

    def test_it_is_utc_to_the_second_without_an_offset(self):
        self.assertRegex(self.written(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")

    def test_it_sorts_against_rows_already_in_the_table(self):
        self.assertGreater(self.written(), "2026-06-22T00:00:00")


if __name__ == "__main__":
    unittest.main()
