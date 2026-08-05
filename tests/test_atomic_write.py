"""Files shared between the web app and the analyser.

The state file, the AI feature settings and the configuration module are each
written by one process and read by another, so the writing has to be a
replacement rather than a truncate followed by a fill.

    python -m unittest tests.test_atomic_write
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.atomic_write import write_atomically


class AtomicWrite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "state.json"

    def leftovers(self):
        return [name for name in os.listdir(self.dir.name) if name.endswith(".tmp")]

    def test_writes_a_new_file(self):
        write_atomically(self.path, '{"a": 1}')
        self.assertEqual(self.path.read_text(), '{"a": 1}')
        self.assertEqual(self.leftovers(), [])

    def test_replaces_an_existing_file(self):
        self.path.write_text("old")
        write_atomically(self.path, "new")
        self.assertEqual(self.path.read_text(), "new")
        self.assertEqual(self.leftovers(), [])

    def test_a_failed_replace_keeps_the_old_file_and_drops_the_temp(self):
        self.path.write_text("old")
        with mock.patch("core.atomic_write.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write_atomically(self.path, "new")

        self.assertEqual(self.path.read_text(), "old")
        self.assertEqual(self.leftovers(), [])

    def test_non_ascii_survives_the_round_trip(self):
        write_atomically(self.path, "sécurité 🇧🇪")
        self.assertEqual(self.path.read_text(encoding="utf-8"), "sécurité 🇧🇪")


if __name__ == "__main__":
    unittest.main()
