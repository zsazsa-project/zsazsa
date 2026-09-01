"""MISP object templates must follow UUID and UI ordering conventions."""

import json
import unittest
from pathlib import Path


_OBJECTS_DIR = Path(__file__).parent.parent / "webapp" / "misp_objects" / "objects"


class MispObjectTemplates(unittest.TestCase):
    def test_template_uuids_are_v4_and_attribute_priorities_are_unique(self):
        for path in _OBJECTS_DIR.glob("*/definition.json"):
            with self.subTest(path=path):
                definition = json.loads(path.read_text())
                template_uuid = definition["uuid"]
                self.assertEqual(template_uuid[14], "4")
                self.assertIn(template_uuid[19].lower(), "89ab")
                priorities = [
                    attribute["ui-priority"]
                    for attribute in definition["attributes"].values()
                ]
                self.assertEqual(len(priorities), len(set(priorities)))


if __name__ == "__main__":
    unittest.main()
