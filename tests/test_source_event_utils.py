import unittest

from webapp.routes.source_event_utils import flattened_references


class FlattenedReferences(unittest.TestCase):
    def test_combines_external_links_source_links_and_event_urls_in_order(self):
        rows = flattened_references(
            ["https://ext.example/a", "https://ext.example/a", ""],
            [
                {
                    "url": "https://misp.example/events/view/1",
                    "info": "Event 1",
                    "date": "2026-07-31",
                    "orgc": "ACME",
                    "links": ["https://article.example/x", "https://article.example/x"],
                }
            ],
        )
        self.assertEqual(
            [row["url"] for row in rows],
            [
                "https://ext.example/a",
                "https://article.example/x",
                "https://misp.example/events/view/1",
            ],
        )
        self.assertEqual(rows[0]["kind"], "external")
        self.assertEqual(rows[1]["kind"], "source-link")
        self.assertEqual(rows[2]["kind"], "source-event")
        self.assertEqual(rows[2]["info"], "Event 1")


if __name__ == "__main__":
    unittest.main()
