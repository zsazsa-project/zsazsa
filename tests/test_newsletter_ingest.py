"""Tests for the shared newsletter ingest helper.

    python -m unittest tests.test_newsletter_ingest
"""

import unittest
from unittest import mock

from webapp import newsletter_ingest


class PublishArticles(unittest.TestCase):
    def setUp(self):
        # Every link here counts as public, without a DNS lookup; Refused
        # covers the check itself.
        patcher = mock.patch.object(newsletter_ingest, "is_safe_public_url", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_counts_published_and_no_subscriber(self):
        articles = [
            {"url": "http://a", "title": "A", "section": "Malware", "priority": "critical"},
            {"url": "http://b", "title": "B"},
        ]
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=[1, 0]) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", articles)
        self.assertEqual(pub.call_count, 2)
        self.assertEqual(counts, {"published": 2, "failed": 0, "no_subscriber": 1, "refused": 0})

    def test_skips_articles_without_url(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", return_value=1) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"title": "no url"}])
        pub.assert_not_called()
        self.assertEqual(counts["published"], 0)

    def test_publish_failure_counted(self):
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=OSError("down")):
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", [{"url": "http://a"}])
        self.assertEqual(counts, {"published": 0, "failed": 1, "no_subscriber": 0, "refused": 0})

    def test_message_carries_feed_and_section_tags(self):
        captured = {}

        def fake_publish(message):
            captured.update(message)
            return 1

        article = {"url": "http://a", "title": "T", "section": "Vulnerabilities", "priority": "urgent"}
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish", side_effect=fake_publish):
            newsletter_ingest.publish_articles("ETDA CTI Robot", [article])
        self.assertEqual(captured["link"], "http://a")
        self.assertEqual(captured["feed"], "ETDA CTI Robot")
        self.assertIn('zsazsa:newsletter-section="vulnerabilities"', captured["feed_tags"])
        self.assertIn('zsazsa:newsletter-priority="urgent"', captured["feed_tags"])


class Refused(unittest.TestCase):
    """A newsletter can come from anyone who can mail the mailbox, and the
    scraper fetches what it is sent (GHSA-24wh-h52p-fcgg)."""

    def test_a_link_that_is_not_public_is_not_sent_to_the_scraper(self):
        articles = [{"url": "http://127.0.0.1:8080/admin"}, {"url": "https://news.example.org/a"}]
        with mock.patch.object(newsletter_ingest, "is_safe_public_url",
                               side_effect=lambda url: "127.0.0.1" not in url) as check, \
             mock.patch("webapp.newsletter_ingest.scraper_queue.publish", return_value=1) as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot", articles)
        self.assertEqual([c.args[0] for c in check.call_args_list],
                         ["http://127.0.0.1:8080/admin", "https://news.example.org/a"])
        self.assertEqual([c.args[0]["link"] for c in pub.call_args_list], ["https://news.example.org/a"])
        self.assertEqual(counts["refused"], 1)
        self.assertEqual(counts["published"], 1)

    def test_the_real_check_refuses_an_internal_address(self):
        """No stand-in here: a literal address needs no DNS lookup."""
        with mock.patch("webapp.newsletter_ingest.scraper_queue.publish") as pub:
            counts = newsletter_ingest.publish_articles("ETDA CTI Robot",
                                                        [{"url": "http://169.254.169.254/latest/meta-data/"}])
        pub.assert_not_called()
        self.assertEqual(counts["refused"], 1)


class ArticlesFromParsed(unittest.TestCase):
    def test_maps_and_drops_urlless(self):
        parsed = {
            "articles": [
                {"primary_url": "http://a", "title": "A", "section": "S", "priority_key": "critical"},
                {"primary_url": "", "title": "no url"},
            ]
        }
        out = newsletter_ingest.articles_from_parsed(parsed)
        self.assertEqual(out, [
            {"url": "http://a", "title": "A", "section": "S", "priority": "critical"},
        ])


if __name__ == "__main__":
    unittest.main()
