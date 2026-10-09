"""Tests for the IMAP collector runner: which source a message belongs to, and
what the poll does with it.

    python -m unittest tests.test_run_imap_collector
"""

import email
import unittest
from unittest import mock

import run_imap_collector


def _msg(subject: str, sender: str):
    return email.message_from_string(f"Subject: {subject}\nFrom: {sender}\n\nbody")


NEWSLETTER = """\
[FIRST] ETDA Cyber Threat Intelligence of 1 January 2026

Malware

* Sample Loader

"A sample loader."
Priority: 2 - Urgent
Relevance: General

<https://example.org/loader>

TLP: GREEN
"""


class MatchSource(unittest.TestCase):
    def setUp(self):
        self.sources = [
            {"name": "ETDA", "subjects": ["etda"], "senders": []},
            {"name": "Weekly", "subjects": [], "senders": ["weekly@vendor.com"]},
        ]

    def test_matches_by_subject(self):
        s = run_imap_collector._match_source(_msg("Fwd: ETDA digest", "a@b.c"), self.sources)
        self.assertEqual(s["name"], "ETDA")

    def test_matches_by_sender(self):
        s = run_imap_collector._match_source(_msg("anything", "weekly@vendor.com"), self.sources)
        self.assertEqual(s["name"], "Weekly")

    def test_no_match_returns_none(self):
        self.assertIsNone(run_imap_collector._match_source(_msg("sales", "x@y.z"), self.sources))

    def test_first_matching_source_wins(self):
        # A catch-all source (no criteria) placed first takes every message.
        sources = [{"name": "All", "subjects": [], "senders": []}] + self.sources
        s = run_imap_collector._match_source(_msg("Fwd: ETDA digest", "a@b.c"), sources)
        self.assertEqual(s["name"], "All")


class AutoMode(unittest.TestCase):
    """A newsletter on auto mode goes straight to the scraper. Links that are
    not public addresses are refused on the way (GHSA-24wh-h52p-fcgg), and a
    newsletter left with none to send waits for review instead."""

    source = {"name": "ETDA", "parser": "ETDA CTI Robot", "mode": "auto"}

    def ingest(self, counts, public=True):
        with mock.patch.object(run_imap_collector.newsletter_ingest, "is_safe_public_url",
                               return_value=public), \
             mock.patch.object(run_imap_collector.misp_store, "create_newsletter_event",
                               return_value="event-uuid") as archive, \
             mock.patch.object(run_imap_collector.misp_store, "mark_newsletter_pending") as pending, \
             mock.patch.object(run_imap_collector.newsletter_ingest, "publish_articles",
                               return_value=counts) as publish:
            run_imap_collector._ingest_message(self.source, NEWSLETTER)
        self.archived_urls = archive.call_args.kwargs["article_urls"]
        return publish, pending

    def test_a_newsletter_whose_links_were_all_refused_waits_for_review(self):
        publish, pending = self.ingest({"published": 0, "failed": 0, "no_subscriber": 0, "refused": 1})
        publish.assert_called_once()
        pending.assert_called_once_with("event-uuid")

    def test_a_newsletter_with_links_sent_does_not(self):
        _publish, pending = self.ingest({"published": 1, "failed": 0, "no_subscriber": 0, "refused": 0})
        pending.assert_not_called()
        self.assertEqual(self.archived_urls, ["https://example.org/loader"])

    def test_a_refused_link_is_not_recorded_as_pushed(self):
        self.ingest({"published": 0, "failed": 0, "no_subscriber": 0, "refused": 1}, public=False)
        self.assertEqual(self.archived_urls, [])

    def test_a_redis_failure_and_refusal_are_both_logged(self):
        with self.assertLogs(run_imap_collector.logger, level="WARNING") as captured:
            _publish, pending = self.ingest(
                {"published": 0, "failed": 1, "no_subscriber": 0, "refused": 1})
        pending.assert_called_once_with("event-uuid")
        self.assertIn("1 failed, 1 refused", captured.output[0])


class PollMailbox(unittest.TestCase):
    """What the poll does with each message: archive it, then mark it. A message
    is only marked once it is in MISP, so a failure anywhere means it is offered
    again on the next run rather than lost."""

    mailbox = {
        "name": "Mailbox",
        "sources": [{"name": "ETDA", "enabled": True, "parser": "ETDA CTI Robot",
                     "subjects": ["etda"], "senders": [], "mode": "manual"}],
    }

    def poll(self, message, marked=True):
        self.archived = []
        self.marks = []

        def archive(*args, **kwargs):
            self.archived.append((args, kwargs))
            return "event-uuid"

        def mark(conn, uid):
            self.marks.append(uid)
            return marked

        with mock.patch.object(run_imap_collector.imap_collector, "fetch_unprocessed",
                               return_value=[(mock.Mock(), b"7", message)]), \
             mock.patch.object(run_imap_collector.imap_collector, "mark_processed",
                               side_effect=mark), \
             mock.patch.object(run_imap_collector.misp_store, "create_newsletter_event",
                               side_effect=archive):
            return run_imap_collector._poll_mailbox(dict(self.mailbox))

    def test_newsletter_is_archived_for_review_and_marked(self):
        message = email.message_from_string(
            f"Subject: [1st-news] ETDA digest\nFrom: robot@etda.example\n\n{NEWSLETTER}")
        result = self.poll(message)
        self.assertEqual(result["processed"], 1)
        (feed, body), kwargs = self.archived[0]
        self.assertEqual(feed, "ETDA")
        self.assertIn("Sample Loader", body)
        self.assertEqual(kwargs["status"], "pending-review")
        self.assertEqual(kwargs["parsed_articles"], 1)
        self.assertEqual(self.marks, [b"7"])

    def test_a_message_with_no_text_is_archived_not_dropped(self):
        message = email.message_from_string(
            "Subject: ETDA digest\nFrom: robot@etda.example\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: application/pdf\n"
            "Content-Disposition: attachment; filename=edition.pdf\n\nJVBERi0=\n--b--\n")
        self.poll(message)
        (feed, body), kwargs = self.archived[0]
        self.assertEqual(feed, "ETDA")
        self.assertIn("edition.pdf", body)          # the message source, so nothing is lost
        self.assertEqual(kwargs["parsed_articles"], 0)
        self.assertEqual(kwargs["status"], "pending-review")
        self.assertEqual(self.marks, [b"7"])

    def test_the_flag_counts_what_the_review_page_will_show(self):
        # An article with no link is listed for review but cannot be pushed. The
        # queue flags a mail the parser made nothing of, so it must count the
        # rows the page will show rather than the ones the scraper can take.
        message = email.message_from_string(
            "Subject: ETDA digest\nFrom: robot@etda.example\n\n"
            + NEWSLETTER.replace("<https://example.org/loader>\n", ""))
        self.poll(message)
        self.assertEqual(self.archived[0][1]["parsed_articles"], 1)

    def test_a_message_that_cannot_be_marked_is_reported(self):
        message = email.message_from_string(
            f"Subject: ETDA digest\nFrom: robot@etda.example\n\n{NEWSLETTER}")
        with self.assertLogs("run_imap_collector", level="ERROR") as logs:
            result = self.poll(message, marked=False)
        self.assertEqual(result["processed"], 1)    # it did reach MISP
        self.assertIn("collected again", logs.output[0])

    def test_a_message_that_fails_to_archive_stays_unmarked(self):
        message = email.message_from_string(
            f"Subject: ETDA digest\nFrom: robot@etda.example\n\n{NEWSLETTER}")
        with mock.patch.object(run_imap_collector.imap_collector, "fetch_unprocessed",
                               return_value=[(mock.Mock(), b"7", message)]), \
             mock.patch.object(run_imap_collector.imap_collector, "mark_processed") as mark, \
             mock.patch.object(run_imap_collector.misp_store, "create_newsletter_event",
                               side_effect=RuntimeError("MISP down")):
            result = run_imap_collector._poll_mailbox(dict(self.mailbox))
        self.assertEqual(result["processed"], 0)
        mark.assert_not_called()

    def test_a_message_for_no_source_is_left_alone(self):
        with mock.patch.object(run_imap_collector.imap_collector, "fetch_unprocessed",
                               return_value=[(mock.Mock(), b"7", _msg("sales", "x@y.z"))]), \
             mock.patch.object(run_imap_collector.imap_collector, "mark_processed") as mark, \
             mock.patch.object(run_imap_collector.misp_store, "create_newsletter_event") as archive:
            result = run_imap_collector._poll_mailbox(dict(self.mailbox))
        self.assertEqual(result["processed"], 0)
        mark.assert_not_called()
        archive.assert_not_called()


if __name__ == "__main__":
    unittest.main()
