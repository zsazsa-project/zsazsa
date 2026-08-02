"""Tests for the Mattermost notifier.

Covers the two things that are easy to get wrong when a product is posted: the
message splitter must not lose or truncate content, and a failing webhook must
not write its own secret into the log.

    python -m unittest tests.test_mattermost
"""

import logging
import re
import unittest
from io import StringIO
from unittest import mock

import requests

from notifier import mattermost

_PART_HEADING = re.compile(r"^\*\*Part \d+/\d+\*\*\n\n")


class Chunking(unittest.TestCase):
    def setUp(self):
        self.sent = []
        patcher = mock.patch.object(
            mattermost, "_post", side_effect=lambda urls, payload, label: self.sent.append(payload["text"]) or True
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _send(self, body):
        mattermost._chunk_and_send([{"url": "https://mm.test/hooks/x"}], body, "label")
        return [_PART_HEADING.sub("", chunk) for chunk in self.sent]

    def test_a_short_message_goes_out_whole(self):
        self.assertEqual(self._send("hello"), ["hello"])
        self.assertEqual(len(self.sent), 1)

    def test_every_character_survives_the_split(self):
        for body in ("x" * 3501,
                     "z" * 9000,
                     "\n\n".join(f"para {i} " + "y" * 200 for i in range(40)),
                     "\n\n".join(["a" * 50, "b" * 4000, "c" * 50])):
            self.sent.clear()
            delivered = "".join(self._send(body))
            self.assertEqual("".join(body.split()), "".join(delivered.split()))

    def test_the_part_heading_still_leaves_the_chunk_within_budget(self):
        self.sent.clear()
        self._send("z" * 9000)
        self.assertGreater(len(self.sent), 1)
        for chunk in self.sent:
            self.assertLessEqual(len(chunk), 3500)


class WebhookSecrets(unittest.TestCase):
    """A Mattermost webhook URL's path is its credential."""

    def setUp(self):
        self.buffer = StringIO()
        self.handler = logging.StreamHandler(self.buffer)
        self.logger = logging.getLogger("notifier.mattermost")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.addCleanup(self.logger.removeHandler, self.handler)

    def test_a_failing_webhook_does_not_log_its_token(self):
        url = "https://mm.example.com/hooks/abcd1234SECRETTOKEN"
        failure = requests.RequestException(
            "Max retries exceeded with url: /hooks/abcd1234SECRETTOKEN"
        )
        with mock.patch.object(mattermost.requests, "post", side_effect=failure):
            mattermost._post([{"url": url}], {"text": "x"}, "FIA-1")

        logged = self.buffer.getvalue()
        self.assertNotIn("abcd1234SECRETTOKEN", logged)
        # The host still has to be there, or the operator cannot tell which
        # channel failed.
        self.assertIn("mm.example.com", logged)

    def test_a_successful_send_names_the_host_only(self):
        url = "https://mm.example.com/hooks/abcd1234SECRETTOKEN"
        with mock.patch.object(mattermost.requests, "post") as post:
            post.return_value.raise_for_status.return_value = None
            mattermost._post([{"url": url}], {"text": "x"}, "FIA-1")

        logged = self.buffer.getvalue()
        self.assertNotIn("abcd1234SECRETTOKEN", logged)
        self.assertIn("mm.example.com", logged)


if __name__ == "__main__":
    unittest.main()
