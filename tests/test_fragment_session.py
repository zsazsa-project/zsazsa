"""A fragment the page loads says so when the session has expired.

The recipients preview, a briefing's source events, the scope preview of the
PIR and GIR lists, an indicator feed's results and an RFI's attachments and
notes are HTML read from zsazsa and put in the page. After the session ended,
the request was sent on to the MISP login page, and that page went in their
place, or, on another origin, failed with a network error that said nothing.
Each now asks without following redirects and reads the answer through
zsazsaReadHtml in base.html, which tells the analyst to sign in again and
passes on the line of text a route refuses with.

    python -m unittest tests.test_fragment_session
"""

import re
import unittest
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "webapp" / "templates"
LOADERS = ("_recipients_modal.html", "_source_events_card_js.html", "requirements/_list_scope_js.html",
           "indicator_feed/_query_js.html", "rfi/form.html")


class FragmentSession(unittest.TestCase):
    def test_base_reads_a_fragment_as_the_json_answers_are_read(self):
        base = (TEMPLATES / "base.html").read_text()
        helper = base.split("function zsazsaReadHtml(response) {", 1)[1].split("\n  }\n", 1)[0]
        self.assertIn("response.type === 'opaqueredirect' || response.redirected || response.status === 403", helper)
        self.assertIn("throw new Error(ZSAZSA_SESSION_EXPIRED);", helper)
        # The JSON reader says the same.
        self.assertEqual(base.count("throw new Error(ZSAZSA_SESSION_EXPIRED);"), 2)

    def test_every_fragment_loader_reads_through_it_without_following_redirects(self):
        for name in LOADERS:
            with self.subTest(name):
                text = (TEMPLATES / name).read_text()
                self.assertIn(".then(zsazsaReadHtml)", text)
                self.assertIn("redirect: 'manual'", text)

    def test_no_template_puts_a_fragment_in_the_page_unread(self):
        bare = re.compile(r"\.then\(function\s*\(r\)\s*\{\s*return r\.text\(\);\s*\}\)")
        offenders = [str(p.relative_to(TEMPLATES)) for p in TEMPLATES.rglob("*.html") if bare.search(p.read_text())]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
