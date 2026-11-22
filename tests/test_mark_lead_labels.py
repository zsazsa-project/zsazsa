"""Briefing story labels are shown like the bold labels of the other products.

The five story lines open with "What happened:", "Who is affected:", … as plain
text. mark_lead_labels wraps those in .pretext, which the PDF and the
on-screen preview set in bold.

    python -m unittest tests.test_mark_lead_labels
"""

import unittest

from webapp.utils import mark_lead_labels, md_to_html, md_to_html_inline


def _render(text):
    return mark_lead_labels(md_to_html(text))


class MarkLeadLabels(unittest.TestCase):
    def test_every_story_label_is_marked(self):
        story = "\n".join([
            "What happened: A new variant was disclosed.",
            "Who is affected: EU manufacturing.",
            "Why it matters: We assess with high confidence that it is exploited.",
            "Indicators or technical detail: `T1190`.",
            "What to watch or do: Apply the patch.",
            "Threat actor type: Criminal",
        ])
        html = _render(story)
        for label in ("What happened:", "Who is affected:", "Why it matters:",
                      "Indicators or technical detail:", "What to watch or do:",
                      "Threat actor type:"):
            self.assertIn(f'<span class="pretext">{label}</span>', html)

    def test_content_is_left_intact(self):
        html = _render("What happened: A new variant was disclosed.")
        self.assertIn("A new variant was disclosed.", html)

    def test_colon_inside_a_sentence_is_not_marked(self):
        html = _render("Exploitation was observed in the wild: two victims so far.")
        self.assertNotIn("pretext", html)

    def test_indicator_opening_a_line_is_not_marked(self):
        html = _render("`CVE-2024-1234`: exploited in the wild.")
        self.assertNotIn("pretext", html)

    def test_heading_is_not_marked(self):
        html = _render("## What happened: something")
        self.assertNotIn("pretext", html)


class RawHtml(unittest.TestCase):
    """Story text, advisory fields and write-ups come from ingested articles and
    from the model, and the md filters mark their output safe. HTML in that text
    has to arrive as text, not as markup in the analyst's page."""

    def test_html_in_the_source_is_escaped(self):
        # The attribute names survive as text, which is inert; what matters is
        # that no tag is opened.
        for text, tag in [("<script>alert(1)</script>", "<script"),
                          ("<img src=x onerror=alert(1)>", "<img"),
                          ("before <b onmouseover=alert(1)>hover</b> after", "<b ")]:
            with self.subTest(text=text):
                html = md_to_html(text)
                self.assertNotIn(tag, html)
                self.assertIn("&lt;", html)

    def test_html_is_escaped_inline_too(self):
        self.assertNotIn("<script", md_to_html_inline("<script>alert(1)</script>"))

    def test_markdown_itself_still_renders(self):
        html = md_to_html("**bold** and [link](https://example.org)\nsecond line")
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn('<a href="https://example.org">link</a>', html)
        self.assertIn("<br />", html)


if __name__ == "__main__":
    unittest.main()
