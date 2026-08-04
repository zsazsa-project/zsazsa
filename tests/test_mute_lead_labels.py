"""Briefing story labels read as pretext, not as content.

The five story lines open with "What happened:", "Who is affected:", … as plain
text. mute_lead_labels wraps those in .pretext so the PDF and the on-screen
preview set them smaller and lighter than the sentence they introduce.

    python -m unittest tests.test_mute_lead_labels
"""

import unittest

from webapp.utils import md_to_html, mute_lead_labels


def _render(text):
    return mute_lead_labels(md_to_html(text))


class MuteLeadLabels(unittest.TestCase):
    def test_every_story_label_is_muted(self):
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

    def test_colon_inside_a_sentence_is_not_muted(self):
        html = _render("Exploitation was observed in the wild: two victims so far.")
        self.assertNotIn("pretext", html)

    def test_indicator_opening_a_line_is_not_muted(self):
        html = _render("`CVE-2024-1234`: exploited in the wild.")
        self.assertNotIn("pretext", html)

    def test_heading_is_not_muted(self):
        html = _render("## What happened: something")
        self.assertNotIn("pretext", html)


if __name__ == "__main__":
    unittest.main()
