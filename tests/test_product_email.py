"""Tests for the branded HTML product e-mail builder.

Covers the markdown split every product renderer feeds it (title, "**Key:**"
metadata, "## section" blocks) and the daily briefing body built from the
briefing object.

    python -m unittest tests.test_product_email
"""

import html as html_module
import re
import unittest
from datetime import datetime
from types import SimpleNamespace

from notifier import product_email
from webapp import branding


FIA_MARKDOWN = """# Flash intel alert: LockBit hits logistics

**ID:** FIA-00042
**Classification:** tlp:amber
**Author:** koen

---

## Summary

We assess with **high** confidence that this is ongoing.

---

## Why it matters

- **Likely impact:** unspecified
"""


class SplitMarkdown(unittest.TestCase):
    def test_title_metadata_and_body(self):
        title, meta, body = product_email._split_markdown(FIA_MARKDOWN)
        self.assertEqual(title, "Flash intel alert: LockBit hits logistics")
        self.assertEqual(meta, [("ID", "FIA-00042"), ("Classification", "tlp:amber"),
                                ("Author", "koen")])
        # The body keeps the content and none of the metadata.
        self.assertIn("## Summary", body)
        self.assertNotIn("FIA-00042", body)

    def test_bold_text_further_down_is_not_taken_for_metadata(self):
        markdown = "# Feed\n\nA description.\n\n**12 indicators:** as of today.\n"
        _title, meta, body = product_email._split_markdown(markdown)
        self.assertEqual(meta, [])
        self.assertIn("12 indicators", body)

    def test_sections_split_on_headings(self):
        _title, _meta, body = product_email._split_markdown(FIA_MARKDOWN)
        self.assertEqual([h for h, _ in product_email._sections(body)],
                         ["Summary", "Why it matters"])


class StoryBlock(unittest.TestCase):
    def test_carries_the_story_number_and_title(self):
        block = product_email._story_block(branding.brand(), 2, "Second story",
                                           "<p>body</p>", "")
        self.assertIn(">2<", block)
        self.assertIn("Second story", block)
        self.assertIn("<p>body</p>", block)


class MarkdownHtml(unittest.TestCase):
    def test_renders_header_title_and_sections(self):
        html = product_email.markdown_html(FIA_MARKDOWN, "Flash Intel Alert")
        self.assertIn("Flash Intel Alert", html)
        self.assertIn("LockBit hits logistics", html)
        self.assertIn("TLP:AMBER", html)
        self.assertIn("Summary", html)
        self.assertIn("<strong>high</strong>", html)

    def test_bold_field_labels_render_as_muted_pretext(self):
        html = product_email.markdown_html(FIA_MARKDOWN, "Flash Intel Alert")
        self.assertNotIn("<strong>Likely impact:</strong>", html)
        self.assertIn("Likely impact:</span>", html)


def _briefing():
    story = SimpleNamespace(
        title="Ransomware crew hits logistics",
        content="ACME was hit.",
        source_url="https://example.org/article",
        source_event_uuid="8bff3417-1af2-4ccb-81be-26a8bc99605f",
        geographic_scope=["Belgium"], sectors=["Transport"], threat_actors=["LockBit"],
        techniques=["T1566"], threat_actor_types=["Cybercriminals"],
        source_reliability="B", information_credibility="2", cti_evaluation={},
    )
    return SimpleNamespace(
        date="2026-07-30", title="Daily briefing", author="koen", tlp="clear",
        created_at=datetime(2026, 7, 30), stories=[story],
        escalations="None today.", notes="", summary="", summary_stale=False,
        geographic_scope=[], sectors=[], threat_actors=[], mitre_attack_techniques=[],
        threat_types=[], technology=[], vendor=[], incident=[], campaign=[],
    )


class BriefingHtml(unittest.TestCase):
    def setUp(self):
        self.html = product_email.briefing_html(_briefing(), "https://cti.test/briefing/1")

    def test_stories_keep_their_title(self):
        self.assertIn("Ransomware crew hits logistics", self.html)

    def test_scope_is_labelled_per_category(self):
        for label in ("Geographic scope:", "Sector:", "Threat actor:", "Techniques:"):
            self.assertIn(label, self.html)

    def test_techniques_carry_their_name(self):
        self.assertIn("T1566 - Phishing", self.html)

    def test_source_misp_event_is_not_listed(self):
        self.assertNotIn("8bff3417-1af2-4ccb-81be-26a8bc99605f", self.html)

    def test_preview_link_is_included(self):
        self.assertIn("https://cti.test/briefing/1", self.html)

    def test_summary_opens_the_mail_above_the_stories(self):
        briefing = _briefing()
        briefing.summary = "Three stories, all ransomware against EU transport."
        html = product_email.briefing_html(briefing)
        self.assertIn("Three stories, all ransomware against EU transport.", html)
        self.assertLess(html.index("Briefing summary"), html.index("Today&#x27;s stories"))

    def test_no_summary_section_without_a_summary(self):
        self.assertNotIn(">Briefing summary<", self.html)

    def test_story_lead_labels_are_muted(self):
        # Story labels are plain prose, not bold, so the bold-label rule alone
        # would leave them looking like content.
        briefing = _briefing()
        briefing.stories[0].content = (
            "What happened: ACME was hit.\nWho is affected: EU transport."
        )
        html = product_email.briefing_html(briefing)
        for label in ("What happened:", "Who is affected:"):
            self.assertIn(f"{label}</span>", html)
        self.assertIn("ACME was hit.", html)

    def test_story_footer_lists_every_scope_row(self):
        """Guards the per-story rows, which the scope summary would otherwise mask."""
        from webapp.misp_store import briefing_story_scope_rows

        story = _briefing().stories[0]
        footer = product_email._story_footer(story, branding.brand())
        for label, values in briefing_story_scope_rows(story):
            self.assertIn(label + ":", footer)
            for value in values:
                self.assertIn(value, footer)

    def test_neither_body_loses_content_the_other_keeps(self):
        """The two bodies are built by different code, so they can drift apart.

        briefing_html() reads the briefing object; the plaintext alternative is
        render_briefing_markdown(). This is a coarse guard: it catches a story or
        a scope category disappearing from one body, not where it is placed.
        """
        from webapp.misp_store import briefing_story_scope_rows, render_briefing_markdown

        briefing = _briefing()
        text = render_briefing_markdown(briefing)
        rich = html_module.unescape(re.sub(r"<[^>]+>", " ", product_email.briefing_html(briefing)))
        for story in briefing.stories:
            self.assertIn(story.title, text)
            self.assertIn(story.title, rich)
            for _label, values in briefing_story_scope_rows(story):
                for value in values:
                    self.assertIn(value, text)
                    self.assertIn(value, rich)


if __name__ == "__main__":
    unittest.main()
