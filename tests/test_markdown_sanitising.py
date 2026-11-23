"""Markdown rendered in the browser goes through DOMPurify.

Report and article text comes from outside: feeds, newsletters, the model. Two
pages fell back to inserting marked's raw HTML when DOMPurify was missing, so a
CDN that served marked but not DOMPurify turned a report into script on the
analyst's page. Every call to marked.parse now sits inside DOMPurify.sanitize,
and without DOMPurify the text is shown as text.

Both libraries load from one include, _markdown_js.html, pinned by hash, and
pages render through its zsazsaRenderMarkdown, or zsazsaRenderMarkdownBlocks
for the Markdown field, so the fallback and the pin cannot drift apart page by
page again. A page has that include itself, or through _markdown_field_js.html
or _preview_toggle_js.html.
Every script from a CDN is pinned by hash.

    python -m unittest tests.test_markdown_sanitising
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent / "webapp"


class MarkedOutputIsSanitised(unittest.TestCase):
    def test_every_marked_parse_is_wrapped_in_dompurify(self):
        sources = list((_ROOT / "templates").rglob("*.html")) + list((_ROOT / "static").rglob("*.js"))
        offenders = []
        for path in sources:
            text = path.read_text(encoding="utf-8")
            if len(re.findall(r"marked\.parser?\(", text)) != len(re.findall(r"DOMPurify\.sanitize\(marked\.parser?\(", text)):
                offenders.append(str(path.relative_to(_ROOT)))
        self.assertEqual(offenders, [])


class OneIncludeLoadsThem(unittest.TestCase):
    def templates(self):
        return {str(p.relative_to(_ROOT)): p.read_text(encoding="utf-8")
                for p in (_ROOT / "templates").rglob("*.html")}

    def test_no_page_loads_or_calls_the_libraries_itself(self):
        offenders = [name for name, text in self.templates().items()
                     if name != "templates/_markdown_js.html"
                     and ("marked.min.js" in text or "DOMPurify." in text or re.search(r"\bmarked\.\w+\(", text))]
        self.assertEqual(offenders, [])

    def test_a_page_that_renders_markdown_includes_the_helper(self):
        offenders = [name for name, text in self.templates().items()
                     if "zsazsaRenderMarkdown" in text and name != "templates/_markdown_js.html"
                     and '{% include "_markdown_js.html" %}' not in text
                     and '{% include "_markdown_field_js.html" %}' not in text
                     and '{% include "_preview_toggle_js.html" %}' not in text]
        self.assertEqual(offenders, [])

    def test_every_cdn_script_and_stylesheet_is_pinned_by_hash(self):
        tags = [tag for text in self.templates().values()
                for tag in re.findall(r"<(?:script|link)\b[^>]*https://cdnjs[^>]*>", text)]
        self.assertTrue(tags)
        self.assertEqual([t for t in tags if 'integrity="sha512-' not in t], [])
        script = (_ROOT / "static/js/rulezet-code-modal.js").read_text(encoding="utf-8")
        self.assertIn("s.integrity = 'sha512-", script)


if __name__ == "__main__":
    unittest.main()
