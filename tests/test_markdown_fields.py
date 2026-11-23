"""Markdown fields: saved as typed, and shown as Markdown wherever they go.

The briefing edit page and the manual entry page put their Markdown fields in
the shared editor of _markdown_field_js.html, which they opt into with
data-markdown. The textarea stays the form field, so what an analyst typed is
what the route saves: a briefing posted from the edit form reaches MISP with
every field as typed and reads back the same. Its bold, italic, headings, lists,
quotes, tables and code then render as such in the PDF, the mail, the pages and
the briefing's report on MISP, and raw HTML in it stays text.

Story labels stored as plain "What happened:" open in the editor as
**What happened:**, which is how they are shown everywhere, and a drafted story
has them so too.

MISP is patched; the database, the collection cache and the log are temporary.

    python -m unittest tests.test_markdown_fields
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP

import config
from analyser import llm
from notifier import product_email
from webapp import audit, collection_cache, create_app, job_store, misp_store
from webapp.routes import daily_briefing, data_collection
from webapp.utils import bold_lead_labels, mark_lead_labels, md_to_html

UUID = "083cbc49-3d45-461f-a637-333626b07e60"

# Everything an analyst might use, with Windows line ends as a browser posts them.
MARKDOWN = (
    "**What happened:** A *new* campaign hit _Belgian_ hauliers.\r\n"
    "Why it matters: the same crew as in October.\r\n"
    "\r\n"
    "## Indicators\r\n"
    "\r\n"
    "- `evil[.]be`\r\n"
    "- 192.0.2.10\r\n"
    "  - seen twice\r\n"
    "\r\n"
    "1. Patch\r\n"
    "2. Hunt\r\n"
    "\r\n"
    "> Quoted from the vendor.\r\n"
    "\r\n"
    "| Host | Seen |\r\n"
    "|------|------|\r\n"
    "| web1 | yes |\r\n"
    "\r\n"
    "<script>alert(1)</script> & <b>raw</b>"
)

# What the Markdown above has to come out as, wherever it is rendered.
RENDERED = [
    "<strong>What happened:</strong>",
    "<em>new</em>",
    "<em>Belgian</em>",
    ">Indicators</h2>",
    "<code>evil[.]be</code>",
    "<ol>",
    "<blockquote",
    "<table",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&lt;b&gt;raw&lt;/b&gt;",
]

FIELDS = ("summary", "escalations", "notes", "detection_rules")


def _briefing_data(**changes):
    data = {
        "date": "2026-11-22", "title": "Daily briefing", "author": "analyst", "tlp": "clear",
        "review_state": "draft", "summary_stale": False,
        "stories": [{"title": "Hauliers hit", "content": MARKDOWN, "source_url": "", "source_event_uuid": ""}],
        **{field: MARKDOWN for field in FIELDS},
    }
    data.update(changes)
    return data


def _through_misp(data):
    """The briefing as MISP hands it back: written as zsazsa writes it, then
    read from the JSON of the event."""
    event = MISPEvent()
    event.info = "Daily briefing"
    event.uuid = UUID
    event.date = "2026-11-22"
    event.add_object(misp_store._briefing_obj(data))
    for i, story in enumerate(data["stories"], 1):
        report = misp_store._briefing_story_report(i, story)
        # The id is MISP's, given when it stores the report.
        event.add_event_report(report.name, report.content).id = str(i)
    stored = MISPEvent()
    stored.from_json(event.to_json())
    return misp_store._briefing_ns(stored)


class App(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp) / "cache.db")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(audit, "record"),
            mock.patch.multiple(misp_store, galaxy_geography=mock.Mock(return_value=[]),
                                galaxy_sectors=mock.Mock(return_value=[]),
                                galaxy_threat_actors=mock.Mock(return_value=[]),
                                galaxy_mitre_attack_patterns=mock.Mock(return_value=[]),
                                list_product_feedback=mock.Mock(return_value=[]),
                                list_stakeholders=mock.Mock(return_value=[])),
        ):
            self.enterContext(patch)
        app = create_app()
        app.testing = True
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")


class BriefingEditPage(App):
    def edit_page(self, briefing):
        with mock.patch.object(misp_store, "get_briefing", return_value=briefing):
            return self.page(f"/briefing/{UUID}/edit")

    def test_every_markdown_field_is_in_the_editor(self):
        page = self.edit_page(_through_misp(_briefing_data()))
        names = [t["name"] for t in page.select("textarea[data-markdown]")]
        self.assertEqual(names, ["summary", "story_1_content", "escalations", "notes", "detection_rules"])
        script = str(page)
        self.assertIn("window.zsazsaMarkdownField = function", script)
        self.assertIn("marked.min.js", script)
        # A story added on the page gets the editor too.
        self.assertIn("zsazsaMarkdownField(document.querySelector('#pane-story-' + idx + ' .story-content'))", script)

    def test_the_fields_open_with_the_text_as_stored(self):
        page = self.edit_page(_through_misp(_briefing_data()))
        for name in ("escalations", "notes", "detection_rules"):
            text = page.select_one(f'textarea[name="{name}"]').text
            self.assertEqual(text.replace("\r\n", "\n"), MARKDOWN.replace("\r\n", "\n"))

    def test_plain_story_labels_open_in_bold(self):
        story = "What happened: ACME was hit.\nWho is affected: EU transport.\nSee CVE-2026-1: not a label."
        page = self.edit_page(_through_misp(_briefing_data(
            stories=[{"title": "ACME", "content": story}], summary="Why it matters: two of eight.")))
        self.assertEqual(page.select_one('textarea[name="story_1_content"]').text,
                         "**What happened:** ACME was hit.\n**Who is affected:** EU transport.\nSee CVE-2026-1: not a label.")
        self.assertEqual(page.select_one('textarea[name="summary"]').text, "**Why it matters:** two of eight.")


class BriefingSave(App):
    def post(self, **fields):
        form = {"csrf_token": "tok", "date": "2026-11-22", "title": "Daily briefing", "author": "analyst",
                "tlp": "clear", "story_1_title": "Hauliers hit", **fields}
        stored = _through_misp(_briefing_data())
        with mock.patch.object(misp_store, "get_briefing", return_value=stored), \
             mock.patch.object(misp_store, "update_briefing") as update:
            response = self.client.post(f"/briefing/{UUID}/edit", data=form)
        self.assertEqual(response.status_code, 302)
        return update.call_args[0][1]

    def test_what_was_typed_is_what_is_saved(self):
        data = self.post(story_1_content=MARKDOWN, **{field: MARKDOWN for field in FIELDS})
        for field in FIELDS:
            self.assertEqual(data[field], MARKDOWN, field)
        self.assertEqual(data["stories"][0]["content"], MARKDOWN)

    def test_a_plain_label_typed_is_not_rewritten_on_save(self):
        data = self.post(story_1_content="Note: as typed.", notes="Note: as typed.")
        self.assertEqual((data["stories"][0]["content"], data["notes"]), ("Note: as typed.", "Note: as typed."))

    def test_only_the_blank_space_around_a_field_goes(self):
        data = self.post(story_1_content="\r\n  - one\r\n  - two  \r\n\r\n", notes="  \r\n")
        self.assertEqual((data["stories"][0]["content"], data["notes"]), ("- one\r\n  - two", ""))

    def test_misp_gives_back_what_was_saved(self):
        briefing = _through_misp(_briefing_data())
        for field in FIELDS:
            self.assertEqual(getattr(briefing, field), MARKDOWN, field)
        self.assertEqual(briefing.stories[0].content, MARKDOWN)

    def test_a_story_report_is_the_text_as_json(self):
        report = misp_store._briefing_story_report(1, {"content": MARKDOWN})
        self.assertEqual(json.loads(report.content)["content"], MARKDOWN)


class BriefingRendered(App):
    """Each output of a saved briefing renders every field as Markdown."""

    def setUp(self):
        super().setUp()
        self.briefing = _through_misp(_briefing_data())

    def assertRendered(self, html, what):
        for expected in RENDERED:
            self.assertIn(expected, html, f"{what}: {expected}")
        self.assertNotIn("<script>alert", html, what)

    def test_the_pdf(self):
        with mock.patch.object(misp_store, "get_briefing", return_value=self.briefing), \
             mock.patch.object(daily_briefing.weasyprint, "HTML") as weasy:
            weasy.return_value.write_pdf.return_value = b"%PDF"
            self.client.get(f"/briefing/{UUID}/pdf")
        soup = BeautifulSoup(weasy.call_args.kwargs["string"], "html.parser")
        boxes = soup.select(".section-box") + soup.select(".story-body")
        # The summary, the story, escalations, notes and detection rules.
        self.assertEqual(len(boxes), 5)
        for box in boxes:
            self.assertRendered(str(box), "PDF")

    def test_the_mail(self):
        html = product_email.briefing_html(self.briefing)
        for heading in ("Briefing summary", "Escalations", "Notes", "Detection rules"):
            section = html.split(f">{heading}</div>", 1)[1].split("</div>", 1)[0]
            self.assertRendered(section, f"mail {heading}")
        story = html.split(">Hauliers hit<", 1)[1].split(">Briefing summary</div>", 1)[0]
        self.assertRendered(story, "mail story")

    def test_the_mail_styles_what_has_no_stylesheet(self):
        """Without inline styles a mail shows a table as loose words and a quote as an indent."""
        html = product_email._body_html("| a | b |\n|---|--:|\n| 1 | 2 |\n\n> q", lead_labels=False)
        self.assertIn('<td style="border:1px solid #e2e8f0;padding:4px 8px;">1</td>', html)
        # An aligned column keeps its alignment, after the style of the cell.
        self.assertIn('<td style="border:1px solid #e2e8f0;padding:4px 8px;text-align:right">2</td>', html)
        self.assertIn('<blockquote style="margin:0 0 10px;padding:0 0 0 10px;border-left:3px solid #cbd5e1;', html)

    def test_only_the_story_and_summary_have_their_labels_set_in_bold(self):
        briefing = _through_misp(_briefing_data(stories=[{"title": "S", "content": "Note: x"}],
                                                summary="Note: x", notes="Note: x", escalations="Note: x"))
        html = product_email.briefing_html(briefing)
        self.assertEqual(html.count('<span style="font-weight:700;">Note:</span>'), 2)

    def test_the_detail_page(self):
        with mock.patch.object(misp_store, "get_briefing", return_value=self.briefing):
            page = self.page(f"/briefing/{UUID}")
        # The summary and the stories are rendered in the browser, from the text as stored.
        self.assertEqual([el["data-md"] for el in page.select(".report-md-body[data-md]")][:2], [MARKDOWN, MARKDOWN])
        cards = {card.select_one(".card-header").get_text(strip=True): card.select_one(".card-body")
                 for card in page.select(".card.content-card") if card.select_one(".card-header")}
        for heading in ("Escalations", "Notes", "Detection rules"):
            self.assertRendered(str(cards[heading]), f"page {heading}")
        self.assertIsNotNone(cards["Detection rules"].select_one("[data-rulezet-rules] strong"))

    def test_the_report_on_misp(self):
        """MISP renders the briefing's report itself, so the text goes in as written."""
        report = misp_store.render_briefing_markdown(self.briefing)
        self.assertEqual(report.count(MARKDOWN), 5)


class ManualEntry(App):
    def test_the_content_and_summary_are_in_the_editor(self):
        sources = [mock.Mock(enabled=True)]
        sources[0].name = "ISAC Mattermost"
        with mock.patch.object(misp_store, "list_collection_sources", return_value=sources):
            page = self.page("/collection/manual/new")
        self.assertEqual([t["name"] for t in page.select("textarea[data-markdown]")], ["description", "summary"])
        self.assertIsNone(page.select_one(".md-tabs"))
        self.assertIn("zsazsaRefreshMarkdown(summary)", str(page))

    def test_what_was_typed_reaches_misp(self):
        sources = [mock.Mock(enabled=True)]
        sources[0].name = "ISAC Mattermost"
        with mock.patch.object(misp_store, "list_collection_sources", return_value=sources), \
             mock.patch.object(misp_store, "create_manual_collection_event", return_value="u1") as create, \
             mock.patch.object(data_collection, "_cache_manual_event"):
            self.client.post("/collection/manual/new", data={
                "csrf_token": "tok", "source": "ISAC Mattermost", "title": "Web shells", "tlp": "amber",
                "description": MARKDOWN, "summary": MARKDOWN})
        data = create.call_args[0][0]
        self.assertEqual((data["description"], data["summary"]), (MARKDOWN, MARKDOWN))

        misp = mock.create_autospec(PyMISP, instance=True)
        created = mock.Mock(id="7", uuid="u1")
        with mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_build_scope_tags", return_value=[]):
            misp_store._fill_manual_collection_event(misp, created, data, "Web shells")
        reports = [c.args[1] for c in misp.add_event_report.call_args_list]
        self.assertEqual([r.content for r in reports], [MARKDOWN, MARKDOWN])


class LeadLabels(unittest.TestCase):
    def test_a_plain_label_becomes_bold(self):
        self.assertEqual(bold_lead_labels("What happened: x\r\n  Who is affected: y"),
                         "**What happened:** x\r\n  **Who is affected:** y")

    def test_what_is_not_a_label_is_left_alone(self):
        for text in ("**What happened:** x", "CVE-2026-1234: x", "https://example.org", "Ends with:",
                     "- Note: in a list", "## Note: a heading", "    Code: indented", "a sentence. Then: x",
                     "Label:no space", ""):
            self.assertEqual(bold_lead_labels(text), text)

    def test_a_fenced_block_is_left_alone(self):
        text = "Note: x\n```\nKey: value\n```\n~~~yaml\nKey: value\n~~~\nAfter: y"
        self.assertEqual(bold_lead_labels(text),
                         "**Note:** x\n```\nKey: value\n```\n~~~yaml\nKey: value\n~~~\n**After:** y")

    def test_it_renders_as_the_plain_label_did(self):
        """mark_lead_labels() bolds the plain label when the text is shown, so
        an old story looks the same whether or not it was opened in the editor."""
        text = "What happened: x\nWho is affected: y\n\nWhy it matters: z"
        plain = mark_lead_labels(md_to_html(text), "<strong>").replace("</span>", "</strong>")
        self.assertEqual(md_to_html(bold_lead_labels(text)), plain)

    def test_a_drafted_story_has_its_labels_in_bold(self):
        raw = "What happened: A GPO was abused.\nWho is affected: A manufacturer.\nThreat actor type: Unknown"
        with mock.patch.object(llm, "_call", return_value=raw), \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"), \
             mock.patch.object(llm, "_feature_cfg", return_value={}):
            story, _actor_type = llm.draft_briefing_story("article")
        self.assertEqual(story, "**What happened:** A GPO was abused.\n**Who is affected:** A manufacturer.")


if __name__ == "__main__":
    unittest.main()
