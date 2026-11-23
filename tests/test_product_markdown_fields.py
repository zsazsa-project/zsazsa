"""The Markdown fields of the flash intel alert, the vulnerability advisory, the
threat actor profile, the threat landscape report and the detection engineering
request: saved as typed, and shown as Markdown wherever they go.

Their forms put the fields in the shared editor (data-markdown). What an analyst
typed is what the route saves and what MISP gives back, observed facts,
recommended actions, log sources and test cases included, which keep their blank
lines and indents now that they are Markdown rather than one item per line.
Saved before that, they open as a "- " list. Bold, italic, headings, lists,
quotes, tables and code then render as such on the record's page, in the review
queue, in the PDF and in the mail, and a heading an analyst wrote stays inside
its section of the mail rather than starting one of its own. The Diamond Model
shows the text without its markup. A field too narrow for side by side keeps the
height its rows give it.

MISP is patched; the database, the collection cache and the log are temporary.

    python -m unittest tests.test_product_markdown_fields
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent

import config
from notifier import product_email
from webapp import audit, collection_cache, create_app, job_store, misp_store
from webapp.routes import threat_actor_profile as tap_routes
from webapp.routes import threat_landscape as tlr_routes
from webapp.utils import list_item_count, markdown_list, md_to_text, nest_headings

UUID = "359a6e97-de2f-4bd2-9e29-d04a95d9a17a"

MARKDOWN = (
    "**Bold** and *italic* and _more italic_.\r\n"
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
TYPED = MARKDOWN.replace("\r\n", "\n")

# What MARKDOWN has to come out as, rendered by zsazsa.
RENDERED = ["<strong>Bold</strong>", "<em>italic</em>", "<em>more italic</em>", "Indicators</h",
            "<code>evil[.]be</code>", "<ol>", "<blockquote", "<table", "&lt;script&gt;", "&lt;b&gt;raw&lt;/b&gt;"]

FIA_FIELDS = ("summary", "what_happened", "actor_context", "write_up", "intelligence_gaps")
VEA_FIELDS = ("summary", "immediate_actions")
TAP_FIELDS = ("summary", "capabilities", "mode_of_operation", "infrastructure", "attribution_rationale")
TLR_FIELDS = ("executive_summary", "purpose", "top_threats", "trending_actors",
              *(key for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES),
              "key_incidents", "recommendations", "outlook", "methodology")
# In the order of the form, the findings of the threat assessment after the top threats.
TLR_FORM = (*TLR_FIELDS[:3], "section_findings", *TLR_FIELDS[3:])
DER_FIELDS = ("hypothesis", "log_sources", "expected_output", "test_cases")
# The fields kept as a list of lines.
LINES = ("what_happened", "immediate_actions", "log_sources", "test_cases")


def _through_misp(obj, read):
    """A record as MISP hands it back: its object written as zsazsa writes it,
    then read from the JSON of the event."""
    event = MISPEvent()
    event.info, event.uuid, event.date = "Record", UUID, "2026-11-22"
    event.add_object(obj)
    stored = MISPEvent()
    stored.from_json(event.to_json())
    return read(stored)


def _data(fields, **extra):
    return {"title": "Record", "tlp": "amber",
            **{f: TYPED.split("\n") if f in LINES else TYPED for f in fields}, **extra}


def fia(**extra):
    return _through_misp(misp_store._fia_obj(_data(FIA_FIELDS, fia_id="FIA-00042", **extra)), misp_store._fia_ns)


def vea(**extra):
    extra.setdefault("cve_id", "CVE-2026-1234")
    return _through_misp(misp_store._vea_obj(_data(VEA_FIELDS, vea_id="VEA-00042", **extra)), misp_store._vea_ns)


def tap(**extra):
    return _through_misp(misp_store._tap_obj(_data(TAP_FIELDS, tap_id="TAP-00042", **extra)), misp_store._tap_ns)


def tlr(**extra):
    section = {"title": "Ransomware", "threat_type": "Ransomware", "findings": TYPED, "confidence": "",
               "key_drivers": "", "alternative_hypotheses": "", "recommendations": ""}
    data = _data(TLR_FIELDS, tlr_id="TLR-00042", threat_sections=[section], **extra)
    return _through_misp(misp_store._tlr_obj(data), misp_store._tlr_ns)


def der(**extra):
    return _through_misp(misp_store._der_obj(_data(DER_FIELDS, der_id="DER-00042", **extra)), misp_store._der_ns)


def value(record, field):
    stored = getattr(record, field)
    return "\n".join(stored) if field in LINES else stored


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
                                list_pirs=mock.Mock(return_value=[]),
                                list_stakeholders=mock.Mock(return_value=[]),
                                list_product_feedback=mock.Mock(return_value=[]),
                                list_indicator_feeds=mock.Mock(return_value=[])),
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

    def editor(self, page):
        return [t["name"] for t in page.select("textarea[data-markdown]")]

    def assertRendered(self, html, what):
        for expected in RENDERED:
            self.assertIn(expected, html, f"{what}: {expected}")
        self.assertNotIn("<script>alert", html, what)

    def assertOneSectionEach(self, html, what):
        """The heading the analyst wrote is in its section, not a section of its own."""
        self.assertNotIn(">Indicators</div>", html, what)
        self.assertIn(">Indicators</h", html, what)

    def pdf(self, path):
        with mock.patch("weasyprint.HTML") as weasy:
            weasy.return_value.write_pdf.return_value = b"%PDF"
            response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return weasy.call_args.kwargs["string"]


class FlashIntel(App):
    def test_the_form_has_the_editor_on_its_markdown_fields(self):
        with mock.patch.object(misp_store, "get_fia", return_value=fia()):
            for path in ("/products/flash-intel/new", f"/products/flash-intel/{UUID}/edit"):
                page = self.page(path)
                self.assertEqual(self.editor(page), list(FIA_FIELDS), path)
                self.assertIn("window.zsazsaMarkdownField = function", str(page))

    def test_the_form_opens_with_the_text_as_saved(self):
        with mock.patch.object(misp_store, "get_fia", return_value=fia()):
            page = self.page(f"/products/flash-intel/{UUID}/edit")
        for field in FIA_FIELDS:
            self.assertEqual(page.select_one(f'textarea[name="{field}"]').text.lstrip("\n"), TYPED, field)

    def test_facts_saved_one_per_line_open_as_a_list(self):
        with mock.patch.object(misp_store, "get_fia", return_value=fia(what_happened=["VPN abused", "Data taken"])):
            page = self.page(f"/products/flash-intel/{UUID}/edit")
        self.assertEqual(page.select_one('textarea[name="what_happened"]').text.lstrip("\n"), "- VPN abused\n- Data taken")

    def test_what_was_typed_is_what_is_saved(self):
        form = {"csrf_token": "tok", "title": "Record", "tlp": "amber", "audience": "SOC", "action": "save",
                **{f: MARKDOWN for f in FIA_FIELDS}}
        with mock.patch.object(misp_store, "get_fia", return_value=fia()), \
             mock.patch.object(misp_store, "update_fia") as update:
            self.client.post(f"/products/flash-intel/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        for field in FIA_FIELDS:
            saved = "\n".join(data[field]) if field in LINES else data[field]
            self.assertEqual(saved.replace("\r\n", "\n"), TYPED, field)
        self.assertEqual(value(_through_misp(misp_store._fia_obj(data), misp_store._fia_ns), "what_happened"), TYPED)

    def test_misp_gives_back_what_was_saved(self):
        record = fia()
        for field in FIA_FIELDS:
            self.assertEqual(value(record, field), TYPED, field)

    def test_the_page_renders_every_field_from_the_text_as_saved(self):
        with mock.patch.object(misp_store, "get_fia", return_value=fia()):
            page = self.page(f"/products/flash-intel/{UUID}")
        shown = [el["data-md"] for el in page.select(".report-md-body[data-md]")]
        # Summary, observed facts, threat actor context, write-up, intelligence gaps.
        self.assertEqual(shown.count(TYPED), 5)

    def test_the_review_queue_renders_them_too(self):
        with mock.patch.object(misp_store, "list_fias", return_value=[fia()]):
            page = self.page("/products/flash-intel/")
        self.assertEqual([el["data-md"] for el in page.select(".report-md-body[data-md]")].count(TYPED), 5)

    def test_the_pdf(self):
        with mock.patch.object(misp_store, "get_fia", return_value=fia()):
            html = self.pdf(f"/products/flash-intel/{UUID}/pdf")
        soup = BeautifulSoup(html, "html.parser")
        boxes = [box for box in soup.select(".section-box") if "Bold" in box.get_text()]
        # Summary, what happened, why it matters (context and write-up), gaps.
        self.assertEqual(len(boxes), 4)
        for box in boxes:
            self.assertRendered(str(box), "PDF")
            # Longer than a page, it goes on over the break.
            self.assertIn("prose", box["class"])
        self.assertIn("Threat actor context:", html)

    def test_the_mail_and_the_markdown_every_channel_gets(self):
        markdown = misp_store.render_fia_markdown(fia())
        self.assertNotIn("\n## Indicators", markdown)
        self.assertEqual(markdown.count("#### Indicators"), 5)
        html = product_email.markdown_html(markdown, "Flash Intel Alert")
        self.assertOneSectionEach(html, "mail")
        self.assertEqual(html.count("<table style"), 5)
        self.assertRendered(html, "mail")

    def test_the_drafted_facts_are_a_list(self):
        from analyser.products import flash_intel as drafts
        self.assertEqual(drafts.parse_fia_draft("## What happened\n- One\n- Two")["what_happened"], ["One", "Two"])


class VulnerabilityAdvisory(App):
    def test_the_form_has_the_editor_on_its_markdown_fields(self):
        with mock.patch.object(misp_store, "get_vea", return_value=vea()):
            for path in ("/products/vea/new", f"/products/vea/{UUID}/edit"):
                page = self.page(path)
                self.assertEqual(self.editor(page), list(VEA_FIELDS), path)

    def test_the_cve_ids_are_one_line_with_the_lookup_beside_them_and_the_summary_under(self):
        with mock.patch.object(misp_store, "get_vea", return_value=vea(cve_id="CVE-2026-1, CVE-2026-2")):
            page = self.page(f"/products/vea/{UUID}/edit")
        cve = page.select_one('input[name="cve_id"]')
        self.assertEqual(cve["value"], "CVE-2026-1, CVE-2026-2")
        self.assertIs(cve.find_next_sibling("button"), page.select_one("#btn-vl-lookup"))
        summary = page.select_one('textarea[name="summary"]')
        self.assertEqual(summary["rows"], "8")
        self.assertIn(summary, cve.find_parent(class_="row").find_all("textarea"))
        self.assertTrue(cve.sourceline < summary.sourceline)

    def test_cve_ids_are_saved_one_line_however_they_were_apart(self):
        for typed in ("CVE-2026-1, CVE-2026-2", "CVE-2026-1 CVE-2026-2", "CVE-2026-1;CVE-2026-2", " CVE-2026-1,\nCVE-2026-2 "):
            with mock.patch.object(misp_store, "get_vea", return_value=vea()), \
                 mock.patch.object(misp_store, "update_vea") as update:
                self.client.post(f"/products/vea/{UUID}/edit", data={"csrf_token": "tok", "title": "T", "cve_id": typed})
            self.assertEqual(update.call_args.args[1]["cve_id"], "CVE-2026-1, CVE-2026-2", typed)

    def test_actions_saved_one_per_line_open_as_a_list(self):
        with mock.patch.object(misp_store, "get_vea", return_value=vea(immediate_actions=["Patch", "Hunt"])):
            page = self.page(f"/products/vea/{UUID}/edit")
        self.assertEqual(page.select_one('textarea[name="immediate_actions"]').text.lstrip("\n"), "- Patch\n- Hunt")

    def test_what_was_typed_is_what_is_saved(self):
        form = {"csrf_token": "tok", "title": "Record", "cve_id": "CVE-2026-1234", **{f: MARKDOWN for f in VEA_FIELDS}}
        with mock.patch.object(misp_store, "get_vea", return_value=vea()), \
             mock.patch.object(misp_store, "update_vea") as update:
            self.client.post(f"/products/vea/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        self.assertEqual(data["summary"].replace("\r\n", "\n"), TYPED)
        self.assertEqual("\n".join(data["immediate_actions"]), TYPED)
        self.assertEqual(value(_through_misp(misp_store._vea_obj(data), misp_store._vea_ns), "immediate_actions"), TYPED)

    def test_the_page_and_the_review_queue(self):
        with mock.patch.object(misp_store, "get_vea", return_value=vea()):
            page = self.page(f"/products/vea/{UUID}")
        self.assertIn(TYPED, [el["data-md"] for el in page.select(".report-md-body[data-md]")])
        actions = page.find(string="Recommended actions").find_parent(class_="card")
        self.assertRendered(str(actions), "page actions")
        with mock.patch.object(misp_store, "list_veas", return_value=[vea()]):
            page = self.page("/products/vea/")
        self.assertIn(TYPED, [el["data-md"] for el in page.select(".report-md-body[data-md]")])
        self.assertRendered(str(page.select_one(".md-body:not([data-md])")), "review actions")

    def test_the_pdf(self):
        with mock.patch.object(misp_store, "get_vea", return_value=vea()):
            soup = BeautifulSoup(self.pdf(f"/products/vea/{UUID}/pdf"), "html.parser")
        boxes = [box for box in soup.select(".section-box") if "Bold" in box.get_text()]
        self.assertEqual(len(boxes), 2)
        for box in boxes:
            self.assertRendered(str(box), "PDF")
            # Longer than a page, it goes on over the break.
            self.assertIn("prose", box["class"])

    def test_the_mail_and_the_markdown_every_channel_gets(self):
        markdown = misp_store.render_vea_markdown(vea())
        self.assertIn("#### Indicators", markdown)
        self.assertIn("##### Indicators", markdown)
        html = product_email.markdown_html(markdown, "Vulnerability Advisory")
        self.assertOneSectionEach(html, "mail")
        for heading in ("Summary", "Recommended actions"):
            self.assertRendered(html.split(f">{heading}</div>", 1)[1].split("</div>", 1)[0], f"mail {heading}")


class ThreatActorProfile(App):
    def test_the_form_has_the_editor_on_its_markdown_fields(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap()):
            for path in ("/products/threat-actor-profile/new", f"/products/threat-actor-profile/{UUID}/edit"):
                page = self.page(path)
                self.assertEqual(self.editor(page), list(TAP_FIELDS), path)
                self.assertIn("window.zsazsaMarkdownField = function", str(page))

    def test_what_was_typed_is_what_is_saved(self):
        form = {"csrf_token": "tok", "title": "Record", "tlp": "amber", "audience": "SOC",
                **{f: MARKDOWN for f in TAP_FIELDS}}
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap()), \
             mock.patch.object(misp_store, "update_threat_actor_profile") as update:
            self.client.post(f"/products/threat-actor-profile/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        for field in TAP_FIELDS:
            self.assertEqual(data[field].replace("\r\n", "\n"), TYPED, field)
        record = _through_misp(misp_store._tap_obj(data), misp_store._tap_ns)
        for field in TAP_FIELDS:
            self.assertEqual(getattr(record, field).replace("\r\n", "\n"), TYPED, field)

    def test_the_page(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap()):
            page = self.page(f"/products/threat-actor-profile/{UUID}")
        self.assertEqual([el["data-md"] for el in page.select(".report-md-body[data-md]")].count(TYPED), 5)
        # The Diamond Model shows the text without its markup.
        for node in page.select(".dm-infra .dm-val, .dm-cap .dm-val"):
            self.assertNotIn("**", node.get_text())
            self.assertIn("Bold and italic", node.get_text())

    def test_the_pdf(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap()):
            soup = BeautifulSoup(self.pdf(f"/products/threat-actor-profile/{UUID}/pdf"), "html.parser")
        boxes = [box for box in soup.select(".section-box") if "Bold" in box.get_text()]
        # Summary, the actor details (three fields) and the attribution.
        self.assertEqual(len(boxes), 3)
        for box in boxes:
            self.assertRendered(str(box), "PDF")
            # Longer than a page, it goes on over the break.
            self.assertIn("prose", box["class"])
        # Under the h3 that labels each of the actor details, a heading written in one is an h4.
        self.assertEqual((str(soup).count("Indicators</h2>"), str(soup).count("Indicators</h4>")), (2, 3))

    def test_the_mail_and_the_markdown_every_channel_gets(self):
        markdown = tap_routes._markdown(tap())
        self.assertEqual(markdown.count("#### Indicators"), 5)
        html = product_email.threat_actor_profile_html(markdown, "amber")
        self.assertOneSectionEach(html, "mail")
        self.assertEqual(html.count("<table style"), 5)
        self.assertRendered(html, "mail")


class ThreatLandscape(App):
    def setUp(self):
        super().setUp()
        for patch in (mock.patch.object(misp_store, "get_tlr", return_value=tlr()),
                      mock.patch.object(misp_store, "list_tlrs", return_value=[tlr()]),
                      mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
                      mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
                      mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]),
                      mock.patch.object(misp_store, "list_veas", return_value=[]),
                      mock.patch.object(tlr_routes, "_queued_events", return_value=[])):
            self.enterContext(patch)

    def test_the_form_has_the_editor_on_its_markdown_fields(self):
        # A new report has no threat assessment yet.
        for path, fields in (("/products/threat-landscape/new", [f for f in TLR_FORM if f != "section_findings"]),
                             (f"/products/threat-landscape/{UUID}/edit", list(TLR_FORM))):
            page = self.page(path)
            self.assertEqual(self.editor(page), fields, path)
            self.assertIn("window.zsazsaMarkdownField = function", str(page))
            # A threat assessment added on the page gets the editor too.
            template = page.select_one("#tlr-section-template")
            self.assertEqual([t["name"] for t in template.select("textarea[data-markdown]")], ["section_findings"])
            self.assertIn("forEach(zsazsaMarkdownField)", str(page))

    def test_the_form_opens_with_the_text_as_saved(self):
        page = self.page(f"/products/threat-landscape/{UUID}/edit")
        for field in TLR_FORM:
            self.assertEqual(page.select_one(f'#tlr-sections textarea[name="{field}"], form > div textarea[name="{field}"]')
                             .text.lstrip("\n"), TYPED, field)

    def test_what_was_typed_is_what_is_saved(self):
        form = {"csrf_token": "tok", "title": "Record", "tlp": "amber",
                **{f"section_{key}": "" for key in misp_store.TLR_SECTION_FIELDS}, "section_title": "Ransomware",
                **{f: MARKDOWN for f in TLR_FORM}}
        with mock.patch.object(misp_store, "update_tlr") as update:
            self.client.post(f"/products/threat-landscape/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        for field in TLR_FIELDS:
            self.assertEqual(data[field].replace("\r\n", "\n"), TYPED, field)
        self.assertEqual(data["threat_sections"][0]["findings"].replace("\r\n", "\n"), TYPED)
        record = _through_misp(misp_store._tlr_obj(data), misp_store._tlr_ns)
        for field in TLR_FIELDS:
            self.assertEqual(getattr(record, field).replace("\r\n", "\n"), TYPED, field)
        self.assertEqual(record.threat_sections[0]["findings"].replace("\r\n", "\n"), TYPED)

    def test_the_page_and_the_list(self):
        page = self.page(f"/products/threat-landscape/{UUID}")
        shown = page.select(".report-md-body[data-md]")
        self.assertEqual([el["data-md"] for el in shown].count(TYPED), len(TLR_FORM))
        # Styled as the editor's preview is.
        self.assertTrue(all("md-body" in el["class"] for el in shown if el["data-md"] == TYPED))
        page = self.page("/products/threat-landscape/")
        # The purpose and the top threats.
        self.assertEqual([el["data-md"] for el in page.select(".report-md-body.md-body[data-md]")].count(TYPED), 2)

    def test_the_pdf_and_the_brief(self):
        soup = BeautifulSoup(self.pdf(f"/products/threat-landscape/{UUID}/pdf"), "html.parser")
        boxes = [box for box in soup.select(".section-box") if "Bold" in box.get_text()]
        # Executive summary, purpose, top threats, the assessment, the actors, key incidents,
        # recommendations, outlook and methodology.
        self.assertEqual(len(boxes), 9)
        for box in boxes:
            self.assertRendered(str(box), "PDF")
            # Longer than a page, it goes on over the break.
            self.assertIn("prose", box["class"])
        # Under the h3 that labels the findings and each kind of actor, a heading written in one is an h4.
        self.assertEqual(str(soup).count("Indicators</h4>"), 5)
        soup = BeautifulSoup(self.pdf(f"/products/threat-landscape/{UUID}/brief.pdf"), "html.parser")
        box = soup.find(string="Bottom line").find_next(class_="section-box")
        self.assertRendered(str(box), "brief")
        self.assertIn("prose", box["class"])

    def test_the_mail_and_the_markdown_every_channel_gets(self):
        markdown = misp_store.render_tlr_markdown(tlr())
        self.assertNotIn("\n## Indicators", markdown)
        self.assertNotIn("\n### Indicators", markdown)
        self.assertEqual(markdown.count("\n#### Indicators"), 8)
        # Under the "### " of the findings and of each kind of actor.
        self.assertEqual(markdown.count("\n##### Indicators"), 5)
        html = product_email.markdown_html(markdown, "Threat Landscape Report")
        self.assertOneSectionEach(html, "mail")
        self.assertEqual(html.count("<table style"), len(TLR_FORM))
        self.assertRendered(html, "mail")


class DetectionEngineering(App):
    def setUp(self):
        super().setUp()
        for patch in (mock.patch.object(misp_store, "get_der", return_value=der()),
                      mock.patch.object(misp_store, "list_ders", return_value=[der()]),
                      mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
                      mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]),
                      mock.patch.object(misp_store, "fetch_source_events", return_value=[])):
            self.enterContext(patch)

    def test_the_form_has_the_editor_on_its_markdown_fields(self):
        for path in ("/products/detection-eng/new", f"/products/detection-eng/{UUID}/edit"):
            page = self.page(path)
            self.assertEqual(self.editor(page), list(DER_FIELDS), path)
            self.assertIn("window.zsazsaMarkdownField = function", str(page))

    def test_the_form_opens_with_the_text_as_saved(self):
        page = self.page(f"/products/detection-eng/{UUID}/edit")
        for field in DER_FIELDS:
            self.assertEqual(page.select_one(f'textarea[name="{field}"]').text.lstrip("\n"), TYPED, field)

    def test_lists_saved_one_per_line_open_as_a_list(self):
        with mock.patch.object(misp_store, "get_der", return_value=der(log_sources=["Sysmon EID 1", "EDR"],
                                                                       test_cases=["Run wmic /node"])):
            page = self.page(f"/products/detection-eng/{UUID}/edit")
        self.assertEqual(page.select_one('textarea[name="log_sources"]').text.lstrip("\n"), "- Sysmon EID 1\n- EDR")
        self.assertEqual(page.select_one('textarea[name="test_cases"]').text.lstrip("\n"), "- Run wmic /node")

    def test_what_was_typed_is_what_is_saved(self):
        form = {"csrf_token": "tok", "title": "Record", "tlp": "amber", **{f: MARKDOWN for f in DER_FIELDS}}
        with mock.patch.object(misp_store, "update_der") as update:
            self.client.post(f"/products/detection-eng/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        record = _through_misp(misp_store._der_obj(data), misp_store._der_ns)
        for field in DER_FIELDS:
            saved = "\n".join(data[field]) if field in LINES else data[field]
            self.assertEqual(saved.replace("\r\n", "\n"), TYPED, field)
            self.assertEqual(value(record, field).replace("\r\n", "\n"), TYPED, field)

    def test_the_page(self):
        page = self.page(f"/products/detection-eng/{UUID}")
        bodies = [str(body) for body in page.select(".md-body") if "Bold" in body.get_text()]
        self.assertEqual(len(bodies), 4)
        for body in bodies:
            self.assertRendered(body, "page")
        # The counts beside the title count the items of the lists, not the lines.
        kpis = [kpi.get_text(" ", strip=True) for kpi in page.select(".record-kpi")]
        self.assertIn("4 log sources", kpis)
        self.assertIn("4 test cases", kpis)

    def test_lists_saved_one_per_line_still_show_as_bullets(self):
        with mock.patch.object(misp_store, "get_der", return_value=der(log_sources=["Sysmon", "EDR"], test_cases=["Run"])):
            page = self.page(f"/products/detection-eng/{UUID}")
            soup = BeautifulSoup(self.pdf(f"/products/detection-eng/{UUID}/pdf"), "html.parser")
        for where in (page, soup):
            self.assertEqual([li.get_text() for li in where.find(string="Log sources").find_next("ul").select("li")],
                             ["Sysmon", "EDR"])
        kpis = [kpi.get_text(" ", strip=True) for kpi in page.select(".record-kpi")]
        self.assertIn("2 log sources", kpis)
        self.assertIn("1 test case", kpis)
        self.assertIn("- Sysmon\n- EDR", misp_store.render_der_markdown(der(log_sources=["Sysmon", "EDR"])))

    def test_the_review_queue(self):
        page = self.page("/products/detection-eng/")
        bodies = [str(body) for body in page.select(".md-body") if "Bold" in body.get_text()]
        # The hypothesis, the log sources and the expected rule output.
        self.assertEqual(len(bodies), 3)
        for body in bodies:
            self.assertRendered(body, "review")

    def test_the_pdf(self):
        soup = BeautifulSoup(self.pdf(f"/products/detection-eng/{UUID}/pdf"), "html.parser")
        boxes = [box for box in soup.select(".section-box") if "Bold" in box.get_text()]
        self.assertEqual(len(boxes), 4)
        for box in boxes:
            self.assertRendered(str(box), "PDF")
            # Longer than a page, it goes on over the break.
            self.assertIn("prose", box["class"])

    def test_the_mail_and_the_markdown_every_channel_gets(self):
        markdown = misp_store.render_der_markdown(der())
        self.assertNotIn("\n## Indicators", markdown)
        self.assertEqual(markdown.count("\n#### Indicators"), 4)
        html = product_email.markdown_html(markdown, "Detection Engineering Request")
        self.assertOneSectionEach(html, "mail")
        self.assertEqual(html.count("<table style"), 4)
        self.assertRendered(html, "mail")


class Helpers(unittest.TestCase):
    def test_lines_saved_one_item_each_become_a_list(self):
        self.assertEqual(markdown_list(["Patch", "Hunt"]), "- Patch\n- Hunt")

    def test_text_that_is_markdown_already_is_left_as_written(self):
        for lines in (["- Patch", "Hunt"], ["Patch", "", "Hunt"], ["| a |", "|---|"], ["## Do", "Patch"], []):
            self.assertEqual(markdown_list(lines), "\n".join(lines))

    def test_headings_go_down_under_the_product_sections(self):
        self.assertEqual(nest_headings("# One\n## Two\n###### Six\n#tag\n```\n## code\n```"),
                         "### One\n#### Two\n###### Six\n#tag\n```\n## code\n```")
        self.assertEqual(nest_headings("## Two", levels=3), "##### Two")

    def test_a_list_counts_its_items_not_its_lines(self):
        self.assertEqual(list_item_count(["- One", "  - under it", "", "- Two"]), 2)
        self.assertEqual(list_item_count(["Sysmon", "EDR"]), 2)
        self.assertEqual(list_item_count(["A paragraph", "over two lines", "", "and another"]), 1)
        self.assertEqual(list_item_count([]), 0)

    def test_a_narrow_field_keeps_its_height_side_by_side_or_not(self):
        """Stacked in a column, a pane given flex: 1 1 0 shrinks to one line
        whatever its rows say, as Escalations and Notes did on the briefing."""
        css = (Path(__file__).parent.parent / "webapp/static/css/app.css").read_text()
        self.assertIn(".md-field.md-stacked .md-panes > * { flex: none; }", css)

    def test_the_diamond_gets_plain_text(self):
        self.assertEqual(md_to_text("**C2** over _HTTPS_\n\n- Cobalt Strike\n- `beacon` & <x>"),
                         "C2 over HTTPS\nCobalt Strike\nbeacon & <x>")


if __name__ == "__main__":
    unittest.main()
