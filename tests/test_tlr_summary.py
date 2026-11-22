"""The executive summary and the drafted methodology of a threat landscape report.

A report opens with its bottom line and its key judgements, each with its
confidence and what it means for the organisation: the wizard takes them, the
report page, the PDF and the Markdown of the mail show them first, and the AI
draft proposes the summary and the judgements but leaves what they mean to the
analyst. The report records which sections the AI drafted. "Draft from the
dataset" writes the methodology from the data: the sources and the period,
what was left out, how the events were rated, what changed in collection since
the previous report, the imported threat reports, where AI was used, and the
limitations. MISP, the cache and the model are patched out; the database and
log are temporary.

    python -m unittest tests.test_tlr_summary
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from werkzeug.datastructures import MultiDict

import config
from analyser import llm
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
JUDGEMENTS = [{"judgement": "Ransomware very likely remains the main threat to the sector.", "confidence": "moderate",
               "implication": "The recovery budget request stands."},
              {"judgement": "Hacktivist DDoS is a nuisance, not a risk.", "confidence": "high", "implication": ""}]


def _entry(n, **fields):
    data = {"event_uuid": f"ev-{n}", "event_info": f"Event {n}", "event_date": "2026-08-0" + str(n),
            "source_id": "scraper", **fields}
    return misp_store._tlr_entry_obj(data)


def _report(entries=(), **fields):
    """A report as MISP holds it, read back as the pages get it."""
    data = {"tlr_id": "TLR-00007", "title": "Q3", "tlp": "amber", "reporting_period": "2026 Q3",
            "period_start": "2026-07-01", "period_end": "2026-09-30", **fields}
    objects = [misp_store._tlr_obj(data)] + list(entries)
    return misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=objects, published=False, date=None))


class Form(unittest.TestCase):
    def test_key_judgements_are_kept_per_row_and_an_empty_one_is_dropped(self):
        form = MultiDict([("kj_judgement", " Ransomware stays. "), ("kj_confidence", "moderate"), ("kj_implication", " Budget "),
                          ("kj_judgement", ""), ("kj_confidence", "high"), ("kj_implication", "lost"),
                          ("kj_judgement", "DDoS is a nuisance"), ("kj_confidence", "certain"), ("kj_implication", "")])
        self.assertEqual(threat_landscape._form_data(form)["key_judgements"],
                         [{"judgement": "Ransomware stays.", "confidence": "moderate", "implication": "Budget"},
                          {"judgement": "DDoS is a nuisance", "confidence": "", "implication": ""}])

    def test_only_the_sections_the_ai_drafts_are_recorded_once_each(self):
        form = MultiDict([("ai_drafted", "top_threats"), ("ai_drafted", "methodology"), ("ai_drafted", "top_threats"),
                          ("ai_drafted", "key_judgements")])
        self.assertEqual(threat_landscape._form_data(form)["ai_drafted"], ["top_threats", "key_judgements"])

    def test_they_are_stored_and_read_back(self):
        report = _report(executive_summary="Ransomware grew.", key_judgements=JUDGEMENTS, ai_drafted=["outlook"])
        self.assertEqual((report.executive_summary, report.key_judgements, report.ai_drafted),
                         ("Ransomware grew.", JUDGEMENTS, ["outlook"]))
        self.assertEqual((_report().key_judgements, _report().ai_drafted), ([], []))

    def test_the_template_declares_them(self):
        path = Path(__file__).parent.parent / "webapp/misp_objects/objects/zsazsa-threat-landscape-report/definition.json"
        declared = json.loads(path.read_text())["attributes"]
        for relation in ("executive-summary", "key-judgements", "ai-drafted"):
            self.assertIn(relation, declared)


class Markdown(unittest.TestCase):
    def test_the_mail_opens_with_the_summary_and_the_judgements(self):
        text = misp_store.render_tlr_markdown(_report(executive_summary="Ransomware grew.", key_judgements=JUDGEMENTS,
                                                      purpose="Budget"))
        summary = text.index("## Executive summary")
        self.assertLess(summary, text.index("## Purpose"))
        self.assertIn("- **Ransomware very likely remains the main threat to the sector** (Moderate confidence). "
                      "*What it means for us:* The recovery budget request stands.", text)
        self.assertIn("- **Hacktivist DDoS is a nuisance, not a risk** (High confidence).\n", text)

    def test_a_report_without_one_has_no_such_section(self):
        self.assertNotIn("Executive summary", misp_store.render_tlr_markdown(_report()))


class TrendDraft(unittest.TestCase):
    def test_the_key_judgements_stay_a_list_of_what_holds(self):
        answer = {"top_threats": ["- a", "- b"], "executive_summary": "Ransomware grew.",
                  "key_judgements": [{"judgement": "  Ransomware   stays. ", "confidence": "Moderate"},
                                     {"judgement": "", "confidence": "high"}, "not a judgement",
                                     {"judgement": "DDoS fades", "confidence": "certain"}]}
        with mock.patch.object(llm, "_call", return_value=json.dumps(answer)), \
             mock.patch.object(llm, "_feature_cfg", return_value={}):
            sections = llm.draft_landscape_trends("Q3", [{"title": "E"}])
        self.assertEqual(sections["top_threats"], "- a\n- b")
        self.assertEqual(sections["executive_summary"], "Ransomware grew.")
        self.assertEqual(sections["key_judgements"], [{"judgement": "Ransomware stays.", "confidence": "moderate"},
                                                      {"judgement": "DDoS fades", "confidence": ""}])

    def test_a_section_sent_as_objects_becomes_bullets(self):
        """The model was asked for Markdown and sent the trending actors as a
        list of objects, which were stored as Python dicts."""
        answer = {"trending_actors": [
            {"actor_name": "APT 29", "source_count": 2, "activity_change": "Phishing against the Energy sector."},
            {"actor_name": "Akira", "source_count": 1, "activity_change": ""},
            {"actor_name": "", "source_count": 0}]}
        with mock.patch.object(llm, "_call", return_value=json.dumps(answer)), \
             mock.patch.object(llm, "_feature_cfg", return_value={}):
            sections = llm.draft_landscape_trends("Q3", [{"title": "E"}])
        self.assertEqual(sections["trending_actors"],
                         "- **APT 29** (source count 2): Phishing against the Energy sector.\n"
                         "- **Akira** (source count 1)")


class Methodology(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(collection_cache, "_build_sources",
                                          return_value=[{"id": "scraper", "label": "MISP scraper"},
                                                        {"id": "partner", "label": "Partner MISP"}]),
                        mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]),
                        mock.patch.object(config, "THREAT_LANDSCAPE_THREAT_TYPES", [], create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def draft(self, report, previous=None, ai_drafted=()):
        return threat_landscape._methodology_draft(report, previous, list(ai_drafted))

    def test_it_names_the_sources_the_period_and_what_was_left_out(self):
        report = _report([_entry(1, source_reliability="B", information_credibility="2", threat_type="Ransomware"),
                          _entry(2, source_id="partner", event_date="2026-09-20"),
                          _entry(3, source_id="manual-isac-feed", excluded=True)])
        text = self.draft(report)
        self.assertIn("This report covers 2026-07-01 to 2026-09-30. It is built from 2 events collected by zsazsa from "
                      "2 sources: MISP scraper (1), Partner MISP (1).", text)
        self.assertIn("The events are dated 2026-08-01 to 2026-09-20.", text)
        self.assertIn("1 more was queued for it and left out at triage", text)
        self.assertIn("threat type from the prime threats of the ENISA Threat Landscape", text)
        self.assertIn("Of the events in the analysis, 1 has no Admiralty rating and 1 has no threat type.", text)
        self.assertIn("no section was drafted with AI", text)
        self.assertIn("Limitations: no events are marked as duplicates, so what several sources report counts once "
                      "for each of them.", text)

    def test_a_change_in_collection_since_the_previous_report_is_named(self):
        report = _report([_entry(1), _entry(2, source_id="partner")])
        previous = _report([_entry(1, source_id="manual-isac-feed"), _entry(2), _entry(3)], tlr_id="TLR-00006")
        text = self.draft(report, previous)
        self.assertIn("Counts are compared with TLR-00006, which had 3 events against 2 here. The collection changed in "
                      "between (Partner MISP added; isac feed no longer used)", text)

    def test_the_same_collection_has_no_caveat(self):
        report = _report([_entry(1)])
        text = self.draft(report, _report([_entry(2)], tlr_id="TLR-00006"))
        self.assertIn("Counts are compared with TLR-00006", text)
        self.assertNotIn("collection changed", text)

    def test_it_says_what_the_ai_drafted_and_of_the_imported_reports(self):
        story = {"uuid": "ev-1", "tags": [misp_store.report_tag("rep-1")]}
        reports = {"rep-1": SimpleNamespace(uuid="rep-1", title="State of Security", provider="Recorded Future")}
        with mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[story]), \
             mock.patch.object(threat_landscape, "_reports_of", return_value=reports):
            text = self.draft(_report([_entry(1), _entry(2)]), ai_drafted=["executive_summary", "outlook"])
        self.assertIn("it draws on 1 imported threat report: State of Security by Recorded Future (1 story)", text)
        self.assertIn("AI drafted the executive summary and outlook from the events", text)
        self.assertIn("AI named the stories of the imported threat reports", text)


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
            mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]),
            mock.patch.object(collection_cache, "_build_sources", return_value=[]),
            mock.patch.object(threat_landscape.audit, "record"),
            mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]),
            mock.patch.object(misp_store, "galaxy_sectors", return_value=["Energy"]),
            mock.patch.object(misp_store, "galaxy_geography", return_value=["Belgium"]),
            mock.patch.object(misp_store, "list_veas", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        self.report = _report([_entry(1)], executive_summary="Ransomware **grew**.", key_judgements=JUDGEMENTS,
                              ai_drafted=["top_threats"])

    def get(self, path, tlrs=None):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=tlrs or [self.report]):
            reply = self.client.get(path)
        self.assertEqual(reply.status_code, 200)
        return BeautifulSoup(reply.data, "html.parser")

    def test_the_report_page_opens_with_the_summary(self):
        page = self.get(f"/products/threat-landscape/{UUID}")
        card = page.select_one(".col-lg-8 > .card")
        self.assertIn("Executive summary", card.select_one(".card-header").get_text())
        self.assertEqual(card.select_one(".report-md-body")["data-md"], "Ransomware **grew**.")
        rows = [[td.get_text(strip=True) for td in tr.select("td")] for tr in card.select("tbody tr")]
        self.assertEqual(rows[0], [JUDGEMENTS[0]["judgement"], "Moderate", JUDGEMENTS[0]["implication"]])
        self.assertEqual(rows[1][2], "-")

    def test_the_wizard_takes_them_and_keeps_what_the_ai_drafted(self):
        page = self.get(f"/products/threat-landscape/{UUID}/edit")
        step = page.select_one("#step-summary")
        self.assertEqual(step.select_one("textarea[name=executive_summary]").get_text(), "Ransomware **grew**.")
        rows = step.select("#tlr-judgements .tlr-judgement")
        self.assertEqual([r.select_one("[name=kj_judgement]").get_text() for r in rows], [j["judgement"] for j in JUDGEMENTS])
        self.assertTrue(rows[0].select_one("[name=kj_confidence] option[value=moderate][selected]"))
        # A template's contents are not part of the page; they are the fragment a new row is cloned from.
        template = BeautifulSoup(page.select_one("#tlr-judgement-template").decode_contents(), "html.parser")
        self.assertTrue(template.select_one("[name=kj_implication]"))
        self.assertEqual([i["value"] for i in page.select("#tlr-ai-drafted input[name=ai_drafted]")], ["top_threats"])
        self.assertEqual(page.select_one("#tlr-methodology-draft")["data-url"],
                         f"/products/threat-landscape/{UUID}/draft-methodology")
        info = page.select_one('[data-bs-target="#tlr-methodology-info"]')
        self.assertEqual(info.find_parent().select_one("#tlr-methodology-draft")["id"], "tlr-methodology-draft",
                         "the info icon sits beside the button")
        self.assertEqual(len(page.select("#tlr-methodology-info li")), 7)
        self.assertEqual([s.get_text(strip=True) for s in page.select(".step-num")], [str(n) for n in range(1, 12)])

    def test_saving_the_wizard_stores_the_summary_and_what_the_ai_drafted(self):
        form = MultiDict([("csrf_token", "tok"), ("title", "Q3"), ("executive_summary", " Ransomware grew. "),
                          ("kj_judgement", "Ransomware stays."), ("kj_confidence", "high"), ("kj_implication", "Budget"),
                          ("ai_drafted", "top_threats"), ("ai_drafted", "executive_summary")])
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "update_tlr") as update:
            self.client.post(f"/products/threat-landscape/{UUID}/edit", data=form)
        data = update.call_args.args[1]
        self.assertEqual((data["executive_summary"], data["key_judgements"], data["ai_drafted"]),
                         ("Ransomware grew.", [{"judgement": "Ransomware stays.", "confidence": "high",
                                                "implication": "Budget"}], ["top_threats", "executive_summary"]))

    def test_a_new_report_has_no_methodology_draft_yet(self):
        with mock.patch.object(threat_landscape, "_queued_events", return_value=[]):
            page = self.get("/products/threat-landscape/new")
        self.assertIsNone(page.select_one("#tlr-methodology-draft"))
        self.assertTrue(page.select_one("#step-summary"))

    def test_the_pdf_opens_with_the_summary(self):
        with mock.patch("weasyprint.HTML") as html:
            html.return_value.write_pdf.return_value = b"%PDF"
            with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
                 mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]):
                self.client.get(f"/products/threat-landscape/{UUID}/pdf")
        page = BeautifulSoup(html.call_args.kwargs["string"], "html.parser")
        heading = page.select_one(".section-heading")
        self.assertEqual(heading.get_text(), "Executive summary")
        table = heading.find_next_sibling(class_="section-box").select_one("table.grid-table")
        self.assertEqual(table.select("tr")[1].select("td")[1].get_text(), "Moderate")

    def test_the_methodology_is_drafted_with_the_sections_the_form_drafted(self):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report]):
            reply = self.client.post(f"/products/threat-landscape/{UUID}/draft-methodology",
                                     data={"ai_drafted": "outlook"}, headers={"X-CSRF-Token": "tok"})
        text = reply.get_json()["text"]
        self.assertIn("AI drafted the top threats and outlook from the events", text)

    def test_a_report_without_events_or_gone_has_no_draft(self):
        empty = _report()
        with mock.patch.object(misp_store, "get_tlr", return_value=empty):
            reply = self.client.post(f"/products/threat-landscape/{UUID}/draft-methodology", headers={"X-CSRF-Token": "tok"})
        self.assertEqual(reply.status_code, 400)
        with mock.patch.object(misp_store, "get_tlr", return_value=None):
            reply = self.client.post(f"/products/threat-landscape/{UUID}/draft-methodology", headers={"X-CSRF-Token": "tok"})
        self.assertEqual(reply.status_code, 404)


if __name__ == "__main__":
    unittest.main()
