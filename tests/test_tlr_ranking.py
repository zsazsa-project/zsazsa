"""The threat ranking, the charts and the management brief of a threat landscape report.

The ranking lists the threat types of the dataset, those of the previous report
it no longer has included, and its five most frequent threat actors, each with
its incidents beside the previous report's, how that moved, its incidents of
high relevance and why the analyst says it matters. The most incidents of high
relevance come first, then those that hit the organisation, those growing and
the most incidents; a report saved with an exposure per threat shows none. The
report page, the PDF, the brief and the mail show the ranking. The charts are SVG drawn from the
dataset, with every label escaped. The brief is one page of the summary, the
ranking and the incidents per threat type. MISP is patched out; the database
and log are temporary. The analyst can leave figures out of the PDF, the brief
and the mail; a report saved before shows them all.

    python -m unittest tests.test_tlr_ranking
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import render_template
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _entry(n, **fields):
    data = {"event_uuid": f"ev-{n}", "event_info": f"Event {n}", "event_date": "2026-08-0" + str(n % 9 + 1),
            "source_id": "scraper", **fields}
    return misp_store._tlr_entry_obj(data)


def _report(entries=(), tlr_id="TLR-00007", **fields):
    data = {"tlr_id": tlr_id, "title": "Q3", "tlp": "amber", "reporting_period": "2026 Q3", **fields}
    return misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[misp_store._tlr_obj(data)] + list(entries),
                                              published=False, date=None))


NOW = [_entry(1, threat_type="Ransomware", relevance="high", threat_actors=["Akira"], sectors=["Energy"]),
       _entry(2, threat_type="Ransomware", threat_actors=["Akira"]),
       _entry(3, threat_type="Ransomware", threat_actors=["Qilin"]),
       _entry(4, threat_type="Malware"),
       _entry(5, threat_type="Social engineering", relevance="medium")]
BEFORE = [_entry(11, threat_type="Ransomware"), _entry(12, threat_type="Malware"), _entry(13, threat_type="Malware"),
          _entry(14, threat_type="Supply chain attacks")]


def _rows(report, previous=None):
    return {(r["kind"], r["name"]): r for r in threat_landscape._threat_ranking(report, previous)}


class Order(unittest.TestCase):
    def test_high_relevance_then_ours_then_growing_then_the_most(self):
        now = [_entry(1, threat_type="Malware"), _entry(2, threat_type="Malware"), _entry(3, threat_type="Malware"),
               _entry(4, threat_type="Supply chain attacks"),
               _entry(5, threat_type="Social engineering"),
               _entry(6, threat_type="DDoS", source_id="soc"),
               _entry(7, threat_type="Ransomware", relevance="high")]
        before = [_entry(11, threat_type="Malware"), _entry(12, threat_type="Malware"), _entry(13, threat_type="Malware"),
                  _entry(14, threat_type="Supply chain attacks"), _entry(15, threat_type="Supply chain attacks"),
                  _entry(16, threat_type="DDoS"), _entry(17, threat_type="Ransomware")]
        ranking = threat_landscape._threat_ranking(_report(now), _report(before, tlr_id="TLR-00006"), {"soc": "SOC"})
        self.assertEqual([r["name"] for r in ranking],
                         ["Ransomware", "DDoS", "Social engineering", "Malware", "Supply chain attacks"])


class Ranking(unittest.TestCase):
    def test_each_threat_type_with_its_movement_since_the_previous_report(self):
        rows = _rows(_report(NOW), _report(BEFORE, tlr_id="TLR-00006"))
        ransomware = rows[("threat type", "Ransomware")]
        self.assertEqual((ransomware["incidents"], ransomware["previous"], ransomware["movement"], ransomware["high"]),
                         (3, 1, "up", 1))
        self.assertEqual(rows[("threat type", "Malware")]["movement"], "down")
        self.assertEqual(rows[("threat type", "Social engineering")]["movement"], "new")
        gone = rows[("threat type", "Supply chain attacks")]
        self.assertEqual((gone["incidents"], gone["previous"], gone["movement"]), (0, 1, "down"))

    def test_without_a_previous_report_nothing_moves(self):
        rows = _rows(_report(NOW))
        self.assertEqual((rows[("threat type", "Ransomware")]["previous"], rows[("threat type", "Ransomware")]["movement"]),
                         (None, ""))

    def test_the_most_frequent_threat_actors_and_any_the_analyst_said_why_of(self):
        many = NOW + [_entry(20 + n, threat_actors=[f"Actor {n}"]) for n in range(6)] + [
            _entry(30, threat_actors=["Sandworm"])]
        report = _report(many, threat_ranking=[{"kind": "threat actor", "name": "Sandworm", "rationale": "Targets the grid"}])
        rows = _rows(report)
        actors = [name for kind, name in rows if kind == "threat actor"]
        self.assertIn("Akira", actors)
        self.assertEqual(len(actors), 6, "the five most frequent and the one the analyst said why of")
        self.assertEqual(rows[("threat actor", "Sandworm")]["rationale"], "Targets the grid")

    def test_a_threat_ranked_before_with_no_events_now_or_before_has_no_row(self):
        report = _report(NOW, threat_ranking=[{"kind": "threat type", "name": "Supply chain attacks", "rationale": "Was big"},
                                              {"kind": "threat actor", "name": "Sandworm", "rationale": "Targets the grid"}])
        names = [name for _kind, name in _rows(report)]
        self.assertNotIn("Supply chain attacks", names, "its events were triaged to another threat type since")
        self.assertNotIn("Sandworm", names)
        previous = _report([_entry(9, threat_type="Supply chain attacks")], tlr_id="TLR-00006")
        gone = {r["name"]: r for r in threat_landscape._threat_ranking(report, previous)}["Supply chain attacks"]
        self.assertEqual((gone["incidents"], gone["previous"], gone["rationale"]), (0, 1, "Was big"), "gone since the last one")

    def test_a_report_saved_with_an_exposure_keeps_its_why_and_the_order_of_the_triage(self):
        report = _report(NOW, threat_ranking=[{"kind": "threat type", "name": "Malware", "exposure": "critical",
                                               "rationale": "Our EDR gap"}])
        ranking = threat_landscape._threat_ranking(report, None)
        self.assertEqual(ranking[0]["name"], "Ransomware", "the one of high relevance, whatever exposure was set")
        malware = next(r for r in ranking if r["name"] == "Malware")
        self.assertEqual(malware["rationale"], "Our EDR gap")
        self.assertNotIn("exposure", malware)

    def test_the_form_keeps_the_rows_with_a_why(self):
        form = MultiDict([("rank_kind", "threat type"), ("rank_name", "Ransomware"), ("rank_rationale", " Backups "),
                          ("rank_kind", "threat type"), ("rank_name", "Malware"), ("rank_rationale", "  "),
                          ("rank_kind", "threat actor"), ("rank_name", "Akira"), ("rank_rationale", "Watch"),
                          ("rank_kind", "vendor"), ("rank_name", "Acme"), ("rank_rationale", "Not a threat")])
        self.assertEqual(threat_landscape._form_data(form)["threat_ranking"],
                         [{"kind": "threat type", "name": "Ransomware", "rationale": "Backups"},
                          {"kind": "threat actor", "name": "Akira", "rationale": "Watch"}])

    def test_the_mail_lists_every_threat_of_the_ranking(self):
        report = _report(NOW, threat_ranking=[{"kind": "threat type", "name": "Ransomware", "rationale": "Backups are tested."}])
        text = misp_store.render_tlr_markdown(report, ranking=threat_landscape._threat_ranking(report, None))
        ranking = text.split("## Threat ranking\n\n")[1].split("\n\n")[0].splitlines()
        self.assertEqual(ranking[0], "- **Ransomware** (threat type): 3 events, 1 of high relevance. Backups are tested.")
        self.assertIn("- **Malware** (threat type): 1 event.", ranking)
        self.assertNotIn("exposure", text)

    def test_the_charts_draw_the_dataset(self):
        report = _report(NOW)
        ranking = threat_landscape._threat_ranking(report, _report(BEFORE, tlr_id="TLR-00006"))
        charts = threat_landscape._charts(report, _report(BEFORE, tlr_id="TLR-00006"), ranking)
        self.assertEqual(charts["threat_types"][0], ("Ransomware", 3, 1))
        self.assertEqual([month for month, _n in charts["months"]], ["2026-08"])


class Figures(unittest.TestCase):
    CHARTS = {"threat_types": [("Ransomware", 3, 1)], "months": [("2026-08", 2), ("2026-09", 1)],
              "sectors": [("Energy", 5, None)], "techniques": []}

    def test_the_unticked_figures_are_left_out(self):
        form = MultiDict([("title", "Q3"), ("figure", "threat_types"), ("figure", "sectors")])
        self.assertEqual(threat_landscape._form_data(form)["hidden_figures"], ["months", "techniques"])
        self.assertEqual(_report(hidden_figures=["months"]).hidden_figures, ["months"])

    def test_a_figure_is_drawn_when_shown_and_there_is_something_to_draw(self):
        self.assertEqual(threat_landscape._shown_figures(_report(), self.CHARTS), ["threat_types", "months", "sectors"])
        self.assertEqual(threat_landscape._shown_figures(_report(hidden_figures=["threat_types"]), self.CHARTS),
                         ["months", "sectors"])
        one_month = dict(self.CHARTS, months=[("2026-08", 2)])
        self.assertNotIn("months", threat_landscape._shown_figures(_report(), one_month))

    def test_the_mail_lists_the_figures_shown(self):
        previous = _report(tlr_id="TLR-00006")
        text = misp_store.render_tlr_markdown(_report(hidden_figures=["sectors"]), charts=self.CHARTS, previous=previous)
        figures = text.split("## In figures")[1]
        self.assertIn("In brackets, the count in TLR-00006.", figures)
        self.assertIn("**Events per threat type:** Ransomware 3 (1)", figures)
        self.assertIn("**Events per month:** 2026-08 2, 2026-09 1", figures)
        self.assertNotIn("Sectors", figures)
        self.assertNotIn("In figures", misp_store.render_tlr_markdown(
            _report(hidden_figures=[key for key, _l in misp_store.TLR_FIGURES]), charts=self.CHARTS))


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
        self.app = create_app()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "tok"
        self.report = _report(NOW, executive_summary="Ransomware grew.", threat_ranking=[
            {"kind": "threat type", "name": "Ransomware", "rationale": "Two suppliers hit"}])
        self.previous = _report(BEFORE, tlr_id="TLR-00006")
        self.previous.review_state = "published"

    def get(self, path):
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[self.report, self.previous]):
            return self.client.get(path)

    def pdf_html(self, path):
        with mock.patch("weasyprint.HTML") as html:
            html.return_value.write_pdf.return_value = b"%PDF"
            reply = self.get(path)
        self.assertEqual(reply.data, b"%PDF")
        return reply, BeautifulSoup(html.call_args.kwargs["string"], "html.parser")

    def test_the_report_page_shows_the_ranking_and_its_chart(self):
        page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}").data, "html.parser")
        table = page.select_one("table.tlr-ranking")
        rows = table.select("tbody tr")
        self.assertIn("Supply chain attacks", table.get_text(), "every threat, without an exposure picked")
        row = rows[0]
        cells = [td.get_text(" ", strip=True) for td in row.select("td")]
        self.assertEqual((cells[0], cells[2], cells[3]), ("Ransomware threat type", "1", "Two suppliers hit"))
        self.assertIn("3 (1 before)", cells[1])
        self.assertIsNone(table.select_one(".tlr-exposure"))
        self.assertEqual(row.select_one(".tlr-move-up").get_text(), "↑")
        chart = table.find_next("svg", class_="tlr-chart")
        self.assertIn("Ransomware: 3", chart["aria-label"])
        self.assertEqual(page.select_one(f'a[href="/products/threat-landscape/{UUID}/brief.pdf"]').get_text(strip=True),
                         "Management brief")

    def test_the_wizard_offers_each_threat_with_its_why(self):
        page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}/edit").data, "html.parser")
        rows = page.select("#step-ranking tbody tr")
        names = [r.select_one("input[name=rank_name]")["value"] for r in rows]
        self.assertEqual(names[0], "Ransomware")
        self.assertIn("Supply chain attacks", names)
        self.assertIn("Akira", names)
        self.assertEqual(rows[0].select_one("input[name=rank_rationale]")["value"], "Two suppliers hit")
        self.assertIsNone(page.select_one("[name=rank_exposure]"))
        self.assertIsNone(page.select_one("#tlr-ranking-propose"))

    def test_saving_the_wizard_stores_the_ranking(self):
        form = MultiDict([("csrf_token", "tok"), ("title", "Q3"), ("rank_kind", "threat type"), ("rank_name", "Malware"),
                          ("rank_rationale", "Our EDR gap"), ("rank_kind", "threat type"), ("rank_name", "DDoS"),
                          ("rank_rationale", "")])
        with mock.patch.object(misp_store, "get_tlr", return_value=self.report), \
             mock.patch.object(misp_store, "update_tlr") as update:
            self.client.post(f"/products/threat-landscape/{UUID}/edit", data=form)
        self.assertEqual(update.call_args.args[1]["threat_ranking"],
                         [{"kind": "threat type", "name": "Malware", "rationale": "Our EDR gap"}])

    def test_the_pdf_has_the_ranking_and_the_figures(self):
        reply, page = self.pdf_html(f"/products/threat-landscape/{UUID}/pdf")
        self.assertEqual(reply.headers["Content-Disposition"], 'attachment; filename="TLR-00007.pdf"')
        headings = [h.get_text() for h in page.select(".section-heading")]
        self.assertLess(headings.index("Executive summary"), headings.index("Threat ranking"))
        self.assertLess(headings.index("Threat ranking"), headings.index("In figures"))
        self.assertGreaterEqual(len(page.select("svg.tlr-chart")), 2)

    def test_the_brief_is_the_summary_ranking_and_threat_types(self):
        reply, page = self.pdf_html(f"/products/threat-landscape/{UUID}/brief.pdf")
        self.assertEqual(reply.headers["Content-Disposition"], 'attachment; filename="TLR-00007-brief.pdf"')
        self.assertEqual([h.get_text(strip=True) for h in page.select(".section-heading")],
                         ["Bottom line", "Threat ranking", "Events per threat type, beside TLR-00006 in grey"])
        self.assertIn("TLP:AMBER", page.get_text())

    def test_the_pdf_and_the_brief_leave_out_the_unticked_figures(self):
        self.report.hidden_figures = ["threat_types", "techniques"]
        _reply, pdf = self.pdf_html(f"/products/threat-landscape/{UUID}/pdf")
        self.assertEqual([h.get_text() for h in pdf.select(".section-box h3")
                          if h.get_text() in ("Events per month", "Sectors most named")], ["Sectors most named"])
        self.assertNotIn("Events per threat type", pdf.get_text())
        _reply, brief = self.pdf_html(f"/products/threat-landscape/{UUID}/brief.pdf")
        self.assertIsNone(brief.select_one("svg.tlr-chart"))

    def test_the_wizard_ticks_the_figures_shown(self):
        self.report.hidden_figures = ["months"]
        page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}/edit").data, "html.parser")
        boxes = {b["value"]: b.has_attr("checked") for b in page.select(".form-save input[name=figure]")}
        self.assertEqual(boxes, {"threat_types": True, "months": False, "sectors": True, "techniques": True})

    def test_the_report_page_says_which_figures_are_in(self):
        self.report.hidden_figures = ["months"]
        with mock.patch.object(threat_landscape, "_charts",
                               return_value={"threat_types": [("Ransomware", 3, 1)], "months": [("2026-08", 2), ("2026-09", 1)],
                                             "sectors": [], "techniques": [("T1486", 2)]}):
            page = BeautifulSoup(self.get(f"/products/threat-landscape/{UUID}").data, "html.parser")
        card = page.select_one(".tlr-figures").find_parent(class_="card")
        self.assertEqual({li["data-figure"]: " ".join(li.get_text(" ").split()) for li in card.select("li")},
                         {"threat_types": "Events per threat type", "months": "Events per month: left out",
                          "sectors": "Sectors most named: no data to show", "techniques": "ATT&CK techniques most seen"})
        self.assertEqual(card.select_one(".card-header a")["href"], f"/products/threat-landscape/{UUID}/edit#figures")

    def test_a_brief_of_no_report_is_not_found(self):
        with mock.patch.object(misp_store, "get_tlr", return_value=None):
            self.assertEqual(self.client.get(f"/products/threat-landscape/{UUID}/brief.pdf").status_code, 404)

    def test_a_chart_escapes_its_labels(self):
        with self.app.test_request_context():
            html = render_template("threat_landscape/brief.html", tlr=self.report, ranking=[], previous=None,
                                   charts={"threat_types": [('<script>alert(1)</script>', 2, None)]}, shown=["threat_types"],
                                   css_url="", brand={"color1": "#000", "color2": "#111", "color3": "#222"},
                                   linked_pirs=[], annex=[], **threat_landscape._report_context())
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
