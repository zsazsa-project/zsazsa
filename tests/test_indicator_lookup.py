"""Looking an indicator from a report up in MISP, and adding the answer to the event.

The lookup asks the data collection's MISP servers, one or every one, for the
to_ids attributes of published events with that value, leaves zsazsa's own
records out as an indicator feed does, and links each event to the server that
has it. /api/indicator-lookup takes only an indicator core.indicators accepts
and a server zsazsa knows. The answer can be added to the event of a Data
collection page as a report, for our organisation only, where an AI summary
may be: the lookup runs again for it, the event on another MISP server is
published again, and nothing from MISP in it reads as Markdown or HTML. Such a
report is zsazsa's own, never the article. The event page marks the attribute
values that can be looked up, and the pages that show reports have the lookup.

MISP is an autospec of PyMISP; the databases and log are temporary.

    python -m unittest tests.test_indicator_lookup
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent, MISPEventReport, PyMISP

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import api, data_collection

UUID = "3947bfb3-0115-45a2-b757-ad66a7d9f629"
OTHER = "6cb94c67-172c-436e-bf15-8bf6bee32566"
SERVERS = [{"id": "misp-intern", "label": "MISP-Intern", "url": "https://intern.example", "api_key": "k"},
           {"id": "scraper", "label": "MISP scraper", "url": "https://scraper.example", "api_key": "k"}]


def _attribute(event_uuid, info, ts, event_tags=()):
    return {"id": "1", "event_id": "334426", "type": "ip-dst", "value": "45.227.254.43", "to_ids": True,
            "timestamp": str(ts), "Tag": [],
            "Event": {"id": "334426", "uuid": event_uuid, "info": info, "date": "2026-10-21",
                      "Orgc": {"name": "CERT.be_3091"}, "Tag": [{"name": t} for t in event_tags]}}


class Lookup(unittest.TestCase):
    def setUp(self):
        self.clients = {s["url"]: mock.create_autospec(PyMISP, instance=True) for s in SERVERS}
        for client in self.clients.values():
            client.search.return_value = []
        self.enterContext(mock.patch.object(misp_store, "_collection_servers", return_value=SERVERS))
        self.enterContext(mock.patch.object(misp_store, "_feed_client", side_effect=lambda s: self.clients[s["url"]]))

    def answers(self, url, *attributes):
        self.clients[url].search.return_value = list(attributes)

    def test_to_ids_attributes_of_published_events_with_that_value(self):
        misp_store.lookup_indicator("45.227.254.43", "misp-intern")
        kwargs = self.clients["https://intern.example"].search.call_args.kwargs
        self.assertEqual({k: kwargs[k] for k in ("controller", "value", "to_ids", "published", "limit")},
                         {"controller": "attributes", "value": "45.227.254.43", "to_ids": 1, "published": True,
                          "limit": misp_store.LOOKUP_LIMIT})
        self.assertIn('zsazsa:ctiproduct=%', str(kwargs["tags"]))
        self.clients["https://scraper.example"].search.assert_not_called()

    def test_every_server_and_each_event_linked_on_its_own(self):
        self.answers("https://intern.example", _attribute(UUID, "INC and The Gentlemen", 1761049000))
        self.answers("https://scraper.example", _attribute(OTHER, "CTM360 Collection", 1763801640),
                     _attribute(UUID, "INC and The Gentlemen", 1761049000))
        rows, more, failures = misp_store.lookup_indicator("45.227.254.43")
        self.assertEqual([(r["event_title"], r["server_label"], r["event_url"]) for r in rows], [
            ("CTM360 Collection", "MISP scraper", f"https://scraper.example/events/view/{OTHER}"),
            ("INC and The Gentlemen", "MISP-Intern", f"https://intern.example/events/view/{UUID}")])
        self.assertEqual((more, failures), (False, []))

    def test_each_row_has_its_events_tlp(self):
        """What decides whether it may go into a product's text: the strictest
        TLP tag, amber when there is none, red for one that names no level."""
        self.answers("https://intern.example", _attribute(UUID, "a", 3, ["tlp:clear"]),
                     _attribute(OTHER, "b", 2), _attribute("00000000-0000-4000-8000-000000000001", "c", 1, ["tlp:ex:chr"]))
        rows = misp_store.lookup_indicator("45.227.254.43", "misp-intern")[0]
        self.assertEqual([r["tlp"] for r in rows], ["clear", "amber", "red"])

    def test_an_attribute_tlp_does_not_lower_its_events(self):
        """The first TLP tag was taken, the attribute's: a TLP:CLEAR attribute
        on a TLP:RED event put the event's title into a TLP:CLEAR product."""
        row = _attribute(UUID, "a", 3, ["tlp:red"])
        row["Tag"] = [{"name": "tlp:clear"}]
        self.answers("https://intern.example", row)
        self.assertEqual(misp_store.lookup_indicator("45.227.254.43", "misp-intern")[0][0]["tlp"], "red")

    def test_an_event_without_a_tlp_tag_is_amber_and_says_it_has_none(self):
        """Read as amber, it was held out of a TLP:CLEAR text as coming from an
        event with a stricter TLP, which it does not have."""
        self.answers("https://intern.example", _attribute(UUID, "a", 2, ["tlp:amber"]), _attribute(OTHER, "b", 1))
        rows = misp_store.lookup_indicator("45.227.254.43", "misp-intern")[0]
        self.assertEqual([(r["tlp"], r["tlp_tagged"]) for r in rows], [("amber", True), ("amber", False)])

    def test_zsazsa_own_records_are_left_out(self):
        self.answers("https://intern.example", _attribute(OTHER, "FIA-00042", 1, ['zsazsa:ctiproduct="flash-intel"']))
        self.assertEqual(misp_store.lookup_indicator("45.227.254.43", "misp-intern")[0], [])

    def test_a_server_that_does_not_answer_is_named(self):
        self.clients["https://scraper.example"].search.side_effect = ConnectionError("refused")
        self.answers("https://intern.example", _attribute(UUID, "INC and The Gentlemen", 1))
        rows, _more, failures = misp_store.lookup_indicator("45.227.254.43")
        self.assertEqual(len(rows), 1)
        self.assertEqual(failures, ["MISP scraper could not be reached"])

    def test_nobody_answering_is_not_an_empty_answer(self):
        for client in self.clients.values():
            client.search.side_effect = ConnectionError("refused")
        with self.assertRaisesRegex(RuntimeError, "MISP-Intern could not be reached"):
            misp_store.lookup_indicator("45.227.254.43")

    def test_an_answer_at_the_limit_says_there_are_more(self):
        self.answers("https://intern.example",
                     *[_attribute(f"{i:08d}-0000-4000-8000-000000000000", "e", i) for i in range(misp_store.LOOKUP_LIMIT)])
        self.assertTrue(misp_store.lookup_indicator("45.227.254.43", "misp-intern")[1])


class Api(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.register_blueprint(api.bp)
        self.client = app.test_client()
        self.enterContext(mock.patch.object(misp_store, "lookup_servers", return_value=[
            {"id": s["id"], "label": s["label"], "url": s["url"]} for s in SERVERS]))
        row = {"event_id": "334426", "event_uuid": UUID, "event_url": f"https://intern.example/events/view/{UUID}",
               "event_title": "INC", "creator_org": "CERT.be_3091", "value": "45.227.254.43", "event_date": "2026-10-21",
               "attribute_timestamp": "2026-10-21 12:16", "type": "ip-dst", "server_label": "MISP-Intern",
               "tags": ["tlp:clear"], "tlp": "clear", "tlp_tagged": True, "_ts": 1, "attribute_id": "1", "to_ids": True,
               "server_id": "misp-intern"}
        self.lookup = self.enterContext(mock.patch.object(misp_store, "lookup_indicator", return_value=([row], False, [])))

    def ask(self, **body):
        return self.client.post("/api/indicator-lookup", json={"kind": "ip", "value": "45.227.254[.]43",
                                                               "server": "misp-intern", **body})

    def test_a_lookup_answers_with_the_rows_the_table_shows(self):
        response = self.ask()
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual((data["value"], data["server"]), ("45.227.254.43", "MISP-Intern"))
        self.assertNotIn("tags", data["rows"][0])
        self.assertIs(data["rows"][0]["tlp_tagged"], True)
        self.lookup.assert_called_once_with("45.227.254.43", "misp-intern")

    def test_every_server(self):
        self.assertEqual(self.ask(server="all").get_json()["server"], "every server")
        self.lookup.assert_called_once_with("45.227.254.43", "all")

    def test_what_is_refused_before_misp_is_asked(self):
        for body in ({"kind": "cve", "value": "CVE-2026-35616"}, {"kind": "ip", "value": "10.0.0.1"},
                     {"kind": "shell", "value": "x"}, {"value": "evil.com/x", "kind": "domain"},
                     {"server": "elsewhere"}, {"server": None}):
            with self.subTest(body):
                self.assertEqual(self.ask(**body).status_code, 400)
        self.lookup.assert_not_called()

    def rows_of(self, *tlps):
        base = self.lookup.return_value[0][0]
        rows = [dict(base, event_uuid=f"{i:08d}-0000-4000-8000-000000000000", event_title=f"Event {tlp}", tlp=tlp)
                for i, tlp in enumerate(tlps)]
        self.lookup.return_value = (rows, False, [])

    def test_from_a_products_text_only_what_its_tlp_allows_goes_in(self):
        """A TLP:AMBER event's title must not go into a TLP:CLEAR briefing."""
        self.rows_of("clear", "amber", None)
        data = self.ask(for_tlp="clear").get_json()
        self.assertEqual([r["withheld"] for r in data["rows"]], [False, True, True])
        self.assertEqual(data["withheld"], 2)
        self.assertIn("Event clear", data["markdown"])
        self.assertNotIn("Event amber", data["markdown"])
        self.assertTrue(data["markdown"].startswith("**Lookup of 45.227.254.43.**"))

    def test_a_stricter_product_takes_more(self):
        self.rows_of("clear", "amber", "red")
        data = self.ask(for_tlp="amber").get_json()
        self.assertEqual(data["withheld"], 1)
        self.assertIn("Event amber", data["markdown"])

    def test_on_a_page_that_is_not_a_product_nothing_is_held_back(self):
        data = self.ask().get_json()
        self.assertNotIn("markdown", data)
        self.assertNotIn("withheld", data["rows"][0])

    def test_a_tlp_that_names_no_level_is_refused(self):
        self.assertEqual(self.ask(for_tlp="purple").status_code, 400)
        self.lookup.assert_not_called()

    def test_a_cve_comes_with_its_text_for_the_editor(self):
        info = {"description": "Improper access control", "cvss_score": "9.1", "cvss_severity": "CRITICAL"}
        with mock.patch.object(api, "fetch_cve_info", return_value=info):
            plain = self.client.post("/api/cve-lookup", json={"cve_ids": ["CVE-2026-35616"]}).get_json()
            edited = self.client.post("/api/cve-lookup", json={"cve_ids": ["CVE-2026-35616"], "markdown": True}).get_json()
        self.assertNotIn("markdown", plain["results"][0])
        self.assertTrue(edited["results"][0]["markdown"].startswith("**CVE-2026-35616.**"))
        self.assertIn("- **CVSS:** 9.1 CRITICAL", edited["results"][0]["markdown"])

    def test_no_server_answering_says_so(self):
        self.lookup.side_effect = RuntimeError("MISP-Intern could not be reached")
        response = self.ask()
        self.assertEqual((response.status_code, response.get_json()["error"]), (502, "MISP-Intern could not be reached"))


class AddedAsReport(unittest.TestCase):
    SOURCE = "misp-intern"

    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp) / "cache.db")))
        collection_cache.init_db()
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.add_event_report.return_value = {}
        self.misp.publish.return_value = {}
        self.event = MISPEvent()
        self.event.uuid, self.event.id, self.event.info, self.event.date = UUID, 334426, "INC and The Gentlemen", "2026-10-21"
        self.misp.get_event.return_value = self.event
        collection_cache.insert_event(collection_cache._extract_row(self.event, self.SOURCE))
        self.src = {"id": self.SOURCE, "kind": "misp", "label": "MISP-Intern", "url": "https://intern.example",
                    "allow_reports": True}
        self.enterContext(mock.patch.object(data_collection, "_find_source", side_effect=lambda sid: self.src))
        self.enterContext(mock.patch.object(data_collection, "_connect_source", return_value=(self.misp, None)))
        self.enterContext(mock.patch.object(misp_store, "lookup_servers", return_value=[
            {"id": s["id"], "label": s["label"], "url": s["url"]} for s in SERVERS]))
        self.audit = self.enterContext(mock.patch.object(data_collection.audit, "record"))
        row = {"event_id": "342392", "event_uuid": OTHER, "event_url": f"https://intern.example/events/view/{OTHER}",
               "event_title": "CTM360 <img src=x onerror=alert(1)> | [x](javascript:alert(1))",
               "creator_org": "CTM360_6493", "value": "45.227.254.43", "event_date": "2026-07-15",
               "attribute_timestamp": "2026-11-22 08:54", "type": "ip-dst", "server_label": "MISP-Intern"}
        self.lookup = self.enterContext(mock.patch.object(misp_store, "lookup_indicator", return_value=([row], False, [])))
        app = Flask(__name__)
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def add(self, **body):
        return self.client.post(f"/collection/{UUID}/lookup-report",
                                json={"source": self.SOURCE, "kind": "ip", "value": "45.227.254[.]43",
                                      "server": "misp-intern", **body})

    def report(self):
        event_id, report = self.misp.add_event_report.call_args.args
        return event_id, report

    def test_the_answer_is_added_for_our_organisation_only(self):
        response = self.add()
        self.assertEqual(response.status_code, 200, response.get_json())
        event_id, report = self.report()
        self.assertEqual((event_id, report.distribution), (334426, 0))
        self.assertEqual(report.name, "[zsazsa-lookup] 45.227.254.43 on MISP-Intern")
        self.assertIn(f"[342392](https://intern.example/events/view/{OTHER})", report.content)
        self.lookup.assert_called_once_with("45.227.254.43", "misp-intern")
        self.audit.assert_called_once()
        self.assertIn("for your organisation only", response.get_json()["message"])

    def test_nothing_from_misp_reads_as_markdown_or_html(self):
        self.add()
        content = self.report()[1].content
        self.assertIn(r"CTM360 \<img src=x onerror=alert\(1\)\> \| \[x\]\(javascript:alert\(1\)\)", content)
        self.assertNotRegex(content, r"(?<!\\)[<>]")

    def test_on_another_misp_server_the_event_is_published_again(self):
        """MISP unpublishes an event a report is added to, and only published
        events are read from another server."""
        self.add()
        self.misp.publish.assert_called_once_with(334426, alert=False)

    def test_zsazsa_own_misp_is_not_published(self):
        self.src = {"id": self.SOURCE, "kind": "scraper", "label": "MISP scraper", "url": "https://scraper.example"}
        self.assertEqual(self.add().status_code, 200)
        self.misp.publish.assert_not_called()

    def test_a_server_that_does_not_allow_reports(self):
        self.src = dict(self.src, allow_reports=False)
        self.assertEqual(self.add().status_code, 400)
        self.misp.add_event_report.assert_not_called()

    def test_an_event_that_is_not_collected(self):
        response = self.client.post(f"/collection/{OTHER}/lookup-report",
                                    json={"source": self.SOURCE, "kind": "ip", "value": "45.227.254.43", "server": "all"})
        self.assertEqual(response.status_code, 404)
        self.misp.add_event_report.assert_not_called()

    def test_what_is_refused(self):
        for body in ({"kind": "ip", "value": "10.0.0.1"}, {"server": "elsewhere"}, {"kind": "domain", "value": "x"}):
            with self.subTest(body):
                self.assertEqual(self.add(**body).status_code, 400)
        self.misp.add_event_report.assert_not_called()

    def test_a_cve_from_vulnerability_lookup(self):
        info = {"title": "", "description": "Improper access control in FortiClientEMS", "cvss_score": "9.1",
                "cvss_severity": "CRITICAL", "cisa_kev": "Yes", "products": ["Fortinet FortiClientEMS"],
                "references": ["https://fortiguard.fortinet.com/psirt/FG-IR-26-099", "javascript:alert(1)"]}
        with mock.patch.object(data_collection.vuln_lookup, "lookup_cve", return_value=info) as lookup:
            self.assertEqual(self.add(kind="cve", value="cve-2026-35616").status_code, 200)
        lookup.assert_called_once_with("CVE-2026-35616")
        content = self.report()[1].content
        self.assertIn("- **CVSS:** 9.1 CRITICAL", content)
        self.assertIn("<https://fortiguard.fortinet.com/psirt/FG-IR-26-099>", content)
        self.assertNotIn("javascript", content)
        self.lookup.assert_not_called()

    def test_the_event_shows_a_report_that_is_not_the_article(self):
        """A report zsazsa added has to stay out of what it summarises and what
        the analyser reads as the article, as an AI summary does."""
        names = ["[zsazsa-lookup] 45.227.254.43 on MISP-Intern"]
        self.assertTrue(collection_cache.is_own_report(names[0]))
        lookup, article = MISPEventReport(), MISPEventReport()
        lookup.name, lookup.content = names[0], "| table |"
        article.name, article.content = "Article", "The investigation began"
        self.assertIs(collection_cache.article_report([lookup, article]), article)
        self.event.add_event_report(name=names[0], content="| table |")
        self.assertEqual(collection_cache._extract_row(self.event, self.SOURCE)["source_report_count"], 0)


class NotTheEventsText(unittest.TestCase):
    """A lookup report lists other events. Their titles must not reach the AI
    as this event's source text, nor match a correlation search on it."""

    REPORTS = [{"name": "[zsazsa-lookup] 45.227.254.43 on MISP-Intern", "content": "| CTM360 Collection |"},
               {"name": "Article", "content": "The investigation began"},
               {"name": "[AI-Summary] INC and The Gentlemen", "content": "Summary"}]

    def test_the_source_text_of_a_product_leaves_it_out(self):
        events = [{"reports": self.REPORTS}]
        self.assertEqual(api._report_content(events), "The investigation began\n\n---\n\nSummary")
        self.assertEqual(api._report_content(events, raw_only=True), "The investigation began")

    def test_a_correlation_does_not_read_it(self):
        event = MISPEvent()
        event.info = "INC and The Gentlemen"
        for r in self.REPORTS:
            event.add_event_report(name=r["name"], content=r["content"])
        self.assertNotIn("CTM360", misp_store._event_text(event))
        self.assertIn("The investigation began", misp_store._event_text(event))

    def test_nor_a_story_pulled_from_the_event(self):
        """Its rows are not held to any TLP. Pulled into a briefing story with
        the event's attributes, a TLP:RED event's title went with them."""
        event = MISPEvent()
        event.add_attribute("ip-dst", "45.227.254.43")
        for r in self.REPORTS:
            event.add_event_report(name=r["name"], content=r["content"])
        text = misp_store.format_event_attributes_text(event)
        self.assertNotIn("CTM360", text)
        self.assertIn("45.227.254.43", text)
        self.assertIn("The investigation began", text)


class ReportContent(unittest.TestCase):
    def test_a_server_that_did_not_answer_is_named(self):
        """Without it, a lookup on every server read as if each had nothing."""
        content = misp_store.lookup_report_content("45.227.254.43", "every server", [], False,
                                                   ["MISP scraper could not be reached"])
        self.assertIn("MISP scraper could not be reached, so it is not in this answer.", content)
        self.assertIn("Nothing found.", content)

    def test_a_cve_vulnerability_lookup_does_not_have(self):
        content = misp_store.cve_report_content("CVE-2026-0300", {})
        self.assertIn("Vulnerability-Lookup does not have it.", content)

    def test_where_a_lookup_looked(self):
        with mock.patch.object(misp_store, "lookup_servers", return_value=[
                {"id": "misp-intern", "label": "MISP-Intern", "url": "https://intern.example"}]):
            self.assertEqual([misp_store.lookup_server_label(s) for s in ("misp-intern", "all", "elsewhere", None)],
                             ["MISP-Intern", "every server", None, None])


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(misp_store, "lookup_servers", return_value=[
                {"id": s["id"], "label": s["label"], "url": s["url"]} for s in SERVERS]),
        ):
            self.enterContext(patch)
        self.client = create_app().test_client()

    def event_page(self, src):
        event = MISPEvent()
        event.uuid, event.id, event.info, event.date = UUID, 334426, "INC and The Gentlemen", "2026-10-21"
        event.add_attribute("ip-dst", "45.227.254.43")
        event.add_attribute("text", "45.227.254.43 as text")
        # Of a type the lookup takes, but a value it refuses: no card for them.
        event.add_attribute("url", "evil.example/gate.php")
        event.add_attribute("ip-dst", "10.0.0.1")
        reports = [{"name": "Article", "content": "Server at 45.227.254[.]43", "date": "", "tags": []}]
        with mock.patch.object(data_collection, "_find_source", return_value=src), \
             mock.patch.object(data_collection, "_event_with_reports", return_value=(event, reports, None)), \
             mock.patch.object(data_collection, "_draft_briefings", return_value=[]):
            response = self.client.get(f"/collection/{UUID}?source={src['id']}")
        self.assertEqual(response.status_code, 200)
        return response.data.decode()

    def test_the_event_page_knows_its_event_and_marks_the_attribute_values(self):
        html = self.event_page({"id": "misp-intern", "kind": "misp", "label": "MISP-Intern",
                                "url": "https://intern.example/", "allow_reports": True})
        marks = BeautifulSoup(html, "html.parser").select("span.ioc")
        self.assertEqual([(m["data-ioc-kind"], m["data-ioc-value"]) for m in marks], [("ip", "45.227.254.43")])
        self.assertIn(f'"uuid": "{UUID}"', html)
        self.assertIn('"server": "misp-intern"', html)
        self.assertIn('"writable": true', html)
        self.assertIn(f'"reportUrl": "/collection/{UUID}/lookup-report"', html)

    def test_where_reports_may_not_be_added_the_page_does_not_offer_it(self):
        html = self.event_page({"id": "misp-intern", "kind": "misp", "label": "MISP-Intern",
                                "url": "https://intern.example", "allow_reports": False})
        self.assertIn('"writable": false', html)

    def test_the_pages_that_show_reports_and_the_product_forms_have_the_lookup(self):
        templates = Path(__file__).resolve().parent.parent / "webapp" / "templates"
        reading = ["data_collection/detail.html", "data_collection/list.html", "data_collection/manual_detail.html",
                   "daily_briefing/detail.html", "daily_briefing/list.html", "flash_intel/detail.html",
                   "flash_intel/review.html", "vea/detail.html", "vea/review.html", "threat_actor_profile/detail.html",
                   "threat_actor_profile/review.html", "threat_landscape/detail.html", "threat_landscape/list.html",
                   "threat_landscape/entries.html", "detection_eng/detail.html", "detection_eng/review.html"]
        include = '{% include "_indicator_lookup.html" %}'
        for name in reading:
            with self.subTest(name):
                self.assertIn(include, (templates / name).read_text())
        # The product forms, for the preview of their Markdown fields; not the
        # manual entry, whose text is the article.
        for name in ("daily_briefing/form.html", "flash_intel/wizard.html", "vea/wizard.html",
                     "threat_actor_profile/form.html", "detection_eng/wizard.html", "threat_landscape/wizard.html"):
            with self.subTest(name):
                self.assertIn(include, (templates / name).read_text())
        self.assertNotIn(include, (templates / "data_collection/manual_entry.html").read_text())

    def test_the_lookup_script_puts_text_in_with_text_content_only(self):
        script = (Path(__file__).resolve().parent.parent / "webapp/templates/_indicator_lookup.html").read_text()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("insertAdjacentHTML", script)


class Servers(unittest.TestCase):
    def test_the_scraper_and_the_enabled_servers_each_once_and_not_the_store(self):
        """zsazsa's own store is not a server to look an indicator up on. Here
        the scraper writes to the store, as it often does: it is offered as
        the scraper, and the pipeline counts that server once, as the store."""
        servers = [{"id": "misp-intern", "label": "MISP-Intern", "url": "https://intern.example/", "api_key": "k"},
                   {"id": "off", "label": "Off", "url": "https://off.example", "api_key": "k", "enabled": False},
                   {"id": "nokey", "label": "No key", "url": "https://nokey.example", "api_key": ""},
                   {"id": "again", "label": "Again", "url": "https://scraper.example", "api_key": "k"}]
        with mock.patch.multiple(config, MISP_URL="https://scraper.example", MISP_KEY="k", MISP_VERIFYCERT=True,
                                 MISP_WEBAPP_URL="https://scraper.example", MISP_WEBAPP_KEY="k", MISP_SERVERS=servers), \
             mock.patch.object(misp_store, "scraper_enabled", return_value=True):
            found = misp_store.lookup_servers()
            counted = [s["id"] for s in misp_store.indicator_stat_servers()]
        self.assertEqual(found, [
            {"id": "scraper", "label": "MISP scraper", "url": "https://scraper.example"},
            {"id": "misp-intern", "label": "MISP-Intern", "url": "https://intern.example"}])
        self.assertNotIn("api_key", str(found))
        self.assertEqual(counted, ["zsazsa-store", "misp-intern"])


if __name__ == "__main__":
    unittest.main()
