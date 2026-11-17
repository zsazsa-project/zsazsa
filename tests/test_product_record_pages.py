"""The product pages in the layout of the stakeholder, PIR, GIR and briefing
pages: flash intel alerts, vulnerability advisories, threat actor profiles,
detection engineering requests, threat landscape reports and collection events.

A list opens on the compact banner with its figures and the button that opens
how the product is made, and groups its table by state, a state no lane has
counting as a draft; an alert and an advisory say after their title when they
were made. The detection requests keep their engineering board, with
the hooks its script drags by. A record page has the record banner with its
buttons at the bottom left, Resend only for those who may publish, its TLP and
where it stands, and names the sections with nothing in them on one line. A
failed notification is listed step by step. An alert with source events shows
its source articles in a card above the summary, read from MISP once, and its
page and form each have a button that queues them all for the threat landscape
and says how many. A form has numbered sections and an
"As it will appear" card with Save in the side column, and a new profile's form
gets the scripts that fill it. A collection event's page says where the event
stands from its tags, offers the products to make from it in the banner, and
shows each tag in a colour that can be read.

MISP is patched; the database and log are temporary.

    python -m unittest tests.test_product_record_pages
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP

import config
from webapp import audit, collection_cache, create_app, job_store, misp_session, misp_store
from webapp.routes import data_collection, threat_landscape

UUID = "8261112b-619c-4ee0-9409-c898df74520c"
SOURCES = {"0c1d6a8e-61b4-4f0b-9a55-1f4f1d2f0a01": "scraper", "5e2f9b3c-0d7a-4c41-8e66-2a5b3c4d0b02": "partner"}


def _sources(count=2):
    """Source events as fetch_source_events() gives them."""
    return [{"uuid": uid, "info": f"Article {n}", "date": "2026-11-10", "orgc": "CIRCL",
             "source_id": sid, "source_label": sid, "source_url": "", "tags": [], "attributes": [],
             "objects": [], "reports": [{"name": "Report", "date": "", "content": f"Full text {n}"}]}
            for n, (uid, sid) in enumerate(list(SOURCES.items())[:count])]


def _event():
    event = MISPEvent()
    event.uuid, event.id, event.date, event.info = UUID, "42", "2026-10-26", "Example product"
    return event


def _fia(state="draft", **fields):
    fia = misp_store._fia_ns(_event())
    fia.review_state, fia.title, fia.audience, fia.tlp = state, "VPN appliance exploited", "SOC", "amber"
    for name, value in fields.items():
        setattr(fia, name, value)
    return fia


def _tlr(state="draft", **fields):
    tlr = misp_store._tlr_ns(_event())
    tlr.review_state, tlr.title, tlr.tlp = state, "Q3 landscape", "amber"
    for name, value in fields.items():
        setattr(tlr, name, value)
    return tlr


def _vea(state="draft", **fields):
    vea = misp_store._vea_ns(_event())
    vea.review_state, vea.title, vea.cve_id, vea.audience, vea.tlp = state, "PHP OOM RCE", "CVE-2026-1", "SOC", "amber"
    for name, value in fields.items():
        setattr(vea, name, value)
    return vea


def _tap(status="Draft", **fields):
    tap = misp_store._tap_ns(_event())
    tap.status, tap.title, tap.audience, tap.tlp = status, "ALLANITE", "SOC", "amber"
    for name, value in fields.items():
        setattr(tap, name, value)
    return tap


def _der(state="draft", **fields):
    der = misp_store._der_ns(_event())
    der.review_state, der.title, der.audience, der.tlp = state, "Detect PAN-OS exploitation", "SOC", "amber"
    for name, value in fields.items():
        setattr(der, name, value)
    return der


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch("webapp._setup_file_logging"),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(job_store, "by_entity", return_value={}),
            mock.patch.object(audit, "record"),
            mock.patch.object(audit, "latest_notify_status", return_value=None),
            mock.patch.object(misp_session, "current_user_can_publish", return_value=True),
            mock.patch.multiple(misp_store, list_product_feedback=mock.Mock(return_value=[]),
                                list_stakeholders=mock.Mock(return_value=[]), list_pirs=mock.Mock(return_value=[]),
                                galaxy_sectors=mock.Mock(return_value=[]),
                                galaxy_geography=mock.Mock(return_value=[]),
                                list_briefings=mock.Mock(return_value=[])),
            mock.patch.object(threat_landscape, "_queued_events", return_value=[]),
        ):
            self.enterContext(patch)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")

    def with_sources(self, path, kind="fia", count=2):
        """A page of an alert, or with kind "vea" an advisory, with source events
        read from MISP as fetch_source_events() gives them."""
        sources = _sources(count)
        make, getter, lister = {"fia": (_fia, "get_fia", "list_fias"), "vea": (_vea, "get_vea", "list_veas")}[kind]
        record = make("draft", source_event_uuids=[ev["uuid"] for ev in sources],
                      source_event_hints={ev["uuid"]: ev["source_id"] for ev in sources})
        with mock.patch.object(misp_store, getter, return_value=record), \
             mock.patch.object(misp_store, lister, return_value=[]), \
             mock.patch.object(misp_store, "fetch_source_events", return_value=sources) as fetched:
            page = self.page(path)
        return page, fetched


class FlowPanel(Pages):
    def test_each_list_opens_how_its_product_is_made_from_its_banner(self):
        lists = {"/products/flash-intel/": "list_fias", "/products/vea/": "list_veas",
                 "/products/threat-actor-profile/": "list_threat_actor_profiles",
                 "/products/indicator-feed/": "list_indicator_feeds", "/products/detection-eng/": "list_ders"}
        for path, lister in lists.items():
            with self.subTest(path), mock.patch.object(misp_store, lister, return_value=[]):
                page = self.page(path)
                button = page.select_one('section.record-hero .hero-actions [data-bs-target="#product-flow"]')
                self.assertTrue(button.get_text(strip=True).startswith("How a"))
                self.assertIn("collapse", page.select_one("#product-flow")["class"])



class FlashIntelPages(Pages):
    def test_each_listed_alert_and_advisory_says_when_it_was_made(self):
        """After the title: the published date is another one, in its own column."""
        for path, lister, record in (("/products/flash-intel/", "list_fias", _fia("draft")),
                                     ("/products/vea/", "list_veas", _vea("draft"))):
            with self.subTest(path), mock.patch.object(misp_store, lister, return_value=[record]):
                page = self.page(path)
                made = page.select_one(f"td a.title[href$='{UUID}'] + .made-on")
                self.assertEqual((made.get_text(), made["title"]), ("2026-10-26", "Made on 2026-10-26"))
        undated = _fia("draft", created_at=None)
        with mock.patch.object(misp_store, "list_fias", return_value=[undated]):
            self.assertIsNone(self.page("/products/flash-intel/").select_one(".made-on"))

    def test_the_list_groups_the_alerts_by_review_state(self):
        alerts = [_fia("approved"), _fia("pending-review"), _fia("draft")]
        for n, alert in enumerate(alerts):
            alert.uuid = f"alert-{n}"
        with mock.patch.object(misp_store, "list_fias", return_value=alerts):
            page = self.page("/products/flash-intel/")
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-compact", hero["class"])
        self.assertIn("1 waiting for review", hero.select_one(".record-kpis").get_text(" ", strip=True))
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Waiting for review", "Draft", "Approved"])
        self.assertIsNotNone(page.select_one("form.record-filters"))

    def test_an_alert_in_a_state_no_lane_has_is_still_listed(self):
        """Grouping by state lost a record whose state was set by hand in MISP."""
        alert = _fia("on-hold")
        with mock.patch.object(misp_store, "list_fias", return_value=[alert]):
            page = self.page("/products/flash-intel/")
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")], ["Draft"])
        self.assertIsNotNone(page.select_one(f"tr#fia-row-{alert.uuid}"))

    def test_an_approved_alert_page(self):
        with mock.patch.object(misp_store, "get_fia", return_value=_fia("approved")):
            page = self.page(f"/products/flash-intel/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-detail", hero["class"])
        self.assertEqual(hero.select_one("h1").get_text(strip=True), "VPN appliance exploited")
        self.assertIn("TLP:AMBER", hero.select_one(".hero-tlp").get_text())
        self.assertIsNotNone(hero.select_one(".delivery"))
        actions = {b.get_text(strip=True): b for b in hero.select(".hero-actions .btn")}
        self.assertIn("Resend", actions)
        self.assertTrue(actions["Delete FIA"].has_attr("disabled"))
        self.assertIsNone(hero.select_one(f'a[href="/products/flash-intel/{UUID}/edit"]'))

    def test_a_draft_alert_page_offers_edit_and_delete(self):
        with mock.patch.object(misp_store, "get_fia", return_value=_fia("draft")):
            page = self.page(f"/products/flash-intel/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertEqual(hero.select_one(".hero-actions .btn-hero").get_text(strip=True), "Edit")
        self.assertIsNotNone(hero.select_one(f'form[action="/products/flash-intel/{UUID}/delete"]'))

    def test_an_alert_page_shows_its_source_articles_above_the_summary(self):
        page, fetched = self.with_sources(f"/products/flash-intel/{UUID}")
        # Read once, for the references and for the card both.
        fetched.assert_called_once()
        header = page.select_one("#source-events-header")
        self.assertEqual(header.find("span").get_text(strip=True), "Source events (2)")
        self.assertEqual(header.select_one("#source-events-toggle").get_text(strip=True), "Show")
        self.assertIsNone(header.select_one("[data-tlr-url], .zs-pill"))
        cards = [c.select_one(".card-header").get_text(" ", strip=True) for c in page.select(".col-lg-8 > .card")]
        self.assertLess(cards.index("Source events (2) Show"), cards.index("Summary SOC"))
        # Rendered on the server, so the card reads the same when it loads them later.
        bodies = [el.get_text(strip=True) for el in page.select("#source-events-accordion .report-md-body")]
        self.assertEqual(bodies, ["Full text 0", "Full text 1"])
        self.assertIsNone(page.select_one("#source-events-accordion [data-md]"))
        self.assertIsNone(page.select_one("#source-events-accordion .add-fact-btn"))

    def test_an_alert_page_queues_its_source_articles_for_the_threat_landscape(self):
        page, _ = self.with_sources(f"/products/flash-intel/{UUID}")
        actions = page.select("section.record-hero .hero-actions > *")
        button = actions[-1]
        self.assertEqual(" ".join(button.get_text().split()), "Queue 2 articles for threat landscape")
        self.assertIn("Delete FIA", actions[-2].get_text())
        # The route queues the sources stored on the alert, not ids from the page.
        self.assertEqual(button["data-tlr-url"], f"/products/flash-intel/{UUID}/queue-for-tlr")

    def test_one_source_article_is_counted_as_one(self):
        page, _ = self.with_sources(f"/products/flash-intel/{UUID}", count=1)
        button = page.select_one("[data-tlr-url]")
        self.assertEqual(" ".join(button.get_text().split()), "Queue 1 article for threat landscape")

    def queue(self, alert):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        with mock.patch.object(misp_store, "get_fia", return_value=alert), \
             mock.patch.object(data_collection, "queue_events_for_tlr",
                               return_value={"ok": True, "message": "2 events queued"}) as queued:
            reply = self.client.post(f"/products/flash-intel/{UUID}/queue-for-tlr",
                                     headers={"X-CSRF-Token": "test-token"})
        return reply, queued

    def test_the_route_queues_the_sources_stored_on_the_alert(self):
        """Wherever they are: one older than Data collection holds is queued too."""
        uuids = list(SOURCES)
        reply, queued = self.queue(_fia("approved", source_event_uuids=uuids,
                                        source_event_hints={uuids[1]: "partner"}))
        self.assertEqual(reply.get_json()["message"], "2 events queued")
        self.assertEqual(queued.call_args.args[0], [(uuids[0], "scraper"), (uuids[1], "partner")])
        self.assertEqual(queued.call_args.kwargs["collected_only"], False)
        self.assertEqual(queued.call_args.kwargs["audit_id"], UUID)

    def test_the_route_answers_for_an_alert_only(self):
        reply, queued = self.queue(None)
        self.assertEqual(reply.status_code, 404)
        queued.assert_not_called()

    def test_an_alert_without_source_events_offers_neither(self):
        with mock.patch.object(misp_store, "get_fia", return_value=_fia("draft")):
            page = self.page(f"/products/flash-intel/{UUID}")
        self.assertIsNone(page.select_one("#source-events-header"))
        self.assertIsNone(page.select_one("[data-tlr-url]"))

    def test_the_form_queues_the_source_articles_left_of_the_ai_assistance(self):
        page, _ = self.with_sources(f"/products/flash-intel/{UUID}/edit")
        tools = page.select_one("#source-events-header > div")
        button = tools.select_one("[data-tlr-url]")
        self.assertEqual(button["data-tlr-url"], f"/products/flash-intel/{UUID}/queue-for-tlr")
        self.assertEqual(" ".join(button.get_text().split()), "Queue 2 articles for threat landscape")
        labels = [" ".join(el.get_text().split()) for el in tools.find_all(recursive=False)]
        self.assertLess(labels.index("Queue 2 articles for threat landscape"), labels.index("AI assistance"))
        # The form keeps adding attributes to the observed facts.
        self.assertIsNone(page.select_one("#source-events-accordion .report-md-body:not(.text-muted)"))

    def test_the_form(self):
        with mock.patch.object(misp_store, "get_fia", return_value=_fia("draft")), \
             mock.patch.object(misp_store, "list_fias", return_value=[]):
            page = self.page(f"/products/flash-intel/{UUID}/edit")
        steps = ["summary", "happened", "matters", "scope", "actions", "detection", "references"]
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         [f"#step-{s}" for s in steps])
        for step in steps:
            self.assertIsNotNone(page.select_one(f".form-step#step-{step}"), step)
        self.assertIsNotNone(page.select_one("#step-summary #fia-title"))
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertEqual(card.select_one(".card-header").get_text(strip=True), "As it will appear")
        self.assertIsNotNone(card.select_one("#btn-fia-save"))
        self.assertIsNotNone(card.select_one("#btn-fia-submit"))
        self.assertEqual([r["value"] for r in page.select("input[name=tlp]")], misp_store.FIA_TLP_LEVELS)
        self.assertEqual(page.select_one("input[name=audience][value=SOC]").has_attr("checked"), True)


class TechniquePicker(Pages):
    """A technique a story's scope or a source kept by its id alone was ticked
    in the pick-list as "T1059", without its name, beside an unticked galaxy
    entry for the same technique."""
    GALAXY = ["Command and Scripting Interpreter - T1059", "Valid Accounts - T1078",
              "PowerShell - T1059.001"]

    def test_an_id_picks_the_galaxy_entry_with_its_name(self):
        self.assertEqual(misp_store.galaxy_values(["T1059", "Valid Accounts - T1078", "Watering holes"], self.GALAXY),
                         ["Command and Scripting Interpreter - T1059", "Valid Accounts - T1078", "Watering holes"])

    def test_the_alert_form_ticks_the_named_technique(self):
        # The page names techniques from a cache; this list must not stay in it.
        with mock.patch.object(misp_store, "get_fia", return_value=_fia("draft", mitre_attack_techniques=["T1059"])), \
             mock.patch.object(misp_store, "list_fias", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=self.GALAXY), \
             mock.patch.dict(misp_store._mitre_name_cache, clear=True), \
             mock.patch.object(misp_store, "_mitre_name_ts", 0.0):
            page = self.page(f"/products/flash-intel/{UUID}/edit")
        ticked = [b["value"] for b in page.select("#gms-mitre_attack_techniques input:checked")]
        self.assertEqual(ticked, ["Command and Scripting Interpreter - T1059"])
        self.assertIsNone(page.select_one('#gms-mitre_attack_techniques input[value="T1059"]'))


class FormPreview(Pages):
    def test_a_missing_audience_shows_in_red(self):
        """"None yet, one is needed to publish" read as grey, as if nothing were missing."""
        with mock.patch.object(misp_store, "list_fias", return_value=[]), \
             mock.patch.object(misp_store, "list_veas", return_value=[]):
            for path in ("/products/flash-intel/new", "/products/vea/new"):
                with self.subTest(path):
                    page = self.page(path)
                    self.assertTrue(page.select_one('.form-save dd[data-preview-choice="audience"]').has_attr("data-required"))
                    script = "".join(s.get_text() for s in page.select("script"))
                    self.assertIn("el.classList.toggle('text-danger', missing);", script)

    def test_what_the_cve_lookup_fills_reaches_the_preview(self):
        """The lookup set the CVSS without the input event "As it will appear" listens for."""
        with mock.patch.object(misp_store, "list_veas", return_value=[]):
            script = "".join(s.get_text() for s in self.page("/products/vea/new").select("script"))
        self.assertIn("if (el && !el.value.trim()) zsazsaSetField(el, val);", script)
        self.assertIn("el.dispatchEvent(new Event('input', {bubbles: true}));", script)


class AiTargets(Pages):
    """Build with AI outlines the sections it fills, as the manual entry does:
    each one it names is on the page, and the script that outlines them is."""

    def targets(self, page, selector):
        return [t.strip() for t in page.select_one(selector)["data-ai-targets"].split(",")]

    def assert_on_page(self, page, targets):
        for target in targets:
            self.assertIsNotNone(page.select_one(target), target)
        self.assertIn("window.zsazsaAiTargets = function(el, on)", str(page))

    def test_the_alert_s_build_names_the_six_sections_it_fills(self):
        page, _ = self.with_sources(f"/products/flash-intel/{UUID}/edit")
        wanted = ["#step-summary", "#step-happened", "#step-matters", "#step-scope", "#step-actions", "#step-detection"]
        self.assertEqual(self.targets(page, "#build-ai-btn"), wanted)
        for option in page.select(".build-ai-option"):
            self.assertEqual([t.strip() for t in option["data-ai-targets"].split(",")], wanted)
        self.assert_on_page(page, wanted)

    def test_the_advisory_s_build_names_what_its_mode_fills(self):
        page, _ = self.with_sources(f"/products/vea/{UUID}/edit", "vea")
        lookup, summary = page.select(".build-ai-option")
        self.assertEqual(self.targets(page, "#build-ai-btn"), [t.strip() for t in lookup["data-ai-targets"].split(",")])
        # Only the lookup fills the identification and the references.
        self.assertIn("#step-ident", lookup["data-ai-targets"])
        self.assertNotIn("#step-ident", summary["data-ai-targets"])
        self.assert_on_page(page, self.targets(page, "#build-ai-btn"))

    def test_drafting_an_advisory_without_sources_names_its_sections_too(self):
        with mock.patch.object(misp_store, "list_veas", return_value=[]):
            page = self.page("/products/vea/new")
        self.assert_on_page(page, self.targets(page, "#btn-draft-vea"))


class AdvisoryPages(Pages):
    def test_the_list_groups_the_advisories_by_review_state(self):
        advisories = [_vea("approved", cisa_kev="Yes"), _vea("rejected"), _vea("draft")]
        for n, vea in enumerate(advisories):
            vea.uuid = f"vea-{n}"
        with mock.patch.object(misp_store, "list_veas", return_value=advisories):
            page = self.page("/products/vea/")
        figures = page.select_one("section.record-hero .record-kpis").get_text(" ", strip=True)
        self.assertIn("3 advisories", figures)
        self.assertIn("1 KEV listed", figures)
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Draft", "Approved", "Rejected"])
        self.assertEqual(page.select_one("section.record-hero .btn-hero")["href"], "/products/vea/new")
        self.assertIsNotNone(page.select_one('form.record-filters select[name="exploitation"]'))

    def test_an_approved_advisory_page(self):
        with mock.patch.object(misp_store, "get_vea", return_value=_vea("approved", cvss="9.2 CRITICAL", cwe="CWE-416, CWE-755")):
            page = self.page(f"/products/vea/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertEqual(hero.select_one("h1").get_text(strip=True), "PHP OOM RCE")
        self.assertIn("CVE-2026-1", hero.select_one(".record-facts").get_text())
        actions = {b.get_text(strip=True): b for b in hero.select(".hero-actions .btn")}
        self.assertIn("Resend", actions)
        self.assertTrue(actions["Delete VEA"].has_attr("disabled"))
        self.assertEqual([b.get_text() for b in page.select(".chip-tag-generic")], ["CWE-416", "CWE-755"])

    def test_resend_is_disabled_without_publish_rights(self):
        """The route refuses a resend without them, so the page offers none."""
        status = {"tone": "danger", "label": "Failed", "timestamp": "2026-10-23 15:23", "details": "could not reach mattermost"}
        for path, getter, record in ((f"/products/vea/{UUID}", "get_vea", _vea("approved")),
                                     (f"/products/flash-intel/{UUID}", "get_fia", _fia("approved")),
                                     (f"/products/detection-eng/{UUID}", "get_der", _der("approved")),
                                     (f"/products/threat-actor-profile/{UUID}", "get_threat_actor_profile", _tap("Published"))):
            with self.subTest(path), mock.patch.object(misp_store, getter, return_value=record), \
                 mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]), \
                 mock.patch.object(audit, "latest_notify_status", return_value=status), \
                 mock.patch.object(misp_session, "current_user_can_publish", return_value=False):
                page = self.page(path)
                resend = page.select_one(".hero-actions .btn-hero")
                self.assertEqual(resend.get_text(strip=True), "Resend")
                self.assertTrue(resend.has_attr("disabled"))
                self.assertIsNone(page.select_one('form[action$="/resend"], form[action$="/notify"]'))

    def test_empty_sections_are_named_on_one_line(self):
        with mock.patch.object(misp_store, "get_vea", return_value=_vea("draft", worst_case="Full takeover")):
            page = self.page(f"/products/vea/{UUID}")
        headers = [h.get_text(strip=True) for h in page.select(".card-header")]
        self.assertIn("Risk assessment", headers)
        self.assertNotIn("Recommended actions", headers)
        self.assertNotIn("Detection guidance", headers)
        line = page.select_one("#empty-sections").get_text(" ", strip=True)
        self.assertIn("Recommended actions and Detection guidance", line)
        self.assertEqual(page.select_one(".hero-actions .btn-hero").get_text(strip=True), "Edit")

    def test_a_failed_notification_is_listed_step_by_step(self):
        status = {"tone": "danger", "label": "Failed", "timestamp": "2026-10-23 15:23",
                  "details": "publish: 1 eligible recipient(s). Channels: sent via email; could not reach mattermost; "
                             "Flowintel case creation on demo failed: timed out"}
        with mock.patch.object(misp_store, "get_vea", return_value=_vea("approved")), \
             mock.patch.object(audit, "latest_notify_status", return_value=status):
            page = self.page(f"/products/vea/{UUID}")
        lines = page.select("#notify-card .notify-trail li")
        self.assertEqual([li.select_one("i")["class"][1] for li in lines], ["fa-check", "fa-xmark", "fa-xmark"])
        self.assertIsNotNone(page.select_one(f'#notify-card form[action="/products/vea/{UUID}/resend"]'))

    def test_the_form(self):
        with mock.patch.object(misp_store, "get_vea", return_value=_vea("draft")), \
             mock.patch.object(misp_store, "list_veas", return_value=[]):
            page = self.page(f"/products/vea/{UUID}/edit")
        steps = ["ident", "tech", "expl", "risk", "actions", "detection", "references"]
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         [f"#step-{s}" for s in steps])
        self.assertIsNotNone(page.select_one("#step-ident #vea-title"))
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertIsNotNone(card.select_one("#btn-vea-save"))
        self.assertIsNotNone(card.select_one("#btn-vea-submit"))
        self.assertTrue(page.select_one('input[name=tlp][value=amber]').has_attr("checked"))
        self.assertTrue(page.select_one("input.vea-audience-cb[value=SOC]").has_attr("checked"))
        self.assertIsNotNone(page.select_one(".ai-actions #btn-draft-vea"))
        self.assertIsNotNone(page.select_one(".ai-actions .qa-review-btn"))

    def test_an_advisory_page_shows_its_source_articles_above_the_summary(self):
        page, fetched = self.with_sources(f"/products/vea/{UUID}", "vea")
        fetched.assert_called_once()
        header = page.select_one("#source-events-header")
        self.assertEqual(header.find("span").get_text(strip=True), "Source events (2)")
        cards = [h.get_text(" ", strip=True) for h in page.select(".col-lg-8 > .card > .card-header")]
        self.assertEqual(cards.index("Source events (2) Show") + 1, [i for i, c in enumerate(cards) if c.startswith("Summary")][0])
        self.assertEqual([el.get_text(strip=True) for el in page.select("#source-events-accordion .report-md-body")],
                         ["Full text 0", "Full text 1"])

    def test_an_advisory_page_queues_its_source_articles_for_the_threat_landscape(self):
        page, _ = self.with_sources(f"/products/vea/{UUID}", "vea")
        actions = page.select("section.record-hero .hero-actions > *")
        self.assertIn("Delete VEA", actions[-2].get_text())
        self.assertEqual(" ".join(actions[-1].get_text().split()), "Queue 2 articles for threat landscape")
        self.assertEqual(actions[-1]["data-tlr-url"], f"/products/vea/{UUID}/queue-for-tlr")

    def test_the_form_queues_the_source_articles_left_of_the_ai_assistance(self):
        page, _ = self.with_sources(f"/products/vea/{UUID}/edit", "vea")
        tools = page.select_one("#vea-source-events-header > div")
        labels = [el.get_text(" ", strip=True) for el in tools.find_all(recursive=False)]
        self.assertLess(labels.index("Queue 2 articles for threat landscape"), labels.index("AI assistance"))
        self.assertEqual(tools.select_one("[data-tlr-url]")["data-tlr-url"], f"/products/vea/{UUID}/queue-for-tlr")

    def test_the_route_queues_the_sources_stored_on_the_advisory(self):
        uuids = list(SOURCES)
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        with mock.patch.object(misp_store, "get_vea", return_value=_vea("approved", source_event_uuids=uuids,
                                                                        source_event_hints={uuids[1]: "partner"})), \
             mock.patch.object(data_collection, "queue_events_for_tlr", return_value={"ok": True}) as queued:
            reply = self.client.post(f"/products/vea/{UUID}/queue-for-tlr", headers={"X-CSRF-Token": "test-token"})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(queued.call_args.args[0], [(uuids[0], "scraper"), (uuids[1], "partner")])
        self.assertEqual((queued.call_args.kwargs["collected_only"], queued.call_args.kwargs["audit_type"]),
                         (False, "vea"))

    def test_the_route_refuses_an_unknown_advisory_or_one_without_sources(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        for advisory, status in ((None, 404), (_vea("draft"), 400)):
            with self.subTest(status), mock.patch.object(misp_store, "get_vea", return_value=advisory), \
                 mock.patch.object(data_collection, "queue_events_for_tlr") as queued:
                reply = self.client.post(f"/products/vea/{UUID}/queue-for-tlr", headers={"X-CSRF-Token": "test-token"})
                self.assertEqual(reply.status_code, status)
                queued.assert_not_called()


class ProfilePages(Pages):
    def test_the_list_groups_the_profiles_by_state(self):
        profiles = [_tap("Published", threat_actors=["ALLANITE"]), _tap("Draft", threat_actors=[])]
        for n, tap in enumerate(profiles):
            tap.uuid = f"tap-{n}"
        with mock.patch.object(misp_store, "list_threat_actor_profiles", return_value=profiles):
            page = self.page("/products/threat-actor-profile/")
        figures = page.select_one("section.record-hero .record-kpis").get_text(" ", strip=True)
        self.assertIn("1 threat actor profiled", figures)
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Draft", "Published"])
        self.assertIn("No threat actor picked yet", page.select_one("tr.draft-row").get_text())
        self.assertIsNotNone(page.select_one('section.record-hero a[href="/export/threat-actor-profiles"]'))

    def test_a_profile_with_another_status_is_listed_as_a_draft(self):
        with mock.patch.object(misp_store, "list_threat_actor_profiles", return_value=[_tap("published")]):
            page = self.page("/products/threat-actor-profile/")
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")], ["Draft"])

    def test_a_reference_that_is_not_a_web_address_is_not_a_link(self):
        tap = _tap("Published", external_references=["javascript:alert(1)", "https://ref.example/report"])
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap), \
             mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]):
            page = self.page(f"/products/threat-actor-profile/{UUID}")
        self.assertEqual([a["href"] for a in page.select("a[href*='alert'], a[href*='ref.example']")],
                         ["https://ref.example/report"])
        self.assertIn("javascript:alert(1)", page.get_text())

    def test_a_published_profile_page(self):
        tap = _tap("Published", threat_actors=["ALLANITE"], mitre_attack_techniques=["T1566", "T1078"],
                   geographic_scope=["Belgium"])
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap), \
             mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]):
            page = self.page(f"/products/threat-actor-profile/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertIn("Diamond Model, 3 of 4", hero.select_one(".delivery").get_text(" ", strip=True))
        self.assertEqual([leg.get("class") for leg in hero.select(".delivery .leg")],
                         [["leg", "done"], ["leg", "done"], ["leg"], ["leg", "done"]])
        actions = {b.get_text(strip=True): b for b in hero.select(".hero-actions .btn")}
        self.assertIn("Resend", actions)
        self.assertTrue(actions["Delete"].has_attr("disabled"))
        self.assertIn("No notes and no recommendations yet.", page.select_one("#empty-sections").get_text(" ", strip=True))

    def test_a_draft_profile_without_an_audience_cannot_be_published(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=_tap("Draft", audience="")), \
             mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]):
            page = self.page(f"/products/threat-actor-profile/{UUID}")
        publish = page.select_one(".hero-actions .btn-hero")
        self.assertEqual(publish.get_text(strip=True), "Publish")
        self.assertTrue(publish.has_attr("disabled"))
        self.assertIsNotNone(page.select_one(f'.hero-actions form[action="/products/threat-actor-profile/{UUID}/delete"]'))

    def test_the_form(self):
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=_tap("Draft")), \
             mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_threat_actors", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]), \
             mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]):
            page = self.page(f"/products/threat-actor-profile/{UUID}/edit")
        steps = ["summary", "actors", "details", "attribution", "recs", "scope", "references"]
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         [f"#step-{s}" for s in steps])
        self.assertIsNotNone(page.select_one("#step-summary #tap-title"))
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertIsNotNone(card.select_one("#tap-submit"))
        self.assertTrue(page.select_one("input[name=tlp][value=amber]").has_attr("checked"))
        self.assertTrue(page.select_one("input.tap-audience[value=SOC]").has_attr("checked"))
        # Completing from the galaxy is no AI action: it sits with the actors it reads.
        self.assertIsNotNone(page.select_one("#step-actors .card-body > #tap-enrich #tap-enrich-btn"))
        self.assertIsNone(page.select_one(".ai-actions #tap-enrich-btn"))
        self.assertIsNotNone(page.select_one(".ai-actions #tap-draft-btn"))


class DetectionRequestPages(Pages):
    def test_the_list_keeps_the_board_and_groups_the_table(self):
        requests = [_der("approved", status="In Test"), _der("draft", status="Pending"), _der("rejected", status="Pending")]
        for n, der in enumerate(requests):
            der.uuid = f"der-{n}"
        with mock.patch.object(misp_store, "list_ders", return_value=requests):
            page = self.page("/products/detection-eng/")
        figures = page.select_one("section.record-hero .record-kpis").get_text(" ", strip=True)
        self.assertIn("1 in test", figures)
        board = page.select_one(".kanban-board")
        columns = {c.select_one(".kanban-col-header").get_text(" ", strip=True): c for c in board.select(".kanban-col")}
        self.assertEqual(list(columns), ["Pending 1", "In Dev 0", "In Test 1", "Active 0", "Retired 0", "Rejected 1"])
        # The board script moves cards between these and updates the count badge.
        self.assertEqual(columns["In Test 1"]["data-status"], "In Test")
        card = columns["In Test 1"].select_one(".kanban-card")
        self.assertEqual(card["draggable"], "true")
        self.assertEqual(card["data-update-url"], "/products/detection-eng/der-0/status-update")
        self.assertIsNotNone(columns["Pending 1"].select_one(".approval-open"))
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Draft", "Approved", "Rejected"])

    def test_a_draft_request_page(self):
        der = _der("draft", status="In Dev", technique=["T1190"], cve_ids=["CVE-2024-3400"], log_sources=["EDR"])
        with mock.patch.object(misp_store, "get_der", return_value=der):
            page = self.page(f"/products/detection-eng/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertEqual([leg.get("class") for leg in hero.select(".delivery .leg")],
                         [["leg", "done"], ["leg", "done"], ["leg"], ["leg"]])
        self.assertEqual(hero.select_one(".hero-actions .btn-hero").get_text(strip=True), "Edit")
        self.assertIsNotNone(page.select_one(".col-lg-8 #der-draft-rule-form"))
        self.assertIsNotNone(page.select_one('.col-lg-4 form[action$="/approve"]'))
        line = page.select_one("#empty-sections").get_text(" ", strip=True)
        self.assertIn("Expected rule output and Test cases", line)
        self.assertIn("add them with Edit", line)

    def test_the_form(self):
        with mock.patch.object(misp_store, "get_der", return_value=_der("draft")), \
             mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]):
            page = self.page(f"/products/detection-eng/{UUID}/edit")
        self.assertEqual([a["href"] for a in page.select("section.record-hero .form-steps a")],
                         ["#step-request", "#step-techniques", "#step-hypothesis", "#step-sources"])
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertIsNotNone(card.select_one("#btn-der-save"))
        self.assertIsNotNone(card.select_one("#btn-der-submit"))
        self.assertTrue(page.select_one("input[name=tlp][value=amber]").has_attr("checked"))
        self.assertTrue(page.select_one("input.der-audience-cb[value=SOC]").has_attr("checked"))


class NewProfileForm(Pages):
    def test_a_new_profile_gets_the_step_and_preview_scripts(self):
        """They sat in the edit-only part of the page, so a new profile's form
        never marked its sections done or filled "As it will appear"."""
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_threat_actors", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]), \
             mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]):
            page = self.page("/products/threat-actor-profile/new")
        scripts = " ".join(s.get_text() for s in page.select("script"))
        self.assertIn(".form-step[data-step]", scripts)
        self.assertIn("data-preview-text", scripts)


class ThreatLandscapePages(Pages):
    def test_the_list_groups_the_reports_by_review_state_and_follows_with_the_queue(self):
        reports = [_tlr("published"), _tlr("draft")]
        for n, report in enumerate(reports):
            report.uuid = f"report-{n}"
        with mock.patch.object(misp_store, "list_tlrs", return_value=reports):
            page = self.page("/products/threat-landscape/")
        self.assertIn("record-hero-compact", page.select_one("section.record-hero")["class"])
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Draft", "Published"])
        self.assertIsNone(page.select_one("#queue"))
        self.assertIsNone(page.select_one('section.record-hero a[href="#queue"]'),
                          "an empty queue has no card for the figure to point at")

    def test_the_queue_figure_leads_to_the_queue(self):
        queued = [{"uuid": "queued-1", "info": "Cloud attack", "date": "2026-11-13", "source_id": "scraper",
                   "tags": [], "context": {}}]
        with mock.patch.object(misp_store, "list_tlrs", return_value=[]), \
             mock.patch.object(threat_landscape, "_queued_events", return_value=queued):
            page = self.page("/products/threat-landscape/")
        self.assertIsNotNone(page.select_one('section.record-hero a.warn[href="#queue"]'))
        self.assertIsNotNone(page.select_one("#queue"))

    def test_a_report_page_shows_when_each_review_step_was_reached(self):
        log = [{"from": "draft", "to": "internal-review", "by": "analyst@example.org",
                "at": "2026-10-27T09:00:00", "comment": ""}]
        with mock.patch.object(misp_store, "get_tlr", return_value=_tlr("internal-review", review_log=log)), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[]):
            page = self.page(f"/products/threat-landscape/{UUID}")
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-detail", hero["class"])
        self.assertIn("TLP:AMBER", hero.select_one(".hero-tlp").get_text())
        legs = {leg.contents[1].strip(): leg for leg in hero.select(".delivery .leg")}
        self.assertEqual(list(legs), ["Draft", "Internal review", "Stakeholder review", "Approved", "Published"])
        self.assertIn("done", legs["Internal review"]["class"])
        self.assertIn("analyst@example.org", legs["Internal review"].small.get_text())
        self.assertNotIn("done", legs["Approved"]["class"])

    def test_the_form(self):
        with mock.patch.object(misp_store, "get_tlr", return_value=_tlr("draft")), \
             mock.patch.object(misp_store, "list_tlrs", return_value=[]):
            page = self.page(f"/products/threat-landscape/{UUID}/edit")
        self.assertEqual(len(page.select("section.record-hero .form-steps a")), 9)
        self.assertEqual(len(page.select(".form-step")), 9)
        card = page.select_one(".col-lg-4 > .form-save")
        self.assertEqual(card.select_one(".card-header").get_text(strip=True), "As it will appear")
        self.assertEqual(card.select_one("button[type=submit]").get_text(strip=True), "Update report")
        self.assertEqual([r["value"] for r in page.select("input[name=tlp]")], misp_store.FIA_TLP_LEVELS)
        self.assertIsNone(page.select_one("#tlr-draft-btn"), "a report with no events has nothing to draft from")


class CollectionEventPage(Pages):
    def setUp(self):
        super().setUp()
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.get_event_reports.return_value = []
        source = {"id": "scraper", "label": "MISP scraper", "kind": "scraper", "url": "https://misp.example.org"}
        self.enterContext(mock.patch.object(data_collection, "_find_source", return_value=source))
        self.enterContext(mock.patch.object(data_collection, "_connect_source", return_value=(self.misp, None)))

    def event(self, tags, links=()):
        event = MISPEvent()
        event.from_dict(Event={
            "uuid": UUID, "id": "7", "info": "Cloud attack", "date": "2026-11-13", "threat_level_id": "2",
            "analysis": "2", "Tag": [{"name": name, "colour": colour} for name, colour in tags],
            "Attribute": [{"type": "link", "category": "External analysis", "value": v} for v in links]})
        self.misp.get_event.return_value = event
        return self.page(f"/collection/{UUID}?source=scraper")

    def test_where_the_event_stands_comes_from_its_tags(self):
        page = self.event([("tlp:clear", "#ffffff"), ('workflow:state="ongoing"', "#ff0099"),
                           ('zsazsa:product="threat-landscape-report"', "#cc44cc"),
                           ('admiralty-scale:source-reliability="b"', "#004400")])
        hero = page.select_one("section.record-hero")
        self.assertIn("ongoing", hero.select_one(".eyebrow").get_text())
        self.assertIn("TLP:CLEAR", hero.select_one(".hero-tlp").get_text())
        legs = [leg.get_text(" ", strip=True) for leg in hero.select(".delivery .leg")]
        self.assertEqual(legs, ["Collected MISP scraper", "Workflow ongoing",
                                "Threat landscape report queue tagged", "Source reliability B (Admiralty)"])
        form = hero.select_one('form[action="/products/threat-landscape/remove-from-queue"]')
        self.assertEqual(form.select_one("input[name=event]")["value"], UUID)
        self.assertTrue(form.has_attr("data-submit-confirm"))

    def test_an_untagged_event_is_not_offered_queue_removal(self):
        page = self.event([])
        hero = page.select_one("section.record-hero")
        self.assertIsNone(hero.select_one(".hero-tlp"))
        self.assertIsNone(hero.select_one('form[action="/products/threat-landscape/remove-from-queue"]'))
        self.assertIn("Product queue none", hero.select_one(".delivery").get_text(" ", strip=True))

    def test_the_products_menu_is_in_the_banner_and_opens_over_it(self):
        toggle = self.event([]).select_one("section.record-hero .hero-actions .dropdown-toggle")
        self.assertEqual(toggle["data-bs-popper-config"], '{"strategy":"fixed"}')
        self.assertIn("Flash intel", toggle.find_next_sibling("ul").get_text())

    def test_the_original_article_is_linked_and_the_feed_is_not(self):
        page = self.event([], links=["https://example.org/rss.xml", "https://example.org/story"])
        self.assertEqual(page.select_one("section.record-hero a[rel~=noopener][href^='https://example.org']")["href"],
                         "https://example.org/story")

    def test_a_link_that_is_not_a_web_address_is_not_offered(self):
        page = self.event([], links=["javascript:alert(1)"])
        self.assertNotIn("Original article", page.select_one("section.record-hero").get_text())

    def test_a_tag_reads_on_its_own_colour(self):
        """A light tag had white text on it, so tlp:clear could not be read at all."""
        tags = {a.get_text(strip=True): a["style"] for a in self.event(
            [("tlp:clear", "#ffffff"), ("retention:99d", "#7a3a00"), ("odd", "red;background:url(x)")]
        ).select(".col-lg-4 a.badge")}
        self.assertIn("color:#000000", tags["tlp:clear"])
        self.assertIn("color:#ffffff", tags["retention:99d"])
        self.assertIn("background:#aaaaaa", tags["odd"])

    def test_the_banner_rise_leaves_no_transform_behind(self):
        """A transform left by the animation made the banner the box the fixed
        menu was placed in, and its overflow cut the menu off."""
        css = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "css" / "app.css").read_text()
        rule = next(line for line in css.splitlines() if line.startswith(".rise {"))
        self.assertIn("backwards", rule)
        self.assertNotIn(" both", rule)

    def test_the_save_card_of_a_form_stays_where_it_is(self):
        """It followed the page down, which confused; the stakeholder form's
        side column still does."""
        css = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "css" / "app.css").read_text()
        sticky = [line.strip() for line in css.splitlines() if "position: sticky" in line]
        self.assertFalse([line for line in sticky if ".form-save" in line], sticky)
        self.assertIn(".form-aside { position: sticky; top: var(--form-top); }", sticky)

    def test_the_ai_assistance_card_is_tinted(self):
        css = (Path(__file__).resolve().parent.parent / "webapp" / "static" / "css" / "app.css").read_text()
        self.assertIn(".content-card:has(> .ai-actions) > .card-header {", css)


if __name__ == "__main__":
    unittest.main()
