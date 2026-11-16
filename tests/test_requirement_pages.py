"""The PIR, GIR and RFI pages since the status board went: a list row's "Move
to" menu and a record page's lifecycle offer the moves the status routes
allow, and nothing before triage. The banners show the figures and actions the
old pages had in their cards, and a review that is past is said to be. Each list
shows where a record stands as a row of steps, and the badges have the colours
of their status, priority and level. The forms ask the classification as
choices, and an RFI form shows the response and feedback only once triaged.
Every banner is the compact one of the stakeholder list, a record's with its
buttons at the bottom left, and a form keeps its Save button in view.

Records come from the store's own builders, so they have every field the
templates read; the database and log are temporary.

    python -m unittest tests.test_requirement_pages
"""

import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent

import config
from webapp import collection_cache, create_app, misp_store


def _record(builder, reader, n, **fields):
    event = MISPEvent()
    event.uuid = f"00000000-0000-4000-8000-{n:012d}"
    event.id = n
    event.date = "2026-10-01"
    event.add_object(builder(fields))
    return reader(event)


def _pir(n, **fields):
    return _record(misp_store._pir_obj, misp_store._pir_ns, n, pir_id=f"PIR-00{n}", question=f"Question {n}", **fields)


def _gir(n, **fields):
    return _record(misp_store._gir_obj, misp_store._gir_ns, n, gir_id=f"GIR-00{n}", topic=f"Topic {n}", **fields)


def _rfi(n, status, **fields):
    fields.setdefault("priority", "Medium")
    return _record(misp_store._rfi_obj, misp_store._rfi_ns, n, rfi_id=f"RFI-00{n}", question=f"Question {n}",
                   status=status, **fields)


def _uuid(n):
    return f"00000000-0000-4000-8000-{n:012d}"


LONG_AGO = (date.today() - timedelta(days=10)).isoformat()


class _Pages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        galaxies = {name: mock.Mock(return_value=[]) for name in (
            "galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker"),
                        mock.patch.object(misp_store, "list_stakeholders", return_value=[]),
                        mock.patch.object(misp_store, "list_pirs", return_value=[]),
                        mock.patch.object(misp_store, "list_girs", return_value=[]),
                        mock.patch.object(misp_store, "list_product_feedback", return_value=[]),
                        mock.patch.multiple(misp_store, **galaxies)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")

    def moves(self, scope):
        """The statuses offered and the route each goes to."""
        return [(b["data-status-to"], b["data-update-url"]) for b in scope.select("[data-status-to]")]

    def row(self, page, record_id):
        badge = [b for b in page.select("tbody .req-id-badge") if b.get_text() == record_id][0]
        return badge.find_parent("tr")


class ListMenus(_Pages):
    def test_a_pir_moves_only_after_triage(self):
        pirs = [_pir(1, status="Active"), _pir(2, status="Pending"),
                _pir(3, status="Pending", intake_status="rejected")]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs):
            page = self.page("/pirs?rejected=1")
        url = f"/pirs/{_uuid(1)}/status"
        self.assertEqual(self.moves(self.row(page, "PIR-001")),
                         [(s, url) for s in ("In Development", "Under Evaluation", "Implemented", "Retired")])
        pending = self.row(page, "PIR-002")
        self.assertEqual(self.moves(pending), [])
        self.assertIsNotNone(pending.select_one(".triage-toggle"))
        self.assertEqual(self.moves(self.row(page, "PIR-003")), [])
        self.assertIsNone(page.select_one(".kanban-board"))

    def test_the_menu_asks_first(self):
        with mock.patch.object(misp_store, "list_pirs", return_value=[_pir(1, status="Active")]):
            page = self.page("/pirs")
        retire = page.select_one('[data-status-to="Retired"]')
        self.assertEqual(retire["data-confirm"], "Move PIR-001 to Retired?")
        self.assertIn("data-status-to", "".join(s.get_text() for s in page.select("script")))

    def test_a_gir_moves_anywhere(self):
        with mock.patch.object(misp_store, "list_girs", return_value=[_gir(1, status="Pending")]):
            page = self.page("/girs")
        self.assertEqual([s for s, _ in self.moves(self.row(page, "GIR-001"))], ["Active", "Retired"])

    def test_an_rfi_moves_only_after_triage_and_never_back_to_new(self):
        rfis = [_rfi(1, "New"), _rfi(2, "Acknowledged")]
        with mock.patch.object(misp_store, "list_rfis", return_value=rfis):
            page = self.page("/rfis/")
        self.assertEqual(self.moves(self.row(page, "RFI-001")), [])
        self.assertIsNotNone(self.row(page, "RFI-001").select_one(".triage-toggle"))
        self.assertEqual([s for s, _ in self.moves(self.row(page, "RFI-002"))], ["In Progress", "Delivered", "Closed"])

    def test_the_rows_by_status_and_a_review_that_is_past(self):
        pirs = [_pir(1, status="Retired", next_review=LONG_AGO), _pir(2, status="Active", next_review=LONG_AGO),
                _pir(3, status="Pending")]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs):
            page = self.page("/pirs")
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["Active", "Pending", "Retired"])
        self.assertEqual(self.row(page, "PIR-002").select_one(".overdue").get_text(), "10 days overdue")
        self.assertIsNone(self.row(page, "PIR-001").select_one(".overdue"))
        kpis = page.select_one(".record-kpis").get_text(" ", strip=True)
        self.assertIn("1 active", kpis)
        self.assertIn("1 waiting for triage", kpis)
        self.assertIn("1 active PIR past the review", kpis)

    def test_an_overdue_rfi_says_by_how_much(self):
        rfis = [_rfi(1, "Acknowledged", due_date=LONG_AGO), _rfi(2, "In Progress")]
        with mock.patch.object(misp_store, "list_rfis", return_value=rfis):
            page = self.page("/rfis/")
        self.assertEqual(self.row(page, "RFI-001").select_one(".sla-cell").get_text(" ", strip=True), "10 days overdue")
        self.assertIn("No due date", self.row(page, "RFI-002").select_one(".sla-cell").get_text())
        self.assertIn("1 past the due date", page.select_one(".record-kpis").get_text(" ", strip=True))


class ListLooks(_Pages):
    """Each list shows where a record stands as a row of steps, the RFIs in
    groups by status as the PIRs and GIRs are, and the levels in their colours."""

    def steps(self, row):
        return [i.get("class", [""])[0] if i.get("class") else "" for i in row.select(".status-steps i")]

    def test_the_status_steps_of_a_pir_and_a_gir(self):
        with mock.patch.object(misp_store, "list_pirs", return_value=[_pir(1, status="Under Evaluation", intel_level=["Strategic"]),
                                                                       _pir(2, status="Pending")]), \
             mock.patch.object(misp_store, "list_girs", return_value=[_gir(1, status="Active")]):
            pirs, girs = self.page("/pirs"), self.page("/girs")
        self.assertEqual(self.steps(self.row(pirs, "PIR-001")), ["done", "done", "done", "now", "", ""])
        pending = self.row(pirs, "PIR-002")
        self.assertEqual(self.steps(pending), ["now", "", "", "", "", ""])
        self.assertIsNotNone(pending.select_one(".triage-toggle"))
        self.assertEqual(self.row(pirs, "PIR-001").select_one(".level-badge")["class"], ["badge", "level-badge", "level-strategic"])
        self.assertEqual(self.steps(self.row(girs, "GIR-001")), ["done", "now", ""])
        self.assertIn("Review", [th.get_text(strip=True) for th in girs.select("thead th")])

    def test_the_rfis_in_groups_by_status(self):
        rfis = [_rfi(1, "Closed"), _rfi(2, "New"), _rfi(3, "In Progress")]
        with mock.patch.object(misp_store, "list_rfis", return_value=rfis):
            page = self.page("/rfis/?closed=1")
        self.assertEqual([th.select_one(".lane-name").get_text() for th in page.select("tr.lane-head th")],
                         ["New", "In Progress", "Closed"])
        self.assertEqual(self.steps(self.row(page, "RFI-003")), ["done", "done", "now", "", ""])


class DetailLooks(_Pages):
    def test_a_pir_banner(self):
        pir = _pir(1, status="Pending", priority="Could have", intel_level=["Strategic", "Operational"],
                   collection_sources=["misp-scraper"], next_review=LONG_AGO, mitre_attack_techniques=["T1190"])
        with mock.patch.object(misp_store, "get_pir", return_value=pir):
            page = self.page(f"/pirs/{_uuid(1)}")
        hero = page.select_one(".record-hero")
        self.assertEqual([b["class"][-1] for b in hero.select(".badge")],
                         ["status-pending", "priority-could-have", "level-strategic", "level-operational"])
        self.assertIn("Collection misp-scraper", hero.select_one(".record-facts").get_text(" ", strip=True))
        self.assertIn("Review 10 days overdue", hero.select_one(".hero-block").get_text(" ", strip=True))
        self.assertIsNotNone(page.select_one(".attack-card .attack-technique-badge"))

    def test_a_gir_banner(self):
        gir = _gir(1, status="Active", intel_level=["Tactical"], mitre_attack_techniques=["T1190"])
        with mock.patch.object(misp_store, "get_gir", return_value=gir):
            page = self.page(f"/girs/{_uuid(1)}")
        hero = page.select_one(".record-hero")
        self.assertEqual([b["class"][-1] for b in hero.select(".badge")], ["status-active", "level-tactical"])
        self.assertEqual([t.get_text(" ", strip=True) for t in hero.select(".record-tile")],
                         ["0 scope items", "0 of them focus points"])
        self.assertIsNotNone(page.select_one(".attack-card"))

    def test_an_rfi_banner(self):
        with mock.patch.object(misp_store, "get_rfi", return_value=_rfi(1, "In Progress", priority="High")):
            page = self.page(f"/rfis/{_uuid(1)}")
        self.assertEqual([b["class"][-1] for b in page.select_one(".record-hero").select(".badge")],
                         ["status-in-progress", "priority-must-have"])


class CompactBanners(_Pages):
    """Every list, record and form opens on the compact banner of the
    stakeholder list, so the page starts higher. A list's banner has no
    sentence on what the page is, and its breakdowns are in a panel of their
    own under the figures."""

    def hero(self, page):
        hero = page.select_one("section.record-hero")
        self.assertIn("record-hero-compact", hero["class"])
        return hero

    def test_the_lists(self):
        with mock.patch.object(misp_store, "list_rfis", return_value=[_rfi(1, "New")]), \
             mock.patch.object(misp_store, "list_pirs", return_value=[_pir(2, status="Active", priority="Must have")]), \
             mock.patch.object(misp_store, "list_girs", return_value=[_gir(3, status="Active", review_cycle="Weekly")]):
            for path in ("/pirs", "/girs", "/rfis/"):
                with self.subTest(path):
                    hero = self.hero(self.page(path))
                    self.assertIsNone(hero.select_one(".lead-text"))
                    self.assertIsNotNone(hero.select_one(".hero-main > .hero-icon"))
                    self.assertIsNotNone(hero.select_one(".record-panel.list-stats"))

    def test_the_records_and_the_forms(self):
        for path, getter, record in ((f"/pirs/{_uuid(1)}", "get_pir", _pir(1)),
                                     (f"/girs/{_uuid(2)}", "get_gir", _gir(2)),
                                     (f"/rfis/{_uuid(3)}", "get_rfi", _rfi(3, "New")),
                                     ("/pirs/new", None, None), ("/girs/new", None, None), ("/rfis/new", None, None)):
            with self.subTest(path):
                if getter:
                    with mock.patch.object(misp_store, getter, return_value=record):
                        self.hero(self.page(path))
                else:
                    self.hero(self.page(path))


class RecordPages(_Pages):
    """A record's page has its buttons at the bottom left of the banner, its
    out of scope in the Scope card and no second card repeating the scope,
    each technique by id and name, and a way to its triage on the list."""

    def record_page(self, path, getter, record):
        with mock.patch.object(misp_store, getter, return_value=record):
            return self.page(path)

    def test_the_buttons_are_under_what_the_record_says(self):
        for path, getter, record in ((f"/pirs/{_uuid(1)}", "get_pir", _pir(1, status="Active")),
                                     (f"/girs/{_uuid(2)}", "get_gir", _gir(2)),
                                     (f"/rfis/{_uuid(3)}", "get_rfi", _rfi(3, "In Progress"))):
            with self.subTest(path):
                hero = self.record_page(path, getter, record).select_one("section.record-hero")
                self.assertIn("record-hero-detail", hero["class"])
                body = hero.select_one(".hero-body")
                self.assertEqual([c["class"][0] for c in body.find_all(recursive=False)], ["hero-main", "hero-actions"])
                self.assertIn("Edit", body.select_one(".hero-actions").get_text())

    def test_out_of_scope_is_in_the_scope_card(self):
        for path, getter, record in ((f"/pirs/{_uuid(1)}", "get_pir", _pir(1, out_of_scope=["Consumer fraud"])),
                                     (f"/girs/{_uuid(2)}", "get_gir", _gir(2, out_of_scope=["Consumer fraud"]))):
            with self.subTest(path):
                page = self.record_page(path, getter, record)
                self.assertEqual([t.get_text() for t in page.select(".fp-card .fp-out .source-tag")], ["Consumer fraud"])
                headers = [h.get_text(" ", strip=True) for h in page.select(".card-header")]
                self.assertEqual(len([h for h in headers if h.startswith("Scope")]), 1)
                self.assertNotIn("Boundaries", headers)

    def test_no_out_of_scope_line_without_any(self):
        self.assertIsNone(self.record_page(f"/pirs/{_uuid(1)}", "get_pir", _pir(1)).select_one(".fp-out"))

    def test_a_pir_has_no_collection_coverage_card(self):
        page = self.record_page(f"/pirs/{_uuid(1)}", "get_pir", _pir(1, geographic_scope=["Belgium"]))
        self.assertNotIn("Collection coverage", page.get_text())

    def test_a_technique_shows_its_id_and_its_name(self):
        """However it was stored: the form stores "Phishing - T1566", and the
        name was shown where the id goes. The demo seed stored a bare id."""
        techniques = ["Phishing - T1566", "T1190", "T0885", "Watering holes"]
        with mock.patch.object(misp_store, "galaxy_mitre_attack_patterns",
                               return_value=["Exploit Public-Facing Application - T1190"]), \
             mock.patch.dict(misp_store._mitre_name_cache, clear=True), \
             mock.patch.object(misp_store, "_mitre_name_ts", 0.0):
            for path, getter, record in ((f"/pirs/{_uuid(1)}", "get_pir", _pir(1, mitre_attack_techniques=techniques)),
                                         (f"/girs/{_uuid(2)}", "get_gir", _gir(2, mitre_attack_techniques=techniques))):
                with self.subTest(path):
                    badges = self.record_page(path, getter, record).select(".attack-technique-badge")
                    shown = [(b.select_one(".attack-tid") and b.select_one(".attack-tid").get_text(),
                              b.select_one(".attack-tname") and b.select_one(".attack-tname").get_text()) for b in badges]
                    self.assertEqual(shown, [("T1566", "Phishing"), ("T1190", "Exploit Public-Facing Application"),
                                             ("T0885", None), (None, "Watering holes")])

    def test_triage_on_the_list_names_the_record(self):
        pir = self.record_page(f"/pirs/{_uuid(1)}", "get_pir", _pir(1, status="Pending"))
        rfi = self.record_page(f"/rfis/{_uuid(3)}", "get_rfi", _rfi(3, "New"))
        links = [[a["href"] for a in page.select("a") if "Triage it on the" in a.get_text()] for page in (pir, rfi)]
        self.assertEqual(links, [[f"/pirs?triage={_uuid(1)}"], [f"/rfis/?triage={_uuid(3)}"]])


class FormSaveCard(_Pages):
    """Save and Cancel are in an "As it will appear" card at the top of the
    side column, as on the stakeholder form, which the stylesheet keeps in
    view, rather than at the end of a card further down that scrolled away.
    The card shows the record as the form has it."""

    def test_the_card_shows_the_record(self):
        rfi = _rfi(3, "Acknowledged", requester_name="Ada", requester_team="SOC")
        with mock.patch.object(misp_store, "get_pir", return_value=_pir(1)), \
             mock.patch.object(misp_store, "get_rfi", return_value=rfi):
            pir, new, edit_rfi = self.page(f"/pirs/{_uuid(1)}/edit"), self.page("/pirs/new"), self.page(f"/rfis/{_uuid(3)}/edit")
        for page, record in ((pir, "PIR-001"), (new, "New PIR"), (edit_rfi, "RFI-003")):
            card = page.select_one(".form-save")
            self.assertEqual(card.select_one(".card-header").get_text(strip=True), "As it will appear")
            self.assertEqual(card.select_one(".req-id-badge").get_text(strip=True), record)
        self.assertEqual(pir.select_one(".form-preview-title")["data-preview-text"], "question")
        self.assertEqual([dt.get_text() for dt in edit_rfi.select(".form-save dt")], ["Priority", "Asked by", "Assigned to", "Due"])
        self.assertTrue(any("data-preview-choice" in script.get_text() for script in pir.select("script")))

    def test_the_forms(self):
        for path, label in (("/pirs/new", "Create PIR"), ("/girs/new", "Create GIR"), ("/rfis/new", "Create RFI")):
            with self.subTest(path):
                page = self.page(path)
                card = page.select_one(".col-lg-4 > .form-save")
                self.assertEqual(card.find_previous_sibling(), None)
                self.assertEqual([b.get_text(strip=True) for b in page.select("button[type=submit]")
                                  if b.get_text(strip=True) in (label, "Save changes")], [label])
                self.assertIsNotNone(card.select_one("button[type=submit]"))
                self.assertEqual(card.select_one("a.btn")["href"], path.replace("/new", "") + ("/" if "rfis" in path else ""))


class DetailLifecycles(_Pages):
    def pir_page(self, **fields):
        with mock.patch.object(misp_store, "get_pir", return_value=_pir(1, **fields)):
            return self.page(f"/pirs/{_uuid(1)}")

    def test_an_active_pir_moves_from_its_page(self):
        page = self.pir_page(status="Active", decision_supported="Patch first", decision_maker=["CISO"],
                             consequence=["Outage"], next_review=LONG_AGO)
        self.assertEqual([s for s, _ in self.moves(page.select_one(".lifecycle"))],
                         ["In Development", "Under Evaluation", "Implemented", "Retired"])
        self.assertEqual(page.select_one(".lifecycle li.now").get_text(strip=True), "Active")
        hero = page.select_one(".record-hero")
        self.assertIsNotNone(hero.select_one("#notify-btn[data-notify-url]"))
        self.assertIn("10 days overdue", hero.get_text(" ", strip=True))
        self.assertEqual([s.get_text(" ", strip=True) for s in page.select(".decision-step")],
                         ["Decision Patch first", "Taken by CISO", "If it stays unanswered Outage"])

    def test_a_pending_or_rejected_pir_does_not(self):
        for fields, note in (({"status": "Pending"}, "A pending PIR leaves Pending through triage."),
                             ({"status": "Pending", "intake_status": "rejected"}, "Rejected in triage, so it does not move.")):
            with self.subTest(note):
                page = self.pir_page(**fields)
                self.assertEqual(self.moves(page), [])
                self.assertIn(note, page.select_one(".lifecycle").find_next("p").get_text())

    def test_a_gir_moves_from_its_page(self):
        with mock.patch.object(misp_store, "get_gir", return_value=_gir(1, status="Active", review_cycle="Weekly",
                                                                        next_review=LONG_AGO)):
            page = self.page(f"/girs/{_uuid(1)}")
        self.assertEqual(self.moves(page), [("Pending", f"/girs/{_uuid(1)}/status"), ("Retired", f"/girs/{_uuid(1)}/status")])
        block = page.select_one(".hero-block")
        self.assertIn("late", block["class"])
        self.assertIn("Weekly review 10 days overdue", block.get_text(" ", strip=True))

    def test_an_rfi_moves_from_its_page_once_triaged(self):
        with mock.patch.object(misp_store, "get_rfi", return_value=_rfi(1, "New")):
            new = self.page(f"/rfis/{_uuid(1)}")
        with mock.patch.object(misp_store, "get_rfi", return_value=_rfi(1, "In Progress", due_date=LONG_AGO)):
            started = self.page(f"/rfis/{_uuid(1)}")
        self.assertEqual(self.moves(new), [])
        self.assertIsNone(new.select_one("#notify-btn"))
        self.assertEqual([s for s, _ in self.moves(started)], ["Acknowledged", "Delivered", "Closed"])
        self.assertIsNotNone(started.select_one("#notify-btn"))
        self.assertIn("10 days past the due date", started.select_one(".hero-block").get_text(" ", strip=True))


class StatusRoutes(_Pages):
    """What the menus send: the routes still refuse what the board refused."""

    def post(self, path, status):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"
        return self.client.post(path, data={"csrf_token": "token", "status": status})

    def test_a_pending_pir_is_triaged_first(self):
        with mock.patch.object(misp_store, "get_pir", return_value=_pir(1, status="Pending")), \
             mock.patch.object(misp_store, "update_pir") as update:
            response = self.post(f"/pirs/{_uuid(1)}/status", "Active")
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "Triage this PIR before moving it."))
        update.assert_not_called()

    def test_an_rfi_never_goes_back_to_new(self):
        with mock.patch.object(misp_store, "get_rfi", return_value=_rfi(1, "Acknowledged")), \
             mock.patch.object(misp_store, "update_rfi") as update:
            response = self.post(f"/rfis/{_uuid(1)}/status", "New")
        self.assertEqual((response.status_code, response.get_json()["error"]), (400, "An RFI cannot be moved back to New."))
        update.assert_not_called()


class Forms(_Pages):
    """The forms ask the classification as choices that post what the
    drop-downs did, and before triage an RFI form leaves out the response and
    the feedback it cannot record rather than showing them disabled."""

    def form(self, path, getter=None, record=None):
        if getter:
            with mock.patch.object(misp_store, getter, return_value=record):
                return self.page(path)
        return self.page(path)

    def checked(self, page, name):
        return [box["value"] for box in page.select(f'input[name="{name}"][checked]')]

    def test_every_step_names_a_section(self):
        for path in ("/pirs/new", "/girs/new", "/rfis/new"):
            with self.subTest(path):
                page = self.form(path)
                self.assertEqual([a["href"] for a in page.select(".form-steps a")],
                                 ["#" + card["id"] for card in page.select(".form-step")])

    def test_a_pir_priority_is_a_choice(self):
        self.assertEqual(self.checked(self.form("/pirs/new"), "priority"), ["Should have"])
        page = self.form(f"/pirs/{_uuid(1)}/edit", "get_pir", _pir(1, priority="Must have"))
        self.assertEqual(self.checked(page, "priority"), ["Must have"])
        page = self.form(f"/pirs/{_uuid(1)}/edit", "get_pir", _pir(1, priority="Urgent"))
        self.assertEqual(self.checked(page, "priority"), ["Must have"])

    def test_the_output_formats_are_tiles_the_toggle_reaches(self):
        for path in ("/pirs/new", "/girs/new"):
            with self.subTest(path):
                page = self.form(path)
                boxes = page.select(page.select_one("[data-toggle-all]")["data-toggle-all"])
                self.assertTrue(boxes)
                self.assertTrue(all(box.find_parent("label", class_="product-tile") for box in boxes))

    def test_a_gir_status_and_review_cycle_are_choices(self):
        page = self.form("/girs/new")
        self.assertEqual(page.select('input[name="status"]'), [])
        self.assertEqual(self.checked(page, "review_cycle"), ["Quarterly"])
        page = self.form(f"/girs/{_uuid(1)}/edit", "get_gir", _gir(1, status="Retired", review_cycle="Weekly"))
        self.assertEqual(self.checked(page, "status"), ["Retired"])
        self.assertEqual(self.checked(page, "review_cycle"), ["Weekly"])

    def test_an_rfi_before_triage_has_only_its_formats(self):
        for path, record in (("/rfis/new", None), (f"/rfis/{_uuid(1)}/edit", _rfi(1, "New"))):
            with self.subTest(path):
                page = self.form(path, "get_rfi", record)
                self.assertIsNone(page.select_one('[name="response"]'))
                self.assertIsNone(page.select_one('[name="response_confidence"]'))
                self.assertIsNone(page.select_one('[name^="feedback_"]'))
                self.assertIsNotNone(page.select_one("#fmt-add"))
                self.assertEqual(self.checked(page, "priority"), ["Medium"])

    def test_a_triaged_rfi_records_its_response_and_feedback(self):
        page = self.form(f"/rfis/{_uuid(1)}/edit", "get_rfi", _rfi(1, "Acknowledged", priority="High"))
        fields = page.select('[name="response"], [name="response_confidence"], [name^="feedback_"]')
        self.assertEqual(len(fields), 6)
        self.assertFalse(any(field.has_attr("disabled") for field in fields))
        self.assertEqual(self.checked(page, "priority"), ["High"])


if __name__ == "__main__":
    unittest.main()
