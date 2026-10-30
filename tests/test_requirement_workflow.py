"""The PIR, GIR and RFI workflow: what an edit, a triage and a status move may change.

Products, RFIs and stakeholders point at a requirement by UUID, so an update of
one that has gone fails rather than making a new one. The status of a PIR and an
RFI changes through triage and the status board only, never through the edit
form, and a triage is taken once. A PIR or a GIR is not saved from its form
without an intelligence level. A product or an RFI is linked to an agreed PIR. Matching reads only Active requirements, so a
change of status refreshes it. A product records the PIR it answers on its
object, which is where the statistics and the stakeholder page have to look.

MISP is an autospec of PyMISP or the store functions are patched; nothing leaves
the machine.

    python -m unittest tests.test_requirement_workflow
"""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent, PyMISP

import config
from notifier import dispatcher
from webapp import collection_cache, create_app, misp_store
from webapp.models import INTEL_LEVELS
from webapp.routes import detection_eng, requirements, rfi, stats, threat_actor_profile, vea

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
OTHER = "0b3f6a8e-2c4d-4e5f-9a1b-c2d3e4f5a6b7"


def _pir(uuid=UUID, **fields):
    """A PIR as get_pir returns one, read from a stored event."""
    event = MISPEvent()
    event.uuid = uuid
    event.date = "2026-10-01"
    event.add_object(misp_store._pir_obj({"pir_id": "PIR-001", "question": "Who targets the grid?",
                                          "status": "Pending", "intake_status": "submitted", **fields}))
    return misp_store._pir_ns(event)


def _gir(uuid=UUID, **fields):
    """A GIR as get_gir returns one, read from a stored event."""
    event = MISPEvent()
    event.uuid = uuid
    event.date = "2026-10-01"
    event.add_object(misp_store._gir_obj({"gir_id": "GIR-001", "topic": "Grid threats", **fields}))
    return misp_store._gir_ns(event)


def _app(*blueprints):
    app = Flask(__name__)
    app.secret_key = "test"
    for bp in blueprints:
        app.register_blueprint(bp)
    return app.test_client()


class GoneRecords(unittest.TestCase):
    def test_a_requirement_or_rfi_that_has_gone_is_not_created_again(self):
        """It was, under a new UUID, which left every product and RFI linked to
        it pointing at nothing, and on a passing MISP error made a duplicate."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = {"errors": (404, {"message": "Invalid event"})}
        # Recreating takes a number from the id counter in this install's database.
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(misp_store, "_misp", return_value=misp):
            for update in (misp_store.update_pir, misp_store.update_gir, misp_store.update_rfi):
                with self.subTest(update.__name__), self.assertRaises(ValueError):
                    update(UUID, {"question": "q", "topic": "t"})
        misp.add_event.assert_not_called()


class StatusStaysOutOfTheEditForm(unittest.TestCase):
    """The forms only show the status. A posted one could make a Pending PIR
    Active, or an untriaged RFI Delivered, without triage."""

    def capture(self, path, store_call, form, getter="get_rfi", stored=None):
        captured = {}

        def remember(*args):
            captured.update(args[-1])
            return UUID

        with mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(misp_store, "list_pirs", return_value=[]), \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(misp_store, store_call, side_effect=remember), \
             mock.patch.object(misp_store, getter, return_value=stored), \
             mock.patch("webapp.audit.record"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            _app(requirements.bp, rfi.bp).post(path, data=form)
        return captured

    def test_a_pir_edit_keeps_the_stored_status_and_intake(self):
        pir = _pir(intake_status="acknowledged", acknowledged_by="lead@example.org")
        data = self.capture(f"/pirs/{UUID}/edit", "update_pir",
                            {"question": "Who targets the grid now?", "status": "Active", "intel_level": "Strategic"},
                            getter="get_pir", stored=pir)
        self.assertEqual(data["status"], "Pending")
        self.assertEqual(data["intake_status"], "acknowledged")
        self.assertEqual(data["acknowledged_by"], "lead@example.org")
        self.assertEqual(data["question"], "Who targets the grid now?")

    def test_a_pir_edit_corrects_the_triage_checklist_but_not_the_decision(self):
        pir = _pir(intake_status="approved", status="Active",
                   triage_checklist=["clear_question", "not_duplicate"])
        data = self.capture(f"/pirs/{UUID}/edit", "update_pir",
                            {"question": "q", "intel_level": "Strategic",
                             "triage_checklist": ["clear_question", "sources_available", "made_up"]},
                            getter="get_pir", stored=pir)
        self.assertEqual(data["triage_checklist"], ["clear_question", "sources_available"])
        self.assertEqual(data["intake_status"], "approved")
        self.assertEqual(data["status"], "Active")

    def test_a_gir_edit_ignores_a_status_it_does_not_know(self):
        gir = SimpleNamespace(uuid=UUID, gir_id="GIR-001", status="Active", focus_points=[])
        data = self.capture(f"/girs/{UUID}/edit", "update_gir", {"topic": "t", "status": "Hacked", "intel_level": "Tactical"},
                            getter="get_gir", stored=gir)
        self.assertEqual(data["status"], "Active")

    def test_a_new_rfi_starts_new(self):
        data = self.capture("/rfis/new", "create_rfi", {"question": "q", "status": "Closed"})
        self.assertEqual(data["status"], "New")

    def test_an_rfi_edit_keeps_the_stored_status(self):
        stored = SimpleNamespace(uuid=UUID, rfi_id="RFI-001", status="New", linked_pir_uuid="")
        data = self.capture(f"/rfis/{UUID}/edit", "update_rfi", {"question": "q", "status": "Delivered"},
                            stored=stored)
        self.assertEqual(data["status"], "New")


class IntelligenceLevelRequired(unittest.TestCase):
    """A PIR or GIR is saved only with an intelligence level ticked. The form
    blocks the submit without one, and the routes refuse it too, as they refuse
    a value the form does not offer."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        galaxies = {"galaxy_countries": [], "galaxy_sectors": [], "galaxy_threat_actors": [],
                    "galaxy_mitre_attack": [], "intel_levels": INTEL_LEVELS}
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker"),
                        mock.patch.object(misp_store, "list_stakeholders", return_value=[]),
                        mock.patch.object(misp_store, "list_girs", return_value=[]),
                        mock.patch.object(misp_store, "collection_source_groups", return_value={}),
                        mock.patch.object(misp_store, "get_pir", return_value=_pir()),
                        mock.patch.object(misp_store, "get_gir", return_value=SimpleNamespace(
                            uuid=UUID, gir_id="GIR-001", topic="t", status="Active", focus_points=[],
                            intel_level=[], misp_url="")),
                        mock.patch.object(requirements, "_galaxy_context", return_value=galaxies),
                        mock.patch("webapp.audit.record")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"

    def test_a_save_without_one_is_refused(self):
        for path, store_call in (("/pirs/new", "create_pir"), (f"/pirs/{UUID}/edit", "update_pir"),
                                 ("/girs/new", "create_gir"), (f"/girs/{UUID}/edit", "update_gir")):
            for levels in ([], ["Nonsense"]):
                with self.subTest(path=path, levels=levels), \
                     mock.patch.object(misp_store, store_call) as store:
                    reply = self.client.post(path, data={"csrf_token": "token", "question": "q", "topic": "t",
                                                             "intel_level": levels})
                    store.assert_not_called()
                    self.assertEqual(reply.status_code, 200)
                    self.assertIn(requirements.INTEL_LEVEL_REQUIRED, reply.get_data(as_text=True))

    def test_the_form_marks_it_required(self):
        for path in ("/pirs/new", "/girs/new"):
            with self.subTest(path):
                page = BeautifulSoup(self.client.get(path).data, "html.parser")
                label = page.find("label", string="Intelligence level")
                self.assertIn("required-label", label["class"])
                self.assertIsNotNone(page.select_one("#intel-level-warn"))


class StartedFromAStakeholder(unittest.TestCase):
    """A PIR or GIR started from a stakeholder's page has that stakeholder as
    its owner and in its distribution."""

    setUp = IntelligenceLevelRequired.setUp

    def form(self, path, stakeholders, from_uuid):
        with mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders):
            return self.client.get(f"{path}?from_stakeholder={from_uuid}").get_data(as_text=True)

    def test_the_stakeholder_is_owner_and_ticked_for_distribution(self):
        owner = SimpleNamespace(uuid="9d2e4f10-0000-4000-8000-000000000001", name="Acme SOC", role="SOC")
        other = SimpleNamespace(uuid="9d2e4f10-0000-4000-8000-000000000002", name="Acme IR", role="IR")
        for path in ("/pirs/new", "/girs/new"):
            html = self.form(path, [owner, other], owner.uuid)
            self.assertRegex(html, rf'name="distribution" value="{owner.uuid}"[^>]*checked', path)
            self.assertNotRegex(html, rf'name="distribution" value="{other.uuid}"[^>]*checked', path)
            self.assertRegex(html, rf'<option value="{owner.uuid}"\s+selected', path)

    def test_an_unknown_stakeholder_prefills_nothing(self):
        owner = SimpleNamespace(uuid="9d2e4f10-0000-4000-8000-000000000001", name="Acme SOC", role="SOC")
        for path in ("/pirs/new", "/girs/new"):
            html = self.form(path, [owner], "not-a-stakeholder")
            self.assertNotRegex(html, r'name="distribution"[^>]*checked', path)
            self.assertNotRegex(html, rf'<option value="{owner.uuid}"\s+selected', path)


class CollectionSourcePicker(unittest.TestCase):
    """The sources a PIR or GIR can name are grouped by kind, each with the icon
    the sources page gives it, and a stored one is ticked on edit."""

    setUp = IntelligenceLevelRequired.setUp
    groups = {"scraper": ["misp-scraper"], "misp": ["community"], "imap": ["soc/vendor-feed"], "manual": []}

    def form(self, path):
        with mock.patch.object(misp_store, "collection_source_groups", return_value=self.groups):
            return self.client.get(path).get_data(as_text=True)

    def test_each_kind_has_its_heading_and_icon(self):
        for path in ("/pirs/new", "/girs/new"):
            html = self.form(path)
            self.assertRegex(html, r'fw-semibold[^"]*">Other MISP servers<', path)
            self.assertNotRegex(html, r'fw-semibold[^"]*">Manual sources<', path)
            self.assertRegex(html, r'fa-server[^>]*></i>community', path)
            self.assertRegex(html, r'fa-envelope[^>]*></i>soc/vendor-feed', path)
            self.assertRegex(html, r'misp-logo\.png[^>]*>misp-scraper', path)

    def test_a_stored_source_is_ticked_on_edit(self):
        with mock.patch.object(misp_store, "get_pir", return_value=_pir(collection_sources=["soc/vendor-feed"])):
            html = self.form(f"/pirs/{UUID}/edit")
        self.assertRegex(html, r'value="soc/vendor-feed"\s+id="src_imap_1" checked')
        self.assertNotRegex(html, r'value="community"\s+id="src_misp_1" checked')


class DistributionOrganisationNames(unittest.TestCase):
    """A stakeholder's organisation is stored as the UUID of a registered
    organisation. The distribution picker shows its name, and an organisation
    stored as text the way it was typed."""

    setUp = IntelligenceLevelRequired.setUp
    org_uuid = "7c1d2e3f-0000-4000-8000-0000000000aa"

    def test_the_picker_names_the_organisation(self):
        linked = SimpleNamespace(uuid="9d2e4f10-0000-4000-8000-000000000001", name="Acme SOC",
                                 role="SOC", organization=self.org_uuid)
        typed = SimpleNamespace(uuid="9d2e4f10-0000-4000-8000-000000000002", name="Partner",
                                role="IR", organization="Partner Corp")
        with mock.patch.object(misp_store, "list_stakeholders", return_value=[linked, typed]), \
             mock.patch.object(requirements.org_store, "org_map", return_value={self.org_uuid: "CIRCL"}):
            for path in ("/pirs/new", f"/pirs/{UUID}/edit", "/girs/new", f"/girs/{UUID}/edit"):
                html = self.client.get(path).get_data(as_text=True)
                self.assertIn("SOC &middot; CIRCL", html, path)
                self.assertIn("IR &middot; Partner Corp", html, path)
                self.assertNotIn(self.org_uuid, html, path)


class IntakeChecklistOnTheEditForm(unittest.TestCase):
    """The answers given at triage can be corrected on the edit form. A new PIR
    has not been triaged, so its form has no checklist."""

    setUp = IntelligenceLevelRequired.setUp

    def test_the_edit_form_ticks_the_stored_answers(self):
        with mock.patch.object(misp_store, "get_pir",
                               return_value=_pir(triage_checklist=["not_duplicate"])):
            html = self.client.get(f"/pirs/{UUID}/edit").get_data(as_text=True)
        self.assertIn("Intake checklist", html)
        self.assertRegex(html, r'value="not_duplicate"\s+id="triage_chk_\d+" checked')
        self.assertNotRegex(html, r'value="clear_question"\s+id="triage_chk_\d+" checked')

    def test_a_new_pir_has_no_checklist(self):
        html = self.client.get("/pirs/new").get_data(as_text=True)
        self.assertNotIn("Intake checklist", html)


class RfiPirChoice(unittest.TestCase):
    """An RFI is linked to an agreed PIR, as a product is, or to the one it
    already has, which may since have left Active."""

    THIRD = "9c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5"

    def offered(self, path, stored=None):
        pirs = [_pir(UUID, status="Active"), _pir(OTHER, status="Pending"), _pir(self.THIRD, status="Retired")]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(misp_store, "list_girs", return_value=[]), \
             mock.patch.object(misp_store, "get_rfi", return_value=stored), \
             mock.patch.object(rfi, "render_template", return_value="") as render:
            _app(rfi.bp).get(path)
        return [p.uuid for p in render.call_args.kwargs["pirs"]]

    def test_a_new_rfi_is_offered_the_active_pirs(self):
        self.assertEqual(self.offered("/rfis/new"), [UUID])

    def test_an_edit_keeps_the_pir_the_rfi_is_linked_to(self):
        stored = SimpleNamespace(uuid=UUID, rfi_id="RFI-001", status="Acknowledged", linked_pir_uuid=self.THIRD)
        self.assertEqual(self.offered(f"/rfis/{UUID}/edit", stored), [UUID, self.THIRD])


class PirGirLinks(unittest.TestCase):
    """A PIR is linked to GIRs on its form, which offers the active ones and any
    it is linked to already. The link is kept on the PIR, so the GIR page only
    lists the PIRs that name it."""

    setUp = IntelligenceLevelRequired.setUp
    RETIRED = "9c1d2e3f-4a5b-4c6d-8e7f-a0b1c2d3e4f5"

    def girs(self):
        return [_gir(OTHER, gir_id="GIR-001", topic="Grid threats", status="Active"),
                _gir(self.RETIRED, gir_id="GIR-002", topic="Old topic", status="Retired")]

    def offered(self, page):
        return [(box["value"], box.has_attr("checked")) for box in page.select('input[name="linked_gir_uuids"]')]

    def test_the_form_offers_the_active_girs_and_the_linked_ones(self):
        with mock.patch.object(misp_store, "list_girs", return_value=self.girs()), \
             mock.patch.object(misp_store, "get_pir", return_value=_pir(linked_gir_uuids=[self.RETIRED])):
            new = BeautifulSoup(self.client.get("/pirs/new").data, "html.parser")
            edit = BeautifulSoup(self.client.get(f"/pirs/{UUID}/edit").data, "html.parser")
        self.assertEqual(self.offered(new), [(OTHER, False)])
        self.assertEqual(self.offered(edit), [(OTHER, False), (self.RETIRED, True)])

    def test_a_save_stores_the_ticked_girs_and_a_status_move_keeps_them(self):
        with mock.patch.object(misp_store, "update_pir") as update:
            self.client.post(f"/pirs/{UUID}/edit", data={"csrf_token": "token", "question": "q",
                                                         "intel_level": "Strategic", "linked_gir_uuids": [OTHER]})
        self.assertEqual(update.call_args.args[1]["linked_gir_uuids"], [OTHER])
        self.assertEqual(misp_store.pir_to_data(_pir(linked_gir_uuids=[OTHER]))["linked_gir_uuids"], [OTHER])

    def test_each_page_links_to_the_other(self):
        pir = _pir(linked_gir_uuids=[OTHER])
        with mock.patch.object(misp_store, "list_girs", return_value=self.girs()), \
             mock.patch.object(misp_store, "list_pirs", return_value=[pir, _pir(self.RETIRED)]), \
             mock.patch.object(misp_store, "get_pir", return_value=pir), \
             mock.patch.object(misp_store, "get_gir", return_value=self.girs()[0]), \
             mock.patch.object(misp_store, "pir_collection_gap", return_value={}):
            pir_page = BeautifulSoup(self.client.get(f"/pirs/{UUID}").data, "html.parser")
            gir_page = BeautifulSoup(self.client.get(f"/girs/{OTHER}").data, "html.parser")
        self.assertEqual([a["href"] for a in pir_page.select(".question-banner a")], [f"/girs/{OTHER}"])
        linked = gir_page.find("dt", string="Linked PIRs").find_next_sibling("dd")
        self.assertEqual([a["href"] for a in linked.select("a")], [f"/pirs/{UUID}"])

    def test_each_list_names_the_linked_ones_under_the_title(self):
        with mock.patch.object(misp_store, "list_girs", return_value=self.girs()), \
             mock.patch.object(misp_store, "list_pirs", return_value=[_pir(linked_gir_uuids=[OTHER])]):
            pir_list = BeautifulSoup(self.client.get("/pirs").data, "html.parser")
            gir_list = BeautifulSoup(self.client.get("/girs").data, "html.parser")
        self.assertEqual([a["href"] for a in pir_list.select("tr.req-row .req-links a")], [f"/girs/{OTHER}"])
        self.assertEqual([(a.find_parent("tr")["data-req-id"], a["href"])
                          for a in gir_list.select("tr.req-row .req-links a")], [(OTHER, f"/pirs/{UUID}")])


class ProductPirChoice(unittest.TestCase):
    """The product forms offer the agreed PIRs, as the flash intel and threat
    landscape forms did already, and keep the one a product is linked to,
    whether the form is rendered from the stored product or from a post."""

    def test_each_form_offers_the_active_pirs_and_the_linked_one(self):
        third = RfiPirChoice.THIRD
        pirs = [_pir(UUID, status="Active"), _pir(OTHER, status="Pending"), _pir(third, status="Retired")]
        stored = SimpleNamespace(linked_pir_uuid=third)
        galaxies = {name: mock.Mock(return_value=[]) for name in (
            "galaxy_mitre_attack_patterns", "galaxy_threat_actors", "galaxy_geography",
            "galaxy_sectors", "list_indicator_feeds")}
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs), \
             mock.patch.multiple(misp_store, **galaxies):
            for name, context, expected in (
                ("vea, posted", vea._wizard_context({"linked_pir_uuid": third}), [UUID, third]),
                ("der, stored", detection_eng._wizard_context(stored), [UUID, third]),
                ("tap, stored", threat_actor_profile._form_context(stored), [UUID, third]),
                ("der, new", detection_eng._wizard_context(), [UUID]),
            ):
                with self.subTest(name):
                    self.assertEqual([p.uuid for p in context["pirs"]], expected)


class Triage(unittest.TestCase):
    def setUp(self):
        self.pirs = {UUID: _pir(owner_uuid="owner", distribution=["reader"])}
        self.stakeholders = [SimpleNamespace(uuid=uuid, name=uuid) for uuid in ("owner", "reader", "outsider")]
        patches = (
            mock.patch.object(misp_store, "get_pir", side_effect=self.pirs.get),
            mock.patch.object(misp_store, "list_stakeholders", return_value=self.stakeholders),
            mock.patch.object(misp_store, "update_pir_intake"),
            mock.patch.object(dispatcher, "send_pir_intake"),
            mock.patch.object(requirements._matching, "invalidate_cache"),
            mock.patch("webapp.audit.record"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = _app(requirements.bp)

    def triage(self, decision, **form):
        self.client.post(f"/pirs/{UUID}/triage", data={"decision": decision, **form})
        return misp_store.update_pir_intake

    def test_an_approval_is_matched_straight_away(self):
        self.triage("approved")
        misp_store.update_pir_intake.assert_called_once()
        requirements._matching.invalidate_cache.assert_called_once()

    def test_the_decision_reaches_only_the_owner_and_the_distribution(self):
        """It went to every Mattermost channel there is, with the question and
        the reason for a rejection."""
        self.triage("rejected", reason="Out of scope")
        recipients = dispatcher.send_pir_intake.call_args.args[3]
        self.assertEqual([s.uuid for s in recipients], ["owner", "reader"])

    def test_a_pir_triaged_already_is_not_triaged_again(self):
        """Rejecting an Active PIR left it Active, and so still matched."""
        self.pirs[UUID] = _pir(status="Active", intake_status="approved")
        self.triage("rejected", reason="Changed our mind").assert_not_called()

    def test_a_pir_is_not_merged_into_itself_or_into_one_that_cannot_take_it(self):
        self.pirs[OTHER] = _pir(OTHER, intake_status="rejected")
        for target in (UUID, OTHER, "nonsense", ""):
            with self.subTest(target=target):
                self.triage("merged", linked_pir_uuid=target).assert_not_called()

    def test_a_merge_links_the_pir_it_went_into(self):
        self.pirs[OTHER] = _pir(OTHER, status="Active", intake_status="approved")
        intake = self.triage("merged", linked_pir_uuid=OTHER)
        self.assertEqual(intake.call_args.kwargs["linked_pir_uuid"], OTHER)


class StatusBoard(unittest.TestCase):
    def test_a_move_refreshes_matching(self):
        """Matching reads only Active requirements, so moving one off Active
        kept it matched until the cache ran out."""
        for kind, record in (("pir", _pir(status="Active", intake_status="approved")),
                             ("gir", SimpleNamespace(uuid=UUID, gir_id="GIR-001", status="Active"))):
            with self.subTest(kind), \
                 mock.patch.object(misp_store, f"get_{kind}", return_value=record), \
                 mock.patch.object(misp_store, f"{kind}_to_data", return_value={}), \
                 mock.patch.object(misp_store, f"update_{kind}"), \
                 mock.patch("webapp.audit.record"), \
                 mock.patch.object(requirements._matching, "invalidate_cache") as invalidate:
                _app(requirements.bp).post(f"/{kind}s/{UUID}/status", data={"status": "Retired"})
            invalidate.assert_called_once()


class IntakeChannels(unittest.TestCase):
    def test_only_the_channels_of_the_stakeholders_are_posted_to(self):
        channels = [{"id": "soc", "name": "SOC", "type": "mattermost", "enabled": True,
                     "url": "https://chat.example.org/hooks/soc"},
                    {"id": "partner", "name": "Partner", "type": "mattermost", "enabled": True,
                     "url": "https://partner.example.org/hooks/p"}]
        owner = SimpleNamespace(name="SOC", notification_channels=["soc"])
        with mock.patch.object(config, "NOTIFICATION_CHANNELS", channels), \
             mock.patch.object(config, "FLOWINTEL_INSTANCES", [], create=True), \
             mock.patch("notifier.mattermost.requests.post") as post:
            dispatcher.send_pir_intake(_pir(), "approved", None, [owner])
        self.assertEqual([c.args[0] for c in post.call_args_list], ["https://chat.example.org/hooks/soc"])


def _product(**relations):
    """A product event whose object records the given relations."""
    event = MISPEvent()
    event.uuid = OTHER
    event.info = "[zsazsa:fia] Wiper on the grid"
    event.date = "2026-10-01"
    event.add_tag('zsazsa:ctiproduct="flash-intel"')
    obj = misp_store._build_obj("zsazsa-flash-intel")
    for relation, value in relations.items():
        obj.add_attribute(relation, value=value, type="text")
    event.add_object(obj)
    return event


class ProductLinks(unittest.TestCase):
    """No product names its PIR in its title or a tag, so looking only there
    found none: the statistics said no product answers a PIR."""

    def test_the_linked_pirs_are_read_from_the_object(self):
        self.assertEqual(misp_store.linked_pir_uuids(_product(**{"linked-pir-uuid": UUID})), {UUID})
        report = _product(**{"linked-pir-uuids": json.dumps([UUID, OTHER])})
        self.assertEqual(misp_store.linked_pir_uuids(report), {UUID, OTHER})

    def test_the_statistics_count_a_product_that_answers_a_pir(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [_product(**{"linked-pir-uuid": UUID})]
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "list_rfis", return_value=[]):
            metrics = stats._program_metrics([_pir(status="Active")], [], [])
        self.assertEqual(metrics["products"]["with_pir_link"], 1)

    def test_the_stakeholder_page_lists_a_product_that_answers_their_pir(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = [_product(**{"linked-pir-uuid": UUID})]
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            products = misp_store.products_for_stakeholder(SimpleNamespace(products=[]), [_pir()], [])
        self.assertEqual([p.uuid for p in products], [OTHER])


class GalaxyScopeSync(unittest.TestCase):
    """Scope items no longer have notes. One saved while they did is stored as
    "category|value|notes": it reads back as its value alone, and is written
    again without the note when its category is rebuilt."""

    def setUp(self):
        self.event = MISPEvent()
        self.event.uuid = UUID
        self.event.add_attribute("text", "Sector|Energy|grid operators", comment=misp_store._FP_COMMENT)

    def test_an_old_note_does_not_end_up_in_the_value(self):
        [fp] = [misp_store._fp_ns(a) for a in misp_store._get_fp_attrs(self.event)]
        self.assertEqual((fp.category, fp.value), ("Sector", "Energy"))

    def test_a_rebuilt_category_is_written_without_notes(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = self.event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_rewrite_parent_scope"):
            misp_store.sync_focus_points_category(UUID, "Sector", ["energy", "Transport"])
        written = [c.args[1]["value"] for c in misp.add_attribute.call_args_list]
        self.assertEqual(written, ["Sector|energy", "Sector|Transport"])


if __name__ == "__main__":
    unittest.main()
