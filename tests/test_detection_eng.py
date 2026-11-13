"""Detection engineering requests: the stored object and the engineering status.

A request has two tracks. review_state is the publish workflow (draft ->
pending-review -> approved), status is the engineering team's own tracker
(Pending -> In Dev -> In Test -> Active -> Retired). The second only means
anything on an approved request, and reaching Active is what tells every
stakeholder the detection is live, so these check that it cannot be reached
the wrong way, or twice.

Nothing is written to MISP or sent for real here: the store, Rulezet and the
delivery job are stubbed.

The CVE field is pinned here too: what the form accepts and refuses, and that
the report lists the CVEs. So is what a new request made from collected events
starts with, and that the form keeps every source event a request has.

    python -m unittest tests.test_detection_eng
"""

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask, render_template

import config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import detection_eng

SOURCE_UUID = "8bff3417-1af2-4ccb-81be-26a8bc99605f"
DER_UUID = "u" * 36


def _stored_der(**changes):
    """A request as it comes back from MISP, with every stored field filled in.

    Empty values are never written to the object, so a field left blank here
    would go unnoticed by the checks below however badly it was handled.
    """
    der = SimpleNamespace(
        uuid=DER_UUID, der_id="DER-00042", title="Detect WMI lateral movement",
        technique=["T1047"], cve_ids=["CVE-2024-3400", "CVE-2023-4966"],
        log_sources=["Sysmon", "Windows Security"],
        hypothesis="Actors pivot with wmic.", expected_output="One alert per host.",
        existing_coverage=["rule-1"], test_cases=["Run wmic /node"],
        format="sigma", draft_rule="title: x", priority="High",
        status=misp_store.DER_STATUS_IN_TEST, tlp="amber", author="koen",
        audience="SOC", review_state=misp_store.DER_REVIEW_APPROVED,
        rejection_reason="An earlier reason.",
        source_event_uuids=[SOURCE_UUID], source_event_hints={SOURCE_UUID: "scraper"},
        source_event_uuid=SOURCE_UUID, linked_pir_uuid="p" * 36,
        creator="koen", approved_by="an.earlier.reviewer@example.org",
        created_at=datetime(2026, 9, 1),
    )
    der.__dict__.update(changes)
    return der


def _client():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test"
    app.register_blueprint(detection_eng.bp)
    return app.test_client()


def _relation(field):
    # The only field whose relation is not its name with dashes: the list of
    # source events is kept under the name the single UUID used to have.
    return "source-event-uuid" if field == "source_event_uuids" else field.replace("_", "-")


class DerFieldList(unittest.TestCase):
    """_DER_FIELDS is what every rewrite of the object is built from, so it has
    to stay level with what the object actually holds. A field added to
    _der_obj() and left out of the list is dropped the next time the review
    state, the status or the draft rule changes."""

    def _relations(self):
        return {_relation(f) for f in misp_store._DER_FIELDS}

    def test_it_names_exactly_what_the_object_is_written_with(self):
        written = {attr.object_relation for attr in misp_store._der_obj(_stored_der().__dict__).attributes}
        self.assertEqual(written, self._relations())

    def test_the_misp_object_template_declares_the_same_attributes(self):
        """An attribute the template does not declare still writes, since _oa()
        passes the type itself, but MISP then shows it unnamed on the event."""
        definition = json.loads(
            (Path(misp_store.__file__).parent / "misp_objects" / "objects"
             / "zsazsa-detection-eng-request" / "definition.json").read_text()
        )
        self.assertEqual(set(definition["attributes"]), self._relations())

    def test_what_is_written_reads_back_the_same(self):
        stored = _stored_der()
        event = SimpleNamespace(uuid=DER_UUID, objects=[misp_store._der_obj(stored.__dict__)],
                                published=False, publish_timestamp=None, date=None)
        der = misp_store._der_ns(event)
        for field in misp_store._DER_FIELDS:
            self.assertEqual(getattr(der, field), getattr(stored, field), field)


class PublishKeepsTheStoredFields(unittest.TestCase):
    """Publishing deletes the request object and writes it again, so a field the
    rewrite does not carry across is lost at the moment the request goes out."""

    def _published_object(self):
        der = _stored_der(review_state=misp_store.DER_REVIEW_PENDING, status=misp_store.DER_STATUS_PENDING)
        misp = mock.MagicMock()
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=mock.MagicMock()), \
             mock.patch.object(misp_store, "_der_ns", return_value=der), \
             mock.patch.object(misp_store, "_get_obj", return_value=None), \
             mock.patch.object(misp_store.misp_session, "current_user_email",
                               return_value="reviewer@example.org"):
            misp_store.publish_der(DER_UUID)
        return misp.add_object.call_args_list[0][0][1]

    def test_nothing_is_dropped(self):
        obj = self._published_object()
        for field in misp_store._DER_FIELDS:
            relation = _relation(field)
            self.assertIsNotNone(misp_store._obj_attr(obj, relation), f"publishing dropped {relation}")

    def test_publishing_records_the_new_state_and_approver(self):
        obj = self._published_object()
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), misp_store.DER_REVIEW_APPROVED)
        self.assertEqual(misp_store._obj_attr(obj, "approved-by"), "reviewer@example.org")


class DerData(unittest.TestCase):
    def test_overrides_replace_only_what_they_name(self):
        der = _stored_der()
        data = misp_store._der_data(der, status=misp_store.DER_STATUS_ACTIVE)
        self.assertEqual(data["status"], misp_store.DER_STATUS_ACTIVE)
        self.assertEqual(data["draft_rule"], "title: x")

    def test_the_stored_request_is_not_changed_through_the_dict(self):
        der = _stored_der()
        misp_store._der_data(der)["technique"].append("T1059")
        self.assertEqual(der.technique, ["T1047"])


class ApplyStatus(unittest.TestCase):
    """_apply_der_status() is the one place the status rules live; the detail
    page and the kanban board both go through it."""

    def apply(self, der, status, can_publish=True, rulezet=None, misp_error=None):
        rulezet = {"valid": True} if rulezet is None else rulezet
        with mock.patch.object(detection_eng.misp_session, "current_user_can_publish",
                               return_value=can_publish), \
             mock.patch.object(detection_eng, "validate_rule", return_value=rulezet) as validate, \
             mock.patch.object(detection_eng.misp_store, "update_der", side_effect=misp_error) as update, \
             mock.patch.object(detection_eng.audit, "record"), \
             mock.patch.object(detection_eng, "_start_der_delivery") as deliver:
            error = detection_eng._apply_der_status(der, status)
        return error, update, deliver, validate

    def test_a_write_misp_refuses_is_reported_and_nobody_is_told(self):
        """The kanban board reads the reason from the JSON it gets back, which a
        500 page does not give it."""
        with self.assertLogs(detection_eng.logger, "WARNING"):
            error, _, deliver, _ = self.apply(_stored_der(), misp_store.DER_STATUS_ACTIVE,
                                              misp_error=RuntimeError("MISP said no"))
        self.assertEqual(error, "Could not update the status: MISP said no")
        deliver.assert_not_called()

    def test_an_approved_request_moves_on_and_keeps_its_other_fields(self):
        error, update, deliver, _ = self.apply(
            _stored_der(status=misp_store.DER_STATUS_PENDING), misp_store.DER_STATUS_IN_DEV)
        self.assertIsNone(error)
        data = update.call_args[0][1]
        self.assertEqual(data["status"], misp_store.DER_STATUS_IN_DEV)
        self.assertEqual(data["draft_rule"], "title: x")
        deliver.assert_not_called()

    def test_a_request_that_is_not_approved_cannot_leave_pending(self):
        der = _stored_der(status=misp_store.DER_STATUS_PENDING, review_state=misp_store.DER_REVIEW_PENDING)
        error, update, _, _ = self.apply(der, misp_store.DER_STATUS_IN_DEV)
        self.assertIn("Approve", error)
        update.assert_not_called()

    def test_nor_reach_active_from_further_along(self):
        """A request stored In Test while back in review (written before approval
        was made final) must not be able to go on to Active and notify anyone."""
        der = _stored_der(review_state=misp_store.DER_REVIEW_PENDING)
        error, update, deliver, _ = self.apply(der, misp_store.DER_STATUS_ACTIVE)
        self.assertIn("Approve", error)
        update.assert_not_called()
        deliver.assert_not_called()

    def test_there_is_no_way_back_to_pending(self):
        error, update, _, _ = self.apply(_stored_der(), misp_store.DER_STATUS_PENDING)
        self.assertIn("Pending", error)
        update.assert_not_called()

    def test_an_unknown_status_is_refused(self):
        error, update, _, _ = self.apply(_stored_der(), "Done")
        self.assertEqual(error, "Invalid status.")
        update.assert_not_called()

    def test_the_current_status_changes_nothing(self):
        error, update, deliver, validate = self.apply(
            _stored_der(status=misp_store.DER_STATUS_ACTIVE), misp_store.DER_STATUS_ACTIVE)
        self.assertIsNone(error)
        update.assert_not_called()
        validate.assert_not_called()
        deliver.assert_not_called()

    def test_first_move_into_active_validates_and_notifies(self):
        error, update, deliver, validate = self.apply(_stored_der(), misp_store.DER_STATUS_ACTIVE)
        self.assertIsNone(error)
        validate.assert_called_once_with("sigma", "title: x")
        update.assert_called_once()
        deliver.assert_called_once_with("DER-00042", DER_UUID, "completed")

    def test_switching_a_retired_request_back_on_notifies_nobody_again(self):
        error, update, deliver, validate = self.apply(
            _stored_der(status=misp_store.DER_STATUS_RETIRED), misp_store.DER_STATUS_ACTIVE)
        self.assertIsNone(error)
        validate.assert_called_once()
        update.assert_called_once()
        deliver.assert_not_called()

    def test_active_needs_publish_rights(self):
        error, update, deliver, validate = self.apply(
            _stored_der(), misp_store.DER_STATUS_ACTIVE, can_publish=False)
        self.assertIn("publish rights", error)
        validate.assert_not_called()
        update.assert_not_called()
        deliver.assert_not_called()

    def test_active_needs_a_rule_and_its_format(self):
        error, update, _, validate = self.apply(_stored_der(draft_rule=""), misp_store.DER_STATUS_ACTIVE)
        self.assertIn("draft rule", error)
        validate.assert_not_called()
        update.assert_not_called()

    def test_rulezet_unreachable_is_a_refusal_not_a_pass(self):
        with mock.patch.object(detection_eng.misp_session, "current_user_can_publish", return_value=True), \
             mock.patch.object(detection_eng, "validate_rule", return_value=None), \
             mock.patch.object(detection_eng.misp_store, "update_der") as update, \
             mock.patch.object(detection_eng, "_start_der_delivery") as deliver:
            error = detection_eng._apply_der_status(_stored_der(), misp_store.DER_STATUS_ACTIVE)
        self.assertIn("Could not reach Rulezet", error)
        update.assert_not_called()
        deliver.assert_not_called()

    def test_a_rulezet_error_is_passed_on(self):
        error, update, _, _ = self.apply(_stored_der(), misp_store.DER_STATUS_ACTIVE,
                                         rulezet={"error": "unsupported format"})
        self.assertIn("unsupported format", error)
        update.assert_not_called()

    def test_an_invalid_rule_is_refused_with_rulezets_reasons(self):
        error, update, deliver, _ = self.apply(_stored_der(), misp_store.DER_STATUS_ACTIVE,
                                               rulezet={"valid": False, "errors": ["line 1: bad key"]})
        self.assertIn("line 1: bad key", error)
        update.assert_not_called()
        deliver.assert_not_called()


class Routes(unittest.TestCase):
    """The routes that can change what stakeholders were sent, or send it again."""

    def setUp(self):
        self.client = _client()

    def post(self, path, der, data=None, can_publish=True):
        with mock.patch.object(detection_eng.misp_store, "get_der", return_value=der), \
             mock.patch.object(detection_eng.misp_store, "update_der") as update, \
             mock.patch.object(detection_eng.misp_store, "publish_der") as publish, \
             mock.patch.object(detection_eng.misp_store, "reject_der") as reject, \
             mock.patch.object(detection_eng.misp_store, "fetch_source_events", return_value=[]), \
             mock.patch.object(detection_eng.misp_session, "current_user_can_publish",
                               return_value=can_publish), \
             mock.patch.object(detection_eng, "validate_rule", return_value={"valid": True}), \
             mock.patch.object(detection_eng, "_start_der_delivery") as deliver, \
             mock.patch.object(detection_eng.audit, "record"):
            reply = self.client.post(f"/products/detection-eng/{DER_UUID}/{path}", data=data or {})
        return SimpleNamespace(reply=reply, update=update, publish=publish, reject=reject, deliver=deliver)

    def test_approving_without_publish_rights_is_refused(self):
        der = _stored_der(review_state=misp_store.DER_REVIEW_PENDING, status=misp_store.DER_STATUS_PENDING)
        r = self.post("approve", der, can_publish=False)
        self.assertEqual(r.reply.status_code, 302)
        r.publish.assert_not_called()
        r.deliver.assert_not_called()

    def test_publishing_from_the_wizard_without_rights_only_saves(self):
        der = _stored_der(review_state=misp_store.DER_REVIEW_PENDING, status=misp_store.DER_STATUS_PENDING)
        r = self.post("edit", der, data={"action": "publish", "title": der.title}, can_publish=False)
        r.update.assert_called_once()
        self.assertEqual(r.update.call_args[0][1]["review_state"], misp_store.DER_REVIEW_PENDING)
        r.publish.assert_not_called()
        r.deliver.assert_not_called()

    def test_the_wizard_keeps_the_stored_rule_whatever_the_form_posts(self):
        der = _stored_der(review_state=misp_store.DER_REVIEW_DRAFT, status=misp_store.DER_STATUS_PENDING)
        r = self.post("edit", der, data={"action": "save", "title": der.title,
                                         "format": "yara", "draft_rule": "rule tampered {}"})
        data = r.update.call_args[0][1]
        self.assertEqual(data["format"], "sigma")
        self.assertEqual(data["draft_rule"], "title: x")

    def test_an_approved_request_cannot_be_edited(self):
        r = self.post("edit", _stored_der(), data={"action": "submit", "title": "changed"})
        self.assertEqual(r.reply.status_code, 302)
        r.update.assert_not_called()

    def test_an_approved_request_cannot_be_rejected(self):
        r = self.post("reject", _stored_der(), data={"reason": "no"})
        r.reject.assert_not_called()

    def test_the_rule_of_an_active_request_cannot_be_changed(self):
        r = self.post("draft-rule", _stored_der(status=misp_store.DER_STATUS_ACTIVE),
                      data={"format": "sigma", "draft_rule": "title: unvalidated"})
        r.update.assert_not_called()

    def test_the_rule_needs_a_format_the_form_offers(self):
        r = self.post("draft-rule", _stored_der(), data={"format": "snort", "draft_rule": "alert tcp any"})
        r.update.assert_not_called()

    def test_the_rule_can_be_saved_before_active(self):
        r = self.post("draft-rule", _stored_der(), data={"format": "yara", "draft_rule": "rule x {}"})
        data = r.update.call_args[0][1]
        self.assertEqual((data["format"], data["draft_rule"]), ("yara", "rule x {}"))
        self.assertEqual(data["title"], "Detect WMI lateral movement")

    def test_marking_active_without_publish_rights_is_refused(self):
        r = self.post("status", _stored_der(), data={"status": misp_store.DER_STATUS_ACTIVE},
                      can_publish=False)
        r.update.assert_not_called()
        r.deliver.assert_not_called()

    def test_the_kanban_board_gets_the_same_refusal(self):
        r = self.post("status-update", _stored_der(), data={"status": misp_store.DER_STATUS_ACTIVE},
                      can_publish=False)
        self.assertEqual(r.reply.status_code, 400)
        self.assertIn("publish rights", r.reply.get_json()["error"])
        r.deliver.assert_not_called()

    def test_resubmitting_active_sends_nothing(self):
        r = self.post("status", _stored_der(status=misp_store.DER_STATUS_ACTIVE),
                      data={"status": misp_store.DER_STATUS_ACTIVE})
        r.update.assert_not_called()
        r.deliver.assert_not_called()

    def test_resending_without_publish_rights_is_refused(self):
        r = self.post("resend", _stored_der(), can_publish=False)
        r.deliver.assert_not_called()

    def test_resending_with_publish_rights_starts_delivery(self):
        r = self.post("resend", _stored_der())
        r.deliver.assert_called_once_with("DER-00042", DER_UUID, "resend")


class CveIds(unittest.TestCase):
    """The CVE field takes IDs the way analysts paste them. Anything that is not
    one is refused rather than dropped, so a mistyped CVE is not lost unseen."""

    def test_commas_semicolons_spaces_and_lines_all_separate(self):
        self.assertEqual(detection_eng._cve_ids("CVE-2024-3400, cve-2023-4966\nCVE-2021-44228;CVE-2024-3400"),
                         ["CVE-2024-3400", "CVE-2023-4966", "CVE-2021-44228"])

    def test_what_is_not_a_cve_id_is_kept_and_refused(self):
        cve_ids = detection_eng._cve_ids("CVE-2024-3400 Log4Shell CVE-24-1")
        self.assertEqual(cve_ids, ["CVE-2024-3400", "LOG4SHELL", "CVE-24-1"])
        self.assertEqual(misp_store.der_field_errors({"cve_ids": cve_ids}),
                         ["Not a CVE ID: LOG4SHELL, CVE-24-1. Write each as CVE-2024-3400."])

    def test_valid_or_empty_fields_are_not_refused(self):
        self.assertEqual(detection_eng._cve_ids(""), [])
        self.assertEqual(misp_store.der_field_errors({"cve_ids": []}), [])
        self.assertEqual(misp_store.der_field_errors({"cve_ids": ["CVE-2024-3400"]}), [])


class WizardForm(unittest.TestCase):
    """The wizard stores the CVEs it is given, and stores nothing while one of
    them is not a CVE ID, the title is empty, or a field has a value the form
    does not offer. The API checks with the same misp_store.der_field_errors()."""

    def setUp(self):
        self.client = _client()

    def post(self, path, cve_ids="", review_state=misp_store.DER_REVIEW_DRAFT, **fields):
        der = _stored_der(review_state=review_state, status=misp_store.DER_STATUS_PENDING)
        with mock.patch.object(detection_eng.misp_store, "get_der", return_value=der), \
             mock.patch.object(detection_eng.misp_store, "create_der",
                               return_value=(DER_UUID, "DER-00042")) as create, \
             mock.patch.object(detection_eng.misp_store, "update_der") as update, \
             mock.patch.object(detection_eng.misp_store, "fetch_source_events", return_value=[]), \
             mock.patch.object(detection_eng.product_log, "log_product_sources"), \
             mock.patch.object(detection_eng, "render_template", return_value="form") as render, \
             mock.patch.object(detection_eng.audit, "record"):
            self.client.post(f"/products/detection-eng/{path}",
                             data={"action": "save", "title": der.title, "cve_ids": cve_ids, **fields})
        return SimpleNamespace(create=create, update=update, render=render)

    def test_a_new_request_stores_the_cves_normalised(self):
        r = self.post("new", "cve-2024-3400, CVE-2023-4966")
        self.assertEqual(r.create.call_args[0][0]["cve_ids"], ["CVE-2024-3400", "CVE-2023-4966"])

    def test_a_new_request_with_a_wrong_cve_is_not_created(self):
        r = self.post("new", "CVE-2024-3400, Log4Shell")
        r.create.assert_not_called()
        self.assertEqual(r.render.call_args.kwargs["der"]["cve_ids"], ["CVE-2024-3400", "LOG4SHELL"])

    def test_an_edit_stores_the_cves(self):
        r = self.post(f"{DER_UUID}/edit", "CVE-2021-44228")
        self.assertEqual(r.update.call_args[0][1]["cve_ids"], ["CVE-2021-44228"])

    def test_an_edit_with_a_wrong_cve_is_not_saved(self):
        r = self.post(f"{DER_UUID}/edit", "Log4Shell")
        r.update.assert_not_called()

    def test_a_refused_edit_still_shows_where_the_request_stands(self):
        r = self.post(f"{DER_UUID}/edit", "Log4Shell", review_state=misp_store.DER_REVIEW_PENDING)
        self.assertEqual(r.render.call_args.kwargs["der"].get("review_state"), misp_store.DER_REVIEW_PENDING)

    def test_clearing_the_field_removes_the_cves(self):
        r = self.post(f"{DER_UUID}/edit", "")
        self.assertEqual(r.update.call_args[0][1]["cve_ids"], [])

    def test_a_format_the_page_cannot_change_does_not_hold_up_a_save(self):
        with mock.patch.object(detection_eng.misp_store, "DER_FORMATS", ["yara"]):
            r = self.post(f"{DER_UUID}/edit")
        r.update.assert_called_once()

    def test_an_edit_cannot_empty_the_title(self):
        r = self.post(f"{DER_UUID}/edit", title="  ")
        r.update.assert_not_called()

    def test_a_value_the_form_does_not_offer_is_refused(self):
        """Only a hand-made post can send one, but it would be stored as it came."""
        for field, value in (("tlp", "foo"), ("priority", "Urgent"), ("audience", "Marketing")):
            for path in ("new", f"{DER_UUID}/edit"):
                with self.subTest(field=field, path=path):
                    r = self.post(path, **{field: value})
                    r.create.assert_not_called()
                    r.update.assert_not_called()
        r = self.post("new", format="snort")
        r.create.assert_not_called()

    def test_priority_and_format_can_be_left_at_none(self):
        r = self.post("new", priority="", format="")
        r.create.assert_called_once()


class SeedFromSources(unittest.TestCase):
    """A request made from events on Data collection starts with those events
    linked, and with their ATT&CK techniques and CVEs filled in."""

    EVENT = {"uuid": SOURCE_UUID, "info": "PAN-OS CVE-2024-3400 exploited", "source_url": "https://misp.example",
             "tags": ['misp-galaxy:mitre-attack-pattern="Exploit Public-Facing Application - T1190"', "tlp:clear"],
             "attributes": [{"type": "vulnerability", "value": "cve-2023-4966"},
                            {"type": "vulnerability", "value": "GHSA-jfh8-c2jp-5v3q"}],
             "objects": []}

    def seed(self, method="get", source=f"{SOURCE_UUID}|scraper", events=(EVENT,), cached=()):
        with mock.patch.object(detection_eng.misp_store, "fetch_source_events", return_value=list(events)), \
             mock.patch.object(collection_cache, "get_events_by_uuids", return_value=list(cached)), \
             mock.patch.object(detection_eng, "render_template", return_value="form") as render:
            if method == "get":
                _client().get("/products/detection-eng/new", query_string={"source": source} if source else {})
            else:
                _client().post("/products/detection-eng/new", data={"prefill_only": "1", "source": source})
        return render.call_args.kwargs["der"]

    def test_the_event_is_linked_with_its_techniques_and_cves(self):
        for method in ("get", "post"):
            der = self.seed(method)
            self.assertEqual(der.source_event_uuids, [SOURCE_UUID])
            self.assertEqual(der.source_event_hints, {SOURCE_UUID: "scraper"})
            self.assertEqual(der.technique, ["Exploit Public-Facing Application - T1190"])
            # The GHSA ID is a vulnerability too, but the field would refuse it.
            self.assertEqual(der.cve_ids, ["CVE-2023-4966", "CVE-2024-3400"])

    def test_an_event_that_could_not_be_fetched_has_its_cves_from_the_cache(self):
        der = self.seed(events=(), cached=({"uuid": SOURCE_UUID, "vulnerability_ids": ["CVE-2021-44228"]},))
        self.assertEqual(der.source_event_uuids, [SOURCE_UUID])
        self.assertEqual(der.cve_ids, ["CVE-2021-44228"])

    def test_a_request_without_sources_starts_empty(self):
        self.assertIsNone(self.seed(source=""))


class SourceEventFields(unittest.TestCase):
    """The form has a field for each source event, so that saving it keeps them
    all, and an empty one to add another."""

    def fields(self, der, source_events=()):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(config, create=True, DB_FILE=f"{tmp}/test.db", LOG_FILE=f"{tmp}/test.log"), \
             mock.patch.object(collection_cache, "start_worker"), \
             mock.patch.object(misp_store, "list_selectable_pirs", return_value=[]), \
             mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=[]):
            app = create_app()
            with app.test_request_context():
                html = render_template("detection_eng/wizard.html", is_edit=der is not None,
                                       source_events=list(source_events),
                                       **detection_eng._wizard_context(der, source_events))
        return [i["value"] for i in BeautifulSoup(html, "html.parser").select('input[name="source_event_url_item"]')]

    def test_every_source_event_has_a_field(self):
        other = "0f2c8a3e-5b7d-4e19-9a64-3c1d2b8e7f50"
        der = _stored_der(review_state=misp_store.DER_REVIEW_DRAFT,
                          source_event_uuids=[SOURCE_UUID, other], source_event_uuid=SOURCE_UUID)
        events = [{"uuid": SOURCE_UUID, "source_url": "https://scraper.example"},
                  {"uuid": other, "source_url": "https://misp.example"}]
        self.assertEqual(self.fields(der, events), [f"https://scraper.example/events/view/{SOURCE_UUID}",
                                                    f"https://misp.example/events/view/{other}", ""])

    def test_a_new_request_has_one_empty_field(self):
        self.assertEqual(self.fields(None), [""])


class CveReport(unittest.TestCase):
    """The report, mail and chat post are made from render_der_markdown()."""

    def test_the_cves_are_listed(self):
        markdown = misp_store.render_der_markdown(_stored_der())
        self.assertIn("## CVE(s)", markdown)
        self.assertIn("- CVE-2024-3400", markdown)

    def test_a_request_without_cves_has_no_cve_section(self):
        self.assertNotIn("CVE(s)", misp_store.render_der_markdown(_stored_der(cve_ids=[])))


class FormatHints(unittest.TestCase):
    """Every format Rulezet can check says what it expects to be handed.

    A bare query in a format that wants a whole rule document comes back as
    "Empty or invalid YAML content", which does not say what was wrong, so the
    hint has to be there before the analyst presses Validate.
    """

    def test_every_offered_format_has_a_hint(self):
        self.assertEqual(sorted(misp_store.DER_FORMAT_HINTS), sorted(misp_store.DER_FORMATS))

    def test_no_hint_is_left_empty(self):
        for fmt, hint in misp_store.DER_FORMAT_HINTS.items():
            self.assertTrue(hint.strip(), fmt)


if __name__ == "__main__":
    unittest.main()
