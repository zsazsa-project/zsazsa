"""Detection engineering requests: the stored object and the engineering status.

A request has two tracks. review_state is the publish workflow (draft ->
pending-review -> approved), status is the engineering team's own tracker
(Pending -> In Dev -> In Test -> Active -> Retired). The second only means
anything on an approved request, and reaching Active is what tells every
stakeholder the detection is live, so these check that it cannot be reached
the wrong way, or twice.

Nothing is written to MISP or sent for real here: the store, Rulezet and the
delivery job are stubbed.

    python -m unittest tests.test_detection_eng
"""

import json
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import misp_store
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
        technique=["T1047"], log_sources=["Sysmon", "Windows Security"],
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

    def apply(self, der, status, can_publish=True, rulezet=None):
        rulezet = {"valid": True} if rulezet is None else rulezet
        with mock.patch.object(detection_eng.misp_session, "current_user_can_publish",
                               return_value=can_publish), \
             mock.patch.object(detection_eng, "validate_rule", return_value=rulezet) as validate, \
             mock.patch.object(detection_eng.misp_store, "update_der") as update, \
             mock.patch.object(detection_eng.audit, "record"), \
             mock.patch.object(detection_eng, "_start_der_delivery") as deliver:
            error = detection_eng._apply_der_status(der, status)
        return error, update, deliver, validate

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
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.secret_key = "test"
        app.register_blueprint(detection_eng.bp)
        self.client = app.test_client()

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


if __name__ == "__main__":
    unittest.main()
