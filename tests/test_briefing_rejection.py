"""Briefing rejection, its stored reason and deletion of rejected briefings.

    python -m unittest tests.test_briefing_rejection
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP

import config
from webapp import audit, collection_cache, create_app, job_store, misp_session, misp_store


UUID = "8261112b-619c-4ee0-9409-c898df74520c"


def _event(state="draft", reason=""):
    event = MISPEvent()
    event.uuid, event.id, event.date, event.info = UUID, "42", "2026-10-27", "Daily briefing"
    obj = misp_store._briefing_obj({
        "date": "2026-10-27", "title": "Daily briefing", "review_state": state,
        "rejection_reason": reason, "summary": "Original summary", "summary_stale": True,
        "creator": "analyst@example.org", "story_count": 1,
        "geographic_scope": ["Belgium"], "detection_rules": "rule-1",
    })
    obj.id = 7
    event.add_object(obj)
    event.add_tag(f'workflow:state="{state}"')
    report = event.add_event_report("[story-01]", '{"title":"Story","content":"Original story"}')
    report.id = 1
    return event


class BriefingRejectionStore(unittest.TestCase):
    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.enterContext(mock.patch.object(misp_store, "_misp", return_value=self.misp))

    def test_rejection_updates_the_same_object_without_rewriting_content(self):
        event = _event()
        self.misp.get_event.return_value = event
        misp_store.reject_briefing(UUID, reason="Unsupported claims")
        obj = self.misp.update_object.call_args.args[0]
        self.assertEqual(obj.uuid, event.objects[0].uuid)
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), "rejected")
        self.assertEqual(misp_store._obj_attr(obj, "rejection-reason"), "Unsupported claims")
        for relation, value in (("summary", "Original summary"), ("summary-stale", "true"),
                                ("creator", "analyst@example.org"), ("story-count", "1"),
                                ("geographic-scope", '["Belgium"]'), ("detection-rules", "rule-1")):
            self.assertEqual(misp_store._obj_attr(obj, relation), value)
        self.misp.delete_object.assert_not_called()
        self.misp.add_object.assert_not_called()
        self.misp.delete_event_report.assert_not_called()
        self.misp.add_event_report.assert_not_called()
        self.misp.untag.assert_called_once_with(UUID, 'workflow:state="draft"')
        self.misp.tag.assert_called_once_with(UUID, 'workflow:state="rejected"', local=True)
        self.misp.publish.assert_not_called()
        event.Object[0] = obj
        loaded = misp_store._briefing_ns(event)
        self.assertEqual(loaded.rejection_reason, "Unsupported claims")
        self.assertEqual(loaded.stories[0].content, "Original story")

    def test_older_briefings_have_an_empty_reason(self):
        self.assertEqual(misp_store._briefing_ns(_event()).rejection_reason, "")

    def test_a_published_or_missing_briefing_cannot_be_rejected(self):
        for event in (_event("published"), {"errors": ["not found"]}):
            with self.subTest(event=event):
                self.misp.get_event.return_value = event
                with self.assertRaises((ValueError, RuntimeError)):
                    misp_store.reject_briefing(UUID, reason="No")
                self.misp.update_object.assert_not_called()
                self.misp.tag.assert_not_called()

    def test_misp_errors_are_reported(self):
        self.misp.get_event.return_value = _event()
        self.misp.update_object.return_value = {"errors": ["write refused"]}
        with self.assertRaisesRegex(RuntimeError, "write refused"):
            misp_store.reject_briefing(UUID)
        self.misp.tag.assert_not_called()

    def test_workflow_tag_errors_are_reported(self):
        self.misp.get_event.return_value = _event()
        self.misp.tag.return_value = {"errors": ["tag refused"]}
        with self.assertRaisesRegex(RuntimeError, "tag refused"):
            misp_store.reject_briefing(UUID)

    def test_an_edit_keeps_the_reason_and_a_stale_draft_cannot_undo_rejection(self):
        event = _event("rejected", "Needs verification")
        self.misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_retag_product_sources"):
            misp_store.update_briefing(
                UUID, {"title": "Edited", "review_state": "rejected", "stories": []})
        obj = self.misp.update_object.call_args.args[0]
        self.assertEqual(misp_store._obj_attr(obj, "rejection-reason"), "Needs verification")
        self.misp.update_object.reset_mock()
        with self.assertRaises(misp_store.BriefingStateChanged):
            misp_store.update_briefing(UUID, {"review_state": "draft"}, expected_state="draft")
        self.misp.update_object.assert_not_called()

    def test_a_stale_approval_cannot_publish_a_rejected_briefing(self):
        self.misp.get_event.return_value = _event("rejected", "Needs verification")
        with self.assertRaises(misp_store.BriefingStateChanged):
            misp_store.publish_briefing(UUID)
        self.misp.update_object.assert_not_called()
        self.misp.publish.assert_not_called()

    def test_bulk_deletion_checks_the_state_of_the_event_it_will_delete(self):
        for builder, delete, tag, published in (
            (misp_store._briefing_obj, misp_store.delete_briefing, config.TAG_BRIEFING, "published"),
            (misp_store._fia_obj, misp_store.delete_fia, config.TAG_FLASH_INTEL, "approved"),
            (misp_store._vea_obj, misp_store.delete_vea, config.TAG_VEA, "approved"),
        ):
            for state in ("draft", published, "rejected"):
                with self.subTest(product=delete.__name__, state=state):
                    event = MISPEvent()
                    event.uuid, event.id, event.date = UUID, "42", "2026-10-27"
                    event.add_tag(tag)
                    event.add_object(builder({"review_state": state}))
                    self.misp.get_event.return_value = event
                    if state == "rejected":
                        with mock.patch.object(misp_store, "_retag_product_sources"):
                            delete(UUID, expected_state="rejected")
                        self.misp.delete_event.assert_called_once_with(UUID)
                        self.misp.delete_event.reset_mock()
                    else:
                        with self.assertRaisesRegex(ValueError, "not rejected"):
                            delete(UUID, expected_state="rejected")
                        self.misp.delete_event.assert_not_called()


class BriefingRejectionRoutes(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch("webapp._setup_file_logging"),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(collection_cache, "get_events_by_uuids", return_value=[]),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(job_store, "by_entity", return_value={}),
            mock.patch.object(misp_session, "current_user_can_publish", return_value=False),
        ):
            self.enterContext(patch)
        self.audit = self.enterContext(mock.patch.object(audit, "record"))
        app = create_app()
        app.testing = True
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.headers = {"X-Forwarded-Prefix": "/zsazsa"}

    def post(self, path, **data):
        return self.client.post("/briefing" + path, headers=self.headers,
                                data={"csrf_token": "test-token", **data})

    def messages(self):
        with self.client.session_transaction() as session:
            return " ".join(text for _category, text in session.pop("_flashes", []))

    def test_the_list_filters_and_counts_rejected_briefings_and_offers_matching_controls(self):
        draft = misp_store._briefing_ns(_event())
        rejected = misp_store._briefing_ns(_event("rejected", "No"))
        rejected.uuid = "rejected-briefing"
        with mock.patch.object(misp_store, "list_briefings", return_value=[draft, rejected]):
            page = BeautifulSoup(self.client.get("/briefing/", headers=self.headers).data, "html.parser")
            self.assertIsNotNone(page.select_one('select[name=state] option[value=rejected]'))
            self.assertIsNotNone(page.select_one('a[href*="state=rejected"]'))
            form = page.select_one('form[action="/zsazsa/briefing/rejected/delete"]')
            self.assertIsNotNone(form)
            self.assertIsNone(form.find_parent("form"))
            self.assertIn("regardless of the current filters", form["data-submit-confirm"])
            self.assertIn("(1)", form.get_text())
            preview = page.select_one(f"#briefing-preview-{UUID}")
            rejection = preview.select_one(".inline-rejection-form")
            self.assertEqual(rejection["action"], f"/zsazsa/briefing/{UUID}/reject")
            self.assertFalse(rejection.select_one("textarea").has_attr("required"))
            toggle = preview.select_one('[data-bs-toggle=dropdown]')
            self.assertEqual(toggle.parent, rejection.parent.parent)
            self.assertIsNone(preview.select_one(".qa-review-btn"))
            self.assertIsNone(page.select_one("#briefing-preview-rejected-briefing .inline-approval-form"))
            page = BeautifulSoup(
                self.client.get("/briefing/?state=rejected", headers=self.headers).data, "html.parser")
            self.assertIsNone(page.select_one(f"#briefing-row-{UUID}"))
            self.assertEqual(page.select_one("#briefing-row-rejected-briefing .bg-danger").text, "rejected")

    def test_rejection_accepts_an_optional_reason_without_publish_rights(self):
        with mock.patch.object(misp_store, "get_briefing", return_value=misp_store._briefing_ns(_event())), \
             mock.patch.object(misp_store, "reject_briefing") as reject:
            for reason in ("", "  Unsupported claims  "):
                response = self.post(f"/{UUID}/reject", reason=reason, return_to="review")
                self.assertEqual(response.location, "/zsazsa/briefing/")
                reject.assert_called_with(UUID, reason=reason.strip())
                self.audit.assert_called_with("reject", "daily-briefing", entity_id=UUID,
                                               entity_label="Daily briefing 2026-10-27")
            response = self.post(f"/{UUID}/reject", return_to="https://example.org")
            self.assertEqual(response.location, f"/zsazsa/briefing/{UUID}")

    def test_rejection_refuses_published_and_missing_briefings_and_requires_csrf(self):
        for event in (_event("published"), None):
            with self.subTest(event=event), \
                 mock.patch.object(misp_store, "get_briefing",
                                   return_value=misp_store._briefing_ns(event) if event else None), \
                 mock.patch.object(misp_store, "reject_briefing") as reject:
                response = self.post(f"/{UUID}/reject", return_to="review")
                self.assertEqual(response.status_code, 302 if event else 404)
                reject.assert_not_called()
        self.assertEqual(self.client.post(f"/briefing/{UUID}/reject").status_code, 403)

    def test_rejection_reports_a_failed_write(self):
        with mock.patch.object(misp_store, "get_briefing", return_value=misp_store._briefing_ns(_event())), \
             mock.patch.object(misp_store, "reject_briefing", side_effect=RuntimeError("MISP refused")):
            response = self.post(f"/{UUID}/reject", return_to="review")
        self.assertEqual(response.location, "/zsazsa/briefing/")
        self.assertIn("MISP refused", self.messages())
        self.audit.assert_not_called()

    def test_rejected_briefings_cannot_be_published_by_a_stale_form(self):
        with mock.patch.object(misp_store, "get_briefing",
                               return_value=misp_store._briefing_ns(_event("rejected"))), \
             mock.patch.object(misp_session, "current_user_can_publish", return_value=True), \
             mock.patch.object(misp_store, "publish_briefing") as publish, \
             mock.patch("webapp.routes.daily_briefing._start_briefing_delivery") as deliver:
            response = self.post(f"/{UUID}/publish", return_to="review")
        self.assertEqual(response.location, "/zsazsa/briefing/")
        publish.assert_not_called()
        deliver.assert_not_called()
        self.assertIn("rejected", self.messages().lower())

    def test_inline_approval_warns_about_a_stale_summary_like_the_detail_page(self):
        for stale in (False, True):
            with self.subTest(stale=stale):
                briefing = misp_store._briefing_ns(_event())
                briefing.summary_stale = stale
                with mock.patch.object(misp_store, "list_briefings", return_value=[briefing]):
                    page = BeautifulSoup(self.client.get("/briefing/").data, "html.parser")
                form = page.select_one(".inline-approval-form")
                self.assertEqual(form.has_attr("data-submit-confirm"), stale)
                if stale:
                    self.assertIn("out of date", form["data-submit-confirm"])

    def test_only_draft_details_offer_rejection_and_bulk_delete_is_off_with_nothing_rejected(self):
        for state in ("draft", "published"):
            with self.subTest(state=state), \
                 mock.patch.object(misp_store, "get_briefing",
                                   return_value=misp_store._briefing_ns(_event(state))), \
                 mock.patch.object(misp_store, "list_product_feedback", return_value=[]), \
                 mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
                 mock.patch.object(audit, "latest_notify_status", return_value=None):
                page = BeautifulSoup(self.client.get(f"/briefing/{UUID}").data, "html.parser")
                form = page.select_one(f'form[action="/briefing/{UUID}/reject"]')
                self.assertEqual(form is not None, state == "draft")
        # Nothing rejected: the button is on the table, and off.
        with mock.patch.object(misp_store, "list_briefings", return_value=[misp_store._briefing_ns(_event("draft"))]):
            page = BeautifulSoup(self.client.get("/briefing/").data, "html.parser")
        self.assertTrue(page.select_one('th form[action="/briefing/rejected/delete"] button').has_attr("disabled"))

    def test_metadata_displays_the_saved_reason_as_text(self):
        reason = '<script>alert("no")</script>'
        with mock.patch.object(misp_store, "get_briefing",
                               return_value=misp_store._briefing_ns(_event("rejected", reason))), \
             mock.patch.object(misp_store, "list_product_feedback", return_value=[]), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(audit, "latest_notify_status", return_value=None):
            page = BeautifulSoup(self.client.get(f"/briefing/{UUID}", headers=self.headers).data,
                                 "html.parser")
        metadata = next(card for card in page.select(".card") if card.select_one(".card-header")
                        and "Metadata" in card.select_one(".card-header").get_text())
        self.assertIn(reason, metadata.get_text())
        self.assertIsNone(metadata.select_one("script"))
        self.assertEqual(metadata.select_one(".bg-danger").text, "rejected")
        self.assertIsNone(page.select_one(f'form[action="/zsazsa/briefing/{UUID}/publish"]'))
        self.assertIsNone(page.select_one(f'form[action="/zsazsa/briefing/{UUID}/reject"]'))

    def test_bulk_delete_rechecks_states_and_audits_only_deleted_briefings(self):
        candidates = []
        current = {}
        for index, state in enumerate(("rejected", "published", "draft", None)):
            briefing = misp_store._briefing_ns(_event("rejected"))
            briefing.uuid = f"candidate-{index}"
            candidates.append(briefing)
            loaded = misp_store._briefing_ns(_event(state)) if state else None
            current[briefing.uuid] = loaded
        with mock.patch.object(misp_store, "list_briefings", return_value=candidates), \
             mock.patch.object(misp_store, "get_briefing", side_effect=current.get), \
             mock.patch.object(misp_store, "delete_briefing") as delete:
            response = self.post("/rejected/delete")
        self.assertEqual(response.location, "/zsazsa/briefing/")
        delete.assert_called_once_with("candidate-0", expected_state="rejected")
        self.audit.assert_called_once_with(
            "delete", "daily-briefing", entity_id="candidate-0", entity_label="Daily briefing 2026-10-27")

    def test_bulk_delete_reports_failures_continues_and_requires_post_and_csrf(self):
        one = misp_store._briefing_ns(_event("rejected"))
        two = misp_store._briefing_ns(_event("rejected"))
        two.uuid = "second-briefing"
        with mock.patch.object(misp_store, "list_briefings", return_value=[one, two]), \
             mock.patch.object(misp_store, "get_briefing", return_value=one), \
             mock.patch.object(misp_store, "delete_briefing",
                               side_effect=[RuntimeError("MISP refused"), None]) as delete:
            self.post("/rejected/delete")
        self.assertEqual(delete.call_count, 2)
        messages = self.messages()
        self.assertIn("MISP refused", messages)
        self.assertIn("Deleted 1 rejected briefing.", messages)
        with mock.patch.object(misp_store, "list_briefings", side_effect=RuntimeError("MISP unavailable")):
            self.post("/rejected/delete")
        self.assertIn("MISP unavailable", self.messages())
        self.assertEqual(self.client.post("/briefing/rejected/delete").status_code, 403)
        self.assertEqual(self.client.get("/briefing/rejected/delete").status_code, 405)


if __name__ == "__main__":
    unittest.main()
