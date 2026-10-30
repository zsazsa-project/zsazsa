"""Product forms save drafts; list previews approve through the existing routes.

    python -m unittest tests.test_product_review_actions
"""

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import render_template
from pymisp import MISPEvent

import config
from webapp import audit, collection_cache, create_app, job_store, misp_session, misp_store
from webapp.routes import daily_briefing, flash_intel, threat_actor_profile, vea


UUID = "8261112b-619c-4ee0-9409-c898df74520c"
# Route module, path, list, parser, getter, publisher, state field, published state, action.
PRODUCTS = (
    (flash_intel, "/products/flash-intel", "list_fias", "_fia_ns", "get_fia",
     "publish_fia", "review_state", "approved", "approve"),
    (vea, "/products/vea", "list_veas", "_vea_ns", "get_vea",
     "publish_vea", "review_state", "approved", "approve"),
    (threat_actor_profile, "/products/threat-actor-profile", "list_threat_actor_profiles",
     "_tap_ns", "get_threat_actor_profile", "publish_threat_actor_profile",
     "status", "Published", "publish"),
    (daily_briefing, "/briefing", "list_briefings", "_briefing_ns", "get_briefing",
     "publish_briefing", "review_state", "published", "publish"),
)


def _product(parser):
    event = MISPEvent()
    event.uuid, event.id, event.date, event.info = UUID, "42", "2026-10-26", "Example product"
    product = getattr(misp_store, parser)(event)
    product.audience = "SOC"
    return product


class ProductReviewActions(unittest.TestCase):
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
        ):
            self.enterContext(patch)
        self.can_publish = self.enterContext(
            mock.patch.object(misp_session, "current_user_can_publish", return_value=True))
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        self.headers = {"X-Forwarded-Prefix": "/zsazsa"}

    def test_draft_previews_offer_approval_next_to_recipients_but_published_ones_do_not(self):
        for module, path, listing, parser, _getter, _publish, field, published, action in PRODUCTS:
            product = _product(parser)
            states = ["Draft" if field == "status" else "draft", published]
            if module in (flash_intel, vea):
                states.append("pending-review")
            for state in states:
                for allowed in (True, False):
                    with self.subTest(product=module.__name__, state=state, allowed=allowed), \
                         mock.patch.object(misp_store, listing, return_value=[product]):
                        setattr(product, field, state)
                        self.can_publish.return_value = allowed
                        response = self.client.get(path + "/", headers=self.headers)
                        self.assertEqual(response.status_code, 200)
                        page = BeautifulSoup(response.data, "html.parser")
                        preview = page.select_one(".preview-toggle-btn")
                        self.assertIn("fa-fw", preview.select_one("i")["class"])
                        row = page.find(id=preview["data-target"])
                        self.assertNotIn("Open full profile", row.get_text())
                        form = row.select_one(".inline-approval-form")
                        if state == published:
                            self.assertEqual(preview["title"], "Preview")
                            self.assertIsNone(form)
                            continue
                        self.assertEqual(preview["title"], "Preview and approve")
                        self.assertIn("btn-outline-success", preview["class"])
                        self.assertIsNotNone(preview.select_one(".fa-clipboard-check"))
                        self.assertEqual(form["action"], f"/zsazsa{path}/{UUID}/{action}")
                        self.assertEqual(form.select_one("[name=csrf_token]")["value"], "test-token")
                        self.assertEqual(form.select_one("[name=return_to]")["value"], "review")
                        button = form.select_one("button")
                        self.assertEqual(button.has_attr("disabled"), not allowed)
                        self.assertIn("btn-success", button["class"])
                        recipients = row.select_one("[data-recipients-url]")
                        self.assertIn("btn-xs", button["class"])
                        self.assertIn("btn-xs", recipients["class"])
                        self.assertEqual(form.parent, recipients.parent)
                        self.assertLess(str(form.parent).index("inline-approval-form"),
                                        str(form.parent).index("data-recipients-url"))

    def test_approval_returns_to_the_mounted_list_and_obeys_publish_rights(self):
        for module, path, listing, parser, getter, publisher, field, published, action in PRODUCTS:
            for allowed, state in ((True, "draft"), (False, "draft"), (True, published)):
                with self.subTest(product=module.__name__, allowed=allowed, state=state), \
                     ExitStack() as stack:
                    product = _product(parser)
                    setattr(product, field, "Draft" if field == "status" and state == "draft" else state)
                    self.can_publish.return_value = allowed
                    stack.enter_context(mock.patch.object(misp_store, getter, return_value=product))
                    publish = stack.enter_context(
                        mock.patch.object(misp_store, publisher, return_value=True))
                    stack.enter_context(mock.patch.object(misp_store, listing, return_value=[product]))

                    def publish_product(_uuid):
                        setattr(product, field, published)
                        return True

                    publish.side_effect = publish_product
                    deliveries = []
                    for name in ("_start_flash_intel_delivery", "_start_vea_delivery",
                                 "_start_briefing_delivery"):
                        if hasattr(module, name):
                            deliveries.append(stack.enter_context(mock.patch.object(module, name)))
                    response = self.client.post(
                        f"{path}/{UUID}/{action}", headers=self.headers,
                        data={"csrf_token": "test-token", "return_to": "review"})
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.location, f"/zsazsa{path}/")
                    self.assertEqual(publish.call_count, int(allowed and state != published))
                    for delivery in deliveries:
                        self.assertEqual(delivery.call_count, int(allowed and state != published))
                    if allowed:
                        response = self.client.post(
                            f"{path}/{UUID}/{action}", headers=self.headers,
                            data={"csrf_token": "test-token", "return_to": "review"})
                        self.assertEqual(response.location, f"/zsazsa{path}/")
                        self.assertEqual(publish.call_count, int(state != published))
                        for delivery in deliveries:
                            self.assertEqual(delivery.call_count, int(state != published))
                        response = self.client.get(path + "/")
                        page = BeautifulSoup(response.data, "html.parser")
                        self.assertIsNone(page.select_one(".inline-approval-form"))
                        self.assertEqual(page.select_one(".preview-toggle-btn")["title"], "Preview")

    def test_only_the_review_return_value_changes_the_detail_redirect(self):
        for _module, path, _listing, parser, getter, publisher, field, published, action in PRODUCTS:
            product = _product(parser)
            setattr(product, field, published)
            with mock.patch.object(misp_store, getter, return_value=product), \
                 mock.patch.object(misp_store, publisher) as publish:
                for return_to in (None, "", "detail", "/other-page", "https://example.org"):
                    with self.subTest(product=path, return_to=return_to):
                        data = {"csrf_token": "test-token"}
                        if return_to is not None:
                            data["return_to"] = return_to
                        response = self.client.post(
                            f"{path}/{UUID}/{action}", headers=self.headers, data=data)
                        self.assertEqual(response.status_code, 302)
                        self.assertEqual(response.location, f"/zsazsa{path}/{UUID}")
                publish.assert_not_called()

    def test_approval_of_a_missing_product_returns_404_without_publishing(self):
        for _module, path, _listing, _parser, getter, publisher, _field, _published, action in PRODUCTS:
            with self.subTest(product=path), \
                 mock.patch.object(misp_store, getter, return_value=None), \
                 mock.patch.object(misp_store, publisher) as publish:
                response = self.client.post(
                    f"{path}/{UUID}/{action}",
                    data={"csrf_token": "test-token", "return_to": "review"})
                self.assertEqual(response.status_code, 404)
                publish.assert_not_called()

    def test_approval_errors_return_to_the_list_and_csrf_is_required(self):
        for module, path, _listing, parser, getter, publisher, _field, _published, action in PRODUCTS:
            with self.subTest(product=module.__name__), \
                 mock.patch.object(misp_store, getter, return_value=_product(parser)), \
                 mock.patch.object(misp_store, publisher,
                                   side_effect=RuntimeError("MISP unavailable")) as publish:
                response = self.client.post(
                    f"{path}/{UUID}/{action}", headers=self.headers,
                    data={"csrf_token": "test-token", "return_to": "review"})
                self.assertEqual(response.location, f"/zsazsa{path}/")
                with self.client.session_transaction() as session:
                    self.assertTrue(any("MISP unavailable" in text
                                        for _category, text in session["_flashes"]))
                publish.reset_mock()
                response = self.client.post(
                    f"{path}/{UUID}/{action}", data={"return_to": "review"})
                self.assertEqual(response.status_code, 403)
                publish.assert_not_called()

    def test_rejected_alerts_and_advisories_cannot_be_approved_from_the_preview(self):
        for _module, path, listing, parser, _getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            with self.subTest(path=path):
                product = _product(parser)
                product.review_state = "rejected"
                with mock.patch.object(misp_store, listing, return_value=[product]):
                    response = self.client.get(path + "/")
                page = BeautifulSoup(response.data, "html.parser")
                self.assertEqual(page.select_one(".preview-toggle-btn")["title"], "Preview")
                self.assertIsNone(page.select_one(".inline-approval-form"))

    def test_alert_and_advisory_previews_offer_qa_and_optional_rejection(self):
        for _module, path, listing, parser, _getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            for state in ("draft", "pending-review", "approved", "rejected"):
                with self.subTest(path=path, state=state):
                    product = _product(parser)
                    product.review_state = state
                    with mock.patch.object(misp_store, listing, return_value=[product]):
                        page = BeautifulSoup(
                            self.client.get(path + "/", headers=self.headers).data, "html.parser")
                    row = page.select_one(f"#{kind}-preview-{UUID}")
                    qa = row.select_one(".qa-review-btn")
                    rejection = row.select_one(".inline-rejection-form")
                    if state in ("approved", "rejected"):
                        self.assertIsNone(qa)
                        self.assertIsNone(rejection)
                        continue
                    self.assertEqual(qa["data-kind"], kind)
                    self.assertEqual(qa["data-uuid"], UUID)
                    self.assertIsNotNone(qa.find_parent(class_="qa-review-block")
                                         .select_one(".qa-review-output"))
                    self.assertIn("btn-xs", qa["class"])
                    self.assertEqual(rejection["action"], f"/zsazsa{path}/{UUID}/reject")
                    self.assertEqual(rejection.select_one("[name=csrf_token]")["value"], "test-token")
                    self.assertEqual(rejection.select_one("[name=return_to]")["value"], "review")
                    reason = rejection.select_one("textarea[name=reason]")
                    self.assertFalse(reason.has_attr("required"))
                    self.assertIsNotNone(rejection.select_one(f'label[for="{reason["id"]}"]'))
                    toggle = row.select_one(f'[aria-controls="{rejection.parent["id"]}"]')
                    self.assertEqual(toggle.get_text(strip=True), "Reject")
                    self.assertIn("btn-xs", toggle["class"])
                    self.assertEqual(toggle["data-bs-toggle"], "dropdown")
                    self.assertEqual(toggle.parent, rejection.parent.parent)
                    self.assertIn("dropdown-menu", rejection.parent["class"])
                    self.assertIn("width:20rem", rejection.parent["style"])
                    self.assertIn("p-2", rejection["class"])
                    self.assertEqual(reason["rows"], "2")
                    self.assertIsNotNone(rejection.select_one("button[type=button]"))
                    self.assertTrue(any("QA review did not complete" in (script.string or "")
                                        for script in page.find_all("script")))

    def test_inline_rejection_reuses_the_existing_workflow_and_returns_to_the_list(self):
        for module, path, _listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            for reason in ("", "  Source does not support this claim.  "):
                with self.subTest(path=path, reason=reason), \
                     mock.patch.object(misp_store, getter, return_value=_product(parser)), \
                     mock.patch.object(misp_store, f"reject_{kind}") as reject:
                    self.can_publish.return_value = False
                    response = self.client.post(
                        f"{path}/{UUID}/reject", headers=self.headers,
                        data={"csrf_token": "test-token", "return_to": "review", "reason": reason})
                    self.assertEqual(response.location, f"/zsazsa{path}/")
                    reject.assert_called_once_with(UUID, reason=reason.strip())
                    module.audit.record.assert_called_with(
                        "reject", kind, entity_id=UUID, entity_label=getattr(_product(parser), f"{kind}_id"))

    def test_rejection_protects_published_products_and_preserves_detail_redirects(self):
        for _module, path, _listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            for state in ("draft", "approved", None):
                for return_to in ("review", "", "https://example.org/"):
                    with self.subTest(path=path, state=state, return_to=return_to):
                        product = _product(parser) if state else None
                        if product:
                            product.review_state = state
                        with mock.patch.object(misp_store, getter, return_value=product), \
                             mock.patch.object(misp_store, f"reject_{kind}") as reject:
                            response = self.client.post(
                                f"{path}/{UUID}/reject", headers=self.headers,
                                data={"csrf_token": "test-token", "return_to": return_to})
                        self.assertEqual(reject.call_count, int(state == "draft"))
                        if state is None:
                            self.assertEqual(response.status_code, 404)
                        else:
                            target = "/" if return_to == "review" else f"/{UUID}"
                            self.assertEqual(response.location, f"/zsazsa{path}{target}")

    def test_inline_rejection_surfaces_errors_and_requires_csrf(self):
        for _module, path, _listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            with self.subTest(path=path), \
                 mock.patch.object(misp_store, getter, return_value=_product(parser)), \
                 mock.patch.object(misp_store, f"reject_{kind}",
                                   side_effect=RuntimeError("MISP unavailable")) as reject:
                response = self.client.post(
                    f"{path}/{UUID}/reject", headers=self.headers,
                    data={"csrf_token": "test-token", "return_to": "review"})
                self.assertEqual(response.location, f"/zsazsa{path}/")
                with self.client.session_transaction() as session:
                    messages = session.pop("_flashes", [])
                self.assertTrue(any("MISP unavailable" in text for _category, text in messages))
                reject.reset_mock()
                self.assertEqual(self.client.post(f"{path}/{UUID}/reject").status_code, 403)
                reject.assert_not_called()

    def test_bulk_delete_counts_all_rejected_products_even_when_the_list_is_filtered(self):
        for _module, path, listing, parser, _getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            with self.subTest(path=path):
                draft, rejected = _product(parser), _product(parser)
                rejected.uuid = "rejected-product"
                rejected.review_state = "rejected"
                for products, count in (([draft, rejected], 1), ([draft], 0)):
                    with mock.patch.object(misp_store, listing, return_value=products):
                        page = BeautifulSoup(
                            self.client.get(path + "/?state=draft", headers=self.headers).data,
                            "html.parser")
                    form = page.select_one(f'form[action="/zsazsa{path}/rejected/delete"]')
                    self.assertIsNotNone(form)
                    self.assertIsNone(form.find_parent("form"))
                    self.assertEqual(form["method"], "post")
                    self.assertIn("regardless of the current filters", form["data-submit-confirm"])
                    self.assertEqual(form.select_one("[name=csrf_token]")["value"], "test-token")
                    button = form.select_one("button")
                    self.assertIn("Delete rejected", button.get_text())
                    # On the table with the entries, not with the filters.
                    self.assertIsNotNone(form.find_parent("th"))
                    self.assertEqual(button.has_attr("disabled"), count == 0)
                    self.assertIn(str(count), button.get_text())

    def test_bulk_delete_only_removes_products_that_are_still_rejected(self):
        for module, path, listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            candidates = []
            current = {}
            for index, state in enumerate(("rejected", "approved", "draft", "pending-review", None)):
                product = _product(parser)
                product.uuid = f"candidate-{index}"
                product.review_state = "rejected"
                candidates.append(product)
                current[product.uuid] = SimpleNamespace(review_state=state) if state else None
            with self.subTest(path=path), \
                 mock.patch.object(misp_store, listing, return_value=candidates) as listing_mock, \
                 mock.patch.object(misp_store, getter, side_effect=current.get), \
                 mock.patch.object(misp_store, f"delete_{kind}") as delete:
                self.can_publish.return_value = False
                module.audit.record.reset_mock()
                response = self.client.post(
                    path + "/rejected/delete", headers=self.headers, data={"csrf_token": "test-token"})
                self.assertEqual(response.location, f"/zsazsa{path}/")
                listing_mock.assert_called_once_with(review_state="rejected")
                delete.assert_called_once_with("candidate-0", expected_state="rejected")
                module.audit.record.assert_called_once_with(
                    "delete", kind, entity_id="candidate-0",
                    entity_label=getattr(candidates[0], f"{kind}_id"))

    def test_bulk_delete_reports_errors_and_requires_post_and_csrf(self):
        for _module, path, listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            rejected = _product(parser)
            rejected.review_state = "rejected"
            for listing_error in (False, True):
                with self.subTest(path=path, listing_error=listing_error), \
                     mock.patch.object(misp_store, listing, return_value=[rejected],
                                       side_effect=RuntimeError("MISP unavailable") if listing_error else None), \
                     mock.patch.object(misp_store, getter, return_value=rejected), \
                     mock.patch.object(misp_store, f"delete_{kind}",
                                       side_effect=RuntimeError("Delete refused")) as delete:
                    response = self.client.post(
                        path + "/rejected/delete", headers=self.headers, data={"csrf_token": "test-token"})
                    self.assertEqual(response.location, f"/zsazsa{path}/")
                    with self.client.session_transaction() as session:
                        messages = session.pop("_flashes", [])
                    error = "MISP unavailable" if listing_error else "Delete refused"
                    self.assertTrue(any(error in text for _category, text in messages))
                    delete.reset_mock()
                    self.assertEqual(self.client.post(path + "/rejected/delete").status_code, 403)
                    self.assertEqual(self.client.get(path + "/rejected/delete").status_code, 405)
                    delete.assert_not_called()

    def test_bulk_delete_continues_after_a_failure_and_audits_only_deletions(self):
        for module, path, listing, parser, getter, _publisher, _field, _published, _action in PRODUCTS[:2]:
            kind = "fia" if parser == "_fia_ns" else "vea"
            failed, deleted = _product(parser), _product(parser)
            for index, product in enumerate((failed, deleted)):
                product.uuid = f"rejected-{index}"
                product.review_state = "rejected"
            with self.subTest(path=path), \
                 mock.patch.object(misp_store, listing, return_value=[failed, deleted]), \
                 mock.patch.object(misp_store, getter, return_value=deleted), \
                 mock.patch.object(misp_store, f"delete_{kind}",
                                   side_effect=[RuntimeError("Delete refused"), None]) as delete:
                module.audit.record.reset_mock()
                self.client.post(path + "/rejected/delete", data={"csrf_token": "test-token"})
                self.assertEqual(delete.call_args_list,
                                 [mock.call(failed.uuid, expected_state="rejected"),
                                  mock.call(deleted.uuid, expected_state="rejected")])
                module.audit.record.assert_called_once_with(
                    "delete", kind, entity_id=deleted.uuid, entity_label=getattr(deleted, f"{kind}_id"))
                with self.client.session_transaction() as session:
                    messages = session.pop("_flashes", [])
                self.assertTrue(any("Delete refused" in text for _category, text in messages))
                self.assertTrue(any("Deleted 1 rejected" in text for _category, text in messages))

    def test_a_product_with_a_required_audience_cannot_be_approved_without_one(self):
        for _module, path, listing, parser, getter, publisher, _field, _published, action in PRODUCTS[:3]:
            with self.subTest(path=path):
                product = _product(parser)
                product.audience = "  "
                with mock.patch.object(misp_store, listing, return_value=[product]), \
                     mock.patch.object(misp_store, getter, return_value=product), \
                     mock.patch.object(misp_store, publisher) as publish:
                    response = self.client.get(path + "/")
                    page = BeautifulSoup(response.data, "html.parser")
                    self.assertTrue(page.select_one(".inline-approval-form button").has_attr("disabled"))
                    response = self.client.post(
                        f"{path}/{UUID}/{action}", headers=self.headers,
                        data={"csrf_token": "test-token", "return_to": "review"})
                    self.assertEqual(response.location, f"/zsazsa{path}/")
                    publish.assert_not_called()

    def test_profile_detail_disables_publish_without_an_audience(self):
        for audience in ("", "  ", "SOC"):
            with self.subTest(audience=audience), self.app.test_request_context("/"):
                profile = _product("_tap_ns")
                profile.audience = audience
                html = render_template(
                    "threat_actor_profile/detail.html", tap=profile, recipients=[],
                    pir=None, feedback=[], linked_feeds=[], can_publish=True,
                )
                page = BeautifulSoup(html, "html.parser")
                button = next(button for button in page.select("button")
                              if button.get_text(strip=True) == "Publish")
                self.assertEqual(button.has_attr("disabled"), not audience.strip())

    def test_forms_have_matching_draft_actions_and_no_publish_button(self):
        save_classes = []
        for template, name, parser in (
            ("flash_intel/wizard.html", "fia", "_fia_ns"),
            ("vea/wizard.html", "vea", "_vea_ns"),
            ("detection_eng/wizard.html", "der", "_der_ns"),
            ("threat_actor_profile/form.html", "tap", "_tap_ns"),
        ):
            for editing in (False, True):
                with self.subTest(template=template, editing=editing), self.app.test_request_context("/"):
                    html = render_template(
                        template, **{name: _product(parser) if editing else None},
                        is_edit=editing, can_publish=True, source_events=[], audiences=["SOC"],
                        source_event_tags=[],
                        tlp_levels=["amber"], formats=[], statuses=misp_store.DER_STATUSES,
                        pirs=[], feeds=[], form_values=None,
                    )
                    page = BeautifulSoup(html, "html.parser")
                    actions = page.select_one(".zs-actions")
                    self.assertIsNotNone(actions)
                    self.assertIsNone(actions.select_one("[value=publish]"))
                    save = actions.select_one('button[type=submit][value=save]')
                    cancel = actions.select_one("a")
                    save_classes.append(save["class"])
                    self.assertEqual(save["class"], cancel["class"])
                    if name == "tap":
                        self.assertEqual(len(actions.select("button, a")), 2)
                        self.assertIsNone(page.select_one("#tap-recipients-btn"))
                        self.assertIsNone(page.select_one("#recipientsModal"))
                    else:
                        self.assertEqual(len(actions.select("button, a")), 3)
                        self.assertEqual(actions.select_one("[value=submit]").get_text(strip=True),
                                         "Submit for review")
        self.assertTrue(all(classes == save_classes[0] for classes in save_classes))

    def test_briefing_recipient_preview_uses_delivery_subscription_and_tlp_rules(self):
        """A subscriber cleared below the briefing's TLP is listed as blocked,
        as on the other products, rather than left out without a word."""
        briefing = _product("_briefing_ns")
        briefing.tlp = "green"
        stakeholders = [
            SimpleNamespace(name="SOC analyst", role="SOC", tlp_clearance="amber",
                            products=["Daily threat briefing"]),
            SimpleNamespace(name="Comms", role="Other", tlp_clearance="clear",
                            products=["Daily threat briefing"]),
            SimpleNamespace(name="Board", role="CISO / Leadership", tlp_clearance="red", products=[]),
        ]
        with mock.patch.object(misp_store, "get_briefing", return_value=briefing), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders):
            response = self.client.get(f"/briefing/{UUID}/recipients")
        self.assertEqual(response.status_code, 200)
        page = BeautifulSoup(response.data, "html.parser")
        self.assertEqual([b.contents[0].strip() for b in page.select(".delivery-ok")], ["SOC analyst"])
        self.assertEqual([b.contents[0].strip() for b in page.select(".delivery-blocked")], ["Comms"])
        self.assertIn("TLP clearance (clear) is below TLP:GREEN", page.get_text(" ", strip=True))
        with mock.patch.object(misp_store, "get_briefing", return_value=None):
            self.assertEqual(self.client.get(f"/briefing/{UUID}/recipients").status_code, 404)


class TickedDrafts(unittest.TestCase):
    """Drafts on the alert and advisory lists can be ticked and approved,
    rejected or deleted together, as events are in data collection. Clearing
    out a list of analyser drafts took a click and a confirmation each."""

    setUp = ProductReviewActions.setUp
    LISTS = ((flash_intel, "/products/flash-intel", "fia", "_start_flash_intel_delivery"),
             (vea, "/products/vea", "vea", "_start_vea_delivery"))
    STATES = {"a" * 36: "draft", "b" * 36: "pending-review", "c" * 36: "approved", "d" * 36: "rejected"}

    def records(self, kind):
        records = {}
        for uuid, state in self.STATES.items():
            record = _product(f"_{kind}_ns")
            record.uuid, record.id, record.review_state = uuid, uuid, state
            setattr(record, f"{kind}_id", f"{kind.upper()}-{state}")
            records[uuid] = record
        return records

    def test_only_drafts_and_those_in_review_can_be_ticked(self):
        for module, path, kind, _delivery in self.LISTS:
            with self.subTest(kind), \
                 mock.patch.object(misp_store, f"list_{kind}s", return_value=list(self.records(kind).values())):
                page = BeautifulSoup(self.client.get(path + "/", headers=self.headers).data, "html.parser")
            self.assertEqual([box["value"] for box in page.select(".row-select-cb")], ["a" * 36, "b" * 36])
            self.assertEqual(page.select_one("#selection-form")["action"], f"/zsazsa{path}/selected")
            self.assertIsNotNone(page.select_one("#select-all-cb"))

    def post(self, module, path, kind, delivery, action, allowed=True):
        records = self.records(kind)
        self.can_publish.return_value = allowed
        with mock.patch.object(misp_store, f"get_{kind}", side_effect=records.get), \
             mock.patch.object(misp_store, f"publish_{kind}", return_value=True) as publish, \
             mock.patch.object(misp_store, f"reject_{kind}") as reject, \
             mock.patch.object(misp_store, f"delete_{kind}") as delete, \
             mock.patch.object(module, delivery) as deliver:
            response = self.client.post(path + "/selected", headers=self.headers,
                                        data={"csrf_token": "test-token", "action": action, "ids": list(records)})
        self.assertEqual(response.status_code, 302)
        return SimpleNamespace(publish=publish, reject=reject, delete=delete, deliver=deliver)

    def test_each_action_leaves_what_is_already_published_or_rejected(self):
        for module, path, kind, delivery in self.LISTS:
            with self.subTest(kind):
                calls = self.post(module, path, kind, delivery, "delete")
                self.assertEqual(calls.delete.call_args_list,
                                 [mock.call("a" * 36, expected_state="draft"),
                                  mock.call("b" * 36, expected_state="pending-review")])
                calls = self.post(module, path, kind, delivery, "reject")
                self.assertEqual([c.args[0] for c in calls.reject.call_args_list], ["a" * 36, "b" * 36])
                calls = self.post(module, path, kind, delivery, "approve")
                self.assertEqual([c.args[0] for c in calls.publish.call_args_list], ["a" * 36, "b" * 36])
                self.assertEqual(calls.deliver.call_count, 2)

    def test_approving_needs_publish_rights(self):
        for module, path, kind, delivery in self.LISTS:
            with self.subTest(kind):
                calls = self.post(module, path, kind, delivery, "approve", allowed=False)
                calls.publish.assert_not_called()
                calls.deliver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
