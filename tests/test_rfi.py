"""RFI saves and the SLA clock.

An RFI is stored as one MISP object, and update_rfi writes whatever the caller
hands it: a field left out of that dict is removed from the object and, for the
id, from the event title too. So every save has to carry the whole RFI, not only
the part of the form the analyst touched.

    python -m unittest tests.test_rfi
"""

import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask

import config
from webapp import collection_cache, create_app
from webapp.routes import rfi as rfi_routes


def _rfi(**overrides):
    stored = {
        "id": "rfi-uuid", "uuid": "rfi-uuid", "rfi_id": "RFI-007",
        "question": "Is our sector targeted?", "context": "Asked by the SOC lead",
        "requester_name": "Ada", "requester_team": "SOC",
        "owner_uuid": "stakeholder-uuid", "owner_name": "Ada",
        "priority": "High", "status": "Delivered", "assigned_analyst": "koen",
        "due_date": date(2026, 8, 20),
        "linked_pir_uuid": "pir-uuid", "linked_gir_uuid": "",
        "output_format_list": [{"format": "Flash Intel Alert", "tlp": "amber"}],
        "response": "Yes, twice this month.", "response_confidence": "High",
        "feedback_requirement_met": "", "feedback_on_time": "",
        "feedback_usefulness": "", "feedback_suggestions": "",
        "attachments": [], "notes": [], "created_at": None, "creator": "",
        "misp_url": "", "history_url": "",
    }
    stored.update(overrides)
    return SimpleNamespace(**stored)


class Feedback(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(rfi_routes.bp)
        self.client = app.test_client()

    def post(self, **form):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=_rfi()), \
             mock.patch.object(rfi_routes.misp_store, "update_rfi") as update, \
             mock.patch.object(rfi_routes.audit, "record"):
            self.client.post("/rfis/rfi-uuid/feedback", data=form)
        return update.call_args.args[1]

    def test_the_feedback_is_written(self):
        saved = self.post(feedback_requirement_met="Partially", feedback_on_time="Yes",
                          feedback_usefulness="Very useful",
                          feedback_suggestions="  More IOCs next time  ")
        self.assertEqual(saved["feedback_requirement_met"], "Partially")
        self.assertEqual(saved["feedback_on_time"], "Yes")
        self.assertEqual(saved["feedback_usefulness"], "Very useful")
        self.assertEqual(saved["feedback_suggestions"], "More IOCs next time")

    def test_the_rfi_keeps_its_id(self):
        """Saving feedback used to leave rfi_id out of the update, which drops the
        attribute from the object and rewrites the event title without it."""
        self.assertEqual(self.post()["rfi_id"], "RFI-007")

    def test_the_rest_of_the_rfi_survives(self):
        saved = self.post()
        self.assertEqual(saved["question"], "Is our sector targeted?")
        self.assertEqual(saved["status"], "Delivered")
        self.assertEqual(saved["priority"], "High")
        self.assertEqual(saved["response"], "Yes, twice this month.")
        self.assertEqual(saved["response_confidence"], "High")
        self.assertEqual(saved["due_date"], "2026-08-20")
        self.assertEqual(saved["linked_pir_uuid"], "pir-uuid")
        self.assertEqual(saved["output_format_list"],
                         [{"format": "Flash Intel Alert", "tlp": "amber"}])

    def test_an_unknown_rfi_is_not_written(self):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=None), \
             mock.patch.object(rfi_routes.misp_store, "update_rfi") as update:
            reply = self.client.post("/rfis/nope/feedback", data={})
        self.assertEqual(reply.status_code, 404)
        update.assert_not_called()


class Response(unittest.TestCase):
    """The inline edit on the RFI page saves the response, its confidence and
    the preferred output formats, and nothing else."""

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(rfi_routes.bp)
        self.client = app.test_client()

    def post(self, rfi=None, **form):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=rfi or _rfi()), \
             mock.patch.object(rfi_routes.misp_store, "update_rfi") as update, \
             mock.patch.object(rfi_routes.audit, "record"):
            reply = self.client.post("/rfis/rfi-uuid/response", data=form)
        return reply, update

    def test_the_three_fields_are_written(self):
        _reply, update = self.post(
            response="Twice, both phishing.", response_confidence="Very likely",
            output_format_item=["Indicator feed", ""], output_format_tlp=["green", "amber"])
        saved = update.call_args.args[1]
        self.assertEqual(saved["response"], "Twice, both phishing.")
        self.assertEqual(saved["response_confidence"], "Very likely")
        self.assertEqual(saved["output_format_list"], [{"format": "Indicator feed", "tlp": "green"}])

    def test_the_rest_of_the_rfi_survives(self):
        _reply, update = self.post(response="New text.")
        saved = update.call_args.args[1]
        self.assertEqual(saved["rfi_id"], "RFI-007")
        self.assertEqual(saved["question"], "Is our sector targeted?")
        self.assertEqual(saved["status"], "Delivered")
        self.assertEqual(saved["due_date"], "2026-08-20")
        self.assertEqual(saved["linked_pir_uuid"], "pir-uuid")

    def test_an_rfi_not_yet_triaged_takes_no_response(self):
        reply, update = self.post(rfi=_rfi(status="New"), response="Too early.")
        self.assertEqual(reply.status_code, 302)
        update.assert_not_called()


class RenderedPages(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(rfi_routes.misp_store, "get_pir", return_value=None),
            mock.patch.object(rfi_routes.misp_store, "get_gir", return_value=None),
            mock.patch.object(rfi_routes.misp_store, "list_product_feedback", return_value=[]),
            mock.patch.object(rfi_routes.misp_store, "list_stakeholders", return_value=[]),
            mock.patch.object(rfi_routes.misp_store, "list_pirs", return_value=[]),
            mock.patch.object(rfi_routes.misp_store, "list_girs", return_value=[]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, path, rfi):
        with mock.patch.object(rfi_routes.misp_store, "get_rfi", return_value=rfi):
            return BeautifulSoup(self.client.get(path).data, "html.parser")

    def test_the_rfi_page_offers_an_inline_edit_of_the_response(self):
        page = self.page("/rfis/rfi-uuid", _rfi(status="Acknowledged"))
        form = page.select_one('form[action="/rfis/rfi-uuid/response"]')
        self.assertIsNotNone(form)
        self.assertIsNotNone(form.select_one("textarea[name=response]"))
        self.assertIsNotNone(form.select_one("select[name=response_confidence]"))
        self.assertIsNotNone(form.select_one("select[name=output_format_item]"))
        self.assertIsNotNone(form.select_one("input[name=csrf_token]"))

    def test_an_rfi_not_yet_triaged_has_no_inline_edit(self):
        page = self.page("/rfis/rfi-uuid", _rfi(status="New"))
        self.assertIsNone(page.select_one('form[action="/rfis/rfi-uuid/response"]'))

    def test_the_formats_are_sorted_and_carry_their_icon(self):
        for path in ("/rfis/rfi-uuid", "/rfis/rfi-uuid/edit"):
            with self.subTest(path=path):
                page = self.page(path, _rfi(output_format_list=[{"format": "Flash intel alert", "tlp": "amber"}]))
                self.assertIn("Preferred output formats", page.get_text())
                select = page.select_one("select[name=output_format_item]")
                names = [o.get_text() for o in select.select("option") if o.get("value")]
                self.assertEqual(names, sorted(names, key=str.lower))
                self.assertIsNotNone(select.find_previous_sibling(class_="fmt-icon").select_one("i.fa-bolt"))

    def test_a_format_no_longer_offered_survives_a_save(self):
        page = self.page("/rfis/rfi-uuid", _rfi(output_format_list=[{"format": "Weekly digest", "tlp": "amber"}]))
        form = page.select_one('form[action="/rfis/rfi-uuid/response"]')
        self.assertEqual(form.select_one("select[name=output_format_item] option[selected]")["value"],
                         "Weekly digest")

    def test_cancel_reloads_instead_of_hiding_the_edits(self):
        page = self.page("/rfis/rfi-uuid", _rfi(status="Acknowledged"))
        form = page.select_one('form[action="/rfis/rfi-uuid/response"]')
        self.assertIsNotNone(form.find("a", href="/rfis/rfi-uuid", string="Cancel"))

    def test_the_details_show_the_format_with_its_icon(self):
        page = self.page("/rfis/rfi-uuid", _rfi(output_format_list=[{"format": "Indicator feed", "tlp": "green"}]))
        details = page.find("dt", string="Preferred output formats").find_next_sibling("dd")
        self.assertIsNotNone(details.select_one("i.fa-satellite-dish"))


class SlaStatus(unittest.TestCase):
    """What the SLA badge on the list page shows."""

    def state(self, **overrides):
        return rfi_routes._sla_status(_rfi(**overrides))

    def test_a_delivered_rfi_has_stopped_its_clock(self):
        self.assertEqual(self.state(status="Delivered"), ("done", None))
        self.assertEqual(self.state(status="Closed"), ("done", None))

    def test_an_open_rfi_without_a_due_date_is_unknown_rather_than_fine(self):
        self.assertEqual(self.state(status="In Progress", due_date=None), ("amber", None))

    def test_an_overdue_rfi_is_red_with_the_days_it_is_over(self):
        state, days = self.state(status="In Progress", due_date=date.today() - timedelta(days=3))
        self.assertEqual((state, days), ("red", -3))

    def test_due_today_or_tomorrow_is_amber(self):
        self.assertEqual(self.state(status="New", due_date=date.today())[0], "amber")
        self.assertEqual(self.state(status="New", due_date=date.today() + timedelta(days=1))[0], "amber")

    def test_further_out_is_green(self):
        self.assertEqual(self.state(status="New", due_date=date.today() + timedelta(days=2))[0], "green")


class SuggestedDueDate(unittest.TestCase):
    def test_it_follows_the_sla_for_the_priority(self):
        for priority, days in rfi_routes.misp_store.RFI_SLA_DAYS.items():
            expected = (date.today() + timedelta(days=days)).isoformat()
            self.assertEqual(rfi_routes._suggested_due_date(priority), expected, priority)

    def test_an_unknown_priority_falls_back_to_the_medium_sla(self):
        expected = (date.today() + timedelta(days=5)).isoformat()
        self.assertEqual(rfi_routes._suggested_due_date("Whenever"), expected)


if __name__ == "__main__":
    unittest.main()
