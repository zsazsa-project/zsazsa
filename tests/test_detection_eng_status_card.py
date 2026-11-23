"""The compact engineering status card keeps all status choices and form fields.

    python -m unittest tests.test_detection_eng_status_card
"""

import unittest
from pathlib import Path

from bs4 import BeautifulSoup
from flask import Flask, render_template
from jinja2 import ChoiceLoader, DictLoader
from pymisp import MISPEvent

from webapp import misp_store
from webapp.routes import detection_eng
from webapp.utils import list_item_count, markdown_list


class EngineeringStatusCard(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__, template_folder=str(
            Path(__file__).resolve().parent.parent / "webapp" / "templates"))
        self.app.secret_key = "test"
        self.app.register_blueprint(detection_eng.bp)
        self.app.jinja_loader = ChoiceLoader([
            DictLoader({"base.html": "{% block content %}{% endblock %}"}),
            self.app.jinja_loader,
        ])
        self.app.jinja_env.filters["md_inline"] = lambda text: text
        self.app.jinja_env.filters["md"] = lambda text: text
        self.app.jinja_env.filters["markdown_list"] = markdown_list
        self.app.jinja_env.filters["list_item_count"] = list_item_count
        self.app.jinja_env.filters["slug"] = lambda text: text.lower()
        self.app.jinja_env.filters["scope_rows"] = misp_store.briefing_story_scope_rows
        self.app.jinja_env.globals["csrf_token"] = lambda: "test-token"
        event = MISPEvent()
        event.uuid = "8261112b-619c-4ee0-9409-c898df74520c"
        event.date = "2026-10-26"
        self.der = misp_store._der_ns(event)

    def render(self):
        with self.app.test_request_context("/"):
            return render_template(
                "detection_eng/detail.html", der=self.der, recipients=[], feedback=[],
                statuses=misp_store.DER_STATUSES, formats=misp_store.DER_FORMATS,
                format_hints=misp_store.DER_FORMAT_HINTS, can_publish=True,
            )

    def test_each_status_has_its_kanban_colour_and_icon_without_changing_the_form(self):
        styles = {
            "Pending": ("secondary", "fa-hourglass-half"),
            "In Dev": ("primary", "fa-code"),
            "In Test": ("warning", "fa-flask"),
            "Active": ("success", "fa-circle-check"),
            "Retired": ("secondary", "fa-box-archive"),
        }
        for status, (tone, icon) in styles.items():
            with self.subTest(status=status):
                self.der.status = status
                card = BeautifulSoup(self.render(), "html.parser").select_one(
                    ".der-engineering-status")
                badge = card.select_one(".card-header .badge")
                self.assertEqual(badge.get_text(strip=True), status)
                self.assertIn(f"bg-{tone}-subtle", badge["class"])
                self.assertIsNotNone(badge.select_one(f".{icon}[aria-hidden='true']"))
                form = card.select_one("form")
                self.assertEqual(form["method"], "post")
                self.assertEqual(form["action"],
                                 f"/products/detection-eng/{self.der.uuid}/status")
                self.assertEqual(form.select_one("[name=csrf_token]")["value"], "test-token")
                select = form.select_one("select[name=status]")
                self.assertEqual([o["value"] for o in select.select("option")],
                                 misp_store.DER_STATUSES)
                self.assertEqual(select.select_one("option[selected]")["value"], status)
                self.assertEqual(form.select_one("label")["for"], select["id"])
                self.assertIn("Approval is required to leave Pending.", card.get_text())
                self.assertIn("passes Rulezet validation.", card.get_text())


if __name__ == "__main__":
    unittest.main()
