"""A threat landscape report goes out as a PDF and by mail and Mattermost, under its TLP.

The PDF carries the TLP banner and renders its fields as Markdown. Publishing
hands delivery to a background job, which sends only to the stakeholders who
are subscribed, cleared for the report's TLP and in its audience; a resend
does the same. The mail puts the TLP in its subject and lifts the metadata into
its grid. MISP, the job thread and the channels are patched out.

    python -m unittest tests.test_tlr_delivery
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask

import config
from notifier import dispatcher, email, product_email
from webapp import collection_cache, create_app, misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _report(**fields):
    data = {key: "" for key in misp_store.TLR_DIRECTION_FIELDS}
    data.update({key: [] for key in misp_store.TLR_DIRECTION_LISTS})
    data.update({key: "" for key, _label, _icon in misp_store.TLR_ACTOR_CATEGORIES})
    data.update(uuid=UUID, tlr_id="TLR-00009", title="Q3 landscape", reporting_period="2026 Q3", tlp="red",
                author="CTI", audience="SOC", top_threats="**Ransomware** first", trending_actors="",
                key_incidents="", recommendations="", outlook="", threat_sections=[], review_log=[], corrections=[], entries=[],
                review_state="published", creator="", approved_by="", created_at=None, misp_url="")
    data.update(fields)
    return SimpleNamespace(**data)


class Pdf(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_pdf_carries_the_tlp_and_renders_markdown(self):
        report = _report(threat_sections=[{"title": "Grid", "findings": "- up by half", "confidence": "high"}])
        writer = mock.Mock()
        writer.write_pdf.return_value = b"%PDF"
        app = create_app()
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch("weasyprint.HTML", return_value=writer) as html:
            reply = app.test_client().get(f"/products/threat-landscape/{UUID}/pdf")
        self.assertEqual(reply.data, b"%PDF")
        self.assertIn('filename="TLR-00009.pdf"', reply.headers["Content-Disposition"])
        page = html.call_args.kwargs["string"]
        self.assertIn('class="cover-tlp-badge tlp-red">TLP:RED', page)
        self.assertIn("<strong>Ransomware</strong> first", page)
        self.assertIn("<li>up by half</li>", page)
        self.assertIn("High", page)
        self.assertNotIn("stakeholder review", page)

    def test_a_copy_taken_for_review_says_so(self):
        writer = mock.Mock()
        writer.write_pdf.return_value = b"%PDF"
        with mock.patch.object(misp_store, "get_tlr", return_value=_report(review_state="stakeholder-review")), \
             mock.patch("weasyprint.HTML", return_value=writer) as html:
            create_app().test_client().get(f"/products/threat-landscape/{UUID}/pdf")
        self.assertIn("stakeholder review", html.call_args.kwargs["string"])


class Delivery(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_landscape.bp)
        self.app = app

    def deliver(self, report, preview):
        """Start a delivery and run the job's work in this thread instead."""
        with self.app.test_request_context(), \
             mock.patch.object(threat_landscape.notify_jobs, "start") as start:
            threat_landscape._start_delivery(report, "publish")
        work = start.call_args.args[2]
        stakeholders = [SimpleNamespace(uuid="s1"), SimpleNamespace(uuid="s2")]
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch.object(misp_store, "recipient_preview", return_value=preview), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=stakeholders), \
             mock.patch.object(dispatcher, "send_threat_landscape_report", return_value={}) as send, \
             mock.patch.object(dispatcher, "delivery_outcome", return_value=(True, "sent")):
            self.assertEqual(work(lambda line: None), (True, "sent"))
        return send

    def test_only_the_cleared_and_subscribed_stakeholders_receive_it(self):
        preview = [{"uuid": "s1", "status": "green"}, {"uuid": "s2", "status": "yellow"}]
        send = self.deliver(_report(), preview)
        report, markdown, stakeholders = send.call_args.args
        self.assertEqual([s.uuid for s in stakeholders], ["s1"])
        self.assertIn("**Classification:** TLP:RED", markdown)
        self.assertIn(f"/products/threat-landscape/{UUID}", markdown)

    def test_the_draft_route_refuses_a_resend(self):
        with mock.patch.object(misp_store, "get_tlr", return_value=_report(review_state="draft")), \
             mock.patch.object(threat_landscape, "_start_delivery") as start:
            self.app.test_client().post(f"/products/threat-landscape/{UUID}/resend")
        start.assert_not_called()


class Mail(unittest.TestCase):
    def test_the_subject_names_the_tlp_and_the_metadata_fills_the_grid(self):
        markdown = misp_store.render_tlr_markdown(_report(scope_sectors=["Energy"]))
        with mock.patch.object(email, "send_email", return_value=True) as send, \
             mock.patch.object(email, "_recipients", return_value=["a@example.org"]):
            email.send_threat_landscape_report_notification(_report(), markdown)
        self.assertEqual(send.call_args.args[1], "[CTI] TLP:RED - TLR-00009: Q3 landscape")
        title, meta, _body = product_email._split_markdown(markdown)
        self.assertEqual(title, "Q3 landscape")
        self.assertIn(("Scope", "Energy"), meta)
        self.assertIn(("Classification", "TLP:RED"), meta)


if __name__ == "__main__":
    unittest.main()
