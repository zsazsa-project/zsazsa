"""Files attached to a flash intel alert: who may change them, and how they go out.

Mattermost cannot carry a file, so it only gets the names the rendered content
already lists. E-mail gets the bytes. The alert has to go out either way, which
is why the download happens once, up front, and a file that will not come back
is dropped rather than allowed to fail the delivery.

    python -m unittest tests.test_flash_intel_attachments_delivery
"""

import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest import mock

from flask import Flask

import config
from notifier import dispatcher, email
from webapp.routes import flash_intel


class DispatchCarriesAttachments(unittest.TestCase):
    def setUp(self):
        self._orig = config.NOTIFICATION_CHANNELS
        config.NOTIFICATION_CHANNELS = [
            {"id": "mm1", "name": "MM", "type": "mattermost", "url": "x", "enabled": True},
            {"id": "em1", "name": "Mail", "type": "email", "recipient": "soc@x.test", "enabled": True},
        ]
        self.files = [("report.pdf", b"%PDF", "application", "pdf")]

    def tearDown(self):
        config.NOTIFICATION_CHANNELS = self._orig

    def _send(self, channel):
        fia = SimpleNamespace(fia_id="FIA-00042", uuid="u" * 36, tlp="amber")
        stakeholder = SimpleNamespace(name="Acme", notification_channels=[channel])
        with mock.patch.object(dispatcher.email, "send_flash_intel_alert", return_value=True) as mail, \
             mock.patch.object(dispatcher.mattermost, "send_flash_intel_alert", return_value=True) as mm:
            dispatcher.send_flash_intel(fia, "# Alert", [stakeholder], self.files)
        return mail, mm

    def test_the_e_mail_sender_is_handed_the_files(self):
        mail, _mm = self._send("em1")
        self.assertEqual(mail.call_args.kwargs["attachments"], self.files)

    def test_mattermost_is_not_asked_to_carry_them(self):
        _mail, mm = self._send("mm1")
        self.assertNotIn("attachments", mm.call_args.kwargs)

    def test_an_alert_without_files_still_sends(self):
        fia = SimpleNamespace(fia_id="FIA-00042", uuid="u" * 36, tlp="amber")
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["em1"])
        with mock.patch.object(dispatcher.email, "send_flash_intel_alert", return_value=True) as mail:
            summary = dispatcher.send_flash_intel(fia, "# Alert", [stakeholder])
        self.assertEqual(summary["sent_types"], ["email"])
        self.assertIsNone(mail.call_args.kwargs["attachments"])


class EmailAttachesThem(unittest.TestCase):
    def test_the_files_reach_the_message(self):
        fia = SimpleNamespace(fia_id="FIA-00042", tlp="amber")
        files = [("report.pdf", b"%PDF", "application", "pdf")]
        with mock.patch.object(email, "send_email", return_value=True) as send, \
             mock.patch.object(email, "_recipients", return_value=["soc@x.test"]):
            email.send_flash_intel_alert(fia, "# Alert", channel_ids=["em1"], attachments=files)
        self.assertEqual(send.call_args[0][4], files)

    def test_the_subject_still_carries_the_id_and_classification(self):
        fia = SimpleNamespace(fia_id="FIA-00042", tlp="amber")
        with mock.patch.object(email, "send_email", return_value=True) as send, \
             mock.patch.object(email, "_recipients", return_value=["soc@x.test"]):
            email.send_flash_intel_alert(fia, "# Alert")
        subject = send.call_args[0][1]
        self.assertIn("FIA-00042", subject)
        self.assertIn("AMBER", subject.upper())


class PublishedAlertsAreFrozen(unittest.TestCase):
    """Attachments are alert content, so they follow the rule the rest of it
    follows: once an alert is published it no longer changes. The page hides the
    controls; these check the routes refuse too, since the page is not the only
    way to reach them."""

    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.secret_key = "test"
        app.register_blueprint(flash_intel.bp)
        self.client = app.test_client()
        self.uuid = "u" * 36

    def _post(self, path, review_state, **data):
        fia = SimpleNamespace(uuid=self.uuid, fia_id="FIA-00042", review_state=review_state)
        with mock.patch.object(flash_intel.misp_store, "get_fia", return_value=fia), \
             mock.patch.object(flash_intel.misp_store, "add_fia_attachment", return_value="a" * 36) as add, \
             mock.patch.object(flash_intel.misp_store, "delete_fia_attachment") as delete, \
             mock.patch.object(flash_intel.audit, "record"):
            reply = self.client.post(f"/products/flash-intel/{self.uuid}{path}",
                                     data=data, content_type="multipart/form-data")
        return reply, add, delete

    def test_a_draft_accepts_an_upload(self):
        _reply, add, _delete = self._post(
            "/attachments", "draft", attachment=(BytesIO(b"%PDF"), "report.pdf"))
        add.assert_called_once()
        self.assertEqual(add.call_args[0][1], "report.pdf")

    def test_a_published_alert_refuses_an_upload(self):
        _reply, add, _delete = self._post(
            "/attachments", "approved", attachment=(BytesIO(b"%PDF"), "report.pdf"))
        add.assert_not_called()

    def test_a_draft_accepts_a_delete(self):
        _reply, _add, delete = self._post(f"/attachments/{'a' * 36}/delete", "draft")
        delete.assert_called_once_with("a" * 36)

    def test_a_published_alert_refuses_a_delete(self):
        _reply, _add, delete = self._post(f"/attachments/{'a' * 36}/delete", "approved")
        delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
