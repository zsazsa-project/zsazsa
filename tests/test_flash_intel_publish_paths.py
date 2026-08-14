"""Publishing an alert from the wizard does what approving it from the detail page does.

There are two ways to publish a flash intel alert: approve it from the detail
page, or save the wizard with the publish action. The second called a helper that
had been renamed out from under it, so it raised NameError after the alert had
already been updated, leaving it marked approved with the MISP event unpublished
and nobody notified.

Nothing is published for real here: the store and the delivery job are stubbed.

    python -m unittest tests.test_flash_intel_publish_paths
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp.routes import flash_intel


class WizardPublish(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.secret_key = "test"
        app.register_blueprint(flash_intel.bp)
        self.client = app.test_client()
        self.uuid = "u" * 36
        self.fia = SimpleNamespace(uuid=self.uuid, fia_id="FIA-00042", audience="SOC",
                                   review_state="draft", tlp="amber")

    def post(self, action):
        with mock.patch.object(flash_intel.misp_store, "get_fia", return_value=self.fia), \
             mock.patch.object(flash_intel.misp_store, "update_fia") as update, \
             mock.patch.object(flash_intel.misp_store, "publish_fia") as publish, \
             mock.patch.object(flash_intel.misp_store, "fetch_source_events", return_value=[]), \
             mock.patch.object(flash_intel, "_form_data", return_value={"audience": "SOC"}), \
             mock.patch.object(flash_intel, "_start_flash_intel_delivery") as deliver, \
             mock.patch.object(flash_intel.audit, "record"):
            reply = self.client.post(f"/products/flash-intel/{self.uuid}/edit",
                                     data={"action": action})
        return reply, update, publish, deliver

    def test_publishing_from_the_wizard_publishes_the_event_and_starts_delivery(self):
        reply, update, publish, deliver = self.post("publish")
        self.assertEqual(reply.status_code, 302)
        update.assert_called_once()
        publish.assert_called_once_with(self.uuid)
        deliver.assert_called_once_with("FIA-00042", self.uuid, "publish")

    def test_saving_publishes_nothing_and_notifies_nobody(self):
        _reply, update, publish, deliver = self.post("save")
        update.assert_called_once()
        publish.assert_not_called()
        deliver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
