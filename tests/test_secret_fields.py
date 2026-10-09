"""Stored secrets never go back to the browser, nor to a new address (GHSA-v6rj-fh3w-rx8x).

The settings pages used to write every key and password into the page source.
They are write-only now: a secret field is shown empty, an empty one keeps what
is stored, a "Remove" box clears it, and a secret stays with the address it was
entered for. Pointing a setting elsewhere without entering the secret again is
refused, and so is a connection test that would send it to another host.

    python -m unittest tests.test_secret_fields
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

import config as _config
from webapp import collection_cache, create_app
from webapp.routes import collection_sources, config_page

SECRETS = {
    "MISP_WEBAPP_KEY": "secret-webapp-key",
    "MISP_KEY": "secret-scraper-key",
    "SMTP_PASSWORD": "secret-smtp-password",
    "OPENAI_API_KEY": "secret-openai-key",
    "LOCAL_LLM_API_KEY": "secret-local-llm-key",
    "SCRAPER_REDIS_PASSWORD": "secret-scraper-redis",
    "MISP_SESSION_REDIS_PASSWORD": "secret-session-redis",
}
SERVER = {"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
          "api_key": "secret-partner-key", "verify_tls": True, "enabled": True}
MAILBOX = {"id": "inbox", "name": "Inbox", "enabled": True, "host": "imap.example.org",
           "port": 993, "ssl": True, "username": "cti", "password": "secret-imap-password",
           "folder": "INBOX", "sources": []}
FLOWINTEL = {"id": "fi", "name": "Flowintel", "url": "https://flowintel.example.org",
             "api_key": "secret-flowintel-key", "enabled": True, "verify_tls": True}
CHANNEL = {"id": "soc", "name": "SOC", "type": "mattermost",
           "url": "https://chat.example.org/hooks/secret-webhook", "enabled": True}


class RenderedPages(unittest.TestCase):
    def test_no_stored_secret_is_in_the_settings_pages(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(_config, create=True,
                                 DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log"),
                                 MISP_SERVERS=[SERVER], IMAP_SOURCES=[MAILBOX],
                                 FLOWINTEL_INSTANCES=[FLOWINTEL], NOTIFICATION_CHANNELS=[CHANNEL],
                                 MISP_SESSION_REDIRECT_TO_LOGIN=False,
                                 MISP_SESSION_COOKIE_NAME="MISP-test", **SECRETS), \
             mock.patch.object(config_page, "importlib"), \
             mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
             mock.patch.object(collection_sources.misp_store, "list_collection_sources", return_value=[]), \
             mock.patch.object(collection_cache, "start_worker"):
            client = create_app().test_client()
            pages = {path: client.get(path).get_data(as_text=True)
                     for path in ("/config", "/config/sources/")}
        for path, html in pages.items():
            self.assertIn("Configured, leave blank to keep", html)
            for secret in [*SECRETS.values(), SERVER["api_key"], MAILBOX["password"],
                           FLOWINTEL["api_key"], "secret-webhook"]:
                with self.subTest(path=path, secret=secret):
                    self.assertNotIn(secret, html)


class SavedSecrets(unittest.TestCase):
    """The saves, against a copy of the config file."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(config_page.bp)
        app.register_blueprint(collection_sources.bp)
        self.client = app.test_client()

        patches = [
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
            mock.patch.object(config_page.misp_session, "derive_cookie_name", return_value=""),
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
            mock.patch.multiple(_config, create=True, MISP_WEBAPP_URL="https://misp.example.org",
                                SMTP_HOST="smtp.example.org", MISP_URL="https://scraper.example.org",
                                MISP_SERVERS=[SERVER], **SECRETS),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        namespace = {}
        exec(compile(self.target.read_text(), str(self.target), "exec"), namespace)
        return namespace

    def post_config(self, **fields):
        form = {"MISP_WEBAPP_URL": "https://misp.example.org", "MISP_WEBAPP_KEY": "",
                "SMTP_HOST": "smtp.example.org", "SMTP_PASSWORD": ""}
        form.update(fields)
        return self.client.post("/config", data=form)

    def test_an_empty_secret_field_keeps_the_stored_secret(self):
        self.post_config()
        self.assertEqual(self.saved()["MISP_WEBAPP_KEY"], SECRETS["MISP_WEBAPP_KEY"])
        self.assertEqual(self.saved()["SMTP_PASSWORD"], SECRETS["SMTP_PASSWORD"])

    def test_a_new_secret_replaces_the_stored_one(self):
        self.post_config(MISP_WEBAPP_KEY="new-key")
        self.assertEqual(self.saved()["MISP_WEBAPP_KEY"], "new-key")

    def test_remove_clears_a_secret(self):
        self.post_config(remove_SMTP_PASSWORD="true")
        self.assertEqual(self.saved()["SMTP_PASSWORD"], "")

    def test_a_new_address_without_its_secret_is_not_saved(self):
        before = self.target.read_text()
        self.post_config(MISP_WEBAPP_URL="https://attacker.example")
        self.assertEqual(self.target.read_text(), before)

    def test_a_new_address_with_its_secret_is_saved(self):
        self.post_config(MISP_WEBAPP_URL="https://misp2.example.org", MISP_WEBAPP_KEY="key-2")
        self.assertEqual(self.saved()["MISP_WEBAPP_URL"], "https://misp2.example.org")
        self.assertEqual(self.saved()["MISP_WEBAPP_KEY"], "key-2")

    def test_the_session_redis_cannot_be_changed_from_the_page(self):
        self.post_config(MISP_SESSION_REDIS_HOST="attacker.example", MISP_SESSION_REDIS_PORT="6380",
                         MISP_SESSION_REDIS_PASSWORD="x")
        saved = self.saved()
        self.assertEqual(saved["MISP_SESSION_REDIS_HOST"], _config.MISP_SESSION_REDIS_HOST)
        self.assertEqual(saved["MISP_SESSION_REDIS_PORT"], _config.MISP_SESSION_REDIS_PORT)
        self.assertEqual(saved["MISP_SESSION_REDIS_PASSWORD"], SECRETS["MISP_SESSION_REDIS_PASSWORD"])

    def test_emptying_the_scraper_address_drops_its_key(self):
        self.client.post("/config/sources/save-scraper", data={"MISP_URL": "", "MISP_KEY": ""})
        self.assertEqual(self.saved()["MISP_KEY"], "")

    def test_a_partner_server_keeps_its_key_but_not_for_another_url(self):
        server = {**SERVER, "original_id": "partner", "api_key": ""}
        resp = self.client.post("/config/sources/save-server", json=server)
        self.assertTrue(resp.get_json()["ok"])
        self.assertEqual(self.saved()["MISP_SERVERS"][0]["api_key"], SERVER["api_key"])

        resp = self.client.post("/config/sources/save-server",
                                json={**server, "url": "https://attacker.example"})
        self.assertEqual(resp.status_code, 400)


class ConnectionTests(unittest.TestCase):
    """A test run with an empty key uses the stored one, for its own address only."""

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()
        patches = [
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
            mock.patch.object(config_page.audit, "record"),
            mock.patch.multiple(_config, create=True, MISP_SERVERS=[SERVER],
                                SMTP_HOST="smtp.example.org", SMTP_PASSWORD="secret-smtp-password"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_misp(self):
        with mock.patch.object(config_page.misp_store, "_test_connection",
                               return_value={"ok": True}) as test:
            self.client.post("/config/test_misp_connection", json={"url": SERVER["url"]})
            test.assert_called_once_with(SERVER["url"], SERVER["api_key"], True)

            resp = self.client.post("/config/test_misp_connection", json={"url": "https://attacker.example"})
            self.assertEqual(resp.status_code, 400)
            test.assert_called_once()

    def test_smtp(self):
        from notifier import email
        with mock.patch.object(email, "test_connection", return_value={"ok": True}) as test:
            self.client.post("/config/test-smtp-connection", json={"host": "smtp.example.org"})
            self.client.post("/config/test-smtp-connection", json={"host": "attacker.example"})
        self.assertEqual([c.args[4] for c in test.call_args_list], ["secret-smtp-password", ""])


if __name__ == "__main__":
    unittest.main()
