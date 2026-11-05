"""The AI-connector MISP module on the AI tab of the Settings page.

It pins that the AI tab saves the module's settings, that a save which does not
send them (the setup wizard, the main Settings form) keeps them, that its API
key stays with the LLM endpoint it was entered for, that Test connection pings
the module with what the page holds, and that the fixed "Summarise MISP event"
row is greyed out while the module is disabled.

    python -m unittest tests.test_ai_connector_settings
"""

import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

import config as _config
from core import ai_connector
from webapp import collection_cache, create_app
from webapp.routes import config_page

STORED = {
    "AI_CONNECTOR_ENABLED": True,
    "AI_CONNECTOR_URL": "http://ai-connector",
    "AI_CONNECTOR_PORT": 6667,
    "AI_CONNECTOR_TIMEOUT": 3000,
    "AI_CONNECTOR_SSL_VERIFY_PEER": False,
    "AI_CONNECTOR_SSL_VERIFY_HOST": False,
    "AI_CONNECTOR_SSL_ALLOW_SELF_SIGNED": False,
    "AI_CONNECTOR_SSL_CAFILE": "",
    "AI_CONNECTOR_OPENAI_API_BASE": "http://llm.example.org:11434/v1",
    "AI_CONNECTOR_API_KEY": "secret-ai-connector-key",
    "AI_CONNECTOR_MODEL_ID": "zsazsa-local:latest",
}
POSTED = {
    "enabled": True, "url": "http://ai-connector/", "port": "6667", "timeout": "600",
    "ssl_verify_peer": True, "ssl_verify_host": True, "ssl_allow_self_signed": True,
    "ssl_cafile": "/etc/ssl/ai-ca.pem", "openai_api_base": "http://llm.example.org:11434/v1",
    "api_key": "", "model_id": "gemma4:12b",
}


class Saving(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py.example", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()
        for patcher in (
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
            mock.patch.object(config_page.misp_session, "derive_cookie_name", return_value=""),
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
            mock.patch.multiple(_config, create=True, **STORED),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        namespace = {}
        exec(compile(self.target.read_text(), str(self.target), "exec"), namespace)
        return {name: namespace[name] for name in STORED}

    def save_providers(self, **providers):
        return self.client.post("/config/save-ai-features", json={"providers": {
            "openai": {"enabled": True}, "local": {"enabled": False}, "default": "openai", **providers}})

    def test_the_ai_tab_saves_the_module_settings(self):
        resp = self.save_providers(ai_connector=POSTED)
        self.assertEqual(resp.get_json(), {"ok": True})
        self.assertEqual(self.saved(), {
            "AI_CONNECTOR_ENABLED": True,
            "AI_CONNECTOR_URL": "http://ai-connector",
            "AI_CONNECTOR_PORT": 6667,
            "AI_CONNECTOR_TIMEOUT": 600,
            "AI_CONNECTOR_SSL_VERIFY_PEER": True,
            "AI_CONNECTOR_SSL_VERIFY_HOST": True,
            "AI_CONNECTOR_SSL_ALLOW_SELF_SIGNED": True,
            "AI_CONNECTOR_SSL_CAFILE": "/etc/ssl/ai-ca.pem",
            "AI_CONNECTOR_OPENAI_API_BASE": "http://llm.example.org:11434/v1",
            "AI_CONNECTOR_API_KEY": "secret-ai-connector-key",
            "AI_CONNECTOR_MODEL_ID": "gemma4:12b",
        })

    def test_the_setup_wizard_leaves_the_module_alone(self):
        """Its AI step has no section for the module, so it sends nothing for it."""
        self.assertEqual(self.save_providers().get_json(), {"ok": True})
        self.assertEqual(self.saved(), STORED)

    def test_the_main_settings_form_keeps_the_module_settings(self):
        self.client.post("/config", data={})
        self.assertEqual(self.saved(), STORED)

    def test_the_api_key_is_not_sent_to_another_endpoint(self):
        before = self.target.read_text()
        resp = self.save_providers(ai_connector={**POSTED, "openai_api_base": "https://api.openai.com/v1"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("API key again", resp.get_json()["error"])
        self.assertEqual(self.target.read_text(), before)

    def test_the_api_key_is_not_sent_to_another_module(self):
        """The module is handed the key, so it stays only while the module does."""
        before = self.target.read_text()
        for moved in ({"url": "https://elsewhere.example"}, {"port": "7000"}):
            with self.subTest(moved=moved):
                resp = self.save_providers(ai_connector={**POSTED, **moved})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("API key again", resp.get_json()["error"])
                self.assertEqual(self.target.read_text(), before)

    def test_a_key_entered_for_another_module_is_saved(self):
        moved = {**POSTED, "url": "https://elsewhere.example", "port": "7000", "api_key": "new-key"}
        self.assertEqual(self.save_providers(ai_connector=moved).get_json(), {"ok": True})
        saved = self.saved()
        self.assertEqual((saved["AI_CONNECTOR_URL"], saved["AI_CONNECTOR_PORT"], saved["AI_CONNECTOR_API_KEY"]),
                         ("https://elsewhere.example", 7000, "new-key"))

    def test_the_api_key_can_be_removed(self):
        self.save_providers(ai_connector={**POSTED, "remove_api_key": True})
        self.assertEqual(self.saved()["AI_CONNECTOR_API_KEY"], "")

    def test_an_unusable_port_or_timeout_is_refused(self):
        before = self.target.read_text()
        for field, value in (("port", "70000"), ("port", ""), ("timeout", "0"), ("timeout", "soon")):
            with self.subTest(**{field: value}):
                resp = self.save_providers(ai_connector={**POSTED, field: value})
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(self.target.read_text(), before)


    def test_the_connection_test_uses_the_settings_on_the_page(self):
        with mock.patch.object(config_page.ai_connector, "ping",
                               return_value={"ok": True, "message": "Connection OK"}) as ping:
            resp = self.client.post("/config/test-ai-connector", json=POSTED)
        self.assertEqual(resp.get_json(), {"ok": True, "message": "Connection OK"})
        settings = ping.call_args.args[0]
        self.assertEqual((settings["AI_CONNECTOR_MODEL_ID"], settings["AI_CONNECTOR_API_KEY"]),
                         ("gemma4:12b", "secret-ai-connector-key"))

    def test_the_connection_test_does_not_send_the_key_to_another_endpoint(self):
        with mock.patch.object(config_page.ai_connector, "ping") as ping:
            resp = self.client.post("/config/test-ai-connector",
                                    json={**POSTED, "openai_api_base": "https://elsewhere.example/v1"})
        self.assertEqual(resp.status_code, 400)
        ping.assert_not_called()


    def test_the_connection_test_does_not_send_the_key_to_another_module(self):
        with mock.patch.object(config_page.ai_connector, "ping") as ping:
            resp = self.client.post("/config/test-ai-connector", json={**POSTED, "url": "https://elsewhere.example"})
        self.assertEqual(resp.status_code, 400)
        ping.assert_not_called()


class Ping(unittest.TestCase):
    """The ping is the module's own use case, the one MISP's Test LLM button sends."""

    def ping(self, answer=None, **changed):
        response = mock.Mock(status_code=200)
        response.json.return_value = answer if answer is not None else {"results": {
            "ok": True, "endpoint": "http://llm.example.org:11434/v1", "latency_ms": 42,
            "model": {"name": "zsazsa-local:latest", "server": "ollama 0.32.4"}}}
        with mock.patch.object(ai_connector.requests, "post", return_value=response) as post:
            result = ai_connector.ping({**STORED, **changed})
        return result, post

    def test_a_working_module_names_the_model_and_endpoint(self):
        result, post = self.ping()
        self.assertEqual(result, {"ok": True, "message": "Connection OK: zsazsa-local:latest at "
                                  "http://llm.example.org:11434/v1 (ollama 0.32.4), 42 ms."})
        self.assertEqual(post.call_args.args[0], "http://ai-connector:6667/query")
        self.assertEqual(post.call_args.kwargs["json"], {
            "module": "ai_connector", "use_case": "ping", "timeout": 3000, "params": {
                "openai_api_base": "http://llm.example.org:11434/v1", "api_key": "secret-ai-connector-key",
                "model_id": "zsazsa-local:latest"}})

    def test_settings_left_empty_are_not_sent(self):
        """Sent empty, they would override what the module has in its own .env."""
        _, post = self.ping(AI_CONNECTOR_API_KEY="", AI_CONNECTOR_OPENAI_API_BASE="")
        self.assertEqual(post.call_args.kwargs["json"]["params"], {"model_id": "zsazsa-local:latest"})

    def test_the_certificate_settings_reach_requests(self):
        for changed, verify in (({}, False),
                                ({"AI_CONNECTOR_SSL_VERIFY_PEER": True}, True),
                                ({"AI_CONNECTOR_SSL_VERIFY_PEER": True, "AI_CONNECTOR_SSL_CAFILE": "/ca.pem"}, "/ca.pem")):
            with self.subTest(**changed):
                _, post = self.ping(**changed)
                self.assertEqual(post.call_args.kwargs["verify"], verify)

    def test_the_module_error_is_shown(self):
        result, _ = self.ping({"error": "LLM endpoint returned HTTP 404: model not found"})
        self.assertEqual(result, {"ok": False, "error": "The module answered: LLM endpoint returned HTTP 404: model not found"})

    def test_a_model_ollama_lists_with_its_tag_is_named(self):
        """Ollama takes "zsazsa-local" in a chat but lists it as "zsazsa-local:latest"."""
        error = ("model 'zsazsa-local' is not served by http://llm.example.org:11434/v1 "
                 "(['zsazsa-local:latest', 'gemma4:12b'])")
        result, _ = self.ping({"error": error}, AI_CONNECTOR_MODEL_ID="zsazsa-local")
        self.assertTrue(result["error"].startswith(
            "The endpoint lists the model as zsazsa-local:latest. Enter that as the model."), result)

    def test_a_model_that_is_not_there_at_all_gets_the_module_error_only(self):
        error = "model 'mistral' is not served by http://llm.example.org:11434/v1 (['zsazsa-local:latest'])"
        result, _ = self.ping({"error": error}, AI_CONNECTOR_MODEL_ID="mistral")
        self.assertEqual(result["error"], f"The module answered: {error}")

    def test_an_answer_that_is_not_an_object_is_reported(self):
        result, _ = self.ping(["ai_connector"])
        self.assertEqual(result, {"ok": False, "error": "http://ai-connector:6667/query did not answer as a misp-modules server."})

    def test_an_unreachable_module_is_reported(self):
        with mock.patch.object(ai_connector.requests, "post",
                               side_effect=ai_connector.requests.ConnectionError("connection refused")):
            self.assertEqual(ai_connector.ping(STORED), {"ok": False, "error": "connection refused"})

    def test_a_server_that_is_not_misp_modules_is_reported(self):
        """requests raises its JSONDecodeError, which is a RequestException too."""
        response = mock.Mock(status_code=200)
        response.json.side_effect = ai_connector.requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        with mock.patch.object(ai_connector.requests, "post", return_value=response):
            result = ai_connector.ping(STORED)
        self.assertEqual(result, {"ok": False, "error": "http://ai-connector:6667/query did not answer as a misp-modules server."})


class FeatureRow(unittest.TestCase):
    def page(self, enabled):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log"),
                                 MISP_SESSION_REDIRECT_TO_LOGIN=False,
                                 **{**STORED, "AI_CONNECTOR_ENABLED": enabled}), \
             mock.patch.object(config_page, "importlib"), \
             mock.patch.object(config_page, "_focus_point_choices", return_value=({}, {})), \
             mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
             mock.patch.object(config_page.misp_store, "webapp_key_shortcomings", return_value=None), \
             mock.patch.object(collection_cache, "start_worker"):
            return create_app().test_client().get("/config").get_data(as_text=True)

    def row(self, page):
        return re.search(r'<tr id="aic-feature-row"[^>]*>.*?</tr>', page, re.S).group(0)

    def test_the_row_is_greyed_out_while_the_module_is_disabled(self):
        self.assertIn("opacity-50", self.row(self.page(enabled=False)))
        self.assertNotIn("opacity-50", self.row(self.page(enabled=True)))

    def test_the_row_shows_the_module_model_and_cannot_be_changed_or_saved(self):
        row = self.row(self.page(enabled=True))
        self.assertIn('id="aic-feature-model">zsazsa-local:latest</td>', row)
        self.assertNotIn("<input", row)
        self.assertNotIn("<select", row)
        self.assertIn("AI-connector MISP module", row)
        self.assertNotIn("data-feature-id", row)

    def test_the_stored_api_key_is_not_in_the_page(self):
        self.assertNotIn(STORED["AI_CONNECTOR_API_KEY"], self.page(enabled=True))


if __name__ == "__main__":
    unittest.main()
