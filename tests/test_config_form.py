"""Saving the configuration must only change what was actually submitted.

The page rewrites the whole config module from the posted form, so a field the
form did not carry, a page left open across an upgrade, a tab whose inputs never
rendered, would otherwise be written back as an empty string, an empty list or
False. That silently drops MISP keys, SMTP passwords and TLS switches.

    python -m unittest tests.test_config_form
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

import config as _config
from webapp.routes import config_page


def _keyvals(path):
    namespace = {}
    exec(compile(Path(path).read_text(), str(path), "exec"), namespace)
    return {k: v for k, v in namespace.items() if k.isupper()}


class ConfigSave(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        patches = [
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
            mock.patch.object(config_page.misp_session, "derive_cookie_name", return_value=""),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        return _keyvals(self.target)

    def full_form(self):
        """Everything the rendered page posts, unchanged."""
        return {k: ("true" if v else "false") if isinstance(v, bool) else str(v)
                for k, v in config_page._read().items() if isinstance(v, (str, int, bool))}

    def test_an_empty_post_changes_nothing(self):
        before = self.saved()
        self.client.post("/config", data={})
        self.assertEqual(self.saved(), before)

    def test_a_post_missing_the_credentials_keeps_them(self):
        before = self.saved()
        form = self.full_form()
        for gone in ("MISP_WEBAPP_KEY", "SMTP_PASSWORD", "SMTP_USE_TLS", "SCRAPER_MARKER_TAG"):
            form.pop(gone, None)
        self.client.post("/config", data=form)

        after = self.saved()
        for kept in ("MISP_WEBAPP_KEY", "SMTP_PASSWORD", "SMTP_USE_TLS", "SCRAPER_MARKER_TAG"):
            self.assertEqual(after[kept], before[kept], kept)

    def test_the_scraper_queue_settings_survive_a_save(self):
        """They are edited under Collection sources, so this form has no inputs
        for them, and the file is rewritten whole on every save. Left out of the
        payload they fell back to the built-in defaults, quietly pointing the
        newsletter imports at a Redis nobody listens on.

        The values below are all deliberately unlike the defaults, so the check
        cannot pass just because the developer's own config matches them."""
        configured = {
            "SCRAPER_REDIS_HOST": "10.0.0.9",
            "SCRAPER_REDIS_PORT": 6380,
            "SCRAPER_REDIS_PASSWORD": "s3cret",
            "SCRAPER_REDIS_CHANNEL": "scraper-urls",
        }
        with mock.patch.multiple(_config, **configured):
            form = self.full_form()
            for key in configured:
                form.pop(key, None)
            self.client.post("/config", data=form)

        after = self.saved()
        for key, value in configured.items():
            self.assertEqual(after[key], value, key)

    def test_the_lists_survive_a_post_that_omits_them(self):
        before = self.saved()
        form = self.full_form()   # the list fields are textareas, never in full_form
        self.client.post("/config", data=form)

        after = self.saved()
        for kept in ("PRODUCT_TYPES", "FOCUS_POINTS_SECTORS", "THREAT_ACTOR_TYPES",
                     "RECOMMENDED_ACTIONS_IMMEDIATE"):
            self.assertEqual(after[kept], before[kept], kept)

    def test_edits_and_deliberate_clearing_both_land(self):
        form = self.full_form()
        form["BRAND_COMPANY"] = "New Name"
        form["SMTP_USERNAME"] = ""
        form["SMTP_USE_TLS"] = "false"
        form["PRODUCT_TYPES"] = "Flash intel alert\nDaily threat briefing"
        self.client.post("/config", data=form)

        after = self.saved()
        self.assertEqual(after["BRAND_COMPANY"], "New Name")
        self.assertEqual(after["SMTP_USERNAME"], "")
        self.assertFalse(after["SMTP_USE_TLS"])
        self.assertEqual(after["PRODUCT_TYPES"], ["Flash intel alert", "Daily threat briefing"])

    def test_every_key_survives_a_save(self):
        before = self.saved()
        self.client.post("/config", data=self.full_form())
        self.assertEqual(set(self.saved()), set(before))


if __name__ == "__main__":
    unittest.main()
