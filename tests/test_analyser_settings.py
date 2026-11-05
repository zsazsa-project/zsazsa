"""The analyser's settings, on their own tab of Settings, "Analyser".

Each is a config key with a default, read when it is used, so a value saved on
the page applies to the next run. A value posted out of its range, or one that
cannot be read, takes the default; one the form did not post keeps what is
configured. Every one is in the config example and survives a save of the page,
and a pull score that meets a push score is not saved. tests.test_settings_page
pins how the page lays them out.

    python -m unittest tests.test_analyser_settings
"""

import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask, get_flashed_messages

import config
from analyser import settings
from webapp.routes import config_page

MAX_STORIES = next(s for s in settings.ALL if s.key == "ANALYSER_BRIEFING_MAX_STORIES")
LIMIT = next(s for s in settings.ALL if s.key == "ANALYSER_ALERT_MIN_TIMELINESS")
SCORE = next(s for s in settings.ALL if s.key == "ANALYSER_SAME_STORY_SCORE")
SWITCH = next(s for s in settings.ALL if s.key == "ANALYSER_ADVISORY_KEV_ONLY")


class Values(unittest.TestCase):
    def test_a_setting_is_read_from_config_and_has_its_default_without(self):
        with mock.patch.object(config, "ANALYSER_BRIEFING_MAX_STORIES", 20, create=True):
            self.assertEqual(settings.get("ANALYSER_BRIEFING_MAX_STORIES"), 20)
        with mock.patch.dict(vars(config)):
            vars(config).pop("ANALYSER_BRIEFING_MAX_STORIES", None)
            self.assertEqual(settings.get("ANALYSER_BRIEFING_MAX_STORIES"), 15)

    def test_a_posted_value_is_read_as_its_kind(self):
        self.assertEqual(settings.parse(MAX_STORIES, "20"), 20)
        self.assertEqual(settings.parse(SCORE, "0.8"), 0.8)
        self.assertIs(settings.parse(SWITCH, "true"), True)
        self.assertIs(settings.parse(SWITCH, "false"), False)
        self.assertEqual(settings.parse(LIMIT, ""), "")

    def test_one_out_of_range_or_unreadable_takes_the_default(self):
        for raw in ("500", "0", "many"):
            with self.subTest(raw=raw):
                self.assertEqual(settings.parse(MAX_STORIES, raw), 15)
        self.assertEqual(settings.parse(LIMIT, "extreme"), "high")

    def test_one_not_posted_keeps_what_is_configured(self):
        with mock.patch.object(config, "ANALYSER_BRIEFING_MAX_STORIES", 20, create=True):
            self.assertEqual(settings.parse(MAX_STORIES, None), 20)

    def test_every_one_is_in_the_config_example(self):
        example = Path("config/__init__.py.example").read_text()
        for setting in settings.ALL:
            with self.subTest(key=setting.key):
                self.assertRegex(example, rf"(?m)^{re.escape(setting.key)} = {re.escape(repr(setting.default))}$")


class Conflicts(unittest.TestCase):
    def values(self, **changes):
        return {"ANALYSER_PUSH_ALERT": "very-high", "ANALYSER_PUSH_BRIEFING": "high", "ANALYSER_PULL": "low",
                **changes}

    def test_a_pull_lower_than_both_pushes_goes(self):
        self.assertEqual(settings.conflict(self.values()), "")

    def test_a_score_that_would_push_and_pull_does_not(self):
        """With both at high, an analyst's high was read as pulled, after the
        scraper had been asked for it as pushed."""
        for changes in ({"ANALYSER_PULL": "high"}, {"ANALYSER_PUSH_BRIEFING": "low"},
                        {"ANALYSER_PUSH_ALERT": "moderate", "ANALYSER_PULL": "very-high"}):
            with self.subTest(**changes):
                self.assertIn("has to be lower", settings.conflict(self.values(**changes)))


class SettingsPage(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()
        for patcher in (mock.patch.object(config_page, "_CONFIG_FILE", self.target),
                        mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
                        mock.patch.object(config_page, "importlib"),
                        mock.patch.object(config_page.audit, "record"),
                        mock.patch.object(config_page.misp_session, "derive_cookie_name", return_value=""),
                        mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        namespace = {}
        exec(compile(self.target.read_text(), str(self.target), "exec"), namespace)
        return namespace

    def test_a_value_posted_is_saved_and_the_others_keep_theirs(self):
        self.client.post("/config", data={"ANALYSER_BRIEFING_MAX_STORIES": "20",
                                          "ANALYSER_ALERT_MIN_TIMELINESS": "moderate"})
        saved = self.saved()
        self.assertEqual((saved["ANALYSER_BRIEFING_MAX_STORIES"], saved["ANALYSER_ALERT_MIN_TIMELINESS"]),
                         (20, "moderate"))
        for setting in settings.ALL:
            if setting.key not in ("ANALYSER_BRIEFING_MAX_STORIES", "ANALYSER_ALERT_MIN_TIMELINESS"):
                self.assertEqual(saved[setting.key], settings.get(setting.key), setting.key)

    def test_a_pull_that_meets_a_push_is_not_saved(self):
        before = self.target.read_text()
        with self.client:
            self.client.post("/config", data={"ANALYSER_PULL": "high", "ANALYSER_PUSH_BRIEFING": "high",
                                              "ANALYSER_BRIEFING_MAX_STORIES": "20"})
            self.assertIn("has to be lower", " ".join(get_flashed_messages()))
        self.assertEqual(self.target.read_text(), before)


if __name__ == "__main__":
    unittest.main()
