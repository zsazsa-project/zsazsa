"""The settings of a model feature that took over from another.

The relevance call for the alerts and the briefing replaced the alerts' check.
An administrator who sent that check to a local model did so to keep the
articles in the house; after the update, the new call must not quietly go to
OpenAI. It starts with the old one's provider, model and temperature, but not
its prompt, which asked for a different answer, and its own settings win once
they are saved.

A feature nobody chose a provider for, such as one an update adds, goes to the
default provider of the AI tab, as README says, not to OpenAI.

    python -m unittest tests.test_ai_config
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from core import ai_config


class TakesOver(unittest.TestCase):
    def load(self, saved, feature="judge_relevance", default="openai"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "ai_features.json"
        path.write_text(json.dumps(saved))
        with mock.patch.object(ai_config, "_AI_CONFIG_FILE", path), \
             mock.patch.object(config, "LLM_DEFAULT_PROVIDER", default, create=True):
            return ai_config.load()[feature]

    def test_it_starts_with_the_provider_and_model_of_the_check_it_replaced(self):
        feature = self.load({"check_relevance": {"provider": "local", "model": "qwen3", "temperature": 0.1,
                                                 "prompt": "flash_intel_relevance.md"}})
        self.assertEqual((feature["provider"], feature["model"], feature["temperature"]), ("local", "qwen3", 0.1))
        self.assertEqual(feature["prompt"], "analyser_relevance.md")

    def test_its_own_settings_win_once_saved(self):
        feature = self.load({"check_relevance": {"provider": "local"},
                             "judge_relevance": {"provider": "openai", "model": "gpt-4o-mini"}})
        self.assertEqual(feature["provider"], "openai")

    def test_without_either_it_has_the_defaults(self):
        self.assertEqual(self.load({})["provider"], "openai")

    def test_a_feature_nobody_set_goes_to_the_default_provider(self):
        """Story comparison is new: with a local default it went to OpenAI."""
        saved = {"summarise_report": {"provider": "openai"}}
        self.assertEqual(self.load(saved, "compare_stories", default="local")["provider"], "local")
        self.assertEqual(self.load(saved, "summarise_report", default="local")["provider"], "openai")


if __name__ == "__main__":
    unittest.main()
