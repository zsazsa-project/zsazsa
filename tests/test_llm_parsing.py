"""What comes back from a model, and what the app does with it.

Two answers matter beyond a well-formed one: JSON wrapped in a markdown fence,
which local models produce often, and an empty answer, which is what a model
that runs out of tokens returns instead of an error.

    python -m unittest tests.test_llm_parsing
"""

import unittest
from unittest import mock

from analyser import llm


class JsonAnswers(unittest.TestCase):
    def test_a_fenced_object_is_read(self):
        for text in ('```json\n{"a": 1}\n```', '```\n{"a": 1}\n```', '  ```json \n{"a": 1}\n``` '):
            self.assertEqual(llm._json_object(text, "test"), {"a": 1}, text)

    def test_a_plain_object_still_works(self):
        self.assertEqual(llm._json_object('{"a": 1}', "test"), {"a": 1})

    def test_fences_inside_the_content_are_left_alone(self):
        answer = '{"reason": "the article shows ```code``` here"}'
        self.assertEqual(llm._json_object(answer, "test")["reason"],
                         "the article shows ```code``` here")

    def test_prose_a_list_and_nothing_are_all_refused(self):
        for text in ("Sure! Here you go.", "[1, 2]", "", "   "):
            self.assertIsNone(llm._json_object(text, "test"), text)

    def test_relevance_survives_a_fenced_answer(self):
        """Rejecting it would mark every article as not relevant."""
        fenced = '```json\n{"relevant": true, "reason": "in scope"}\n```'
        with mock.patch.object(llm, "_call", return_value=fenced), \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"):
            self.assertTrue(llm.check_relevance("article", {}, "B")["relevant"])

    def test_a_broken_relevance_answer_still_falls_back_to_not_relevant(self):
        with mock.patch.object(llm, "_call", return_value="no idea"), \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"):
            answer = llm.check_relevance("article", {}, "B")
        self.assertFalse(answer["relevant"])

    def test_overlap_detection_falls_back_to_lexical_matching(self):
        """An unparsable answer still has to flag the near-duplicate stories the
        briefing editor is asking about."""
        stories = [
            {"title": "Ransomware disruption at Antwerp port",
             "content": "Container terminal operations halted after ransomware"},
            {"title": "Antwerp port ransomware disruption update",
             "content": "Container terminal operations still halted"},
            {"title": "New banking trojan campaign",
             "content": "Credential theft against consumer accounts"},
        ]
        with mock.patch.object(llm, "_call", return_value="not JSON"), \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"):
            result = llm.detect_story_overlaps(stories)
        self.assertEqual(result["summary"], "Fallback overlap check used.")
        self.assertEqual([(o["a"], o["b"]) for o in result["overlaps"]], [(1, 2)])


class EmptyAnswers(unittest.TestCase):
    def test_flash_intel_files_nothing_when_the_model_returns_nothing(self):
        """Otherwise it creates an alert holding only its own heading, marks the
        source event handled, and can publish that to subscribers."""
        from analyser.products import flash_intel

        misp, misp_webapp = mock.MagicMock(), mock.MagicMock()
        event = mock.MagicMock(uuid="e" * 36, info="An event")
        with mock.patch.object(flash_intel, "_get_http_error", return_value=None), \
             mock.patch.object(flash_intel, "_get_reports", return_value=("article text", [])), \
             mock.patch.object(flash_intel.llm, "check_relevance",
                               return_value={"relevant": True, "matched_focus_points": []}), \
             mock.patch.object(flash_intel.llm, "generate_flash_intel", return_value="   "), \
             mock.patch.object(flash_intel, "tagger"):
            result = flash_intel.process(misp, misp_webapp, event, {})

        self.assertEqual(result["outcome"], "error")
        misp_webapp.add_event.assert_not_called()
        misp_webapp.add_event_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
