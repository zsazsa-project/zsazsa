"""The QA check against the source: what the model is told.

The draft it reviews opens with the product's own ID and date, which no source
mentions, and the check reported them as fabricated. The prompt says they are
the product's own and not to be reported. No LLM is called.

    python -m unittest tests.test_qa_review_prompt
"""

import unittest
from unittest import mock

from analyser import llm


class QaReviewPrompt(unittest.TestCase):
    def test_the_products_own_id_and_date_are_not_findings(self):
        with mock.patch.object(llm, "_call", return_value='{"verdict": "pass", "findings": []}') as call:
            llm.review_product_draft("Flash intel alert", "**ID:** FIA-10486\n**Date:** 2026-11-15 00:00 UTC", "An article.")
        system = call.call_args[0][0]
        self.assertIn("its ID (such as FIA-10486 or VEA-10218), its date and time", system)
        self.assertIn("Never report them", system)


if __name__ == "__main__":
    unittest.main()
