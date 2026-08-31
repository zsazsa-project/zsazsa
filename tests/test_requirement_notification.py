"""The markdown a PIR or GIR notification is built from.

This is what a stakeholder actually receives, so the scope has to read as prose
rather than as the lists it is stored in, and it has to cover the same scope
dimensions the requirement holds.

    python -m unittest tests.test_requirement_notification
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp.routes import requirements


def _pir(**overrides):
    fields = {
        "pir_id": "PIR-001", "status": "Active", "priority": "Must have",
        "question": "Are our hauliers targeted?", "context": "",
        "decision_supported": "", "decision_maker": [], "consequence": [],
        "deadline": "", "priority_justification": "", "distribution": [],
        "geographic_scope": [], "sectors": [], "threat_actors": [], "threat_types": [],
        "technology": [], "vendor": [], "incident": [], "campaign": [],
        "mitre_attack_techniques": [],
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _markdown(pir):
    with mock.patch.object(requirements.misp_store, "list_stakeholders", return_value=[]):
        return requirements._pir_markdown(pir)


class PirMarkdown(unittest.TestCase):
    def test_a_consequence_reads_as_text_not_as_a_list(self):
        """It is stored as a list, and interpolating it whole put a Python repr
        in front of the stakeholder."""
        md = _markdown(_pir(decision_supported="Patch window",
                            consequence=["Delayed response", "Blind spot"]))
        self.assertIn("**Consequences if unanswered:** Delayed response, Blind spot", md)
        self.assertNotIn("[", md)

    def test_a_single_consequence_is_not_pluralised(self):
        md = _markdown(_pir(decision_supported="Patch window", consequence=["Delayed response"]))
        self.assertIn("**Consequence if unanswered:** Delayed response", md)

    def test_the_scope_section_covers_every_dimension(self):
        md = _markdown(_pir(geographic_scope=["Belgium"], technology=["Fortinet VPN"],
                            mitre_attack_techniques=["Exploit Public-Facing Application - T1190"]))
        self.assertIn("## Scope", md)
        self.assertIn("**Geography:** Belgium", md)
        self.assertIn("**Technology:** Fortinet VPN", md)
        self.assertIn("**ATT&CK techniques:** Exploit Public-Facing Application - T1190", md)

    def test_a_requirement_without_scope_has_no_scope_section(self):
        self.assertNotIn("## Scope", _markdown(_pir()))

    def test_the_question_and_id_are_always_there(self):
        md = _markdown(_pir())
        self.assertTrue(md.startswith("# PIR-001: Priority Intelligence Requirement"))
        self.assertIn("Are our hauliers targeted?", md)


if __name__ == "__main__":
    unittest.main()
