"""Regression tests for webapp.matching term matching.

Pins the short-term false positives that the half-applied _COMPACT_MIN guard
used to allow (e.g. "ai" matching "maintain"). Runs on the standard library:

    python -m unittest tests.test_matching
"""

import unittest
from types import SimpleNamespace

from webapp.matching import (
    _compact,
    _matches_term,
    _norm,
    match_event_to_requirement,
    term_in_text,
)


def _match(term: str, haystack: str) -> bool:
    n = _norm(term)
    return _matches_term(n, _compact(n), _norm(haystack))


def _req(**scope) -> SimpleNamespace:
    """Build a minimal requirement namespace with empty scope by default."""
    base = {
        "uuid": "req-uuid",
        "pir_id": "PIR-001",
        "question": "Test question",
        "out_of_scope": [],
        "geographic_scope": [],
        "sectors": [],
        "threat_actors": [],
        "threat_types": [],
        "technology": [],
        "vendor": [],
        "incident": [],
        "campaign": [],
        "mitre_attack_techniques": [],
    }
    base.update(scope)
    return SimpleNamespace(**base)


def _event(info="", tags=None, galaxy_names=None) -> dict:
    return {
        "uuid": "ev-uuid",
        "info": info,
        "tags": tags or [],
        "galaxy_names": galaxy_names or [],
    }


class ShortTermMatching(unittest.TestCase):
    def test_short_term_does_not_match_inside_word(self):
        self.assertFalse(_match("ai", "maintain the system"))
        self.assertFalse(_match("al", "israel attacks"))
        self.assertFalse(_match("is", "thistle"))

    def test_short_term_matches_whole_word(self):
        self.assertTrue(_match("ai", "using ai tooling"))
        self.assertTrue(_match("is", "this is fine"))

    def test_short_term_with_punctuation(self):
        # Lookarounds keep trailing-punctuation terms working where \b would not.
        self.assertTrue(_match("c++", "c++ programming guide"))


class LongTermMatching(unittest.TestCase):
    def test_long_term_substring_and_compact(self):
        self.assertTrue(_match("Agent Tesla", "agent tesla seen"))
        self.assertTrue(_match("Agent Tesla", "agenttesla loader"))

    def test_long_term_matches_galaxy_tag_text(self):
        self.assertTrue(_match("phishing", 'misp-galaxy:rsit=fraud:phishing'))

    def test_no_spurious_match(self):
        self.assertFalse(_match("ransomware", "no match here"))


class TermInText(unittest.TestCase):
    """The scope-preview matcher reuses the whole-word rules."""

    def test_short_term_does_not_match_inside_word(self):
        # "gas" (energy) must not match Dutch "gasten" (guests).
        title = "Gasten honderd Belgische hotels doelwit van phishingaanvallen"
        self.assertFalse(term_in_text("gas", title))

    def test_short_term_matches_whole_word(self):
        self.assertTrue(term_in_text("gas", "gas pipeline outage in Belgium"))

    def test_empty_term(self):
        self.assertFalse(term_in_text("", "anything"))


class MatchEventToRequirement(unittest.TestCase):
    def test_short_technology_term_matches_only_as_whole_word(self):
        req = _req(technology=["ai"])
        self.assertIsNotNone(match_event_to_requirement(_event(info="Using AI platform"), req, "pir"))
        self.assertIsNone(match_event_to_requirement(_event(info="Maintain the platform"), req, "pir"))

    def test_exclusion_term_blocks_an_otherwise_matching_event(self):
        # Scope matches on "breach", but the out_of_scope term "acme" also
        # matches the title, so the requirement is skipped.
        req = _req(technology=["breach"], out_of_scope=["acme"])
        self.assertIsNone(match_event_to_requirement(_event(info="Acme corp breach"), req, "pir"))
        # Same scope, no exclusion hit -> matches.
        req_ok = _req(technology=["breach"])
        self.assertIsNotNone(match_event_to_requirement(_event(info="Acme corp breach"), req_ok, "pir"))

    def test_galaxy_value_match_on_threat_actor(self):
        req = _req(threat_actors=["APT28"])
        ev = _event(info="incident", galaxy_names=["APT28"])
        m = match_event_to_requirement(ev, req, "pir")
        self.assertIsNotNone(m)
        self.assertEqual(m.req_id, "PIR-001")


class AttackTechniqueScope(unittest.TestCase):
    """A technique put in a requirement's scope flags events the same way the
    other scope dimensions do. It was the one documented scope element the
    matcher did not read, so a PIR scoped on a technique matched nothing."""

    TECHNIQUE = "Exploit Public-Facing Application - T1190"

    def match(self, event):
        return match_event_to_requirement(event, _req(mitre_attack_techniques=[self.TECHNIQUE]), "pir")

    def test_a_galaxy_cluster_on_the_event_matches(self):
        m = self.match(_event(info="Edge appliance abused", galaxy_names=[self.TECHNIQUE]))
        self.assertIsNotNone(m)
        self.assertEqual(m.evidence[0].label, "ATT&CK technique")

    def test_the_galaxy_tag_matches(self):
        tag = f'misp-galaxy:mitre-attack-pattern="{self.TECHNIQUE}"'
        self.assertIsNotNone(self.match(_event(info="Edge appliance abused", tags=[tag])))

    def test_another_technique_does_not_match(self):
        self.assertIsNone(self.match(_event(info="Phishing wave", galaxy_names=["Phishing - T1566"])))


if __name__ == "__main__":
    unittest.main()
