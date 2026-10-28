"""Vulnerability advisories keep every field through a review-state change.

Submitting, approving, publishing and rejecting an advisory write its object
again whole. The review-state change built that write from a hand-written list
of fields that had no summary, CVSS, CWE or context tags, so publishing deleted
them, and the PDF and the mail of a published advisory came out without them
(issue #69). The markdown that is mailed and stored as the MISP report also
never had the analyst's summary, CVSS or CWE.

Nothing is written to MISP here.

    python -m unittest tests.test_vea_fields
"""

import json
import unittest
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

SOURCE_UUID = "8bff3417-1af2-4ccb-81be-26a8bc99605f"
VEA_UUID = "a" * 36


def _stored_vea(**changes):
    """An advisory as it is stored, with every field filled in, since an empty
    value is never written and a dropped one would go unnoticed."""
    fields = dict(
        vea_id="VEA-00210", cve_id="CVE-2026-31431", title="Linux kernel algif_aead",
        summary="In the Linux kernel, crypto: algif_aead reverts to operating out-of-place.",
        cvss="7.8 (HIGH)", cwe="CWE-669; CWE-1288", tlp="red", author="koen",
        audience="Vulnerability Management", affected_product="Linux kernel",
        affected_versions="6.1 < 6.1.120", fixed_version="6.1.120", exposure="Internal servers",
        observed_exploitation="Active exploitation reported", exploit_availability="PoC public",
        exploitation_complexity="Low", threat_actor_interest="High", cisa_kev="Yes",
        source_description="Vendor advisory", source_reliability="B", information_credibility="2",
        worst_case="Root on every server.", most_likely="Local privilege escalation.",
        immediate_actions=["Patch the kernel"], patch_sla_internet="48h", patch_sla_internal="7d",
        target_patch_version="6.1.120", exploitation_indicators=["Unexpected root shells"],
        detection_rules=["sigma: kernel_lpe"], references=["https://example.org/advisory"],
        feedback_deadline=date(2026, 11, 1), review_state=misp_store.VEA_REVIEW_PENDING,
        rejection_reason="An earlier reason.", source_event_uuids=[SOURCE_UUID],
        source_event_hints={SOURCE_UUID: "scraper"}, linked_pir_uuid="p" * 36,
        context_tags=["tlp:red"], analyser_reason="The event names CVE-2026-31431.", creator="koen",
        approved_by="an.earlier.reviewer@example.org",
    )
    fields.update(changes)
    return fields


def _relation(field):
    # The list of source events is kept under the name the single UUID used to have.
    return "source-event-uuid" if field == "source_event_uuids" else field.replace("_", "-")


def _event(fields):
    event = MISPEvent()
    event.id = 210
    event.uuid = VEA_UUID
    event.date = "2026-10-15"
    event.add_object(misp_store._vea_obj(dict(fields)))
    return event


class VeaFieldList(unittest.TestCase):
    """_VEA_FIELDS is what a review-state change rewrites the object from, so it
    has to stay level with what the object holds."""

    def _relations(self):
        return {_relation(f) for f in misp_store._VEA_FIELDS}

    def test_it_names_exactly_what_the_object_is_written_with(self):
        written = {attr.object_relation for attr in misp_store._vea_obj(_stored_vea()).attributes}
        self.assertEqual(written, self._relations())

    def test_the_misp_object_template_declares_the_same_attributes(self):
        definition = json.loads(
            (Path(misp_store.__file__).parent / "misp_objects" / "objects"
             / "zsazsa-vea" / "definition.json").read_text()
        )
        self.assertEqual(set(definition["attributes"]), self._relations())

    def test_what_is_written_reads_back_the_same(self):
        stored = _stored_vea()
        vea = misp_store._vea_ns(_event(stored))
        for field in misp_store._VEA_FIELDS:
            self.assertEqual(getattr(vea, field), stored[field], field)


class ReviewStateKeepsTheStoredFields(unittest.TestCase):
    def _rewritten_object(self, state):
        event = _event(_stored_vea())
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_sync_object_attributes") as sync, \
             mock.patch.object(misp_store, "_write_vea_report"), \
             mock.patch.object(misp_store.misp_session, "current_user_email",
                               return_value="reviewer@example.org"):
            misp_store.set_vea_review_state(VEA_UUID, state)
        return sync.call_args.args[3]

    def test_publishing_drops_nothing(self):
        obj = self._rewritten_object(misp_store.VEA_REVIEW_APPROVED)
        for field in misp_store._VEA_FIELDS:
            relation = _relation(field)
            self.assertIsNotNone(misp_store._obj_attr(obj, relation), f"publishing dropped {relation}")

    def test_the_summary_cvss_and_cwe_survive_every_state_change(self):
        for state in misp_store.VEA_REVIEW_STATES:
            with self.subTest(state=state):
                obj = self._rewritten_object(state)
                self.assertEqual(
                    [misp_store._obj_attr(obj, r) for r in ("summary", "cvss", "cwe")],
                    [_stored_vea()[f] for f in ("summary", "cvss", "cwe")])

    def test_publishing_records_the_new_state_and_approver(self):
        obj = self._rewritten_object(misp_store.VEA_REVIEW_APPROVED)
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), misp_store.VEA_REVIEW_APPROVED)
        self.assertEqual(misp_store._obj_attr(obj, "approved-by"), "reviewer@example.org")


class Markdown(unittest.TestCase):
    """The mail, the MISP report and the chat posts of an advisory."""

    def markdown(self, **changes):
        vea = SimpleNamespace(**_stored_vea(**changes), created_at=datetime(2026, 10, 15))
        return misp_store.render_vea_markdown(vea)

    def summary(self, markdown):
        return markdown.split("## Summary")[1].split("---")[0]

    def test_the_summary_is_the_analysts(self):
        summary = self.summary(self.markdown())
        self.assertIn("algif_aead reverts to operating out-of-place", summary)
        self.assertNotIn("Active exploitation reported", summary)

    def test_cvss_and_cwe_are_in_the_header(self):
        markdown = self.markdown()
        self.assertIn("**CVSS:** 7.8 (HIGH)", markdown)
        self.assertIn("**CWE:** CWE-669; CWE-1288", markdown)

    def test_an_advisory_without_a_summary_names_the_cve_and_product(self):
        self.assertIn("CVE-2026-31431 affects Linux kernel.", self.summary(self.markdown(summary="")))

    def test_the_summary_has_no_action_taken_from_the_risk_assessment(self):
        """An advisory has no action required. The summary showed the most
        likely case under that name, which the risk assessment already has."""
        markdown = self.markdown()
        self.assertNotIn("Action required", markdown)
        self.assertNotIn("Local privilege escalation.", self.summary(markdown))
        self.assertIn("**Most likely:** Local privilege escalation.", markdown)


if __name__ == "__main__":
    unittest.main()
