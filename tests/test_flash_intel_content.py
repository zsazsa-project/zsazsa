"""What a flash intel alert carries beyond its fixed fields, and what survives.

The write-up and the intelligence gaps are free Markdown an analyst may or may
not fill in, and attachments are files added after the alert exists. An empty
field is left out entirely: the markdown here is what the e-mail, the Mattermost
post and the report written back to MISP are all built from, so "unspecified"
repeated four times is noise every reader pays for.

The last group is the one that bites. Changing an alert's review state rebuilds
its whole MISP object from a payload assembled by hand, so a field that payload
forgets is destroyed at the moment the alert is published, and the notification
that goes out is built from whatever survived.

    python -m unittest tests.test_flash_intel_content
"""

import json
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store
from webapp.utils import human_size


def _fia(**over):
    """An alert with nothing optional filled in, as a fresh draft looks."""
    base = dict(
        fia_id="FIA-00042", title="Energy sector intrusion", audience="SOC", tlp="amber",
        summary="Something happened.", action_required="Patch now.",
        what_happened=["A VPN account was abused."],
        source_description="OSINT", source_reliability="B", information_credibility="2",
        likely_impact="", affected_assets="", actor_types=[], actor_context="",
        write_up="", intelligence_gaps="",
        mitre_attack_techniques=[], geographic_scope=[], sectors=[], threat_actors=[],
        threat_types=[], technology=[], vendor=[], incident=[], campaign=[],
        actions_immediate=[], actions_near_term=[], mitre_techniques=[],
        hunting_hypotheses=[], external_references=[], feedback_deadline=None,
        author="koen", source_event_uuids=[], source_event_hints={},
        attachments=[], created_at=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _attachment(filename="report.pdf", content_type="application/pdf", size=20841):
    return SimpleNamespace(uuid="a" * 36, filename=filename,
                           content_type=content_type, size=size)


class WhyItMattersIsOnlyWhatWasFilledIn(unittest.TestCase):
    def test_an_alert_with_no_assessment_has_no_section_at_all(self):
        markdown = misp_store.render_fia_markdown(_fia())
        self.assertNotIn("## Why it matters", markdown)
        self.assertNotIn("unspecified", markdown)

    def test_only_the_filled_assessments_are_listed(self):
        markdown = misp_store.render_fia_markdown(
            _fia(likely_impact="Loss of availability", actor_types=["Cybercriminals"]))
        self.assertIn("- **Likely impact:** Loss of availability", markdown)
        self.assertIn("- **Threat actor types:** Cybercriminals", markdown)
        self.assertNotIn("Affected assets", markdown)
        self.assertNotIn("Threat actor context", markdown)

    def test_a_write_up_alone_still_opens_the_section(self):
        markdown = misp_store.render_fia_markdown(_fia(write_up="The actor pivoted."))
        self.assertIn("## Why it matters", markdown)
        self.assertIn("The actor pivoted.", markdown)

    def test_the_write_up_follows_the_bullets_it_expands_on(self):
        markdown = misp_store.render_fia_markdown(
            _fia(likely_impact="Loss of availability", write_up="## Detail\n\nMore."))
        self.assertLess(markdown.index("Loss of availability"), markdown.index("## Detail"))

    def test_a_write_up_of_only_whitespace_counts_as_empty(self):
        self.assertNotIn("## Why it matters", misp_store.render_fia_markdown(_fia(write_up="  \n ")))


class AssessmentRows(unittest.TestCase):
    """The alert page, the review queue, the PDF and the markdown all show the
    same four assessments, so they take the decision from one place."""

    def test_only_filled_assessments_come_back_and_keep_their_order(self):
        rows = misp_store.fia_assessment_rows(
            _fia(affected_assets="Substation relays", likely_impact="Loss of availability"))
        self.assertEqual(rows, [("Likely impact", "Loss of availability"),
                                ("Affected assets", "Substation relays")])

    def test_a_list_field_is_joined_for_display(self):
        rows = misp_store.fia_assessment_rows(_fia(actor_types=["Cybercriminals", "Hacktivists"]))
        self.assertEqual(rows, [("Threat actor types", "Cybercriminals, Hacktivists")])

    def test_an_alert_with_no_assessment_has_no_rows(self):
        self.assertEqual(misp_store.fia_assessment_rows(_fia()), [])

    def test_the_markdown_is_built_from_the_same_rows(self):
        fia = _fia(likely_impact="Loss of availability", actor_types=["Cybercriminals"])
        markdown = misp_store.render_fia_markdown(fia)
        for label, value in misp_store.fia_assessment_rows(fia):
            self.assertIn(f"- **{label}:** {value}", markdown)


class IntelligenceGaps(unittest.TestCase):
    def test_gaps_are_a_section_of_their_own(self):
        markdown = misp_store.render_fia_markdown(
            _fia(intelligence_gaps="The initial access vector is unknown."))
        self.assertIn("## Intelligence gaps", markdown)
        self.assertIn("The initial access vector is unknown.", markdown)

    def test_nothing_is_written_when_there_are_none(self):
        self.assertNotIn("## Intelligence gaps", misp_store.render_fia_markdown(_fia()))


class AttachmentsAreNamed(unittest.TestCase):
    """Channels that cannot carry a file still have to say one exists."""

    def test_each_attachment_is_listed_with_its_type_and_size(self):
        markdown = misp_store.render_fia_markdown(_fia(attachments=[
            _attachment(),
            _attachment(filename="iocs.csv", content_type="text/csv", size=812),
        ]))
        self.assertIn("- report.pdf (application/pdf, 20.4 KB)", markdown)
        self.assertIn("- iocs.csv (text/csv, 812 B)", markdown)

    def test_no_section_without_attachments(self):
        self.assertNotIn("## Attachments", misp_store.render_fia_markdown(_fia()))

    def test_an_attachment_of_unrecorded_type_still_reads(self):
        markdown = misp_store.render_fia_markdown(
            _fia(attachments=[_attachment(content_type="", size=0)]))
        self.assertIn("- report.pdf (unknown type, 0 B)", markdown)


class HumanSize(unittest.TestCase):
    def test_it_scales_to_the_unit_that_reads(self):
        self.assertEqual(human_size(0), "0 B")
        self.assertEqual(human_size(812), "812 B")
        self.assertEqual(human_size(20841), "20.4 KB")
        self.assertEqual(human_size(5 * 1024 * 1024), "5.0 MB")
        self.assertEqual(human_size(3 * 1024 ** 3), "3.0 GB")

    def test_it_stops_at_gigabytes_rather_than_running_off_the_units(self):
        self.assertEqual(human_size(2048 * 1024 ** 3), "2048.0 GB")

    def test_a_size_that_was_never_recorded_says_so(self):
        self.assertEqual(human_size(None), "unknown size")


class AttachmentMetadata(unittest.TestCase):
    """MISP hands back an attachment's name but neither its size nor its type, so
    both are recorded in the comment when the file is stored."""

    def test_the_comment_carries_the_type_and_size(self):
        comment = misp_store._fia_attachment_comment("application/pdf", 20841)
        self.assertTrue(comment.startswith(misp_store.FIA_ATTACHMENT_COMMENT))
        self.assertEqual(misp_store._parse_fia_attachment_comment(comment),
                         ("application/pdf", 20841))

    def test_a_file_the_browser_did_not_type_falls_back(self):
        comment = misp_store._fia_attachment_comment("", 10)
        self.assertEqual(misp_store._parse_fia_attachment_comment(comment),
                         ("application/octet-stream", 10))

    def test_a_comment_from_before_the_metadata_existed_still_parses(self):
        self.assertEqual(
            misp_store._parse_fia_attachment_comment(misp_store.FIA_ATTACHMENT_COMMENT),
            ("", 0))

    def test_only_zsazsa_attachments_are_listed(self):
        """An analyst can attach files to the event in MISP directly; those are
        not part of the alert and must not be mailed out with it."""
        event = SimpleNamespace(attributes=[
            SimpleNamespace(uuid="a", value="report.pdf", deleted=False,
                            comment=misp_store._fia_attachment_comment("application/pdf", 12)),
            SimpleNamespace(uuid="b", value="unrelated.txt", deleted=False, comment="a note"),
            SimpleNamespace(uuid="c", value="gone.pdf", deleted=True,
                            comment=misp_store._fia_attachment_comment("application/pdf", 12)),
        ])
        self.assertEqual([a.filename for a in misp_store._fia_attachments(event)], ["report.pdf"])


class FetchingTheFile(unittest.TestCase):
    """One fetch serves both the RFI and the flash intel download routes.

    A plain attribute fetch describes an attachment without carrying it, so the
    search has to ask for the file explicitly.
    """

    def _misp(self, found):
        misp = mock.MagicMock()
        misp.search.return_value = found
        return misp

    def _attr(self, data=b"%PDF", comment=""):
        return SimpleNamespace(uuid="a" * 36, value="report.pdf",
                               comment=comment, data=BytesIO(data))

    def test_the_search_asks_misp_to_send_the_file(self):
        misp = self._misp([self._attr()])
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            misp_store.fetch_attachment("a" * 36)
        self.assertTrue(misp.search.call_args.kwargs["with_attachments"])
        self.assertEqual(misp.search.call_args.kwargs["controller"], "attributes")

    def test_an_attachment_that_is_not_there_is_an_error(self):
        with mock.patch.object(misp_store, "_misp", return_value=self._misp([])):
            with self.assertRaises(RuntimeError):
                misp_store.fetch_attachment("a" * 36)

    def test_an_attribute_that_came_back_without_its_file_is_an_error(self):
        attr = self._attr()
        attr.data = None
        with mock.patch.object(misp_store, "_misp", return_value=self._misp([attr])):
            with self.assertRaises(RuntimeError):
                misp_store.fetch_attachment("a" * 36)

    def test_the_rfi_download_returns_the_bytes_and_the_name(self):
        with mock.patch.object(misp_store, "_misp", return_value=self._misp([self._attr()])):
            self.assertEqual(misp_store.get_rfi_attachment_content("a" * 36),
                             (b"%PDF", "report.pdf"))

    def test_the_flash_intel_download_adds_the_recorded_content_type(self):
        attr = self._attr(comment=misp_store._fia_attachment_comment("application/pdf", 4))
        with mock.patch.object(misp_store, "_misp", return_value=self._misp([attr])):
            self.assertEqual(misp_store.get_fia_attachment_content("a" * 36),
                             (b"%PDF", "report.pdf", "application/pdf"))


class AttachmentFilesForEmail(unittest.TestCase):
    def _files(self, downloads):
        with mock.patch.object(misp_store, "get_fia_attachment_content", side_effect=downloads):
            return misp_store.fia_attachment_files([_attachment(), _attachment(filename="iocs.csv")])

    def test_the_content_type_is_split_the_way_the_mailer_wants_it(self):
        files = self._files([(b"%PDF", "report.pdf", "application/pdf"),
                             (b"a,b", "iocs.csv", "text/csv")])
        self.assertEqual(files, [("report.pdf", b"%PDF", "application", "pdf"),
                                 ("iocs.csv", b"a,b", "text", "csv")])

    def test_an_attachment_that_will_not_download_does_not_stop_the_alert(self):
        files = self._files([RuntimeError("gone"), (b"a,b", "iocs.csv", "text/csv")])
        self.assertEqual([f[0] for f in files], ["iocs.csv"])

    def test_a_missing_content_type_still_makes_a_valid_mime_pair(self):
        files = self._files([(b"x", "report.pdf", ""), RuntimeError("skip")])
        self.assertEqual(files[0][2:], ("application", "octet-stream"))


class AttachmentNamesAreNotTrusted(unittest.TestCase):
    """A filename is whatever the uploader called the file. Jinja escapes a
    quote to &#39;, which the browser turns back into a quote before the inline
    JS is parsed, so a name interpolated into a confirm() string would run."""

    def test_no_attachment_name_is_written_into_inline_javascript(self):
        template = (Path(misp_store.__file__).parent / "templates" / "flash_intel"
                    / "detail.html").read_text()
        for line in template.splitlines():
            if "onsubmit" in line:
                self.assertNotIn("att.filename", line, f"filename reaches inline JS: {line.strip()}")


class StoredFields(unittest.TestCase):
    """The new fields have to survive the round trip through the MISP object, or
    they are gone the next time the alert is opened."""

    def _reread(self, data):
        event = SimpleNamespace(
            uuid="u" * 36, objects=[misp_store._fia_obj(data)], attributes=[],
            event_reports=[], published=False, publish_timestamp=None,
            timestamp=None, date=None,
        )
        return misp_store._fia_ns(event)

    def test_the_write_up_and_the_gaps_are_read_back(self):
        fia = self._reread({"fia_id": "FIA-00042", "write_up": "## Detail\n\nMore.",
                            "intelligence_gaps": "Vector unknown."})
        self.assertEqual(fia.write_up, "## Detail\n\nMore.")
        self.assertEqual(fia.intelligence_gaps, "Vector unknown.")

    def test_an_alert_written_before_they_existed_reads_as_empty(self):
        fia = self._reread({"fia_id": "FIA-00042"})
        self.assertEqual(fia.write_up, "")
        self.assertEqual(fia.intelligence_gaps, "")

    def test_the_misp_object_template_declares_them(self):
        """An attribute the template does not declare still writes, since _oa()
        passes the type itself, but MISP then shows it unnamed on the event."""
        definition = json.loads(
            (Path(misp_store.__file__).parent / "misp_objects" / "objects"
             / "zsazsa-flash-intel" / "definition.json").read_text()
        )
        self.assertIn("write-up", definition["attributes"])
        self.assertIn("intelligence-gaps", definition["attributes"])


def _filled_fia_data():
    """Alert data with every stored field set.

    Empty values are never written to the object, so a field left blank here
    would go unnoticed by the check below however badly it was handled.
    """
    return {
        "fia_id": "FIA-00042", "title": "Energy sector intrusion", "audience": "SOC",
        "tlp": "clear", "summary": "Something happened.", "action_required": "Patch now.",
        "what_happened": ["A VPN account was abused."], "source_description": "OSINT",
        "source_reliability": "B", "information_credibility": "2",
        "likely_impact": "Loss of availability", "affected_assets": "Substation relays",
        "actor_types": ["Cybercriminals"], "actor_context": "Financially motivated.",
        "write_up": "## Detail\n\nThe pivot used a private APN.",
        "mitre_attack_techniques": ["T1566"], "geographic_scope": ["Poland"],
        "sectors": ["Energy"], "threat_actors": ["Luna Moth"], "threat_types": ["Ransomware"],
        "technology": ["Fortinet"], "vendor": ["Cisco"], "incident": ["INC-1"],
        "campaign": ["Spider"], "actions_immediate": ["Patch"], "actions_near_term": ["Review"],
        "mitre_techniques": ["T1059: Command and Scripting Interpreter"],
        "hunting_hypotheses": ["EDR: encoded powershell"],
        "external_references": ["https://example.org/advisory"],
        "intelligence_gaps": "The initial access vector is unknown.",
        "feedback_deadline": "2026-09-01", "author": "koen",
        "review_state": misp_store.FIA_REVIEW_DRAFT, "rejection_reason": "",
        "source_event_uuids": ["e" * 36], "source_event_hints": {"e" * 36: "scraper"},
        "context_tags": ["tlp:clear"], "linked_pir_uuid": "p" * 36,
        "creator": "koen@example.org", "approved_by": "",
    }


class ChangingTheReviewStateKeepsTheContent(unittest.TestCase):
    """Approving, publishing and rejecting all go through set_fia_review_state,
    which rebuilds the whole object from a payload it assembles by hand. A field
    that payload does not carry is destroyed at the moment the alert is
    published, and the notification that goes out is built from what survived."""

    def _rebuilt(self, state=misp_store.FIA_REVIEW_APPROVED):
        """The FIA object as it stands after a review-state change."""
        stored = misp_store._fia_obj(_filled_fia_data())
        stored.id = "7"  # only objects fetched from MISP carry one, and it is deleted by id
        event = SimpleNamespace(uuid="u" * 36, id="42", attributes=[], event_reports=[],
                                objects=[stored], published=False, publish_timestamp=None,
                                timestamp=None, date=None)
        misp = mock.MagicMock()
        misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_write_fia_report"), \
             mock.patch.object(misp_store.misp_session, "current_user_email",
                               return_value="reviewer@example.org"):
            misp_store.set_fia_review_state("u" * 36, state)
        return misp.add_object.call_args[0][1]

    def test_the_write_up_and_the_gaps_survive_publishing(self):
        obj = self._rebuilt()
        self.assertEqual(misp_store._obj_attr(obj, "write-up"),
                         "## Detail\n\nThe pivot used a private APN.")
        self.assertEqual(misp_store._obj_attr(obj, "intelligence-gaps"),
                         "The initial access vector is unknown.")

    def test_nothing_else_is_dropped_either(self):
        """Whatever _fia_obj() writes has to come back out, or the rebuild lost it."""
        written = {a.object_relation for a in misp_store._fia_obj(_filled_fia_data()).attributes}
        obj = self._rebuilt()
        survived = {a.object_relation for a in obj.attributes}
        # approved-by is set by the rebuild itself rather than carried across.
        self.assertEqual(written - survived, set())

    def test_publishing_records_the_reviewer(self):
        self.assertEqual(misp_store._obj_attr(self._rebuilt(), "approved-by"),
                         "reviewer@example.org")

    def test_rejecting_keeps_the_content_too(self):
        obj = self._rebuilt(misp_store.FIA_REVIEW_REJECTED)
        self.assertEqual(misp_store._obj_attr(obj, "write-up"),
                         "## Detail\n\nThe pivot used a private APN.")


if __name__ == "__main__":
    unittest.main()
