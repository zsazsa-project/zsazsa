"""External references on a manual collection entry are MISP link attributes.

"link" is what everything downstream looks for when it collects the references
of a source event, so a reference stored as "url" is invisible to every product
built from that entry. These checks pin the type down at the point it is
written, and cover the migration that repairs entries written before the fix.
The MITRE ATT&CK techniques picked on the form are tagged on the entry too.
A repeated URL is saved once, and a save that fails halfway deletes the event
it created.

    python -m unittest tests.test_manual_entry_references
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

from webapp import misp_store

import scripts.convert_url_attributes_to_link as migration


def _created(**over):
    """What add_event answers with, as create_manual_collection_event reads it."""
    base = {"id": "42", "uuid": "e" * 36}
    base.update(over)
    return SimpleNamespace(**base)


class ReferenceAttributeType(unittest.TestCase):
    def _added_attributes(self, data):
        """The attributes create_manual_collection_event writes, by comment."""
        misp = mock.MagicMock()
        misp.add_event.return_value = _created()
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_build_scope_tags", return_value=[]):
            misp_store.create_manual_collection_event(data)
        return [call[0][1] for call in misp.add_attribute.call_args_list]

    def test_a_reference_is_stored_as_a_link(self):
        attrs = self._added_attributes(
            {"title": "An entry", "references": ["https://example.org/advisory"]})
        references = [a for a in attrs if a.value == "https://example.org/advisory"]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].type, "link")
        self.assertEqual(references[0].category, "External analysis")
        self.assertFalse(references[0].to_ids)

    def test_the_source_reference_is_a_link_too(self):
        attrs = self._added_attributes(
            {"title": "An entry", "source_reference": "https://example.org/article"})
        source = [a for a in attrs if a.value == "https://example.org/article"]
        self.assertEqual([a.type for a in source], ["link"])

    def test_blank_references_are_not_written(self):
        attrs = self._added_attributes({"title": "An entry", "references": ["  ", ""]})
        self.assertEqual(attrs, [])

    def test_a_link_reference_reaches_a_product_reference_list(self):
        """The reason the type matters: this is what a product reads."""
        event = {"attributes": [
            {"type": "link", "value": "https://example.org/advisory"},
            {"type": "url", "value": "https://example.org/missed"},
        ]}
        self.assertEqual(misp_store.event_link_attributes(event),
                         ["https://example.org/advisory"])


class RepeatedReferences(unittest.TestCase):
    """MISP refuses a second link with the same value in one event. The event
    is created before its links are added, so a URL given twice used to stop
    the save halfway and leave a half-written entry in MISP."""

    def _save(self, data):
        stored = []

        def add_attribute(event_id, attribute):
            # The answer MISP gives for a repeated value, as seen in the log.
            if any(a.type == attribute.type and a.category == attribute.category
                   and a.value == attribute.value for a in stored):
                return {"errors": (403, {"saved": False, "errors": {
                    "value": ["A similar attribute already exists for this event."]}})}
            stored.append(attribute)
            return attribute

        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event.return_value = _created()
        misp.add_attribute.side_effect = add_attribute
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_build_scope_tags", return_value=[]):
            misp_store.create_manual_collection_event(data)
        return [(a.comment, a.value) for a in stored if a.type == "link"]

    def test_the_source_reference_repeated_as_an_external_reference_is_saved_once(self):
        links = self._save({
            "title": "An entry",
            "source_reference": "https://example.org/article",
            "references": [" https://example.org/article ", "https://example.org/other"],
        })
        self.assertEqual(links, [("Source reference", "https://example.org/article"),
                                 ("External reference", "https://example.org/other")])

    def test_an_external_reference_given_twice_is_saved_once(self):
        links = self._save({
            "title": "An entry",
            "references": ["https://example.org/a", "https://example.org/a", "https://example.org/b"],
        })
        self.assertEqual(links, [("External reference", "https://example.org/a"),
                                 ("External reference", "https://example.org/b")])

    def test_the_form_marks_a_repeated_reference(self):
        """The page says a repeat is saved once instead of leaving it to the save."""
        from pathlib import Path
        page = (Path(misp_store.__file__).parent / "templates" / "data_collection"
                / "manual_entry.html").read_text()
        self.assertIn("function markRepeatedReferences()", page)
        self.assertIn("refList.addEventListener('input', markRepeatedReferences)", page)
        self.assertIn("sourceRef.addEventListener('input', markRepeatedReferences)", page)


class FailedSave(unittest.TestCase):
    """The event is created before its tags, links and reports are added. When
    one of those fails the event is deleted again, so a failed save leaves no
    half-written entry in MISP and a retry does not add a second one."""

    REFUSED = {"errors": (403, {"saved": False, "errors": {"value": ["refused"]}})}

    def _misp(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event.return_value = _created()
        misp.add_attribute.return_value = {}
        misp.add_event_report.return_value = {}
        misp.delete_event.return_value = {}
        return misp

    def _save(self, misp, data):
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_build_scope_tags", return_value=[]):
            return misp_store.create_manual_collection_event(data)

    def test_a_refused_reference_deletes_the_new_event(self):
        misp = self._misp()
        misp.add_attribute.return_value = self.REFUSED
        with self.assertRaisesRegex(RuntimeError, "add external reference"):
            self._save(misp, {"title": "An entry", "references": ["https://example.org/a"]})
        misp.delete_event.assert_called_once_with("e" * 36)

    def test_a_refused_report_deletes_the_new_event(self):
        misp = self._misp()
        misp.add_event_report.return_value = self.REFUSED
        with self.assertRaisesRegex(RuntimeError, "add manual entry report"):
            self._save(misp, {"title": "An entry", "description": "Some text"})
        misp.delete_event.assert_called_once_with("e" * 36)

    def test_the_first_error_is_raised_when_the_delete_fails_too(self):
        """The analyst is told what went wrong with the save, and the log says
        the event could not be deleted."""
        misp = self._misp()
        misp.add_attribute.return_value = self.REFUSED
        misp.delete_event.return_value = self.REFUSED
        with self.assertLogs(misp_store.logger, "WARNING") as logs, \
             self.assertRaisesRegex(RuntimeError, "add source reference"):
            self._save(misp, {"title": "An entry", "source_reference": "https://example.org/a"})
        self.assertIn("Could not delete the unfinished manual entry", logs.output[0])

    def test_a_saved_entry_is_not_deleted(self):
        misp = self._misp()
        uuid = self._save(misp, {"title": "An entry", "references": ["https://example.org/a"],
                                 "description": "Some text"})
        self.assertEqual(uuid, "e" * 36)
        misp.delete_event.assert_not_called()

    def test_nothing_is_deleted_when_the_event_was_never_created(self):
        misp = self._misp()
        misp.add_event.return_value = self.REFUSED
        with self.assertRaises(RuntimeError):
            self._save(misp, {"title": "An entry"})
        misp.delete_event.assert_not_called()


def _attr(uuid, type_, value, category="External analysis", deleted=False):
    return SimpleNamespace(uuid=uuid, type=type_, value=value, category=category,
                           deleted=deleted)


class Techniques(unittest.TestCase):
    def test_the_techniques_picked_on_the_form_are_tagged(self):
        """Only as galaxy tags: _build_scope_tags leaves techniques out, since a
        PIR or GIR keeps them on its object."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event.return_value = _created()
        tag_map = {"Phishing - T1566": 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"'}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_build_scope_tags", return_value=['misp-galaxy:sector="Finance"']), \
             mock.patch.object(misp_store, "_galaxy_tag_map", return_value=tag_map) as galaxy:
            misp_store.create_manual_collection_event(
                {"title": "An entry", "mitre_attack_techniques": ["Phishing - T1566", "Not a technique"]})
        galaxy.assert_called_once_with(misp_store.GALAXY_MITRE_ATTACK)
        self.assertEqual([c.args[1] for c in misp.tag.call_args_list if "galaxy" in c.args[1]],
                         ['misp-galaxy:sector="Finance"', 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"'])

    def test_the_techniques_come_from_the_attack_pattern_galaxy(self):
        """It was d752161c-..., MISP's mitre-malware galaxy, where no technique
        is found, so none was ever tagged."""
        self.assertEqual(misp_store.GALAXY_MITRE_ATTACK, "c4e851fa-775f-11e7-8163-b774922098cd")


class Migration(unittest.TestCase):
    """The repair for entries written before references became links."""

    def _selected(self, attributes):
        event = SimpleNamespace(uuid="e" * 36, attributes=attributes)
        return [a.value for a in migration._url_references(event)]

    def test_it_picks_up_a_reference_still_typed_url(self):
        self.assertEqual(
            self._selected([_attr("a", "url", "https://example.org/advisory")]),
            ["https://example.org/advisory"])

    def test_a_reference_already_converted_is_left_alone(self):
        self.assertEqual(self._selected([_attr("a", "link", "https://example.org/a")]), [])

    def test_a_url_indicator_outside_external_analysis_is_left_alone(self):
        """Retyping a genuine URL indicator would silently drop it from matching."""
        self.assertEqual(
            self._selected([_attr("a", "url", "http://evil.example/c2", category="Network activity")]),
            [])

    def test_a_deleted_attribute_is_skipped(self):
        self.assertEqual(
            self._selected([_attr("a", "url", "https://example.org/a", deleted=True)]), [])

    def _run(self, argv):
        attribute = _attr("a", "url", "https://example.org/advisory")
        misp = mock.MagicMock()
        misp.search.return_value = [SimpleNamespace(uuid="e" * 36, attributes=[attribute])]
        misp.update_attribute.return_value = {}
        with mock.patch.object(migration, "_misp", return_value=misp), \
             mock.patch.object(migration.sys, "argv", ["convert_url_attributes_to_link.py"] + argv):
            migration.main()
        return misp, attribute

    def test_a_dry_run_changes_nothing(self):
        misp, attribute = self._run([])
        misp.update_attribute.assert_not_called()
        self.assertEqual(attribute.type, "url")

    def test_apply_retypes_the_attribute(self):
        misp, attribute = self._run(["--apply"])
        self.assertEqual(attribute.type, "link")
        misp.update_attribute.assert_called_once_with(attribute)


if __name__ == "__main__":
    unittest.main()
