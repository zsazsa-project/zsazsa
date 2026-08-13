"""Which PIRs a product may claim to answer, and the classification on every page.

Two unrelated rules that both go wrong quietly. A PIR still in intake has not
been agreed, so an alert must not be linked to it; and the running TLP header on
a PDF's continuation pages has to carry the document's own classification, not a
colour baked into the stylesheet.

    python -m unittest tests.test_product_pir_choice_and_pdf_tlp
"""

import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from webapp import misp_store
from webapp.routes import flash_intel


def _pir(pir_id, status, uuid=None):
    return SimpleNamespace(pir_id=pir_id, uuid=uuid or pir_id.lower(),
                           status=status, question="Q?")


_PIRS = [
    _pir("PIR-00001", "Active"),
    _pir("PIR-00002", "Pending"),
    _pir("PIR-00003", "Under Evaluation"),
    _pir("PIR-00004", "Retired"),
    _pir("PIR-00005", "Active"),
]


class OnlyAgreedPirsCanBeLinked(unittest.TestCase):
    def _selectable(self, linked=""):
        with mock.patch.object(misp_store, "list_pirs", return_value=_PIRS):
            return [p.pir_id for p in misp_store.list_selectable_pirs(linked)]

    def test_a_pir_still_in_intake_cannot_be_picked(self):
        self.assertEqual(self._selectable(), ["PIR-00001", "PIR-00005"])

    def test_a_retired_pir_cannot_be_picked_either(self):
        self.assertNotIn("PIR-00004", self._selectable())

    def test_the_pir_a_product_is_already_linked_to_stays_on_the_list(self):
        """Otherwise reopening an older alert and saving it drops the link
        without saying so."""
        self.assertEqual(self._selectable("pir-00002"),
                         ["PIR-00001", "PIR-00002", "PIR-00005"])

    def test_a_link_to_a_pir_that_no_longer_exists_adds_nothing(self):
        self.assertEqual(self._selectable("gone"), ["PIR-00001", "PIR-00005"])


class TheWizardAsksForTheRightOnes(unittest.TestCase):
    """The wizard renders both from a saved alert and from the posted form when
    validation sends it back, so the linked PIR has to be found in either."""

    def _pirs_offered(self, fia):
        with mock.patch.object(flash_intel.misp_store, "list_pirs", return_value=_PIRS), \
             mock.patch.object(flash_intel.misp_store, "galaxy_geography", return_value=[]), \
             mock.patch.object(flash_intel.misp_store, "galaxy_sectors", return_value=[]), \
             mock.patch.object(flash_intel.misp_store, "galaxy_threat_actors", return_value=[]), \
             mock.patch.object(flash_intel.misp_store, "galaxy_mitre_attack_patterns", return_value=[]):
            return [p.pir_id for p in flash_intel._wizard_context(fia)["pirs"]]

    def test_a_new_alert_is_offered_the_active_ones(self):
        self.assertEqual(self._pirs_offered(None), ["PIR-00001", "PIR-00005"])

    def test_a_saved_alert_keeps_the_pir_it_is_linked_to(self):
        fia = SimpleNamespace(linked_pir_uuid="pir-00002")
        self.assertIn("PIR-00002", self._pirs_offered(fia))

    def test_a_form_sent_back_by_validation_keeps_it_too(self):
        self.assertIn("PIR-00002", self._pirs_offered({"linked_pir_uuid": "pir-00002"}))

    def test_an_alert_linked_to_nothing_is_offered_the_active_ones(self):
        self.assertEqual(self._pirs_offered({"linked_pir_uuid": ""}),
                         ["PIR-00001", "PIR-00005"])


_CSS = Path(misp_store.__file__).parent / "static" / "css" / "product_pdf.css"
_PDF_TEMPLATES = {
    "daily_briefing": "briefing.tlp",
    "flash_intel": "fia.tlp",
    "threat_actor_profile": "tap.tlp",
    "vea": "vea.tlp",
}


class TheClassificationHeaderFollowsTheDocument(unittest.TestCase):
    """Page one carries the TLP on its cover badge; every page after it carries
    the running header instead. A page margin box cannot see the badge, so the
    colour travels through a custom property set on the root element."""

    def test_the_running_header_takes_its_colour_from_the_document(self):
        top_right = re.search(r"@top-right\s*\{(.*?)\}", _CSS.read_text(), re.S).group(1)
        self.assertIn("var(--tlp-color", top_right)
        self.assertIsNone(re.search(r"color:\s*#[0-9a-f]{6}", top_right),
                          "the running header still has a hard-coded colour")

    def test_every_tlp_the_app_offers_has_a_header_colour(self):
        css = _CSS.read_text()
        for tlp in misp_store.FIA_TLP_LEVELS:
            slug = tlp.replace("+", "-")
            self.assertIn(f':root[data-tlp="{slug}"]', css, f"no header colour for tlp:{tlp}")

    def test_every_product_pdf_puts_its_tlp_on_the_root_element(self):
        """Without it on <html> the custom property never reaches the margin box,
        and the header falls back to the neutral colour."""
        templates = Path(misp_store.__file__).parent / "templates"
        for product, expression in _PDF_TEMPLATES.items():
            html_tag = (templates / product / "pdf.html").read_text().split(">", 2)[1]
            self.assertIn(f'data-tlp="{{{{ {expression} | slug }}}}"', html_tag + ">",
                          f"{product} pdf does not carry its TLP on <html>")

    def test_the_tlp_never_reaches_the_root_as_a_class(self):
        """The .tlp-* classes paint a pill background. On the root that background
        propagates to the page canvas and floods the whole PDF with it, so the
        root has to carry the TLP as an attribute instead."""
        templates = Path(misp_store.__file__).parent / "templates"
        for product in _PDF_TEMPLATES:
            html_tag = (templates / product / "pdf.html").read_text().split(">", 2)[1]
            self.assertNotIn("class=", html_tag,
                             f"{product} pdf puts a class on <html>; a tlp-* one would "
                             "tint every page")

    def test_a_pill_colour_never_applies_to_the_root(self):
        """Reading the stylesheet the way the renderer does: the pill rules must
        not be reachable from :root under any TLP the app offers."""
        css = _CSS.read_text()
        for tlp in misp_store.FIA_TLP_LEVELS:
            slug = tlp.replace("+", "-")
            self.assertNotIn(f":root.tlp-{slug}", css)


if __name__ == "__main__":
    unittest.main()
