"""A product's MISP event has the one TLP tag the product has.

Only a flash intel alert moved its event's tlp: tag when its TLP was edited.
The other products kept the tag they were created with, so a briefing raised
from CLEAR to GREEN still left MISP as tlp:clear, and threat actor profiles and
indicator feeds were created without a TLP tag at all. MISP shares an event by
its tags. MISP is a specced stand-in, and what an edit does besides the tag is
stubbed.

    python -m unittest tests.test_product_tlp_tag
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

import config
from webapp import misp_store

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _event(builder, product_tag, **fields):
    event = MISPEvent()
    event.uuid, event.id, event.date, event.info = UUID, 42, "2026-10-28", "product"
    event.add_tag("tlp:clear")
    event.add_tag(product_tag)
    event.add_object(builder({"tlp": "clear", **fields}))
    return event


class Editing(unittest.TestCase):
    """Each product is stored at TLP:CLEAR and edited."""

    def edit(self, update, event, data, stubbed=()):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = event
        stubs = {name: mock.DEFAULT for name in ("_sync_object_attributes", "_retag_product_sources", *stubbed)}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_tlr_event", return_value=event), \
             mock.patch.object(misp_store, "galaxy_enrichment", return_value={"victimology": []}), \
             mock.patch.multiple(misp_store, **stubs):
            update(UUID, data)
        return misp

    def tlp_calls(self, method):
        return [c.args[1] for c in method.call_args_list if str(c.args[1]).startswith("tlp:")]

    # The update, the object it stores, the product's tag, and what it does
    # besides that would reach MISP.
    PRODUCTS = {
        "alert": (misp_store.update_fia, misp_store._fia_obj, config.TAG_FLASH_INTEL,
                  ("_delete_fia_reports", "_write_fia_report")),
        "advisory": (misp_store.update_vea, misp_store._vea_obj, config.TAG_VEA,
                     ("_delete_vea_reports", "_write_vea_report")),
        "detection request": (misp_store.update_der, misp_store._der_obj, config.TAG_DETECTION_ENG,
                              ("_delete_der_reports", "_write_der_report")),
        "briefing": (misp_store.update_briefing, misp_store._briefing_obj, config.TAG_BRIEFING,
                     ("_replace_reports",)),
        "landscape report": (misp_store.update_tlr, misp_store._tlr_obj, config.TAG_TLR, ()),
        "threat actor profile": (misp_store.update_threat_actor_profile, misp_store._tap_obj,
                                 config.TAG_THREAT_ACTOR_PROFILE, ("_apply_scope_tags", "_add_victimology_notes")),
        "indicator feed": (misp_store.update_indicator_feed, misp_store._indicator_feed_obj,
                           config.TAG_INDICATOR_FEED, ()),
    }

    def form(self, tlp):
        """What a save posts. The review state and the stories are a briefing's;
        the other products leave them out."""
        return {"title": "Edited", "tlp": tlp, "review_state": "draft", "stories": []}

    def test_a_new_tlp_replaces_the_old_tag(self):
        for name, (update, builder, tag, stubbed) in self.PRODUCTS.items():
            with self.subTest(name):
                misp = self.edit(update, _event(builder, tag), self.form("green"), stubbed)
                self.assertEqual(self.tlp_calls(misp.untag), ["tlp:clear"])
                self.assertEqual(self.tlp_calls(misp.tag), ["tlp:green"])

    def test_an_unchanged_tlp_leaves_the_tag_alone(self):
        update, builder, tag, stubbed = self.PRODUCTS["briefing"]
        misp = self.edit(update, _event(builder, tag), self.form("clear"), stubbed)
        self.assertEqual(self.tlp_calls(misp.untag) + self.tlp_calls(misp.tag), [])


class Creating(unittest.TestCase):
    """A profile and a feed were the two products made without a TLP tag."""

    def created_tags(self, create, data):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event.side_effect = lambda event, pythonify: event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_event_uuid", return_value=UUID), \
             mock.patch.object(misp_store, "_reserve_sequence_id", return_value="ID-00001"), \
             mock.patch.object(misp_store, "_tag_local"), \
             mock.patch.object(misp_store, "_check", side_effect=lambda result, label: result), \
             mock.patch.object(misp_store, "galaxy_enrichment", return_value={"victimology": []}), \
             mock.patch.object(misp_store, "_apply_scope_tags"), \
             mock.patch.object(misp_store, "_add_victimology_notes"), \
             mock.patch.object(misp_store.misp_session, "current_user_email", return_value="analyst@example.org"):
            create(data)
        return [t.name for t in misp.add_event.call_args.args[0].tags]

    def test_a_threat_actor_profile(self):
        self.assertIn("tlp:amber", self.created_tags(misp_store.create_threat_actor_profile,
                                                     {"title": "APT29", "tlp": "amber"}))

    def test_an_indicator_feed(self):
        self.assertIn("tlp:green", self.created_tags(misp_store.create_indicator_feed,
                                                     {"name": "Phishing", "tlp": "green"}))


if __name__ == "__main__":
    unittest.main()
