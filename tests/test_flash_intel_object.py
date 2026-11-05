"""The flash intel alert the analyser drafts from an event the verdict wants.

The model drafts it with the prompt of the Build with AI button, and the draft
is read into the alert's fields as that button reads it. The alert names its
source event and the source that event was read from, which is what keeps the
event from a second alert and lets a later edit find it again. It names every
PIR and GIR in its grounds, and is addressed to all their stakeholders, or with
focus points alone to everyone it can reach; its reason quotes the article for
each ground. It is never classified below its source. The source type goes on
the source event when that is zsazsa's own; an event on another organisation's
MISP server is not written to. A draft the model left empty, or one with
neither a summary nor what happened, as when the model declined, files
nothing.

The stored alert keeps the list of requirements through an analyst's edit, and
an alert from before the list reads back with its one PIR.

    python -m unittest tests.test_flash_intel_object
"""

import json
import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import MISPEvent, PyMISP

from analyser.products import flash_intel
from analyser.sources import Source
from webapp import misp_store

DRAFT = """# Flash intel alert: Grid operator hit
## Summary
Ransomware stopped a grid operator.
**Action required:** Check the VPN.
## What happened
- The operator's VPN was breached.
**Source:** Vendor blog
## Recommended actions
### Immediate
- Patch the VPN
"""

PIR = SimpleNamespace(uuid="p" * 36, pir_id="PIR-00002", priority="Must have", owner_uuid="", distribution="")
GIR = SimpleNamespace(uuid="g" * 36, gir_id="GIR-00001", owner_uuid="", distribution="")


def _event(tlp="tlp:clear"):
    return SimpleNamespace(uuid="e" * 36, info="Grid operator hit", date="2026-10-30",
                           tags=[SimpleNamespace(name=tlp),
                                 SimpleNamespace(name='admiralty-scale:source-reliability="b"')])


def _verdict(grounds):
    return {"alert": {"relevant": True, "grounds": grounds, "reason": "An attack on our sector."},
            "source_type": "news-report"}


class Alert(unittest.TestCase):
    def make(self, grounds=({"focus_point": "Energy", "quote": "a grid operator"},), source=None, event=None,
             automated=()):
        source = source or Source("scraper", "scraper", "MISP scraper", mock.create_autospec(PyMISP, instance=True),
                                  True)
        judge = mock.Mock(requirements_of=lambda grounds: [r for r in (PIR, GIR)
                                                           if r.uuid in {g.get("requirement") for g in grounds}])
        self.created = {}
        with mock.patch.object(flash_intel.llm, "generate_fia_draft", return_value=DRAFT) as self.drafted, \
             mock.patch.object(misp_store, "create_fia",
                               side_effect=lambda data: self.created.update(data) or ("u" * 36, "FIA-00042")), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(misp_store, "requirement_audience", return_value="SOC") as self.audience, \
             mock.patch.object(misp_store, "subscriber_audience", return_value="Everyone"), \
             mock.patch.object(misp_store, "stakeholders_on_automated_mode", return_value=list(automated)), \
             mock.patch.object(flash_intel.tagger, "add_tag") as self.tagged:
            event, verdict = event or _event(), _verdict(list(grounds))
            data = flash_intel.draft_alert(event, source, verdict, judge, "The article", "The summary",
                                           "An attack on our sector.")
            fia_id, _problem = flash_intel.file_alert(data, event, source, verdict)
        return fia_id

    def test_it_is_drafted_with_the_analyser_s_own_feature_and_its_grounds(self):
        self.make()
        kwargs = self.drafted.call_args.kwargs
        self.assertEqual(kwargs["feature"], "generate_flash_intel")
        self.assertEqual(kwargs["matched_points"], ["Energy"])
        self.assertEqual(self.drafted.call_args.args[0], "The article")

    def test_the_draft_fills_the_alert_s_fields(self):
        self.assertEqual(self.make(), "FIA-00042")
        self.assertEqual(self.created["summary"], "Ransomware stopped a grid operator.")
        self.assertEqual(self.created["actions_immediate"], ["Patch the VPN"])
        self.assertEqual(self.created["what_happened"], ["The operator's VPN was breached."])
        self.assertEqual(self.created["review_state"], misp_store.FIA_REVIEW_DRAFT)
        self.assertEqual(self.created["author"], "analyser")

    def test_it_names_its_source_event_and_where_it_was_read(self):
        for kind, sid, hint in (("scraper", "scraper", "scraper"), ("manual", "manual", "webapp"),
                                ("misp", "partner", "partner")):
            with self.subTest(kind=kind):
                self.make(source=Source(sid, kind, kind, None, kind != "misp"))
                self.assertEqual(self.created["source_event_uuids"], ["e" * 36])
                self.assertEqual(self.created["source_event_hints"], {"e" * 36: hint})

    def test_with_requirements_it_names_them_all_and_is_for_their_stakeholders(self):
        self.make(grounds=[{"requirement": GIR.uuid, "id": "GIR-00001", "quote": "q"},
                           {"requirement": PIR.uuid, "id": "PIR-00002", "quote": "q"}])
        self.assertEqual(self.created["linked_requirement_uuids"], [PIR.uuid, GIR.uuid])
        # The form edits one PIR, so the first one is that.
        self.assertEqual(self.created["linked_pir_uuid"], PIR.uuid)
        self.assertEqual(self.created["context_tags"], ["match:GIR-00001", "match:PIR-00002"])
        self.assertEqual(self.created["audience"], "SOC")
        self.assertEqual(self.audience.call_args.args[0], [PIR, GIR])

    def test_with_focus_points_alone_it_is_for_everyone_it_can_reach(self):
        self.make()
        self.assertEqual(self.created["audience"], "Everyone")
        self.assertEqual(self.created["linked_requirement_uuids"], [])
        self.assertEqual(self.created["linked_pir_uuid"], "")

    def test_its_reason_quotes_the_article_for_each_ground(self):
        self.make()
        self.assertEqual(self.created["analyser_reason"],
                         'An attack on our sector. Grounds: Energy: "a grid operator"')

    def test_it_is_never_classified_below_its_source(self):
        self.make(event=_event("tlp:red"))
        self.assertEqual(self.created["tlp"], "red")
        self.make()
        self.assertEqual(self.created["tlp"], "amber")

    def test_the_source_reliability_is_the_event_s(self):
        self.make()
        self.assertEqual(self.created["source_reliability"], "B")

    def test_the_source_type_goes_on_zsazsa_s_own_event_only(self):
        self.make()
        self.assertEqual(self.tagged.call_args.args[2], 'osint:source-type="news-report"')
        self.make(source=Source("partner", "misp", "Partner", mock.create_autospec(PyMISP, instance=True), False))
        self.tagged.assert_not_called()


def _alert_event(data):
    event = MISPEvent()
    event.uuid, event.id, event.info, event.date = "u" * 36, "42", "[zsazsa:fia] Alert", "2026-10-30"
    event.add_object(misp_store._fia_obj(data))
    return event


class StoredAlert(unittest.TestCase):
    def stored(self, data):
        return misp_store._fia_ns(_alert_event(data))

    def test_its_requirements_are_read_back(self):
        fia = self.stored({"linked_requirement_uuids": [PIR.uuid, GIR.uuid], "linked_pir_uuid": PIR.uuid})
        self.assertEqual(fia.linked_requirement_uuids, [PIR.uuid, GIR.uuid])

    def test_an_alert_from_before_the_list_has_its_one_pir(self):
        self.assertEqual(self.stored({"linked_pir_uuid": PIR.uuid}).linked_requirement_uuids, [PIR.uuid])
        self.assertEqual(self.stored({}).linked_requirement_uuids, [])

    def test_a_pir_s_product_list_finds_it_by_any_of_its_requirements(self):
        self.assertEqual(misp_store.linked_pir_uuids(_alert_event({"linked_requirement_uuids": [GIR.uuid]})),
                         {GIR.uuid})

    def test_an_analyst_s_edit_keeps_the_list(self):
        """The form does not post it: only the analyser sets it."""
        event = _alert_event({"linked_requirement_uuids": [PIR.uuid, GIR.uuid], "title": "Alert"})
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = event
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, "_sync_object_attributes") as synced, \
             mock.patch.object(misp_store, "_sync_tlp_tag"), \
             mock.patch.object(misp_store, "_delete_fia_reports"), \
             mock.patch.object(misp_store, "_write_fia_report"), \
             mock.patch.object(misp_store, "_retag_product_sources"), \
             mock.patch.object(misp_store.misp_session, "current_user_email", return_value="a@example.org"):
            misp_store.update_fia("u" * 36, {"title": "Alert, edited"})
        written = synced.call_args.args[3]
        self.assertEqual(json.loads(misp_store._obj_attr(written, "linked-requirement-uuids")), [PIR.uuid, GIR.uuid])


if __name__ == "__main__":
    unittest.main()
