"""The zsazsa:product tag on a product's source events, through edits and deletes.

Creating a flash intel alert, an advisory, a detection request or a daily
briefing tags its source events, which data collection shows and the analyser
reads: an event with the vea tag gets no advisory again, and one with the
daily-briefing tag stays out of every later briefing. Deleting the product left
the tag behind, so a deleted draft kept its events from the analyser for good,
and an edit neither tagged a source it added nor untagged one it dropped. Now a
source the product no longer has loses the tag, unless another product of the
same type still has it, and a source it gains is tagged. The workflow state of
the event is left as it is, except that a story an analyst deleted from a
briefing rejects its event, so the next briefing does not propose it again. An
event on another organisation's MISP server is not tagged or rejected there:
that decision is kept in zsazsa instead.

MISP is a specced stand-in, and the collection cache is stubbed.

    python -m unittest tests.test_product_source_tags
"""

import json
import sqlite3
import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

# Real UUIDs: a product drops anything else from its sources.
A, B, C = ("6f4535bb-1b2c-4d5e-8f90-a1b2c3d4e5f6", "76653b51-9c5e-4986-9bed-a3b464c4123e",
           "6fc6df4a-1798-4b83-bba5-36104ae028ab")


def _event(builder, uuid="p" * 36, **fields):
    event = MISPEvent()
    event.uuid, event.id, event.date = uuid, 42, "2026-10-26"
    event.add_object(builder(fields))
    return event


def _briefing_event(sources, uuid="p" * 36, review_state="draft"):
    event = _event(misp_store._briefing_obj, uuid, title="Daily", date="2026-10-26", review_state=review_state)
    for i, source in enumerate(sources, start=1):
        report = event.add_event_report(f"{misp_store._STORY_REPORT_PREFIX}{i:02d}]",
                                        json.dumps({"title": f"Story {i}", "source_event_uuid": source}))
        report.id = i
    return event


class Retag(unittest.TestCase):
    def retag(self, before, after, in_use=()):
        asked = mock.Mock(return_value=set(in_use))
        with mock.patch.object(misp_store, "_tag_scraper_event_as_product_source") as tag, \
             mock.patch.object(misp_store, "_untag_product_source") as untag:
            misp_store._retag_product_sources("vea", before, after, asked)
        return tag, untag, asked

    def test_a_source_added_is_tagged_and_one_dropped_untagged(self):
        tag, untag, _asked = self.retag({A: "", B: "manual-newsletter"}, {B: "manual-newsletter", C: "scraper"})
        tag.assert_called_once_with(C, "vea", source_id="scraper")
        untag.assert_called_once_with(A, "vea", "", reject=False)

    def test_a_source_another_product_has_keeps_its_tag(self):
        _tag, untag, _asked = self.retag({A: "", B: ""}, {}, in_use={A})
        untag.assert_called_once_with(B, "vea", "", reject=False)

    def test_a_failed_read_of_the_other_products_keeps_the_tags(self):
        """The product is deleted by then: the route must not report it as failed."""
        with mock.patch.object(misp_store, "_untag_product_source") as untag, \
             self.assertLogs(misp_store.logger, "WARNING"):
            misp_store._retag_product_sources("vea", {A: ""}, {}, mock.Mock(side_effect=ConnectionError("MISP down")))
        untag.assert_not_called()

    def test_the_other_products_are_only_read_when_a_source_went(self):
        """A review-state change rewrites the product with the same sources."""
        tag, untag, asked = self.retag({A: ""}, {A: ""})
        tag.assert_not_called()
        untag.assert_not_called()
        asked.assert_not_called()


class Untag(unittest.TestCase):
    TAG = 'zsazsa:product="vea"'

    def untag(self, source_id="", tags=(TAG, 'workflow:state="ongoing"'), reject=False):
        self.scraper = mock.create_autospec(PyMISP, instance=True)
        self.webapp = mock.create_autospec(PyMISP, instance=True)
        event = MISPEvent()
        event.uuid = A
        for name in tags:
            event.add_tag(name)
        self.scraper.get_event.return_value = self.webapp.get_event.return_value = event
        with mock.patch.object(misp_store, "_scraper_misp", return_value=self.scraper), \
             mock.patch.object(misp_store, "_misp", return_value=self.webapp), \
             mock.patch.object(misp_store, "scraper_enabled", return_value=True), \
             mock.patch.object(misp_store.event_state, "close") as self.closed, \
             mock.patch("webapp.collection_cache.patch_event_tags") as self.cache:
            misp_store._untag_product_source(A, "vea", source_id, reject=reject)

    def test_the_tag_comes_off_and_the_workflow_state_stays(self):
        self.untag()
        self.scraper.untag.assert_called_once_with(A, self.TAG)
        self.cache.assert_called_once_with(A, [], [self.TAG])

    def test_an_event_without_the_tag_is_left_alone(self):
        self.untag(tags=['workflow:state="ongoing"'])
        self.scraper.untag.assert_not_called()

    def test_a_manual_entry_is_on_our_own_misp(self):
        self.untag("manual-newsletter")
        self.webapp.untag.assert_called_once_with(A, self.TAG)
        self.scraper.get_event.assert_not_called()

    def test_another_server_s_event_is_not_ours_to_change(self):
        self.untag("misp-intern")
        self.scraper.get_event.assert_not_called()
        self.webapp.get_event.assert_not_called()
        self.closed.assert_not_called()

    def test_another_server_s_event_turned_down_is_closed_in_zsazsa(self):
        """Or the next briefing would propose it again."""
        self.untag("misp-intern", reject=True)
        self.closed.assert_called_once_with("misp-intern", A, "Removed by an analyst from a vea")
        self.webapp.tag.assert_not_called()
        self.scraper.tag.assert_not_called()

    def test_an_event_turned_down_is_rejected(self):
        self.untag(reject=True)
        self.scraper.tag.assert_called_once_with(mock.ANY, 'workflow:state="rejected"', local=True)
        self.cache.assert_called_once_with(A, ['workflow:state="rejected"'], [self.TAG, 'workflow:state="ongoing"'])

    def test_a_complete_event_stays_complete(self):
        self.untag(tags=(self.TAG, 'workflow:state="complete"'), reject=True)
        self.scraper.tag.assert_not_called()


class Deleting(unittest.TestCase):
    """A source another product of the type still has keeps its tag; B is in one."""

    def delete(self, delete, event, lister, others):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.delete_event.return_value = {}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, lister, return_value=others), \
             mock.patch.object(misp_store.event_state, "read_again"), \
             mock.patch.object(misp_store, "_untag_product_source") as untag:
            delete(event.uuid)
        misp.delete_event.assert_called_once_with(event.uuid)
        return [c.args[:2] for c in untag.call_args_list]

    def test_an_alert(self):
        event = _event(misp_store._fia_obj, fia_id="FIA-00042", source_event_uuids=[A, B])
        other = SimpleNamespace(source_event_uuids=[B])
        self.assertEqual(self.delete(misp_store.delete_fia, event, "list_fias", [other]), [(A, "flash-intel")])

    def test_an_advisory(self):
        event = _event(misp_store._vea_obj, vea_id="VEA-00042", source_event_uuids=[A, B])
        other = SimpleNamespace(source_event_uuids=[B])
        self.assertEqual(self.delete(misp_store.delete_vea, event, "list_veas", [other]), [(A, "vea")])

    def test_a_detection_request(self):
        event = _event(misp_store._der_obj, der_id="DER-00042", source_event_uuids=[A, B])
        other = SimpleNamespace(source_event_uuids=[B])
        self.assertEqual(self.delete(misp_store.delete_der, event, "list_ders", [other]),
                         [(A, "detection-eng-request")])

    def test_a_daily_briefing(self):
        other = SimpleNamespace(stories=[SimpleNamespace(source_event_uuid=B)])
        self.assertEqual(self.delete(misp_store.delete_briefing, _briefing_event([A, B]), "list_briefings", [other]),
                         [(A, "daily-briefing")])


class Editing(unittest.TestCase):
    """The product had A and B, and the edit keeps B and adds C."""

    def edit(self, update, stored, refreshed, data, patched):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = refreshed
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=stored), \
             mock.patch.object(misp_store, "_sync_object_attributes"), \
             mock.patch.multiple(misp_store, **{name: mock.DEFAULT for name in patched}), \
             mock.patch.object(misp_store, "_tag_scraper_event_as_product_source") as tag, \
             mock.patch.object(misp_store, "_untag_product_source") as untag:
            update("p" * 36, data)
        return [c.args[0] for c in tag.call_args_list], [c.args[0] for c in untag.call_args_list]

    def record(self, update, builder, lister, reports):
        stored = _event(builder, title="Old", source_event_uuids=[A, B])
        refreshed = _event(builder, title="Edited", source_event_uuids=[B, C])
        with mock.patch.object(misp_store, lister, return_value=[]):
            return self.edit(update, stored, refreshed, {"title": "Edited", "source_event_uuids": [B, C]}, reports)

    def test_an_alert(self):
        self.assertEqual(self.record(misp_store.update_fia, misp_store._fia_obj, "list_fias",
                                     ("_delete_fia_reports", "_write_fia_report")), ([C], [A]))

    def test_an_advisory(self):
        self.assertEqual(self.record(misp_store.update_vea, misp_store._vea_obj, "list_veas",
                                     ("_delete_vea_reports", "_write_vea_report")), ([C], [A]))

    def test_a_detection_request(self):
        self.assertEqual(self.record(misp_store.update_der, misp_store._der_obj, "list_ders",
                                     ("_delete_der_reports", "_write_der_report")), ([C], [A]))

    def test_a_daily_briefing(self):
        stories = [{"title": "Kept", "source_event_uuid": B}, {"title": "Added", "source_event_uuid": C}]
        with mock.patch.object(misp_store, "list_briefings", return_value=[]):
            result = self.edit(misp_store.update_briefing, _briefing_event([A, B]), _briefing_event([B, C]),
                               {"title": "Edited", "review_state": "draft", "stories": stories},
                               ("_replace_reports",))
        self.assertEqual(result, ([C], [A]))



class ReadAgain(unittest.TestCase):
    """A deleted product's events are read again by the action that makes that
    product: their tags are local, and the watermarks go by what changed. Not
    those of a rejected product, which an analyst turned down, and not one that
    another product of the type still has."""

    def flagged(self, delete, event, lister, others=()):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.delete_event.return_value = {}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=event), \
             mock.patch.object(misp_store, lister, return_value=list(others)), \
             mock.patch.object(misp_store, "_untag_product_source"), \
             mock.patch.object(misp_store.event_state, "read_again") as read_again:
            delete(event.uuid)
        return [c.args for c in read_again.call_args_list]

    def alert(self, **fields):
        return _event(misp_store._fia_obj, source_event_uuids=[A], **fields)

    def test_a_deleted_alert(self):
        self.assertEqual(self.flagged(misp_store.delete_fia, self.alert(source_event_hints={A: "scraper"}), "list_fias"),
                         [("scraper", A, "flash-intel")])

    def test_a_deleted_advisory_on_a_manual_entry(self):
        event = _event(misp_store._vea_obj, source_event_uuids=[A], source_event_hints={A: "manual-news"})
        self.assertEqual(self.flagged(misp_store.delete_vea, event, "list_veas"), [("manual", A, "vea")])

    def test_a_rejected_alert_stays_turned_down(self):
        event = self.alert(review_state=misp_store.FIA_REVIEW_REJECTED)
        self.assertEqual(self.flagged(misp_store.delete_fia, event, "list_fias"), [])

    def test_a_rejected_advisory_stays_turned_down(self):
        event = _event(misp_store._vea_obj, source_event_uuids=[A], review_state=misp_store.VEA_REVIEW_REJECTED)
        self.assertEqual(self.flagged(misp_store.delete_vea, event, "list_veas"), [])

    def test_an_event_another_alert_has_is_not_read_again(self):
        other = SimpleNamespace(source_event_uuids=[A])
        self.assertEqual(self.flagged(misp_store.delete_fia, self.alert(), "list_fias", [other]), [])

    def test_a_detection_request_has_no_action_to_read_it(self):
        event = _event(misp_store._der_obj, source_event_uuids=[A])
        self.assertEqual(self.flagged(misp_store.delete_der, event, "list_ders"), [])

    def test_a_deleted_draft_briefing_with_what_it_listed_under_also_seen(self):
        event = _briefing_event([A])
        obj = misp_store._get_obj(event, "zsazsa-daily-briefing")
        obj.add_attribute("also-seen", value=json.dumps([{"source_event_uuid": B, "source_id": "partner"}]), type="text")
        self.assertEqual(self.flagged(misp_store.delete_briefing, event, "list_briefings"),
                         [("scraper", A, "daily-briefing"), ("partner", B, "daily-briefing")])

    def test_a_rejected_briefing_stays_turned_down(self):
        self.assertEqual(self.flagged(misp_store.delete_briefing, _briefing_event([A], review_state="rejected"),
                                      "list_briefings"), [])

    def test_a_failed_write_does_not_make_the_delete_look_failed(self):
        with mock.patch.object(misp_store.event_state, "read_again", side_effect=sqlite3.OperationalError("database is locked")), \
             self.assertLogs("webapp.misp_store", level="WARNING"):
            misp_store._retag_product_sources("vea", {A: "scraper"}, {}, set, read_again="vea")


class TurnedDown(unittest.TestCase):
    """A story deleted from a briefing came back in the next briefing that read
    its date, since its event was left open. Now the event is rejected, as are
    those of a rejected briefing that is deleted. A draft deleted to be made
    again gives its events back."""

    def reject_flags(self, change, stored):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = stored
        misp.delete_event.return_value = {}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_zsazsa_event", return_value=stored), \
             mock.patch.object(misp_store, "_sync_object_attributes"), \
             mock.patch.object(misp_store, "_replace_reports"), \
             mock.patch.object(misp_store, "list_briefings", return_value=[]), \
             mock.patch.object(misp_store.event_state, "read_again"), \
             mock.patch.object(misp_store, "_untag_product_source") as untag:
            change()
        return {c.args[0]: c.kwargs["reject"] for c in untag.call_args_list}

    def test_a_story_deleted_from_a_briefing(self):
        data = {"title": "Daily", "review_state": "draft", "stories": [{"title": "Kept", "source_event_uuid": B}]}
        self.assertEqual(self.reject_flags(lambda: misp_store.update_briefing("p" * 36, data),
                                           _briefing_event([A, B])), {A: True})

    def test_a_rejected_briefing_deleted(self):
        self.assertEqual(self.reject_flags(lambda: misp_store.delete_briefing("p" * 36),
                                           _briefing_event([A, B], review_state="rejected")), {A: True, B: True})

    def test_a_draft_deleted_to_be_made_again(self):
        self.assertEqual(self.reject_flags(lambda: misp_store.delete_briefing("p" * 36),
                                           _briefing_event([A, B])), {A: False, B: False})


if __name__ == "__main__":
    unittest.main()
