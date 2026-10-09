"""zsazsa only reads and writes its own records (GHSA-f8wh-26f3-4478).

The routes pass the id from the URL to the store, which acts on it with
zsazsa's own MISP key, and MISP resolves numeric event ids too. Any MISP user
could delete or overwrite events that were never zsazsa records, or reach a
published record through the routes of another type. An event now only counts
as a record when it carries that record type's zsazsa object or its tag, and an
attachment, note or scope item only when it belongs to the record named in the
URL.

    python -m unittest tests.test_record_type
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPAttribute, MISPEvent

from webapp import misp_store
from webapp.routes import flash_intel, indicator_feed, requirements, rfi, threat_actor_profile

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"

# Each record type, its getter and delete, and the object that marks it.
RECORDS = {
    "pir": "zsazsa-pir",
    "gir": "zsazsa-gir",
    "rfi": "zsazsa-rfi",
    "indicator_feed": "zsazsa-indicator-feed",
    "threat_actor_profile": "zsazsa-threat-actor-profile",
    "fia": "zsazsa-flash-intel",
    "vea": "zsazsa-vea",
    "der": "zsazsa-detection-eng-request",
    "briefing": "zsazsa-daily-briefing",
    "tlr": "zsazsa-threat-landscape-report",
}


def _event(object_name=None, tag=None):
    """A MISP event, carrying the given zsazsa object and tag, or neither."""
    event = MISPEvent()
    event.uuid = UUID
    event.id = "42"
    event.info = "Collected intel, not a zsazsa record"
    event.date = "2026-10-09"
    if object_name:
        event.Object.append(misp_store._build_obj(object_name))
    if tag:
        event.add_tag(tag)
    return event


class StoreCase(unittest.TestCase):
    def misp_returning(self, event):
        misp = mock.MagicMock()
        misp.get_event.return_value = event
        patcher = mock.patch.object(misp_store, "_misp", return_value=misp)
        patcher.start()
        self.addCleanup(patcher.stop)
        return misp


class Getters(StoreCase):
    def test_an_event_that_is_not_a_record_is_not_found(self):
        self.misp_returning(_event())
        for kind in RECORDS:
            with self.subTest(kind=kind):
                self.assertIsNone(getattr(misp_store, f"get_{kind}")(UUID))

    def test_a_numeric_event_id_finds_nothing_either(self):
        self.misp_returning(_event())
        self.assertIsNone(misp_store.get_indicator_feed("42"))

    def test_a_record_of_another_type_is_not_found(self):
        self.misp_returning(_event("zsazsa-threat-actor-profile"))
        self.assertIsNone(misp_store.get_indicator_feed(UUID))

    def test_an_alert_from_an_older_analyser_run_is_found_by_its_tag(self):
        """Early automated flash intel alerts were filed with a report and the
        tag, but without the zsazsa object."""
        self.misp_returning(_event(tag=misp_store.config.TAG_FLASH_INTEL))
        self.assertIsNotNone(misp_store.get_fia(UUID))

    def test_the_tag_of_another_type_is_not_enough(self):
        self.misp_returning(_event(tag=misp_store.config.TAG_THREAT_ACTOR_PROFILE))
        self.assertIsNone(misp_store.get_indicator_feed(UUID))

    def test_a_record_of_the_right_type_is_found(self):
        for kind, object_name in RECORDS.items():
            with self.subTest(kind=kind):
                self.misp_returning(_event(object_name))
                self.assertIsNotNone(getattr(misp_store, f"get_{kind}")(UUID))


class Deletes(StoreCase):
    def test_an_event_that_is_not_a_record_is_not_deleted(self):
        misp = self.misp_returning(_event())
        for kind in [*RECORDS, "collection_source"]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                getattr(misp_store, f"delete_{kind}")(UUID)
        misp.delete_event.assert_not_called()

    def test_a_published_profile_cannot_be_deleted_as_a_feed(self):
        misp = self.misp_returning(_event("zsazsa-threat-actor-profile"))
        with self.assertRaises(ValueError):
            misp_store.delete_indicator_feed(UUID)
        misp.delete_event.assert_not_called()

    def test_a_record_of_the_right_type_is_deleted(self):
        misp = self.misp_returning(_event("zsazsa-pir"))
        misp.delete_event.return_value = {"message": "Event deleted."}
        misp_store.delete_pir(UUID)
        misp.delete_event.assert_called_once_with(UUID)


class Writes(StoreCase):
    """Every write that takes an id refuses an event that is not its record."""

    WRITES = [
        ("update_pir", (UUID, {"pir_id": "PIR-1"})),
        ("update_gir", (UUID, {"gir_id": "GIR-1"})),
        ("update_rfi", (UUID, {"rfi_id": "RFI-1"})),
        ("update_indicator_feed", (UUID, {"feed_id": "FEED-1"})),
        ("update_threat_actor_profile", (UUID, {"tap_id": "TAP-1"})),
        ("update_fia", (UUID, {})),
        ("update_vea", (UUID, {})),
        ("update_der", (UUID, {})),
        ("update_briefing", (UUID, {})),
        ("update_tlr", (UUID, {})),
        ("update_collection_source", (UUID, {})),
        ("update_pir_intake", (UUID, "approved")),
        ("set_fia_review_state", (UUID, misp_store.FIA_REVIEW_APPROVED)),
        ("set_vea_review_state", (UUID, misp_store.VEA_REVIEW_APPROVED)),
        ("set_der_review_state", (UUID, misp_store.DER_REVIEW_APPROVED)),
        ("publish_fia", (UUID,)),
        ("publish_vea", (UUID,)),
        ("publish_der", (UUID,)),
        ("publish_briefing", (UUID,)),
        ("publish_tlr", (UUID,)),
        ("publish_threat_actor_profile", (UUID,)),
    ]

    def test_nothing_is_written_to_an_event_that_is_not_a_record(self):
        misp = self.misp_returning(_event())
        for name, args in self.WRITES:
            with self.subTest(write=name), self.assertRaises((ValueError, RuntimeError)):
                getattr(misp_store, name)(*args)
        for call in ("add_object", "update_object", "update_event", "publish",
                     "delete_object", "delete_attribute", "add_attribute", "tag", "untag"):
            with self.subTest(call=call):
                getattr(misp, call).assert_not_called()


class ScopeItems(StoreCase):
    def _requirement(self, *attributes):
        event = _event("zsazsa-pir")
        for uuid, comment in attributes:
            attr = MISPAttribute()
            attr.from_dict(uuid=uuid, type="text", value="Sector|Energy|", comment=comment)
            event.Attribute.append(attr)
        return event

    def test_an_event_that_is_not_a_requirement_is_refused(self):
        misp = self.misp_returning(_event())
        with self.assertRaises(ValueError):
            misp_store.remove_focus_point_with_scope(UUID, "a" * 36)
        misp.delete_attribute.assert_not_called()

    def test_an_attribute_that_is_not_one_of_its_scope_items_stays(self):
        misp = self.misp_returning(self._requirement(("a" * 36, "something else")))
        misp_store.remove_focus_point_with_scope(UUID, "a" * 36)
        misp.delete_attribute.assert_not_called()

    def test_one_of_its_scope_items_is_removed(self):
        misp = self.misp_returning(self._requirement(("a" * 36, misp_store._FP_COMMENT)))
        misp.delete_attribute.return_value = {"message": "Attribute deleted."}
        with mock.patch.object(misp_store, "_rewrite_parent_scope"):
            misp_store.remove_focus_point_with_scope(UUID, "a" * 36)
        misp.delete_attribute.assert_called_once()


def _client(*blueprints):
    app = Flask(__name__)
    app.secret_key = "test"
    for bp in blueprints:
        app.register_blueprint(bp)
    return app.test_client()


class Routes(unittest.TestCase):
    def test_deleting_an_event_through_the_feed_route_deletes_nothing(self):
        """The advisory's reproduction, against the real store."""
        client = _client(indicator_feed.bp)
        misp = mock.MagicMock()
        misp.get_event.return_value = _event()
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[]), \
             mock.patch.object(indicator_feed.audit, "record"):
            client.post("/products/indicator-feed/42/delete")
            misp.delete_event.assert_not_called()
            # A feed is still deleted through the same route.
            misp.get_event.return_value = _event("zsazsa-indicator-feed")
            client.post(f"/products/indicator-feed/{UUID}/delete")
        misp.delete_event.assert_called_once_with(UUID)

    def test_an_attachment_or_note_of_another_record_is_not_found(self):
        """Each route acts on the record's own item and answers 404 for any
        other, so a 404 here cannot come from a route that does not exist."""
        own, other = "a" * 36, "b" * 36
        attachment = SimpleNamespace(uuid=own, filename="report.pdf")
        note = SimpleNamespace(id="7")
        rfi_record = SimpleNamespace(uuid=UUID, rfi_id="RFI-1", attachments=[attachment], notes=[note])
        tap = SimpleNamespace(uuid=UUID, tap_id="TAP-1", notes=[note])
        fia = SimpleNamespace(uuid=UUID, fia_id="FIA-1", review_state="draft", attachments=[attachment])
        cases = [
            (rfi.bp, "get_rfi", rfi_record, "post", "/rfis/{}/attachments/{}/delete",
             "delete_rfi_attachment", own, other),
            (rfi.bp, "get_rfi", rfi_record, "get", "/rfis/{}/attachments/{}/download",
             "get_rfi_attachment_content", own, other),
            (rfi.bp, "get_rfi", rfi_record, "post", "/rfis/{}/notes/{}/delete", "delete_rfi_note", "7", "8"),
            (threat_actor_profile.bp, "get_threat_actor_profile", tap, "post",
             "/products/threat-actor-profile/{}/notes/{}/delete", "delete_rfi_note", "7", "8"),
            (flash_intel.bp, "get_fia", fia, "post", "/products/flash-intel/{}/attachments/{}/delete",
             "delete_fia_attachment", own, other),
            (flash_intel.bp, "get_fia", fia, "get", "/products/flash-intel/{}/attachments/{}/download",
             "get_fia_attachment_content", own, other),
        ]
        for bp, getter, record, method, path, store_call, mine, theirs in cases:
            client = _client(bp)
            with self.subTest(path=path), \
                 mock.patch.object(misp_store, getter, return_value=record), \
                 mock.patch.object(misp_store, store_call, return_value=(b"", "report.pdf", "")) as acted, \
                 mock.patch("webapp.audit.record"):
                resp = getattr(client, method)(path.format(UUID, theirs))
                self.assertEqual(resp.status_code, 404)
                acted.assert_not_called()
                getattr(client, method)(path.format(UUID, mine))
                acted.assert_called_once()

    def test_scope_items_of_an_event_that_is_not_a_requirement_are_refused(self):
        client = _client(requirements.bp)
        with mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch.object(misp_store, "get_gir", return_value=None), \
             mock.patch.object(misp_store, "add_focus_point_with_scope") as add, \
             mock.patch.object(misp_store, "remove_focus_point_with_scope") as remove, \
             mock.patch.object(misp_store, "sync_focus_points_category") as sync:
            for kind in ("pirs", "girs"):
                for path, data in ((f"/{kind}/{UUID}/focus_points", {"category": "Sector", "value": "x"}),
                                   (f"/{kind}/{UUID}/focus_points/{'a' * 36}/delete", {}),
                                   (f"/{kind}/{UUID}/scope/sync", {"category": "Sector"})):
                    with self.subTest(path=path):
                        self.assertEqual(client.post(path, data=data).status_code, 404)
        add.assert_not_called()
        remove.assert_not_called()
        sync.assert_not_called()

        # The same request on a PIR does reach the store.
        with mock.patch.object(misp_store, "get_pir", return_value=SimpleNamespace(uuid=UUID)), \
             mock.patch.object(misp_store, "add_focus_point_with_scope") as add, \
             mock.patch.object(misp_store, "sync_scope_tags_from_store"), \
             mock.patch.object(requirements._matching, "invalidate_cache"):
            client.post(f"/pirs/{UUID}/focus_points", data={"category": "Sector", "value": "x"})
        add.assert_called_once()


if __name__ == "__main__":
    unittest.main()
