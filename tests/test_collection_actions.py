"""What the data collection page may write to, and with which key.

Every action on the page takes an event id and a source from the request and
writes with the key of that source's MISP. For a manual source that is zsazsa's
own MISP, where the id could name a stakeholder, a product or another
organisation's event, so an action only goes ahead for an event the collection
lists under that source. Reading through a manual source shows only manual
entries, a partner server's events are dismissed rather than rejected, and a
product never takes one of zsazsa's own records as its source. A relevance
score that pushes an event into the analysis opens it again when the analyser
had rejected it, in zsazsa for a partner server's event. A score replaces the
earlier value of the same score, a partner server's event is published again
after it, as MISP unpublishes it, and what fails after the score is set is a
warning on a reply that says the score is set. Review by hand flags an event for
follow-up before it opens it again, so that the analyser leaves it open.

MISP is an autospec of PyMISP; the collection cache and the sources are patched,
and the database is temporary.

    python -m unittest tests.test_collection_actions
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent, PyMISP

import config
from core import db
from webapp import misp_store
from webapp.routes import data_collection

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
MANUAL = {"id": "manual-slack", "kind": "manual", "label": "Slack", "url": "https://misp.example.org"}
PARTNER = {"id": "partner", "kind": "misp", "label": "Partner", "url": "https://partner.example.org",
           "api_key": "k", "verify_tls": True}


def _event(*tags):
    event = MISPEvent()
    event.uuid = UUID
    event.id = 7
    event.info = "An event"
    for tag in tags:
        event.add_tag(tag)
    return event


class _Page(unittest.TestCase):
    """The collection blueprint over a webapp MISP and a cache holding `cached`."""

    cached = ()

    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = (
            # A score is recorded for the analyser in SQLite.
            mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")),
            mock.patch.object(data_collection, "_sources", return_value=[MANUAL, PARTNER]),
            mock.patch.object(misp_store, "_misp", return_value=self.misp),
            mock.patch.object(data_collection.collection_cache, "get_events_by_uuids",
                              side_effect=lambda uuids: [r for r in self.cached if r["uuid"] in uuids]),
            mock.patch.object(data_collection.collection_cache, "insert_event"),
            mock.patch.object(data_collection.collection_cache, "flag_event"),
            mock.patch.object(data_collection.collection_cache, "is_flagged", return_value=False),
            mock.patch.object(data_collection.audit, "record"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(data_collection.bp)
        self.client = app.test_client()

    def post(self, path, **body):
        return self.client.post(f"/collection/{UUID}/{path}", json={"source": MANUAL["id"], **body})


class AnEventTheCollectionDoesNotList(_Page):
    """Through a manual source, an id that names some other event on zsazsa's MISP."""

    def test_no_action_writes_to_it(self):
        for path, body in (("cti-tag", {"predicate": "relevance", "value": "high"}),
                           ("scope-tag", {"tag": 'misp-galaxy:country="belgium"'}),
                           ("flag", {}), ("reject", {}), ("dismiss", {}), ("review-by-hand", {})):
            with self.subTest(path):
                self.assertEqual(self.post(path, **body).status_code, 404)
        self.misp.tag.assert_not_called()
        self.misp.untag.assert_not_called()

    def test_a_bulk_reject_counts_it_as_an_error(self):
        reply = self.client.post("/collection/bulk-reject",
                                 json={"events": [{"uuid": UUID, "sourceId": MANUAL["id"]}]})
        self.assertEqual(reply.get_json()["errors"], 1)
        self.misp.get_event.assert_not_called()

    def test_the_page_only_shows_a_manual_entry(self):
        self.misp.get_event.return_value = _event('zsazsa:type="stakeholder"')
        reply = self.client.get(f"/collection/{UUID}/preview?source={MANUAL['id']}")
        self.assertEqual(reply.status_code, 404)
        self.assertIsNone(misp_store.get_manual_collection_event(UUID))
        with self.assertRaises(ValueError):
            misp_store.add_manual_collection_attachment(UUID, "x.txt", b"x")
        self.misp.add_attribute.assert_not_called()


class AnEventTheCollectionLists(_Page):
    cached = ({"uuid": UUID, "source_id": MANUAL["id"]}, {"uuid": UUID, "source_id": PARTNER["id"]})

    def test_it_can_be_tagged(self):
        self.misp.tag.return_value = {}
        reply = self.post("cti-tag", predicate="relevance", value="high")
        self.assertEqual(reply.status_code, 200)
        self.misp.tag.assert_called_once_with(UUID, 'cti-evaluation:relevance="high"', local=False)

    def test_a_relevance_score_that_pushes_it_opens_a_rejected_event_again(self):
        """The analyser does not read a rejected event, and would never see the push."""
        self.misp.tag.return_value = {}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'workflow:state="rejected"')
        with mock.patch.object(data_collection.tagger, "set_workflow_state", return_value=True) as state:
            self.post("cti-tag", predicate="relevance", value="very-high")
        self.assertEqual(state.call_args.args[2], "incomplete")
        self.assertIn(mock.call("reopen", "misp-event", entity_id=UUID,
                                details="pushed into the analysis by its relevance score"),
                      data_collection.audit.record.call_args_list)

    def test_a_reopening_that_fails_still_answers_that_the_score_is_set(self):
        """It is; an error would have the analyst think the click did nothing."""
        self.misp.tag.return_value = {}
        self.misp.get_event.side_effect = [_event(misp_store.TAG_MANUAL_ENTRY), ConnectionError("MISP went away")]
        with self.assertLogs("webapp.routes.data_collection", level="WARNING"):
            reply = self.post("cti-tag", predicate="relevance", value="very-high")
        self.assertEqual(reply.status_code, 200)
        self.assertIn("could not be opened again", reply.get_json()["warning"])

    def test_a_score_replaces_the_earlier_value_of_the_same_score(self):
        """With "low" and "very-high" both on the event, whether it was pushed
        or pulled depended on the order of its tags."""
        self.misp.tag.return_value = self.misp.untag.return_value = {}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'cti-evaluation:relevance="low"',
                                                  'cti-evaluation:usefulness="high"')
        self.post("cti-tag", predicate="relevance", value="very-high")
        self.misp.untag.assert_called_once_with(UUID, 'cti-evaluation:relevance="low"')

    def test_a_score_misp_refuses_leaves_the_earlier_one(self):
        self.misp.tag.return_value = {"errors": "Tagging refused"}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'cti-evaluation:relevance="low"')
        reply = self.post("cti-tag", predicate="relevance", value="very-high")
        self.assertEqual(reply.status_code, 400)
        self.misp.untag.assert_not_called()

    def test_what_fails_after_the_score_is_set_is_a_warning(self):
        """The earlier value that stays, the record for the analyser and the
        reopening each fail after the score is in MISP."""
        self.misp.tag.return_value = {}
        self.misp.untag.return_value = {"errors": "Untagging refused"}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'cti-evaluation:relevance="low"',
                                                  'workflow:state="rejected"')
        with mock.patch.object(data_collection.event_state, "scored_by_analyst",
                               side_effect=OSError("database is locked")), \
             mock.patch.object(data_collection.tagger, "set_workflow_state", return_value=False), \
             self.assertLogs("webapp.routes.data_collection", level="WARNING"):
            reply = self.post("cti-tag", predicate="relevance", value="very-high")
        self.assertEqual(reply.status_code, 200)
        warning = reply.get_json()["warning"]
        for part in ("earlier relevance could not be removed", "may not see it", "could not be opened again"):
            self.assertIn(part, warning)

    def test_the_analyser_reads_an_event_scored_during_its_run_again(self):
        self.misp.tag.return_value = {}
        self.post("cti-tag", predicate="usefulness", value="high")
        self.assertEqual(data_collection.event_state.scored_by_analyst_since("manual", 0), {UUID})

    def test_a_partner_event_is_published_again_after_its_score(self):
        """MISP unpublishes an event that gets a global tag, and a partner's
        events are read published only: the push made it leave the analysis."""
        self.misp.tag.return_value = {}
        with mock.patch.object(data_collection, "_misp_for_source", return_value=(self.misp, "")), \
             mock.patch.object(data_collection.misp_store, "publish_event", return_value=False) as published, \
             mock.patch.object(data_collection.event_state, "reopen"):
            reply = self.client.post(f"/collection/{UUID}/cti-tag",
                                     json={"source": PARTNER["id"], "predicate": "relevance", "value": "high"})
        self.assertEqual(published.call_args.args[:2], (self.misp, UUID))
        self.assertIn("could not be published again", reply.get_json()["warning"])

    def test_a_score_that_pushes_nothing_leaves_it_rejected(self):
        self.misp.tag.return_value = {}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'workflow:state="rejected"')
        for predicate, value in (("relevance", "moderate"), ("usefulness", "very-high")):
            with self.subTest(predicate=predicate), \
                 mock.patch.object(data_collection.tagger, "set_workflow_state") as state:
                self.post("cti-tag", predicate=predicate, value=value)
            state.assert_not_called()

    def test_another_server_s_event_is_opened_again_in_zsazsa(self):
        """Its workflow state is not zsazsa's to change."""
        self.misp.tag.return_value = {}
        with mock.patch.object(data_collection, "_misp_for_source", return_value=(self.misp, "")), \
             mock.patch.object(data_collection.event_state, "reopen") as reopened, \
             mock.patch.object(data_collection.tagger, "set_workflow_state") as state:
            self.client.post(f"/collection/{UUID}/cti-tag",
                             json={"source": PARTNER["id"], "predicate": "relevance", "value": "high"})
        reopened.assert_called_once_with("partner", UUID)
        state.assert_not_called()

    def test_review_by_hand_flags_it_for_follow_up_and_opens_it_again(self):
        self.misp.tag.return_value = {}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'workflow:state="rejected"')
        with mock.patch.object(data_collection.tagger, "set_workflow_state", return_value=True) as state:
            reply = self.post("review-by-hand")
        self.assertEqual(reply.get_json(), {"ok": True})
        self.misp.tag.assert_called_once_with(UUID, 'zsazsa:collection="follow-up"', local=True)
        data_collection.collection_cache.flag_event.assert_called_once_with(UUID)
        self.assertEqual(state.call_args.args[2], "incomplete")
        self.assertIn(mock.call("reopen", "misp-event", entity_id=UUID, details="for review by hand"),
                      data_collection.audit.record.call_args_list)

    def test_review_by_hand_does_not_open_it_again_without_the_flag(self):
        """Open and not flagged, the next run would close it again."""
        self.misp.tag.return_value = {"errors": "Refused"}
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'workflow:state="rejected"')
        with mock.patch.object(data_collection.tagger, "set_workflow_state") as state:
            reply = self.post("review-by-hand")
        self.assertEqual(reply.status_code, 502)
        state.assert_not_called()

    def test_review_by_hand_of_a_flagged_event_only_opens_it_again(self):
        self.misp.get_event.return_value = _event(misp_store.TAG_MANUAL_ENTRY, 'workflow:state="rejected"')
        with mock.patch.object(data_collection.collection_cache, "is_flagged", return_value=True), \
             mock.patch.object(data_collection.tagger, "set_workflow_state", return_value=True) as state:
            self.post("review-by-hand")
        self.misp.tag.assert_not_called()
        state.assert_called_once()

    def test_review_by_hand_of_another_server_s_event_opens_it_again_in_zsazsa(self):
        self.misp.tag.return_value = {}
        with mock.patch.object(data_collection, "_misp_for_source", return_value=(self.misp, "")), \
             mock.patch.object(data_collection.event_state, "reopen") as reopened:
            self.client.post(f"/collection/{UUID}/review-by-hand", json={"source": PARTNER["id"]})
        reopened.assert_called_once_with("partner", UUID)

    def test_a_partner_event_is_dismissed_not_rejected(self):
        """Its workflow state belongs to the other server, as a bulk reject has it."""
        reply = self.client.post(f"/collection/{UUID}/reject", json={"source": PARTNER["id"]})
        self.assertEqual(reply.status_code, 400)
        self.assertIn("dismissed", reply.get_json()["error"])


class Pull(unittest.TestCase):
    def test_one_of_zsazsas_records_is_not_pulled_in(self):
        """The scraper is often the MISP zsazsa keeps its records in."""
        app = Flask(__name__)
        app.register_blueprint(data_collection.bp)
        scraper = {"id": "scraper", "kind": "scraper"}
        with mock.patch.object(data_collection, "_resolve_pull_source", return_value=scraper), \
             mock.patch.object(misp_store, "_scraper_misp"), \
             mock.patch.object(data_collection, "_fetch_event_timed",
                               return_value=(_event('zsazsa:ctiproduct="flash-intel"'), [])), \
             mock.patch.object(data_collection.collection_cache, "insert_event") as insert, \
             mock.patch.object(data_collection.audit, "record"):
            reply = app.test_client().post("/collection/pull", json={"uuid": UUID, "source_id": "scraper"})
        self.assertEqual(reply.status_code, 404)
        insert.assert_not_called()


class PartnerConnection(unittest.TestCase):
    def test_it_has_a_timeout(self):
        """Without one, a partner server that stops answering holds the page."""
        with mock.patch.object(data_collection, "PyMISP") as connect:
            data_collection._connect_source(PARTNER)
        self.assertEqual(connect.call_args.kwargs["timeout"], misp_store.HTTP_TIMEOUT)


class AiSummary(unittest.TestCase):
    def test_a_report_misp_refuses_is_not_called_saved(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event_reports.return_value = [SimpleNamespace(content="An article about a RAT.")]
        misp.add_event_report.return_value = {"errors": (403, {"message": "Not allowed"})}
        # A summary that is wrongly taken as saved goes on to the audit log and
        # the cache, which belong to this install.
        with mock.patch("analyser.llm.summarise_report", return_value="**Summary** A RAT."), \
             mock.patch.object(data_collection.collection_cache, "mark_ai_summary") as mark, \
             mock.patch.object(data_collection.collection_cache, "insert_event"), \
             mock.patch.object(data_collection.audit, "record"):
            ok, message, _status = data_collection._generate_ai_summary(misp, _event(), "scraper")
        self.assertFalse(ok)
        self.assertIn("Could not save", message)
        mark.assert_not_called()


class ProductSource(unittest.TestCase):
    def test_a_zsazsa_record_is_not_tagged_as_a_product_source(self):
        """A product form could name a stakeholder or another product as its source."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = _event('zsazsa:type="stakeholder"')
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            misp_store._tag_scraper_event_as_product_source(UUID, "flash-intel", source_id="webapp")
        misp.tag.assert_not_called()
        misp.untag.assert_not_called()

    def test_a_refused_ongoing_state_keeps_the_one_it_had(self):
        """Its old state was removed first, and an event with none is found by
        no search of the analyser."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.get_event.return_value = _event('workflow:state="incomplete"')
        misp.tag.return_value = {"errors": "Tag refused"}
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch("webapp.collection_cache.patch_event_tags"), \
             self.assertLogs("analyser.tagger", level="ERROR"):
            misp_store._tag_scraper_event_as_product_source(UUID, "flash-intel", source_id="webapp")
        misp.untag.assert_not_called()


if __name__ == "__main__":
    unittest.main()
