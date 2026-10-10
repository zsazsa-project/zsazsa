"""The review, corrections and exports of a threat landscape report, after ENISA.

A report moves from draft through internal and stakeholder review to approval,
each step logged with who, when and why; only an approved report is published,
and approving takes MISP publish rights. Once approved it cannot be changed
until it is sent back to draft. A published report takes dated corrections.
Its dataset annex and its ATT&CK Navigator layer are built from the events left
in the analysis, and the layer carries the report's TLP. MISP is patched out.

    python -m unittest tests.test_tlr_review
"""

import json
import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import PyMISP
from werkzeug.datastructures import MultiDict

from webapp import misp_store
from webapp.routes import threat_landscape

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _entry(**fields):
    data = {key: "" for key in misp_store.TLR_ENTRY_FIELDS}
    data.update({key: [] for key in misp_store.TLR_ENTRY_LISTS})
    data.update(uuid="obj-1", excluded=False)
    data.update(fields)
    return SimpleNamespace(**data)


def _report(**fields):
    data = dict(uuid=UUID, tlr_id="TLR-00009", title="Q3", tlp="amber+strict", review_state="draft",
                entries=[], review_log=[], corrections=[])
    data.update(fields)
    return SimpleNamespace(**data)


class _Routes(unittest.TestCase):
    can_publish = True

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_landscape.bp)
        self.client = app.test_client()
        for patcher in (mock.patch.object(threat_landscape.misp_session, "current_user_can_publish",
                                          return_value=self.can_publish),
                        mock.patch.object(threat_landscape.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, report, path, **form):
        with mock.patch.object(misp_store, "get_tlr", return_value=report), \
             mock.patch.object(misp_store, "set_tlr_state") as move, \
             mock.patch.object(misp_store, "add_tlr_correction") as correct, \
             mock.patch.object(misp_store, "publish_tlr") as publish, \
             mock.patch.object(misp_store, "update_tlr") as update, \
             mock.patch.object(threat_landscape, "_start_delivery"):
            self.client.post(f"/products/threat-landscape/{UUID}/{path}", data=form)
        return SimpleNamespace(move=move, correct=correct, publish=publish, update=update)


class Review(_Routes):
    def test_a_draft_goes_to_internal_review_with_its_comment(self):
        calls = self.post(_report(), "state", state="internal-review", comment=" Please check the trends ")
        calls.move.assert_called_once_with(UUID, "internal-review", "Please check the trends")

    def test_a_step_cannot_be_skipped(self):
        calls = self.post(_report(), "state", state="approved")
        calls.move.assert_not_called()

    def test_a_review_can_send_it_back_to_draft(self):
        calls = self.post(_report(review_state="stakeholder-review"), "state", state="draft")
        calls.move.assert_called_once_with(UUID, "draft", "")

    def test_only_an_approved_report_is_published(self):
        self.post(_report(review_state="stakeholder-review"), "publish").publish.assert_not_called()
        self.post(_report(review_state="approved"), "publish").publish.assert_called_once_with(UUID)

    def test_an_approved_report_cannot_be_edited(self):
        calls = self.post(_report(review_state="approved"), "edit", title="Changed")
        calls.update.assert_not_called()

    def test_a_correction_needs_a_published_report_and_a_text(self):
        self.post(_report(review_state="approved"), "correction", text="Typo").correct.assert_not_called()
        self.post(_report(review_state="published"), "correction", text=" ").correct.assert_not_called()
        self.post(_report(review_state="published"), "correction", text="Typo").correct.assert_called_once_with(UUID, "Typo")


class ReviewWithoutPublishRights(_Routes):
    can_publish = False

    def test_approving_is_refused(self):
        self.post(_report(review_state="stakeholder-review"), "state", state="approved").move.assert_not_called()

    def test_a_review_step_does_not_need_them(self):
        self.post(_report(), "state", state="internal-review").move.assert_called_once()

    def test_a_correction_is_refused(self):
        self.post(_report(review_state="published"), "correction", text="Typo").correct.assert_not_called()


class StoredReview(unittest.TestCase):
    def setUp(self):
        # Specced, so a call to a method PyMISP does not have fails here too.
        self.misp = mock.create_autospec(PyMISP, instance=True)
        stored = misp_store._tlr_obj({"tlr_id": "TLR-00009", "review_state": "stakeholder-review",
                                      "purpose": "Budget", "review_log": [{"to": "stakeholder-review"}]})
        stored.id = 7
        self.event = SimpleNamespace(uuid=UUID, id=1, objects=[stored], tags=[], published=False, date=None)
        for patcher in (mock.patch.object(misp_store, "_misp", return_value=self.misp),
                        mock.patch.object(misp_store, "_tlr_event", return_value=self.event),
                        mock.patch.object(misp_store, "_check"),
                        mock.patch.object(misp_store.misp_session, "current_user_email", return_value="lead@example.org")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def stored(self):
        obj = self.misp.update_object.call_args.args[0]
        return misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[obj], published=False, date=None))

    def test_approving_logs_the_step_and_who_approved(self):
        misp_store.set_tlr_state(UUID, "approved", "Fine by me")
        tlr = self.stored()
        self.assertEqual(tlr.review_state, "approved")
        self.assertEqual(tlr.approved_by, "lead@example.org")
        self.assertEqual(tlr.purpose, "Budget", "the rest of the report is kept")
        step = tlr.review_log[-1]
        self.assertEqual((step["from"], step["to"], step["by"], step["comment"]),
                         ("stakeholder-review", "approved", "lead@example.org", "Fine by me"))
        self.assertEqual(len(tlr.review_log), 2)

    def test_back_to_draft_withdraws_the_approval(self):
        misp_store.set_tlr_state(UUID, "approved")
        approved = self.misp.update_object.call_args.args[0]
        approved.id = 8
        self.event.objects = [approved]
        misp_store.set_tlr_state(UUID, "draft", "One chart is wrong")
        self.assertEqual(self.stored().approved_by, "")

    def test_a_correction_is_kept_and_the_event_published_again(self):
        misp_store.add_tlr_correction(UUID, "The second chart counted July twice.")
        self.assertEqual(self.stored().corrections[0]["text"], "The second chart counted July twice.")
        self.misp.publish.assert_called_once_with(self.event)

    def test_an_edit_keeps_the_review_log(self):
        misp_store.update_tlr(UUID, {"tlr_id": "TLR-00009", "title": "Q3"})
        self.assertEqual(self.stored().review_log, [{"to": "stakeholder-review"}])

    def test_an_edit_changes_the_report_in_place_and_renames_the_event(self):
        """It deleted the object and then called edit_event, which PyMISP does not
        have, so every save left the report empty."""
        misp_store.update_tlr(UUID, {"tlr_id": "TLR-00009", "title": "Q3"})
        self.misp.delete_object.assert_not_called()
        self.assertEqual(self.stored().title, "Q3")
        self.misp.update_event.assert_called_once_with({"Event": {"id": 1, "info": "[zsazsa:tlr] TLR-00009: Q3"}})

    def test_a_report_that_lost_its_object_gets_a_new_one(self):
        self.event.objects = []
        misp_store.update_tlr(UUID, {"tlr_id": "TLR-00009", "title": "Q3"})
        added = self.misp.add_object.call_args.args[1]
        self.assertEqual(misp_store._tlr_ns(SimpleNamespace(uuid=UUID, objects=[added], published=False,
                                                            date=None)).title, "Q3")


class Annex(unittest.TestCase):
    def test_it_describes_the_events_in_the_analysis(self):
        report = _report(entries=[
            _entry(source_id="scraper", event_date="2026-07-02", relevance="high", source_reliability="B"),
            _entry(source_id="scraper", event_date="2026-09-20", relevance="high"),
            _entry(source_id="isac", excluded=True),
        ])
        annex = dict(misp_store.tlr_annex(report))
        self.assertEqual(annex["Events"], "2 in the analysis, 1 left out")
        self.assertEqual(annex["Event dates"], "2026-07-02 to 2026-09-20")
        self.assertEqual(annex["Sources"], "scraper (2)")
        self.assertEqual(annex["Source reliability"], "B (1), not rated (1)")

    def test_a_report_without_events_has_none(self):
        self.assertEqual(misp_store.tlr_annex(_report()), [])


class NavigatorLayer(unittest.TestCase):
    def test_it_scores_the_techniques_and_carries_the_tlp(self):
        app = Flask(__name__)
        app.register_blueprint(threat_landscape.bp)
        report = _report(entries=[
            _entry(techniques=["Phishing - T1566", "T1059.001"]),
            _entry(techniques=["T1566"]),
            _entry(techniques=["Valid Accounts - T1078"], excluded=True),
        ])
        with mock.patch.object(misp_store, "get_tlr", return_value=report):
            reply = app.test_client().get(f"/products/threat-landscape/{UUID}/navigator.json")
        layer = json.loads(reply.data)
        self.assertEqual({t["techniqueID"]: t["score"] for t in layer["techniques"]}, {"T1566": 2, "T1059.001": 1})
        self.assertIn("TLP:AMBER+STRICT", layer["name"])
        self.assertIn({"name": "TLP", "value": "TLP:AMBER+STRICT"}, layer["metadata"])
        self.assertTrue(layer["description"].startswith("TLP:AMBER+STRICT"))


class EntryQuestions(unittest.TestCase):
    def test_the_answers_are_saved_with_the_triage(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(threat_landscape.bp)
        form = MultiDict([("relevance-obj-1", "high"), ("impact-obj-1", " Outage of two days "),
                          ("motivation-obj-1", "Financial")])
        with mock.patch.object(misp_store, "get_tlr", return_value=_report(entries=[_entry()])), \
             mock.patch.object(misp_store, "update_tlr_entries") as update, \
             mock.patch.object(threat_landscape.audit, "record"):
            app.test_client().post(f"/products/threat-landscape/{UUID}/entries", data=form)
        saved = update.call_args.args[1]["obj-1"]
        self.assertEqual((saved["impact"], saved["motivation"], saved["mitigation"]),
                         ("Outage of two days", "Financial", ""))

    def test_the_entry_object_stores_them(self):
        stored = misp_store._tlr_entry(misp_store._tlr_entry_obj({"event_uuid": "e1", "affected_assets": "VPN"}))
        self.assertEqual(stored["affected_assets"], "VPN")


if __name__ == "__main__":
    unittest.main()
