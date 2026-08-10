"""The narrative summary that opens a daily threat briefing.

Covers what the model is given to write it from, what the compose form is
allowed to ask for, and where the answer lands in the markdown every delivery
channel is built from.

    python -m unittest tests.test_briefing_summary
"""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from analyser import llm
from webapp import misp_store
from webapp.routes import api


def _stories():
    return [
        {"title": "Ransomware crew hits logistics", "content": "ACME was hit.",
         "sectors": ["Transport"], "geographic_scope": ["Belgium"],
         "threat_actors": ["LockBit"], "techniques": ["T1566"], "vendor": [],
         "threat_actor_types": ["Cybercriminals"]},
        {"title": "Second haulier breached", "content": "So was BCME.",
         "sectors": ["Transport"], "geographic_scope": ["Netherlands"],
         "threat_actors": [], "techniques": [], "vendor": [],
         "threat_actor_types": []},
    ]


class SummaryInput(unittest.TestCase):
    def _payload(self, stories, scope_summary=None):
        """The user message draft_briefing_summary() sends the model."""
        with mock.patch.object(llm, "_call", return_value="A summary.") as call, \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"):
            llm.draft_briefing_summary(stories, scope_summary, "2026-08-08")
        return json.loads(call.call_args[0][1])

    def test_stories_are_sent_with_their_scope(self):
        payload = self._payload(_stories())
        self.assertEqual(payload["story_count"], 2)
        self.assertEqual(payload["date"], "2026-08-08")
        self.assertEqual(payload["stories"][0]["title"], "Ransomware crew hits logistics")
        self.assertEqual(payload["stories"][0]["sectors"], ["Transport"])
        self.assertEqual(payload["stories"][1]["index"], 2)

    def test_the_scope_counts_say_how_many_stories_share_a_theme(self):
        """Without the counts the model can only guess at what runs through the day."""
        summary = misp_store.briefing_scope_summary(_stories())
        payload = self._payload(_stories(), summary)
        sectors = payload["scope_across_briefing"]["Sector"]
        self.assertEqual(sectors, [{"value": "Transport", "stories": 2}])

    def test_an_empty_answer_comes_back_as_no_summary(self):
        with mock.patch.object(llm, "_call", return_value="   "), \
             mock.patch.object(llm, "_build_system_prompt", return_value="sys"):
            self.assertEqual(llm.draft_briefing_summary(_stories()), "")


class DraftSummaryEndpoint(unittest.TestCase):
    """The compose form drafts from the stories on the page rather than from the
    saved briefing, so what it posts is unsaved and unvalidated."""

    def setUp(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.register_blueprint(api.bp, url_prefix="/api")
        self.client = app.test_client()

    def post(self, **body):
        """Post to the endpoint with the worker thread stubbed out.

        Returns (reply, thread_args) where thread_args is what the job thread
        would have been called with, or None when no job was started.
        """
        started = []
        with mock.patch.object(api.job_store, "create_job", return_value={"id": "job-1"}), \
             mock.patch.object(api.threading, "Thread") as thread:
            thread.side_effect = lambda **kw: started.append(kw["args"]) or mock.MagicMock()
            reply = self.client.post("/api/draft-briefing-summary", json=body)
        return reply, (started[0] if started else None)

    def test_a_briefing_with_no_stories_has_nothing_to_summarise(self):
        reply, args = self.post(stories=[])
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)

    def test_a_story_without_text_stops_the_draft(self):
        """The model would otherwise write around the gap without saying so."""
        reply, args = self.post(stories=[{"title": "Has text", "content": "Something."},
                                         {"title": "Empty", "content": "  "}])
        self.assertEqual(reply.status_code, 400)
        self.assertIsNone(args)

    def test_stories_must_be_a_list(self):
        reply, _args = self.post(stories="one story")
        self.assertEqual(reply.status_code, 400)

    def test_the_stories_reach_the_job_with_their_scope_and_the_date(self):
        reply, args = self.post(date="2026-08-08", stories=[{
            "title": " Ransomware crew hits logistics ",
            "content": "ACME was hit.",
            "sectors": ["Transport", "  ", 42],
            "geographic_scope": ["Belgium"],
        }])
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json(), {"ok": True, "job_id": "job-1"})
        _job_id, stories, date = args
        self.assertEqual(date, "2026-08-08")
        self.assertEqual(stories[0]["title"], "Ransomware crew hits logistics")
        # Anything that is not a filled-in string would come back as a theme
        # running through the briefing.
        self.assertEqual(stories[0]["sectors"], ["Transport"])
        self.assertEqual(stories[0]["threat_actors"], [])


def _briefing(summary=""):
    story = SimpleNamespace(
        title="Ransomware crew hits logistics", content="ACME was hit.",
        source_url="https://example.org/article", source_event_uuid="",
        geographic_scope=[], sectors=[], threat_actors=[], techniques=[],
        threat_actor_types=[], vendor=[], source_reliability="",
        information_credibility="", cti_evaluation={},
    )
    return SimpleNamespace(
        date="2026-08-08", title="Daily briefing", author="koen", tlp="clear",
        created_at=None, stories=[story], escalations="", notes="", summary=summary,
        geographic_scope=[], sectors=[], threat_actors=[], mitre_attack_techniques=[],
        threat_types=[], technology=[], vendor=[], incident=[], campaign=[],
    )


class BriefingMarkdown(unittest.TestCase):
    """The markdown feeds Mattermost and the report written back to MISP."""

    def test_the_summary_comes_before_the_stories(self):
        markdown = misp_store.render_briefing_markdown(
            _briefing("Two hauliers hit in one week."))
        self.assertIn("Two hauliers hit in one week.", markdown)
        self.assertLess(markdown.index("## Briefing summary"), markdown.index("## Today's stories"))

    def test_no_heading_without_a_summary(self):
        self.assertNotIn("## Briefing summary", misp_store.render_briefing_markdown(_briefing()))


class StalenessFlag(unittest.TestCase):
    """The written object carries the stale marker only where it means something,
    so every reader can trust the flag without re-checking the summary."""

    def _stale(self, data):
        obj = misp_store._briefing_obj(data)
        return misp_store._obj_attr(obj, "summary-stale")

    def test_the_flag_is_written_when_the_stories_moved_on(self):
        self.assertEqual(self._stale({"summary": "A summary.", "summary_stale": True}), "true")

    def test_a_current_summary_carries_no_flag(self):
        self.assertIsNone(self._stale({"summary": "A summary.", "summary_stale": False}))

    def test_a_briefing_without_a_summary_is_never_stale(self):
        self.assertIsNone(self._stale({"summary": "", "summary_stale": True}))


class StaleFlagRoundTrip(unittest.TestCase):
    """The write rules above and the read in _briefing_ns() have to agree on how
    the flag is spelled, or the warning the analyst was shown is gone the next
    time the briefing is opened."""

    def _reread(self, data):
        event = SimpleNamespace(
            uuid="u" * 36, objects=[misp_store._briefing_obj(data)],
            event_reports=[], published=False, publish_timestamp=None,
            timestamp=None, date=None,
        )
        return misp_store._briefing_ns(event)

    def test_a_stale_summary_still_reads_as_stale(self):
        briefing = self._reread({"summary": "A summary.", "summary_stale": True})
        self.assertEqual(briefing.summary, "A summary.")
        self.assertTrue(briefing.summary_stale)

    def test_a_current_summary_reads_as_current(self):
        self.assertFalse(self._reread({"summary": "A summary."}).summary_stale)

    def test_a_briefing_written_before_the_summary_existed_reads_as_neither(self):
        """Older briefings carry no summary attribute at all."""
        briefing = self._reread({"date": "2026-08-08"})
        self.assertEqual(briefing.summary, "")
        self.assertFalse(briefing.summary_stale)


class SummaryJob(unittest.TestCase):
    """The compose form applies whatever a completed job carries, so a summary
    the model declined to write has to fail rather than complete empty."""

    def _run(self, drafted):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch("analyser.llm.draft_briefing_summary", return_value=drafted):
            api._run_briefing_summary_job("job-1", _stories(), "2026-08-08")
        return dict(update.call_args.kwargs)

    def test_a_drafted_summary_completes_the_job_with_the_text(self):
        final = self._run("Two hauliers hit in one week.")
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["result"], {"summary": "Two hauliers hit in one week."})

    def test_an_empty_answer_fails_the_job(self):
        final = self._run("")
        self.assertEqual(final["status"], "failed")
        self.assertIn("empty", final["error"])

    def test_a_broken_model_call_fails_the_job_with_its_reason(self):
        with mock.patch.object(api.job_store, "update_job") as update, \
             mock.patch("analyser.llm.draft_briefing_summary",
                        side_effect=RuntimeError("no API key")):
            api._run_briefing_summary_job("job-1", _stories(), "")
        final = dict(update.call_args.kwargs)
        self.assertEqual(final["status"], "failed")
        self.assertIn("no API key", final["error"])


class StoryOrigin(unittest.TestCase):
    """How a story's text was produced survives a save, or the compose form
    cannot tell an untouched AI draft from one an analyst has reworked."""

    def _written(self, story):
        misp = mock.MagicMock()
        misp_store._write_briefing_story_report(misp, "u" * 36, 1, story)
        report = misp.add_event_report.call_args[0][1]
        return json.loads(report.content)

    def test_the_drafting_state_is_stored_with_the_story(self):
        self.assertEqual(self._written({"content": "text", "drafted_by": "ai"})["drafted_by"], "ai")
        self.assertEqual(self._written({"content": "text", "drafted_by": "ai-edited"})["drafted_by"], "ai-edited")

    def test_a_story_written_by_hand_stores_nothing(self):
        self.assertEqual(self._written({"content": "text"})["drafted_by"], "")


def _stored_briefing():
    """A briefing as it comes back from MISP, with every stored field filled in.

    Empty values are never written to the object, so a field left blank here
    would go unnoticed by the checks below however badly it was handled.
    """
    return SimpleNamespace(
        date="2026-08-08", title="Daily briefing", author="koen", tlp="green",
        review_state="draft", story_count=3,
        escalations="One escalation.", notes="A note.",
        summary="Four of six stories concern EU logistics.", summary_stale=True,
        geographic_scope=["Belgium"], sectors=["Transport"], threat_actors=["Luna Moth"],
        mitre_attack_techniques=["T1566"], threat_types=["Ransomware"],
        technology=["Fortinet"], vendor=["Cisco"], incident=["INC-1"], campaign=["Spider"],
        creator="koen", approved_by="an.earlier.reviewer@example.org",
    )


class BriefingFieldList(unittest.TestCase):
    """_BRIEFING_FIELDS is what publishing rebuilds the object from, so it has to
    stay level with what the object actually holds. An attribute added to
    _briefing_obj() and left out of the list is dropped the moment a briefing is
    published, which is how the summary was lost."""

    def _relations(self):
        return {f.replace("_", "-") for f in misp_store._BRIEFING_FIELDS}

    def test_it_names_exactly_what_the_object_is_written_with(self):
        written = {
            attr.object_relation
            for attr in misp_store._briefing_obj(_stored_briefing().__dict__).attributes
        }
        self.assertEqual(written, self._relations())

    def test_the_misp_object_template_declares_the_same_attributes(self):
        """An attribute the template does not declare still writes, since _oa()
        passes the type itself, but MISP then shows it unnamed on the event."""
        definition = json.loads(
            (Path(misp_store.__file__).parent / "misp_objects" / "objects"
             / "zsazsa-daily-briefing" / "definition.json").read_text()
        )
        self.assertEqual(set(definition["attributes"]), self._relations())


class PublishKeepsTheStoredFields(unittest.TestCase):
    """Publishing deletes the briefing object and writes it again, so a field the
    rewrite does not carry across is lost at the moment the briefing goes out."""

    def _published_object(self):
        briefing = _stored_briefing()
        misp = mock.MagicMock()
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_briefing_ns", return_value=briefing), \
             mock.patch.object(misp_store, "_get_obj", return_value=None), \
             mock.patch.object(misp_store.misp_session, "current_user_email",
                               return_value="reviewer@example.org"):
            misp_store.publish_briefing("u" * 36)
        return misp.add_object.call_args[0][1]

    def test_the_summary_survives_publishing(self):
        obj = self._published_object()
        self.assertEqual(misp_store._obj_attr(obj, "summary"),
                         "Four of six stories concern EU logistics.")
        self.assertEqual(misp_store._obj_attr(obj, "summary-stale"), "true")

    def test_nothing_else_is_dropped_either(self):
        obj = self._published_object()
        for field in misp_store._BRIEFING_FIELDS:
            relation = field.replace("_", "-")
            self.assertIsNotNone(misp_store._obj_attr(obj, relation),
                                 f"publishing dropped {relation}")

    def test_publishing_records_the_new_state_and_approver(self):
        obj = self._published_object()
        self.assertEqual(misp_store._obj_attr(obj, "review-state"), "published")
        self.assertEqual(misp_store._obj_attr(obj, "approved-by"), "reviewer@example.org")


if __name__ == "__main__":
    unittest.main()
