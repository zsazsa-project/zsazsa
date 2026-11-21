"""The stories of an imported report (webapp/report_stories.py) and where they go.

The model is asked in parts of the report, a section with the stories under
it; its cut is taken only at the starts it was offered, and its context only
with values of the galaxies and blocks of the story. Each part, and every few
stories, is saved as it is answered, so a stopped run goes on from there, and
nothing is cut again once the analyst has reviewed. The review is checked: the
stories in order from the first block, and a story made into an event kept in
its place. Making the stories gives each an event under a UUID of its own,
found again by a retry, linked to its report, queued for the threat landscape
and cached; what fails is recorded with what was made. The manifest is saved as
a new attachment before the old one goes. The threat landscape lists a
report's stories together, prefills an entry from its story, and drafts from
a document as one source, trimming its input rather than cutting it.

MISP is an autospec, the model is mocked, the jobs stay in memory.

    python -m unittest tests.test_report_stories
"""

import copy
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import MISPEvent, PyMISP

from analyser import llm
from webapp import job_store, misp_store, report_stories as rs
from webapp.routes import threat_landscape

REPORT_UUID = "5f0c1d2e-0000-4000-8000-000000000001"
KNOWN = {"sectors": {"telecommunications": "Telecommunications", "government": "Government"},
         "geographic_scope": {"china": "China", "belgium": "Belgium"},
         "threat_actors": {"apt28": "APT28"},
         "techniques": {"T1190": "Exploit Public-Facing Application - T1190"}}


def _blocks(spec):
    """Blocks from [(page, kind, text)]."""
    return [{"id": i, "page": page, "kind": kind, "text": text} for i, (page, kind, text) in enumerate(spec)]


BLOCKS = _blocks([(1, "h", "Section II"), (1, "p", "Intro. " * 30), (2, "h", "China"), (2, "p", "China text. " * 40),
                  (3, "h", "Telecom targeting"), (3, "p", "Telecom text. " * 40), (4, "h", "Russia"),
                  (4, "p", "Russia text. " * 40), (5, "h", "Looking ahead"), (5, "p", "Outlook. " * 30)])


def _stories(*specs):
    """Stories from [(start, title, path)], measured against BLOCKS."""
    stories = [rs._story(start, title, list(path), id_=f"s{start:03d}xx") for start, title, path in specs]
    return rs._measure(stories, BLOCKS, len(BLOCKS))


def _report(**fields):
    return SimpleNamespace(**{"uuid": REPORT_UUID, "title": "2026 State of Security", "provider": "Recorded Future",
                              "published": "2026-02-12", "collection_source": "CTI reports", "source_reliability": "B",
                              "source_url": "", "tlp": "clear", "version": 3, **fields})



def setUpModule():
    # The built-in kinds, whatever this install's Settings has.
    patch = mock.patch.object(rs.config, "REPORT_STORY_KINDS", rs.DEFAULT_KINDS, create=True)
    patch.start()
    unittest.addModuleCleanup(patch.stop)

class Parts(unittest.TestCase):
    def test_a_section_goes_with_the_stories_under_it(self):
        stories = [{"start": n, "title": t, "path": p} for n, (t, p) in enumerate([
            ("Opening pages", []), ("Section I", []), ("Conflicts", ["Section I"]), ("Outlook", ["Section I"]),
            ("Section II", []), ("China", ["Section II"]), ("Russia", ["Section II"])])]
        parts = [[s["title"] for s in part] for part in rs._parts(stories)]
        # The opening pages, a part of one, join the part after them.
        self.assertEqual(parts, [["Opening pages", "Section I", "Conflicts", "Outlook"], ["Section II", "China", "Russia"]])

    def test_a_long_section_is_asked_by_its_next_level_or_in_runs(self):
        chapter = [{"start": 0, "title": "1 AI", "path": ["Report"]}]
        chapter += [{"start": n, "title": f"Part {n}", "path": ["Report", "1 AI", f"Area {n // 15}"]} for n in range(1, 45)]
        parts = rs._parts(chapter)
        self.assertTrue(all(len(part) <= 20 for part in parts))
        self.assertEqual(sum(len(part) for part in parts), 45)
        self.assertEqual([s["start"] for part in parts for s in part], list(range(45)))

    def test_a_new_manifest_has_its_drafts_and_the_parts_to_ask(self):
        reading = {"blocks": BLOCKS, "outline": [], "structure": "outline", "outline_skipped": 0, "running": [],
                   "tlp": "", "created": "", "title": "",
                   "drafts": [{"title": "Section II", "start": 0, "path": []}, {"title": "China", "start": 2, "path": ["Section II"]},
                              {"title": "Russia", "start": 6, "path": ["Section II"]}]}
        manifest = rs.new_manifest(reading)
        self.assertEqual([(s["start"], s["end"], s["pages"]) for s in manifest["stories"]],
                         [(0, 2, [1, 1]), (2, 6, [2, 3]), (6, 10, [4, 5])])
        self.assertEqual(len({s["id"] for s in manifest["stories"]}), 3)
        self.assertEqual(manifest["ai"], {"parts": [[0, 10]], "split": [], "closed": False})
        self.assertEqual(rs.calls_left(manifest), 4)


class Kinds(unittest.TestCase):
    """The kinds a story can be, as Settings has them."""

    CONFIGURED = [{"name": "campaign", "description": "One named campaign.", "ticked": True},
                  {"name": "forecast", "description": "What comes next.", "ticked": False}]

    def test_without_kinds_in_settings_the_built_in_ones_are_used(self):
        with mock.patch.object(rs.config, "REPORT_STORY_KINDS", [], create=True):
            self.assertEqual(rs.kind_names(), ["assessment", "incident", "finding", "outlook", "context", "excluded"])
            self.assertEqual(rs.unticked_kinds(), ["outlook", "context"])

    def test_the_kinds_of_settings_are_used_with_left_out_besides_them(self):
        with mock.patch.object(rs.config, "REPORT_STORY_KINDS", self.CONFIGURED, create=True):
            self.assertEqual(rs.kind_names(), ["campaign", "forecast", "excluded"])
            self.assertEqual(rs.unticked_kinds(), ["forecast"])
            self.assertEqual(rs.kind_notes()["campaign"], "One named campaign.")
            self.assertIn("no event is made", rs.kind_notes()["excluded"])
            part = _stories((0, "Section II", []), (2, "China", []))
            cut = rs.apply_split(part, {"stories": [{"start": 0, "title": "A", "kind": "campaign"},
                                                    {"start": 2, "title": "B", "kind": "assessment"}]}, BLOCKS)
        self.assertEqual([s["kind"] for s in cut], ["campaign", ""])

    def test_a_story_keeps_a_kind_settings_no_longer_has(self):
        manifest = {"stories": _stories((0, "Section II", []), (2, "China", []))}
        manifest["stories"][1]["kind"] = "assessment"
        sent = [{"id": s["id"], "start": s["start"], "title": s["title"], "kind": k}
                for s, k in zip(manifest["stories"], ("assessment", "assessment"))]
        with mock.patch.object(rs.config, "REPORT_STORY_KINDS", self.CONFIGURED, create=True):
            stories = rs.review(manifest, sent, BLOCKS, KNOWN)
        # The second story had it; the first is given it now, and may not be.
        self.assertEqual([s["kind"] for s in stories], ["", "assessment"])

    def test_names_are_cleaned_and_kept_once(self):
        cleaned = rs.normalise_kinds([{"name": "Aggregate Finding!", "description": "x"}, {"name": "aggregate-finding"},
                                      {"name": "excluded"}, "not a kind", {"name": ""}])
        self.assertEqual(cleaned, [{"name": "aggregate-finding", "description": "x", "ticked": False}])


class Split(unittest.TestCase):
    def setUp(self):
        self.part = _stories((0, "Section II", []), (2, "China", ["Section II"]), (6, "Russia", ["Section II"]))

    def test_the_part_is_described_by_block(self):
        text = rs.drafts_text(self.part, BLOCKS)
        self.assertIn("Draft 2, first block 2, pages 2 to 3", text)
        self.assertIn("Headings inside: [block 4] Telecom targeting", text)
        self.assertIn("Under: Section II", text)

    def test_drafts_are_merged_and_split_where_the_model_says(self):
        answer = {"stories": [{"start": 0, "title": "China: access to telecoms", "kind": "assessment"},
                              {"start": 4, "title": "Telecom targeting", "kind": "incident"},
                              {"start": 6, "title": "Russia", "kind": "assessment"}]}
        cut = rs.apply_split(self.part, answer, BLOCKS)
        self.assertEqual([(s["start"], s["end"], s["title"], s["kind"]) for s in cut],
                         [(0, 4, "China: access to telecoms", "assessment"), (4, 6, "Telecom targeting", "incident"),
                          (6, 10, "Russia", "assessment")])
        self.assertEqual(cut[0]["id"], self.part[0]["id"])
        self.assertEqual(cut[2]["id"], self.part[2]["id"])
        self.assertEqual(cut[1]["path"], ["Section II", "China"])

    def test_only_the_starts_offered_are_taken(self):
        answer = {"stories": [{"start": 3, "title": "Mid paragraph"}, {"start": "6", "title": "As text"},
                              {"start": 99, "title": "Past the end"}, {"start": 6, "title": "Russia", "kind": "rumour"}]}
        cut = rs.apply_split(self.part, answer, BLOCKS)
        # The first story is kept where the part starts, under its draft's title.
        self.assertEqual([(s["start"], s["title"], s["kind"]) for s in cut], [(0, "Section II", ""), (6, "Russia", "")])
        self.assertIsNone(rs.apply_split(self.part, {"stories": [{"start": 3}]}, BLOCKS))
        self.assertIsNone(rs.apply_split(self.part, {"stories": "none"}, BLOCKS))


class Context(unittest.TestCase):
    def setUp(self):
        self.story = _stories((0, "Section II", []), (2, "China", []))[1]

    def test_only_values_of_the_galaxies_with_a_block_of_the_story_are_kept(self):
        answer = {"summary": "  The publisher assesses   access. ", "period": "2025", "kind": "assessment",
                  "sectors": [{"value": "telecommunications", "block": 3}, {"value": "Space mining", "block": 3},
                              {"value": "Government", "block": 1}, {"value": "Government", "block": "3"}],
                  "geographic_scope": [{"value": "China", "block": 5}, "China"],
                  "threat_actors": [{"value": "APT28", "block": 4}],
                  "techniques": [{"value": "T1190", "block": 5}, {"value": "T9999", "block": 5}],
                  "threat_type": {"value": "malware", "block": 3},
                  "impact": {"text": "Long-term access.", "block": 5}, "motivation": {"text": "Spying.", "block": 0},
                  "mitigation": "patch"}
        context = rs.clean_context(answer, self.story, KNOWN)
        self.assertEqual(context["summary"], "The publisher assesses access.")
        # A block number given as text is still a block number.
        self.assertEqual(context["sectors"], [{"value": "Telecommunications", "block": 3},
                                              {"value": "Government", "block": 3}])
        self.assertEqual(context["geographic_scope"], [{"value": "China", "block": 5}])
        self.assertEqual(context["techniques"], [{"value": "Exploit Public-Facing Application - T1190", "block": 5}])
        self.assertEqual(context["threat_type"], {"value": "Malware", "block": 3})
        self.assertEqual(context["impact"], {"text": "Long-term access.", "block": 5})
        self.assertIsNone(context["motivation"])
        self.assertIsNone(context["mitigation"])
        # What did not hold is listed with why, for the analyst.
        self.assertEqual([(d["field"], d["value"], d["why"]) for d in context["left_out"]], [
            ("sectors", "Space mining", "not in the MISP sector galaxy"),
            ("sectors", "Government", "no paragraph of this story says it"),
            ("geographic_scope", "China", "no paragraph of this story says it"),
            ("techniques", "T9999", "not in the MISP ATT&CK galaxy"),
            ("motivation", "Spying.", "no paragraph of this story says it")])

    def test_a_threat_type_outside_the_list_is_left_out(self):
        context = rs.clean_context({"threat_type": {"value": "Cyber war", "block": 3}}, self.story, KNOWN)
        self.assertIsNone(context["threat_type"])
        self.assertEqual(context["left_out"][0]["why"], "not one of the threat types of a threat landscape")

    def test_an_actor_the_galaxy_does_not_know_is_named_to_the_analyst(self):
        answer = {"threat_actors": [{"value": "Gentlemen", "block": 3}, {"value": "apt28", "block": 3}]}
        context = rs.clean_context(answer, self.story, KNOWN)
        self.assertEqual(context["threat_actors"], [{"value": "APT28", "block": 3}])
        self.assertEqual(context["left_out"], [{"field": "threat_actors", "value": "Gentlemen",
                                                "why": "not in the MISP threat actor galaxy"}])

    def test_the_story_text_has_its_block_numbers(self):
        text = rs.story_blocks(self.story, BLOCKS)
        self.assertTrue(text.startswith("[2] # China\n[3] China text."))
        with mock.patch.object(rs, "_STORY_CHARS", 100):
            self.assertTrue(rs.story_blocks(self.story, BLOCKS).endswith("(The rest of the story is left out.)"))


class Review(unittest.TestCase):
    def setUp(self):
        self.manifest = {"stories": _stories((0, "Section II", []), (2, "China", []), (6, "Russia", []))}

    def sent(self, stories=None):
        return [{k: s.get(k) for k in ("id", "start", "title", "kind", "context", "context_for")}
                for s in stories or self.manifest["stories"]]

    def test_the_analysts_context_is_checked_against_the_galaxies(self):
        sent = self.sent()
        sent[1]["context"] = {"summary": "x", "sectors": [{"value": "government", "block": None},
                                                          {"value": "Invented", "block": 3}],
                              "threat_type": {"value": "Ransomware", "block": None},
                              "impact": {"text": "  ", "block": 3},
                              "left_out": [{"field": "threat_actors", "value": "Gentlemen", "why": "not in the galaxy"}, "x"]}
        stories = rs.review(self.manifest, sent, BLOCKS, KNOWN)
        context = stories[1]["context"]
        self.assertEqual(context["sectors"], [{"value": "Government", "block": None}])
        self.assertEqual(context["threat_type"], {"value": "Ransomware", "block": None})
        self.assertIsNone(context["impact"])
        # What the AI named but could not keep stays for the analyst to see.
        self.assertEqual(context["left_out"], [{"field": "threat_actors", "value": "Gentlemen", "why": "not in the galaxy"}])

    def test_what_the_ai_left_out_sent_as_anything_but_a_list_is_dropped(self):
        for left_out in ({"field": "sectors", "value": "x", "why": "y"}, "sectors", 3):
            with self.subTest(left_out=left_out):
                sent = self.sent()
                sent[1]["context"] = {"summary": "x", "left_out": left_out}
                stories = rs.review(self.manifest, sent, BLOCKS, KNOWN)
                self.assertEqual(stories[1]["context"]["left_out"], [])

    def test_a_story_sent_without_a_kind_has_none(self):
        sent = self.sent()
        sent.insert(2, {"id": "new0000001", "start": 4, "title": "Telecom targeting", "context": None})
        sent[1]["kind"] = ["incident"]
        stories = rs.review(self.manifest, sent, BLOCKS, KNOWN)
        self.assertEqual([s["kind"] for s in stories], ["", "", "", ""])

    def test_a_new_story_is_taken_with_the_path_of_the_one_before(self):
        sent = self.sent()
        sent.insert(2, {"id": "new0000001", "start": 4, "title": "Telecom targeting", "kind": "incident", "context": None})
        self.manifest["stories"][1]["path"] = ["Section II"]
        stories = rs.review(self.manifest, sent, BLOCKS, KNOWN)
        self.assertEqual([(s["start"], s["end"]) for s in stories], [(0, 2), (2, 4), (4, 6), (6, 10)])
        self.assertEqual(stories[2]["path"], ["Section II"])

    def test_a_story_made_into_an_event_keeps_its_place(self):
        self.manifest["stories"][1]["event"] = "e-1"
        moved = self.sent()
        moved[2]["start"] = 7
        merged = [s for s in self.sent() if s["start"] != 2]
        for name, sent in (("moved", moved), ("merged", merged)):
            with self.subTest(name), self.assertRaisesRegex(ValueError, "is a collection event already"):
                rs.review(self.manifest, sent, BLOCKS, KNOWN)
        # What it says stays as it was made, whatever a save sends.
        changed = self.sent()
        changed[1].update(title="Renamed", kind="excluded", context={"summary": "other"})
        kept = rs.review(self.manifest, changed, BLOCKS, KNOWN)
        self.assertEqual((kept[1]["event"], kept[1]["title"], kept[1]["kind"], kept[1]["context"]), ("e-1", "China", "", None))


class LeftOut(unittest.TestCase):
    """Paragraphs the analyst leaves out of the stories."""

    def setUp(self):
        self.manifest = {"stories": _stories((0, "Section II", []), (2, "China", []), (6, "Russia", [])),
                         "skipped": [7]}

    def test_the_paragraphs_left_out_are_checked(self):
        self.assertEqual(rs.review_skipped(self.manifest, [3, 1], BLOCKS), [1, 3])
        for sent in ([99], ["3"], "3", [-1]):
            with self.subTest(sent), self.assertRaisesRegex(ValueError, "could not be read"):
                rs.review_skipped(self.manifest, sent, BLOCKS)

    def test_a_story_made_into_an_event_keeps_what_it_left_out(self):
        self.manifest["stories"][2]["event"] = "e-1"
        self.assertEqual(rs.review_skipped(self.manifest, [3, 8], BLOCKS), [3, 7])

    def test_a_paragraph_left_out_is_not_in_the_story(self):
        story = self.manifest["stories"][1]
        whole = story["chars"]
        rs._measure(self.manifest["stories"], BLOCKS, len(BLOCKS), {3})
        self.assertEqual(story["chars"], whole - len(BLOCKS[3]["text"]))
        self.assertNotIn("China text", rs.story_markdown(_report(), story, BLOCKS, {3}))
        self.assertIn("Telecom text", rs.story_markdown(_report(), story, BLOCKS, {3}))
        self.assertNotIn("[3]", rs.story_blocks(story, BLOCKS, {3}))


class Runs(unittest.TestCase):
    """The model's runs and the making of the events, against a manifest held here."""

    def setUp(self):
        self.enterContext(mock.patch.object(job_store, "_command", return_value=None))
        job_store._memory.clear()
        self.addCleanup(job_store._memory.clear)
        self.job = job_store.create_job("report-ai")["id"]
        stories = _stories((0, "Section II", []), (2, "China", ["Section II"]), (6, "Russia", ["Section II"]))
        self.manifest = {"read": {"blocks": len(BLOCKS)}, "stories": stories,
                         "ai": {"parts": [[0, 10]], "split": [], "closed": False}}
        self.saved = []

        def save(uuid, manifest, version, import_state=""):
            self.saved.append((copy.deepcopy(manifest), version, import_state))
            return version + 1

        for target, kwargs in ((misp_store, {"get_report_document": mock.Mock(return_value=_report()),
                                             "report_manifest": mock.Mock(side_effect=lambda r: self.manifest),
                                             "report_reading": mock.Mock(return_value={"blocks": BLOCKS}),
                                             "save_report_manifest": mock.Mock(side_effect=save)}),
                               (rs, {"galaxies": mock.Mock(return_value=KNOWN)})):
            self.enterContext(mock.patch.multiple(target, **kwargs))

    def test_the_cut_of_each_part_is_saved_as_it_is_answered(self):
        answer = {"stories": [{"start": 0, "title": "China", "kind": "assessment"},
                              {"start": 6, "title": "Russia", "kind": "assessment"}]}
        with mock.patch.object(llm, "split_report_stories", return_value=answer) as ask:
            rs.run_split(self.job, REPORT_UUID)
        self.assertEqual(ask.call_args.args[0]["provider"], "Recorded Future")
        manifest, version, _state = self.saved[-1]
        self.assertEqual([(s["start"], s["title"]) for s in manifest["stories"]], [(0, "China"), (6, "Russia")])
        self.assertEqual((manifest["ai"]["split"], version), ([0], 3))
        # A next run has no part left to ask.
        with mock.patch.object(llm, "split_report_stories") as ask:
            rs.run_split(self.job, REPORT_UUID)
        ask.assert_not_called()

    def test_an_answer_that_cannot_be_used_keeps_the_drafts(self):
        with mock.patch.object(llm, "split_report_stories", return_value=None):
            rs.run_split(self.job, REPORT_UUID)
        self.assertEqual([s["title"] for s in self.saved[-1][0]["stories"]], ["Section II", "China", "Russia"])
        self.assertIn("could not be used", job_store.get_job(self.job)["log"][-1]["message"])

    def test_nothing_is_cut_once_the_analyst_has_reviewed(self):
        self.manifest["ai"]["closed"] = True
        with mock.patch.object(llm, "split_report_stories") as ask:
            rs.run_split(self.job, REPORT_UUID)
        ask.assert_not_called()

    def test_each_story_gets_its_context_and_a_failed_one_is_marked(self):
        self.manifest["stories"][0]["kind"] = "excluded"
        answers = [{"summary": "China.", "kind": "incident", "sectors": [{"value": "Government", "block": 3}]}, None]
        with mock.patch.object(llm, "analyse_report_story", side_effect=answers) as ask:
            rs.run_context(self.job, REPORT_UUID)
        self.assertEqual([c.args[1]["title"] for c in ask.call_args_list], ["China", "Russia"])
        stories = self.saved[-1][0]["stories"]
        self.assertEqual((stories[1]["kind"], stories[1]["context"]["sectors"], stories[1]["context_for"]),
                         ("incident", [{"value": "Government", "block": 3}], [2, 6]))
        self.assertTrue(stories[2]["context_failed"])
        self.assertEqual(rs.calls_left(self.saved[-1][0]), 1)

    def test_contexts_are_saved_every_few_stories(self):
        self.manifest["stories"] = _stories(*[(n, f"Story {n}", []) for n in range(7)])
        with mock.patch.object(llm, "analyse_report_story", return_value={"summary": "x"}):
            rs.run_context(self.job, REPORT_UUID)
        self.assertEqual(len(self.saved), 2)

    def make(self, created=None, queue_problem=""):
        made = created or (lambda report, story, text: (f"event-{story['start']}", True))
        with mock.patch.object(misp_store, "create_report_story", side_effect=made) as self.create, \
                mock.patch.object(misp_store, "product_source_problem", return_value=queue_problem) as self.queue, \
                mock.patch.object(misp_store, "_misp", return_value=mock.create_autospec(PyMISP, instance=True)), \
                mock.patch("webapp.routes.data_collection._refresh_cached_event") as self.cache:
            return rs.run_create(self.job, REPORT_UUID)

    def test_each_story_to_make_is_made_queued_and_cached(self):
        self.manifest["skipped"] = [5]
        self.manifest["stories"][0]["kind"] = "excluded"
        self.manifest["stories"][2]["event"] = "made-before"
        for s in self.manifest["stories"][1:]:
            s["kind"] = s["kind"] or "assessment"
        result = self.make()
        self.assertEqual(result, {"made": 1, "queued": 1, "problems": []})
        report, story, text = self.create.call_args.args
        self.assertEqual(story["title"], "China")
        self.assertTrue(text.startswith("*From 2026 State of Security, Recorded Future, pages 2 to 3.*\n\n### China"))
        self.assertNotIn("Telecom text", text)
        self.assertEqual(self.queue.call_args.args, ("event-2", "threat-landscape-report"))
        self.assertEqual(self.cache.call_args.args[:2], ("event-2", "manual-cti-reports"))
        manifest, _version, state = self.saved[-1]
        self.assertEqual([s["event"] for s in manifest["stories"]], ["", "event-2", "made-before"])
        self.assertEqual(state, "created")

    def test_a_story_that_could_not_be_queued_is_said_so(self):
        result = self.make(queue_problem="MISP refused the tag")
        self.assertEqual(result["queued"], 0)
        self.assertIn("was made but not queued: MISP refused the tag", result["problems"][0])

    def test_a_failure_records_what_was_made_and_stops(self):
        def made(report, story, text):
            if story["start"] == 6:
                raise RuntimeError("MISP is down")
            return f"event-{story['start']}", True
        with self.assertRaisesRegex(RuntimeError, "MISP is down"):
            self.make(created=made)
        manifest, _version, state = self.saved[-1]
        self.assertEqual([s["event"] for s in manifest["stories"]], ["event-0", "event-2", ""])
        self.assertEqual(state, "")


class StoryRecord(unittest.TestCase):
    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.enterContext(mock.patch.object(misp_store, "_misp", return_value=self.misp))
        self.enterContext(mock.patch.object(misp_store, "_galaxy_tag_map", return_value={}))
        self.misp.get_event.return_value = {"errors": (404, {"message": "Invalid event"})}
        def add_event(event, pythonify=True):
            event.id = "77"
            return event

        self.misp.add_event.side_effect = add_event
        self.misp.add_attribute.side_effect = lambda *a, **k: SimpleNamespace(uuid="a")
        self.misp.add_event_report.return_value = {}
        self.misp.tag.return_value = {"saved": True}
        self.story = {**_stories((0, "Section II", []), (2, "China", ["Section II"]))[1], "kind": "assessment",
                      "context": {"summary": "The publisher assesses access.", "period": "2025",
                                  "threat_type": {"value": "Malware", "block": 3},
                                  "sectors": [{"value": "Government", "block": 3}], "techniques": [],
                                  "geographic_scope": [], "threat_actors": [], "impact": {"text": "Access.", "block": 3},
                                  "affected_assets": None, "motivation": None, "mitigation": None}}

    def test_a_story_is_a_manual_entry_linked_to_its_report(self):
        uuid, made = misp_store.create_report_story(_report(), self.story, "*From…*")
        self.assertTrue(made)
        self.assertEqual(uuid, misp_store.story_event_uuid(REPORT_UUID, self.story["id"]))
        self.assertEqual(uuid, misp_store.story_event_uuid(REPORT_UUID, self.story["id"]))
        event = self.misp.add_event.call_args.args[0]
        self.assertEqual((event.uuid, event.extends_uuid, str(event.date), event.info),
                         (uuid, REPORT_UUID, "2026-02-12", "China"))
        local = [c.args[1] for c in self.misp.tag.call_args_list if c.kwargs.get("local")]
        # The report's tag first: the analyser must never see the story without it.
        self.assertEqual(local[:4], [misp_store.report_tag(REPORT_UUID), 'zsazsa:report-kind="assessment"',
                                     misp_store.provider_tag("Recorded Future"), misp_store.TAG_MANUAL_ENTRY])
        obj = self.misp.add_object.call_args.args[1]
        self.assertEqual({k: misp_store._obj_attr(obj, k) for k in ("kind", "pages", "blocks", "threat-type", "impact", "section")},
                         {"kind": "assessment", "pages": "2-5", "blocks": "2-9", "threat-type": "Malware",
                          "impact": "Access.", "section": "Section II"})
        self.assertEqual(json.loads(misp_store._obj_attr(obj, "evidence"))["sectors"], [{"value": "Government", "block": 3}])

    def test_a_story_an_earlier_try_made_is_left_as_it_is(self):
        self.misp.get_event.return_value = MISPEvent()
        uuid, made = misp_store.create_report_story(_report(), self.story, "")
        self.assertFalse(made)
        self.misp.add_event.assert_not_called()

    def test_a_story_that_cannot_be_made_whole_is_deleted_again(self):
        self.misp.add_object.return_value = {"errors": "no template"}
        with self.assertRaises(RuntimeError):
            misp_store.create_report_story(_report(), self.story, "")
        self.misp.delete_event.assert_called_once()

    def test_the_tags_say_whose_story_it_is(self):
        tags = [misp_store.report_tag(REPORT_UUID), 'zsazsa:report-kind="outlook"', "tlp:clear"]
        self.assertEqual((misp_store.report_of(tags), misp_store.story_kind(tags)), (REPORT_UUID, "outlook"))
        self.assertEqual((misp_store.report_of(["tlp:clear"]), misp_store.story_kind([])), ("", ""))


class ManifestSave(unittest.TestCase):
    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.enterContext(mock.patch.object(misp_store, "_misp", return_value=self.misp))
        event = MISPEvent()
        event.uuid, event.id = REPORT_UUID, "41"
        event.add_tag(misp_store.TAG_REPORT_DOCUMENT)
        event.add_object(misp_store._report_document_obj({"title": "T", "version": 3, "manifest": "old-file", "stories": 2}))
        self.misp.get_event.return_value = event
        self.misp.add_attribute.side_effect = lambda *a, **k: SimpleNamespace(uuid="new-file")
        self.misp.delete_attribute.return_value = {}

    def test_the_new_manifest_is_attached_before_the_old_one_goes_for_good(self):
        self.misp.update_object.return_value = {}
        version = misp_store.save_report_manifest(REPORT_UUID, {"stories": [1, 2, 3]}, 3, import_state="reviewed")
        self.assertEqual(version, 4)
        obj = self.misp.update_object.call_args.args[0]
        self.assertEqual({k: misp_store._obj_attr(obj, k) for k in ("manifest", "stories", "version", "import-state")},
                         {"manifest": "new-file", "stories": "3", "version": "4", "import-state": "reviewed"})
        self.misp.delete_attribute.assert_called_once_with("old-file", hard=True)

    def test_a_record_that_could_not_be_changed_keeps_its_manifest(self):
        self.misp.update_object.return_value = {"errors": "refused"}
        with self.assertRaises(RuntimeError):
            misp_store.save_report_manifest(REPORT_UUID, {"stories": []}, 3)
        self.misp.delete_attribute.assert_called_once_with("new-file", hard=True)

    def test_each_manifest_has_a_name_misp_has_not_seen_on_the_event(self):
        """MISP refuses an attribute with the value of one the event has, and
        a manifest is attached before the one it replaces goes."""
        names = []

        def add_attribute(_uuid, attr, pythonify=True):
            if attr.value in names:
                return {"errors": (403, {"errors": {"value": ["A similar attribute already exists for this event."]}})}
            names.append(attr.value)
            return SimpleNamespace(uuid=f"file-{len(names)}")

        self.misp.add_attribute.side_effect = add_attribute
        self.misp.update_object.return_value = {}
        created = MISPEvent()
        created.uuid, created.id = REPORT_UUID, "41"
        self.misp.add_event.return_value = created
        self.misp.tag.return_value = {}
        misp_store.create_report_document({"title": "T", "provider": "P", "tlp": "clear", "filename": "r.pdf",
                                           "version": 1}, b"%PDF", {}, {"stories": []})
        for version in (1, 2):
            event = MISPEvent()
            event.uuid, event.id = REPORT_UUID, "41"
            event.add_tag(misp_store.TAG_REPORT_DOCUMENT)
            event.add_object(misp_store._report_document_obj({"title": "T", "version": version, "manifest": "m"}))
            self.misp.get_event.return_value = event
            misp_store.save_report_manifest(REPORT_UUID, {"stories": []}, version)
        manifests = [n for n in names if n.startswith("manifest")]
        self.assertEqual(len(set(manifests)), 3)

    def test_a_manifest_saved_since_is_not_overwritten(self):
        with self.assertRaises(misp_store.ReportChanged):
            misp_store.save_report_manifest(REPORT_UUID, {"stories": []}, 2)
        self.misp.add_attribute.assert_not_called()


class Landscape(unittest.TestCase):
    def queued(self, uuid, kind="", report=REPORT_UUID, date="2026-02-12"):
        tags = [misp_store.report_tag(report), f'zsazsa:report-kind="{kind}"'] if kind else []
        return {"uuid": uuid, "info": uuid, "date": date, "tags": tags, "source_id": "manual-cti-reports"}

    def test_a_reports_stories_are_listed_together_where_the_first_is(self):
        events = [self.queued("s1", "assessment"), self.queued("plain"), self.queued("s2", "outlook"),
                  self.queued("orphan", "incident", report="9" * 8 + "-0000-4000-8000-000000000009")]
        rows = threat_landscape._queue_rows(events, {REPORT_UUID: _report()})
        self.assertEqual([(r[0], [e["uuid"] for e in r[2]] if r[0] == "report" else r[1]["uuid"]) for r in rows],
                         [("report", ["s1", "s2"]), ("event", "plain"), ("event", "orphan")])
        self.assertEqual(events[2]["story_kind"], "outlook")

    def test_an_entry_from_a_story_has_its_reviewed_context(self):
        story = {"threat_type": "Malware", "impact": "Access.", "affected_assets": "", "motivation": "", "mitigation": "",
                 "pages": "12-14"}
        with mock.patch.object(misp_store, "report_story_details", return_value=story):
            entry = threat_landscape._entry_from_event(self.queued("s1", "assessment"), {}, {REPORT_UUID: _report()})
        self.assertEqual((entry["threat_type"], entry["impact"]), ("Malware", "Access."))
        self.assertEqual(entry["note"], "From 2026 State of Security, Recorded Future, pages 12 to 14.")
        self.assertNotIn("motivation", {k for k, v in entry.items() if v})
        plain = threat_landscape._entry_from_event(self.queued("plain"), {}, {REPORT_UUID: _report()})
        self.assertNotIn("note", plain)

    def test_a_story_of_a_deleted_threat_report_keeps_its_context(self):
        story = {"threat_type": "Malware", "impact": "Access.", "affected_assets": "", "motivation": "", "mitigation": "",
                 "pages": "12-14"}
        with mock.patch.object(misp_store, "report_story_details", return_value=story):
            entry = threat_landscape._entry_from_event(self.queued("s1", "assessment"), {}, {})
        self.assertEqual((entry["threat_type"], entry["impact"]), ("Malware", "Access."))
        self.assertNotIn("note", {k for k, v in entry.items() if v})

    def test_a_document_is_drafted_from_the_stories_queued(self):
        manifest = {"stories": [{"title": "China", "kind": "assessment", "event": "s1",
                                 "context": {"summary": "Access.", "period": "2025"}},
                                {"title": "Pitch", "kind": "excluded", "event": ""},
                                {"title": "Outlook", "kind": "outlook", "event": "s2", "context": None}]}
        with mock.patch.object(misp_store, "report_manifest", return_value=manifest):
            documents = threat_landscape._documents([self.queued("s1", "assessment"), self.queued("s2", "outlook"),
                                                     self.queued("plain")], {REPORT_UUID: _report()})
        self.assertEqual(list(documents), [REPORT_UUID])
        self.assertEqual(list(documents.values()), [{"title": "2026 State of Security", "publisher": "Recorded Future",
                                      "published": "2026-02-12",
                                      "stories": [{"title": "China", "kind": "assessment", "period": "2025", "summary": "Access."},
                                                  {"title": "Outlook", "kind": "outlook", "period": "", "summary": ""}]}])

    def test_the_drafts_input_is_trimmed_rather_than_cut(self):
        events = [{"title": f"Event {n}", "date": f"2026-02-{28 - n:02d}"} for n in range(40)]
        documents = [{"title": "D", "publisher": "P", "published": "", "stories": [
            {"title": f"Story {n}", "kind": "assessment", "period": "", "summary": "s" * 600} for n in range(30)]}]
        payload = {"reporting_period": "Q1", "events": events, "documents": documents}
        with mock.patch.object(llm, "_TRENDS_INPUT_CHARS", 3000):
            text = llm._trends_input(payload)
        data = json.loads(text)
        self.assertLessEqual(len(text), 3000)
        self.assertTrue(all(len(s["summary"]) <= 300 for s in data["documents"][0]["stories"]))
        # The newest events stay, and every document keeps stories.
        self.assertEqual(data["events"][:1], events[:1])
        self.assertTrue(data["documents"][0]["stories"])

    def test_the_draft_is_given_its_documents(self):
        with mock.patch.object(llm, "_call", return_value='{"outlook": "x"}') as call, \
                mock.patch.object(llm, "_feature_cfg", return_value={}), \
                mock.patch.object(llm, "_build_system_prompt", return_value="system"):
            llm.draft_landscape_trends("Q1", [{"title": "E"}],
                                       [{"title": "D", "stories": [{"kind": "watch-list", "summary": "s"}]}],
                                       {"watch-list": "Actors to keep an eye on.", "outlook": "Forecasts."})
        sent = json.loads(call.call_args.args[1])
        self.assertEqual((sent["events"], sent["documents"][0]["title"]), ([{"title": "E"}], "D"))
        # What a kind Settings added means, for the kinds of the stories sent.
        self.assertEqual(sent["kinds"], {"watch-list": "Actors to keep an eye on."})


class Prompts(unittest.TestCase):
    def call(self, function, *args, answer='{"stories": []}'):
        with mock.patch.object(llm, "_call", return_value=answer) as call, \
                mock.patch.object(llm, "_feature_cfg", return_value={}), \
                mock.patch.object(llm, "_build_system_prompt", return_value="system"):
            result = function(*args)
        return result, call

    def test_the_report_text_is_sent_as_untrusted_material(self):
        meta = {"title": "2026 State of Security", "provider": "Recorded Future", "published": "2026-02-12"}
        kinds = [{"name": "campaign", "description": "One named campaign.", "ticked": True}]
        _result, call = self.call(llm.split_report_stories, meta, "Draft 1 ...", kinds)
        self.assertEqual(call.call_args.kwargs["feature"], "split_report_stories")
        # The kinds Settings has, outside the fence: they are not the report's.
        self.assertTrue(call.call_args.args[1].startswith('Kinds:\n- "campaign": One named campaign.'))
        self.assertIn(llm._UNTRUSTED_FENCE + "\nReport: 2026 State of Security", call.call_args.args[1])
        self.assertIn("Draft 1 ...", call.call_args.args[1].split(llm._UNTRUSTED_FENCE)[1])
        _result, call = self.call(llm.analyse_report_story, meta, {"title": "China", "path": ["Section II"]},
                                  "[2] # China", kinds, ["Government"], ["Malware"], answer='{"summary": "x"}')
        message = call.call_args.args[1]
        fenced = message.split(llm._UNTRUSTED_FENCE)[1]
        self.assertTrue(message.startswith('Kinds:\n- "campaign"'))
        self.assertIn("Threat types: Malware", message.split(llm._UNTRUSTED_FENCE)[0])
        self.assertIn("Story: China", fenced)
        self.assertIn("Under: Section II", fenced)
        self.assertIn("[2] # China", fenced)

    def test_an_answer_that_is_no_object_is_none(self):
        with self.assertLogs("analyser.llm", "ERROR"):
            result, _call = self.call(llm.split_report_stories, {}, "x", rs.DEFAULT_KINDS, answer="Here are the stories")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
