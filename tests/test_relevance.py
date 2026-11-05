"""The relevance verdict: one model call per event, for the alerts and the briefing.

The model names its grounds, and they are checked before they count. A focus
point has to be one in the settings, or a synonym of a threat actor that is,
which then counts as that actor; a requirement has to be one that was sent, and
a PIR set to "Won't have" never is. Each ground needs a quote of four words or
more that is in the text the model was given, case and whitespace aside: in the
demo, "Energy" was the ground for articles about a supermarket outage and a
robotic arm. One shortened with an ellipsis has its parts in order, each of two
words or more. A "yes" left without a ground is a "no", except a briefing story
that is in as a major development, when that rule is on.

A verdict is kept and reused until what it was judged against changes: the
focus points, the requirements, the prompt or the model. An answer that cannot
be read leaves the event to be judged by the next run, up to three times; a
call that fails outright does not count towards those.

The publication date the model reads is not used when it is after the event's
own date. Without one, a manual entry's or another server's event date stands
in, but never a scraper event's, which is the day of the scrape. Timeliness
comes from that date: an alert needs an article at most three days old and a
story one at most a week, and an article whose date is not known fails neither.
A PIR may give an alert only with a priority of "Must have" or "Should have";
a focus point or a GIR always may.

An analyst's cti-evaluation relevance score pushes an event past the verdict:
very high into the alerts and the briefing, high into the briefing; low or
lower pulls it out of both. Their other scores take the model's place in the
limits, and their overall score the calculated one.

Each focus point goes to the model with its type, from the galaxy it is in.

The database is temporary; MISP and the model are stubbed.

    python -m unittest tests.test_relevance
"""

import os
import tempfile
import unittest
from datetime import date
from types import SimpleNamespace
from unittest import mock

import config
from analyser import event_state, relevance
from analyser.relevance import Judge
from analyser.sources import Reading, Source
from core import db

SCRAPER = Source("scraper", "scraper", "MISP scraper", None, True)
MANUAL = Source("manual", "manual", "Manual entries", None, True)
PIR = SimpleNamespace(uuid="p" * 36, pir_id="PIR-00002", question="Which actors phish Belgian banks?",
                      priority="Must have")
COULD = SimpleNamespace(uuid="c" * 36, pir_id="PIR-00003", question="Who targets our suppliers?",
                        priority="Could have")
WONT = SimpleNamespace(uuid="w" * 36, pir_id="PIR-00004", question="Old question", priority="Won't have")
GIR = SimpleNamespace(uuid="g" * 36, gir_id="GIR-00001", topic="Fraud in the Benelux")
ARTICLE = "A ransomware gang hit a grid operator in Belgium. Cozy Bear phished the bank's staff."
FOCUS = {"FOCUS_POINTS_SECTORS": ["Energy"], "FOCUS_POINTS_GEOGRAPHIES": ["Belgium"],
         "FOCUS_POINTS_THREAT_ACTORS": ["APT29"], "FOCUS_POINTS_THREAT_TYPES": ["Phishing", "ransomware"],
         "FOCUS_POINTS_VENDORS": ["Fortinet"], "FOCUS_POINTS_TECHNOLOGIES": ["VPN"]}
GALAXIES = {
    relevance.misp_store.GALAXY_COUNTRY: ["Belgium"],
    relevance.misp_store.GALAXY_TARGET_INFORMATION: ["Benelux"],
    relevance.misp_store.GALAXY_SECTOR: ["Energy"],
    relevance.misp_store.GALAXY_THREAT_ACTOR: ["APT29"],
    relevance.misp_store.GALAXY_MITRE_ATTACK: ["Phishing - T1566"],
}


def _answer(alert=(), briefing=(), alert_yes=None, briefing_yes=None, major=False, published="2026-10-30",
            scores=None):
    def part(grounds, yes):
        return {"relevant": bool(grounds) if yes is None else yes,
                "grounds": [{"name": name, "quote": quote} for name, quote in grounds], "reason": "Because."}
    return {"alert": part(alert, alert_yes), "briefing": {**part(briefing, briefing_yes), "major_development": major},
            "scores": scores or {}, "publication_date": published, "source_type": "news-report"}


def _event(uuid="e" * 36, day="2026-10-30"):
    return SimpleNamespace(uuid=uuid, info="Grid operator hit", date=date.fromisoformat(day))


class JudgeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patchers = [
            mock.patch.object(config, "DB_FILE", os.path.join(tmp.name, "test.db")),
            mock.patch.multiple(config, create=True, **FOCUS),
            mock.patch.object(relevance.misp_store, "_fetch_galaxy_clusters", side_effect=lambda g: GALAXIES.get(g, [])),
            mock.patch.object(relevance.misp_store, "galaxy_mitre_attack_patterns",
                              return_value=GALAXIES[relevance.misp_store.GALAXY_MITRE_ATTACK]),
            mock.patch.object(relevance.misp_store, "threat_actor_galaxy_meta",
                              return_value={"synonyms": ["Cozy Bear", "The Dukes"]}),
            mock.patch.object(relevance.matching, "get_requirements", return_value=([PIR, COULD, WONT], [GIR])),
            mock.patch.object(relevance.llm, "feature_model", return_value="gpt-4o-mini"),
            mock.patch.object(relevance.llm, "_feature_cfg", return_value={}),
            mock.patch.object(config, "ANALYSER_MAJOR_DEVELOPMENTS", True, create=True),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        self.reading = mock.create_autospec(Reading, instance=True)

    def judge(self, answer, event=None, source=SCRAPER, judge=None, article=ARTICLE, summary="A summary"):
        judge = judge or Judge(self.reading)
        with mock.patch.object(relevance.llm, "judge_relevance", **(
                {"side_effect": answer} if isinstance(answer, Exception) else {"return_value": answer})) as asked:
            verdict = judge.verdict(event or _event(), source, article, summary)
        self.asked = asked
        return verdict


class FocusPoints(JudgeTest):
    def test_each_is_sent_with_the_type_its_galaxy_gives(self):
        lines = [relevance._line(p) for p in relevance.focus_points()]
        self.assertEqual(lines, ["Belgium (country)", "Energy (sector)",
                                 "APT29 (threat actor; also known as Cozy Bear, The Dukes)",
                                 "Phishing (technique, ATT&CK T1566)", "ransomware (threat type)",
                                 "Fortinet (vendor)", "VPN (technology)"])

    def test_a_name_its_galaxy_does_not_have_is_marked_and_sent_with_its_list_s_type(self):
        """The demo had "Luxemburg"; the country galaxy has "Luxembourg"."""
        with mock.patch.object(config, "FOCUS_POINTS_GEOGRAPHIES", ["Luxemburg", "Benelux"]):
            points = {p["name"]: (p["type"], p["found"]) for p in relevance.focus_points()}
        self.assertEqual(points["Luxemburg"], ("geography", False))
        self.assertEqual(points["Benelux"], ("region", True))


class Grounds(JudgeTest):
    def test_a_ground_quoted_from_the_article_counts(self):
        verdict = self.judge(_answer(briefing=[("Energy", "hit a GRID operator  in Belgium")]))
        self.assertTrue(verdict["briefing"]["relevant"])
        self.assertEqual(verdict["briefing"]["grounds"],
                         [{"focus_point": "Energy", "quote": "hit a GRID operator  in Belgium"}])

    def test_one_without_a_quote_from_it_does_not_and_a_yes_without_grounds_is_a_no(self):
        verdict = self.judge(_answer(briefing=[("Energy", "a supermarket delivery outage")]))
        self.assertFalse(verdict["briefing"]["relevant"])
        self.assertEqual(verdict["briefing"]["reason"], "None of the grounds the model gave is quoted from the article")

    def test_a_word_or_two_is_no_quote(self):
        """"grid operator" is in the article, but so is a word like "it" in
        almost any article: a ground needs the passage that concerns it."""
        for quote in ("grid operator", "grid ... grid ... grid ... grid"):
            with self.subTest(quote=quote):
                verdict = self.judge(_answer(briefing=[("Energy", quote)]))
                self.assertEqual(verdict["briefing"]["grounds"], [])

    def test_a_quote_from_the_summary_is_none_from_the_article(self):
        """The summary is a model's account of the article, not the source's words."""
        verdict = self.judge(_answer(briefing=[("Energy", "a summary written by the model")]),
                             summary="A summary written by the model about energy.")
        self.assertEqual(verdict["briefing"]["grounds"], [])

    def test_a_quote_shortened_with_an_ellipsis_counts_when_each_part_is_there(self):
        verdict = self.judge(_answer(alert=[("Belgium", "A ransomware gang ... in Belgium")]))
        self.assertTrue(verdict["alert"]["relevant"])

    def test_words_picked_from_all_over_the_article_are_no_quote(self):
        """Each is in the article, but on its own, and not in that order."""
        for quote in ("ransomware ... grid ... belgium ... operator", "in Belgium ... A ransomware gang"):
            with self.subTest(quote=quote):
                verdict = self.judge(_answer(alert=[("Belgium", quote)]))
                self.assertEqual(verdict["alert"]["grounds"], [])

    def test_a_synonym_counts_as_its_threat_actor(self):
        verdict = self.judge(_answer(alert=[("Cozy Bear", "Cozy Bear phished the bank's staff")]))
        self.assertEqual(verdict["alert"]["grounds"][0]["focus_point"], "APT29")

    def test_a_name_that_is_no_focus_point_or_requirement_does_not_count(self):
        verdict = self.judge(_answer(alert=[("IT", "A ransomware gang hit")]))
        self.assertEqual(verdict["alert"]["grounds"], [])

    def test_a_requirement_counts_by_its_id_and_a_won_t_have_never_does(self):
        verdict = self.judge(_answer(briefing=[("PIR-00002", "phished the bank's staff"),
                                               ("PIR-00004", "phished the bank's staff")]))
        self.assertEqual(verdict["briefing"]["grounds"],
                         [{"requirement": PIR.uuid, "id": "PIR-00002", "quote": "phished the bank's staff"}])

    def test_a_requirement_without_an_id_is_no_ground_for_a_name_left_empty(self):
        unnamed = SimpleNamespace(uuid="u" * 36, pir_id="", question="Draft question", priority="Must have")
        with mock.patch.object(relevance.matching, "get_requirements", return_value=([unnamed], [])):
            verdict = self.judge(_answer(alert=[("", "hit a grid operator in Belgium")]))
        self.assertEqual(verdict["alert"]["grounds"], [])

    def test_a_major_development_needs_no_ground_for_the_briefing_only(self):
        verdict = self.judge(_answer(alert_yes=True, briefing_yes=True, major=True))
        self.assertTrue(verdict["briefing"]["relevant"])
        self.assertTrue(verdict["briefing"]["major_development"])
        self.assertFalse(verdict["alert"]["relevant"])

    def test_not_when_the_rule_is_off(self):
        with mock.patch.object(config, "ANALYSER_MAJOR_DEVELOPMENTS", False, create=True):
            verdict = self.judge(_answer(briefing_yes=True, major=True))
        self.assertFalse(verdict["briefing"]["relevant"])


class Kept(JudgeTest):
    def test_a_verdict_is_reused_until_what_it_was_judged_against_changes(self):
        answer = _answer(briefing=[("Energy", "hit a grid operator in Belgium")])
        self.judge(answer)
        self.judge(answer)
        self.asked.assert_not_called()
        with mock.patch.object(config, "FOCUS_POINTS_SECTORS", ["Energy", "Finance"]):
            self.judge(answer)
        self.asked.assert_called_once()

    def test_an_article_that_changed_is_judged_again(self):
        """Its old verdict quoted text that is not there any more."""
        answer = _answer(briefing=[("Energy", "hit a grid operator in Belgium")])
        self.judge(answer)
        self.judge(answer)
        self.asked.assert_not_called()
        self.judge(answer, article="Another article about a grid operator.")
        self.asked.assert_called_once()

    def test_the_model_changing_judges_it_again(self):
        self.judge(_answer())
        with mock.patch.object(relevance.llm, "feature_model", return_value="gpt-5"):
            self.judge(_answer())
        self.asked.assert_called_once()

    def test_it_is_kept_per_source(self):
        self.judge(_answer())
        self.assertIsNotNone(event_state.load("scraper", "e" * 36)["verdict"])
        self.assertIsNone(event_state.load("partner", "e" * 36)["verdict"])


class NoAnswer(JudgeTest):
    def test_an_answer_that_cannot_be_read_is_tried_again_three_times(self):
        for attempt in (1, 2):
            self.assertIsNone(self.judge(None))
            self.assertEqual(self.reading.retry.call_count, attempt)
        with self.assertLogs(relevance.logger, "WARNING"):
            self.assertIsNone(self.judge(None))
        # Left for the analyst.
        self.assertEqual(self.reading.retry.call_count, 2)

    def test_a_call_that_fails_is_tried_again_without_using_up_an_attempt(self):
        with self.assertLogs(relevance.logger, "WARNING"):
            self.assertIsNone(self.judge(ConnectionError("Connection error.")))
        self.reading.retry.assert_called_once_with("e" * 36)
        self.assertEqual(event_state.load("scraper", "e" * 36)["attempts"], 0)

    def test_a_verdict_starts_the_count_again(self):
        self.judge(None)
        self.judge(_answer())
        self.assertEqual(event_state.load("scraper", "e" * 36)["attempts"], 0)


class PublicationDate(JudgeTest):
    def test_the_article_s_own_date_is_used(self):
        verdict = self.judge(_answer(published="2026-10-28"))
        self.assertEqual((verdict["published"], verdict["published_from"]), ("2026-10-28", "article"))

    def test_one_after_the_event_s_own_date_is_not(self):
        verdict = self.judge(_answer(published="2026-11-02"))
        self.assertIsNone(verdict["published"])

    def test_without_one_a_manual_entry_s_date_stands_in_but_not_a_scraper_event_s(self):
        """A scraper event is dated the day it was scraped."""
        self.assertEqual(self.judge(_answer(published=None), source=MANUAL)["published"], "2026-10-30")
        self.assertIsNone(self.judge(_answer(published="not a date"), event=_event("f" * 36))["published"])


class Wanted(JudgeTest):
    def wants(self, answer, product, today="2026-10-31"):
        """Each answer is about an event of its own, so no verdict is reused."""
        judge = Judge(self.reading)
        self.events = getattr(self, "events", 0) + 1
        verdict = self.judge(answer, event=_event(f"{self.events:036d}"), judge=judge)
        with mock.patch.object(relevance, "datetime") as clock:
            clock.now.return_value.date.return_value = date.fromisoformat(today)
            return judge.wants(verdict, product, SimpleNamespace(tags=[]))

    def test_an_alert_needs_an_article_at_most_three_days_old(self):
        answer = _answer(alert=[("Energy", "hit a grid operator in Belgium")], published="2026-10-28")
        self.assertTrue(self.wants(answer, "alert")[0])
        self.assertEqual(self.wants(answer, "alert", today="2026-11-01"),
                         (False, "Its timeliness score is under the limit for the alerts"))

    def test_a_story_one_at_most_a_week(self):
        answer = _answer(briefing=[("Energy", "hit a grid operator in Belgium")], published="2026-10-25")
        self.assertTrue(self.wants(answer, "briefing")[0])
        self.assertFalse(self.wants(answer, "briefing", today="2026-11-02")[0])

    def test_an_article_whose_date_is_not_known_fails_neither(self):
        answer = _answer(alert=[("Energy", "hit a grid operator in Belgium")], published=None)
        self.assertTrue(self.wants(answer, "alert", today="2027-01-01")[0])

    def test_a_pir_gives_an_alert_only_with_a_high_enough_priority(self):
        could = _answer(alert=[("PIR-00003", "hit a grid operator in Belgium")])
        self.assertEqual(self.wants(could, "alert"), (False, "Its only grounds are PIRs whose priority gives no alert"))
        self.assertTrue(self.wants(_answer(alert=[("PIR-00002", "hit a grid operator in Belgium")]), "alert")[0])

    def test_a_focus_point_or_a_gir_always_may(self):
        for grounds in ([("PIR-00003", "hit a grid operator in Belgium"), ("Energy", "hit a grid operator in Belgium")],
                        [("PIR-00003", "hit a grid operator in Belgium"), ("GIR-00001", "hit a grid operator in Belgium")]):
            with self.subTest(grounds=grounds):
                self.assertTrue(self.wants(_answer(alert=grounds), "alert")[0])

    def wants_with_scores(self, answer, product, *scores):
        judge = Judge(self.reading)
        event = _event()
        verdict = self.judge(answer, event=event, judge=judge)
        event.tags = [SimpleNamespace(name=f'cti-evaluation:{dim}="{level}"') for dim, level in scores]
        with mock.patch.object(relevance, "datetime") as clock:
            clock.now.return_value.date.return_value = date(2026, 10, 31)
            return judge.wants(verdict, product, event)

    def test_an_analyst_pushes_an_event_past_the_verdict(self):
        """Very high relevance pushes to an alert and to the briefing, high to the briefing."""
        no = _answer()
        self.assertTrue(self.wants_with_scores(no, "alert", ("relevance", "very-high"))[0])
        self.assertEqual(self.wants_with_scores(no, "briefing", ("relevance", "high")),
                         (True, "Pushed by an analyst, who scored its relevance high"))
        self.assertFalse(self.wants_with_scores(no, "alert", ("relevance", "high"))[0])
        self.assertFalse(self.wants_with_scores(no, "briefing", ("relevance", "moderate"))[0])

    def test_and_pulls_one_out(self):
        yes = _answer(alert=[("Energy", "hit a grid operator in Belgium")], briefing=[("Energy", "hit a grid operator in Belgium")])
        for product in ("alert", "briefing"):
            with self.subTest(product=product):
                self.assertEqual(self.wants_with_scores(yes, product, ("relevance", "very-low")),
                                 (False, "An analyst scored its relevance very-low"))

    def test_an_analyst_s_score_takes_the_model_s_place_in_the_limits(self):
        with mock.patch.object(config, "ANALYSER_ALERT_MIN_USEFULNESS", "high", create=True):
            useful = _answer(alert=[("Energy", "hit a grid operator in Belgium")], scores={"usefulness": "very-high"})
            self.assertFalse(self.wants_with_scores(useful, "alert", ("usefulness", "low"))[0])
            useless = _answer(alert=[("Energy", "hit a grid operator in Belgium")], scores={"usefulness": "low"})
            self.assertTrue(self.wants_with_scores(useless, "alert", ("usefulness", "high"))[0])

    def test_the_briefing_ranks_by_the_highest_pir_priority(self):
        judge = Judge(self.reading)
        verdict = self.judge(_answer(briefing=[("PIR-00003", "hit a grid operator in Belgium"),
                                               ("PIR-00002", "phished the bank's staff")]),
                             judge=judge)
        self.assertEqual(judge.pir_priority(verdict), 0)


class Scores(unittest.TestCase):
    def test_the_overall_score_is_the_average_of_those_scored(self):
        verdict = {"scores": {"usefulness": "high", "specificity": "moderate", "clarity": "low"}, "published": None}
        self.assertEqual(relevance.overall(verdict), (75 + 50) / 2)
        self.assertIsNone(relevance.overall({"scores": {}, "published": None}))

    def test_its_weights_are_the_settings(self):
        verdict = {"scores": {"usefulness": "very-high", "specificity": "low"}, "published": None}
        with mock.patch.object(config, "ANALYSER_WEIGHT_SPECIFICITY", 3, create=True):
            self.assertEqual(relevance.overall(verdict), (100 + 3 * 25) / 4)

    def test_an_analyst_s_overall_score_takes_its_place(self):
        verdict = {"scores": {"usefulness": "very-high"}, "published": None}
        event = SimpleNamespace(tags=[SimpleNamespace(name='cti-evaluation:overall-score="low"')])
        self.assertEqual(relevance.overall(verdict, event), 25)

    def test_timeliness_follows_the_article_s_age(self):
        for published, expected in (("2026-10-31", "very-high"), ("2026-10-28", "high"), ("2026-10-24", "moderate"),
                                    ("2026-10-01", "low"), ("2026-09-01", "very-low")):
            with self.subTest(published=published):
                self.assertEqual(relevance.timeliness({"published": published}, date(2026, 10, 31)), expected)


if __name__ == "__main__":
    unittest.main()
