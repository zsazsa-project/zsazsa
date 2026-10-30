"""What the analyser's drafts start with, and a run one model call fails on.

An alert or advisory cannot be published without an audience, and the analyser
left it empty on every draft. An alert from a PIR or GIR now takes the roles of
the requirement's owner and of the stakeholders it is distributed to, and falls
back, as an alert from the focus points and an advisory do, to the roles of
everyone the product can reach: its subscribers cleared for its TLP.

A keyword match on a PIR or GIR is only a lead: the model reads the article
against the requirement before an alert is made, and a story an open alert
already tells gets no second one. Each draft says why the analyser made it,
for the list to show under its title: the requirement, the scope items it
matched on and the model's reason, or the CVEs. A CVE that a draft, an
advisory in review or a rejected one covers gets no new advisory: the scraper
reads an updated article again as a new event.

One event the model or MISP fails on no longer ends the run: its summary is
left out, and a briefing relevance check that fails, or whose answer cannot be
read, leaves the story out of the briefing without rejecting its event.

MISP and the model are stubbed.

    python -m unittest tests.test_analyser_drafts
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from webapp import analyser_pipeline, misp_store


def _stakeholder(uuid, role, name="", products=(), tlp="amber"):
    return SimpleNamespace(uuid=uuid, role=role, name=name or uuid, email="", products=list(products),
                           tlp_clearance=tlp)


STAKEHOLDERS = [_stakeholder("owner", "Cyber Threat Intelligence"), _stakeholder("soc", "SOC"),
                _stakeholder("ir", "Incident Response"), _stakeholder("soc2", "SOC")]


class SourceClassification(unittest.TestCase):
    def test_source_tags_can_raise_but_not_lower_the_default(self):
        for tags, default, expected in (
            ([], "amber", "amber"),
            (["tlp:clear"], "amber", "amber"),
            (["tlp:green", "TLP:AMBER_STRICT"], "amber", "amber+strict"),
            (["tlp:red", "tlp:white"], "clear", "red"),
        ):
            with self.subTest(tags=tags, default=default):
                events = [SimpleNamespace(uuid=str(i), tags=[SimpleNamespace(name=name)])
                          for i, name in enumerate(tags)]
                self.assertEqual(misp_store.source_events_tlp(events, default), expected)

    def test_an_unknown_source_classification_is_reported_and_treated_as_red(self):
        event = SimpleNamespace(uuid="restricted", tags=[SimpleNamespace(name="tlp:unknown")])
        with self.assertLogs(misp_store.logger, level="WARNING") as logs:
            self.assertEqual(misp_store.source_events_tlp([event], "amber"), "red")
        self.assertIn("restricted", logs.output[0])


class Audience(unittest.TestCase):
    def test_a_requirement_s_owner_and_distribution(self):
        pir = SimpleNamespace(owner_uuid="owner", distribution=["soc", "soc2"])
        self.assertEqual(misp_store.requirement_audience(pir, STAKEHOLDERS), "Cyber Threat Intelligence, SOC")

    def test_everyone_a_product_can_reach(self):
        subscribed = [_stakeholder("a", "SOC", products=["Flash intel alert"]),
                      _stakeholder("b", "Management", products=["Flash intel alert"], tlp="green"),
                      _stakeholder("c", "Incident Response", products=["Daily threat briefing"])]
        with mock.patch.object(misp_store, "list_stakeholders", return_value=subscribed):
            self.assertEqual(misp_store.subscriber_audience("Flash intel alert", "amber"), "SOC")


class AlertFromARequirement(unittest.TestCase):
    CONFIRMED = {"relevant": True, "matched_focus_points": ["Belgium"], "reason": "Phishing against Belgian banks."}

    def alert(self, pir, manual=False, tlp="", answers=None, open_alerts=(), overlaps=(),
              titles=("Phishing against Belgian banks",), extra_requirements=()):
        """Make the alerts for one event that PIR-0003 and GIR-0001 match.

        `answers` maps a requirement's question to the model's answer about it;
        by default it confirms each."""
        tags = [SimpleNamespace(name=misp_store.TAG_MANUAL_ENTRY)] if manual else []
        if tlp:
            tags.append(SimpleNamespace(name=f"tlp:{tlp}"))
        events = [SimpleNamespace(uuid=c * 36, info=title, tags=tags, galaxies=[]) for c, title in zip("ef", titles)]
        pir.question = "Which actors phish Belgian banks?"
        gir = SimpleNamespace(uuid="g", topic="Fraud in the Benelux", owner_uuid="", distribution=[])
        reports = {e.uuid: [SimpleNamespace(name="Article", content="An article")] for e in events}
        matches = [{"id": "PIR-0003", "uuid": "p", "type": "pir",
                    "matched_terms": ["Belgium (Geography)", "Bank (Sector)"]},
                   {"id": "GIR-0001", "uuid": "g", "type": "gir", "matched_terms": ["Belgium (Geography)"]}]
        matches.extend({"id": req.gir_id, "uuid": req.uuid, "type": "gir", "matched_terms": ["Belgium"]}
                       for req in extra_requirements)
        answers = answers or {}
        created, self.logged = [], []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events",
                               return_value=(None, events, {}, {}, reports)), \
             mock.patch.object(analyser_pipeline.misp_store, "flash_intel_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline, "requirement_matches",
                               return_value={e.uuid: matches for e in events}), \
             mock.patch.object(analyser_pipeline.req_matching, "get_requirements",
                               return_value=([pir], [gir, *extra_requirements])), \
             mock.patch.object(analyser_pipeline.llm, "check_relevance",
                               side_effect=lambda article, scope, reliability: answers.get(
                                   scope["requirement"], self.CONFIRMED)) as self.asked, \
             mock.patch.object(analyser_pipeline, "open_alerts", return_value=list(open_alerts)), \
             mock.patch.object(analyser_pipeline.llm, "detect_story_overlaps",
                               return_value={"overlaps": list(overlaps)}) as self.overlap, \
             mock.patch.object(analyser_pipeline.misp_store, "list_stakeholders", return_value=STAKEHOLDERS), \
             mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="SOC") as reachable, \
             mock.patch.object(analyser_pipeline.misp_store, "create_fia",
                               side_effect=lambda data: created.append(data) or ("u" * 36, f"FIA-0060{len(created)}")), \
             mock.patch.object(analyser_pipeline, "_log",
                               side_effect=lambda e, outcome, detail=None: self.logged.append((outcome, detail))):
            self.result = analyser_pipeline.run_flash_intel_action()
        self.created = created[0] if created else None
        if not created:
            return None, reachable
        self.reason = created[0]["analyser_reason"]
        return created[0]["audience"], reachable

    def test_it_is_for_the_requirement_s_stakeholders(self):
        audience, _reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=["ir"]))
        self.assertEqual(audience, "Cyber Threat Intelligence, Incident Response")

    def test_it_says_what_it_matched_on(self):
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]))
        self.assertEqual(self.reason, "Matches PIR-0003 on Belgium (Geography), Bank (Sector). "
                                      "Phishing against Belgian banks.")

    def test_the_model_judges_the_article_against_the_requirement(self):
        """A single word matched: "M365 Token Spray" went to PIR-003 on "Germany"
        alone, and "AI-Powered Espionage Campaign" to GIR-001 on "Espionage"."""
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[], sectors=["Bank"],
                                   geographic_scope=["Belgium"], out_of_scope=["Caribbean financial services"]))
        article, scope, _reliability = self.asked.call_args_list[0].args
        self.assertEqual(article, "An article")
        self.assertEqual(scope, {"requirement": "Which actors phish Belgian banks?",
                                 "geographic_scope": ["Belgium"], "sectors": ["Bank"],
                                 "out_of_scope": ["Caribbean financial services"]})

    def test_a_match_the_model_turns_down_makes_no_alert(self):
        off = {"relevant": False, "matched_focus_points": [], "reason": "About the Caribbean."}
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]),
                   answers={"Which actors phish Belgian banks?": off, "Fraud in the Benelux": off})
        self.assertIsNone(self.created)
        self.assertEqual(self.logged, [("not_relevant", "PIR-0003, GIR-0001 matched on keywords, "
                                                        "but the model found it not relevant: About the Caribbean.")])

    def test_the_requirement_the_model_confirms_is_the_one_it_is_for(self):
        off = {"relevant": False, "matched_focus_points": [], "reason": "Not a bank."}
        audience, _reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=["ir"]),
                                          answers={"Which actors phish Belgian banks?": off})
        self.assertEqual(audience, "SOC")
        self.assertEqual(self.created["linked_pir_uuid"], "")
        self.assertEqual(self.created["context_tags"], ["match:GIR-0001"])
        self.assertTrue(self.reason.startswith("Matches GIR-0001 on Belgium (Geography)."))

    def test_an_answer_that_cannot_be_read_makes_no_alert(self):
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]),
                   answers={"Which actors phish Belgian banks?": None, "Fraud in the Benelux": None})
        self.assertIsNone(self.created)
        self.assertEqual(self.logged[0][0], "error")
        self.assertEqual(self.asked.call_count, 2)

    def test_a_relevant_requirement_after_the_first_three_is_still_checked(self):
        extra_requirements = [
            SimpleNamespace(uuid="g2", gir_id="GIR-0002", topic="Credential theft", owner_uuid="", distribution=[]),
            SimpleNamespace(uuid="g3", gir_id="GIR-0003", topic="Cloud account takeover", owner_uuid="", distribution=[]),
        ]
        off = {"relevant": False, "matched_focus_points": [], "reason": "Not relevant."}
        answers = {
            "Which actors phish Belgian banks?": off,
            "Fraud in the Benelux": off,
            "Credential theft": off,
        }
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]),
                   answers=answers, extra_requirements=extra_requirements)
        self.assertEqual(self.asked.call_count, 4)
        self.assertEqual(self.created["context_tags"], ["match:GIR-0003"])

    def test_a_story_an_open_alert_already_covers_gets_no_second_one(self):
        """The PHP CVEs got six alerts, one per article about them."""
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]),
                   open_alerts=[{"id": "FIA-00517", "title": "Critical PHP vulnerability", "content": "PHP"}],
                   overlaps=[{"a": 1, "b": 2, "score": 0.8, "reason": "Same CVEs"}])
        self.assertIsNone(self.created)
        self.assertEqual(self.logged, [("not_relevant", "The same story as FIA-00517.")])

    def test_an_alert_made_earlier_in_the_run_counts_as_open(self):
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]),
                   titles=("Inside SiriusQT", "Inside SiriusQT, a skilled RAT"),
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "Same RAT"}])
        self.assertEqual(self.result["created"], 1)
        self.assertEqual(self.overlap.call_args.args[0][1]["id"], "FIA-00601")
        self.assertEqual(self.logged[-1], ("not_relevant", "The same story as FIA-00601."))

    def test_without_their_roles_it_is_for_everyone_it_can_reach(self):
        audience, reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="", distribution=[]))
        self.assertEqual(audience, "SOC")
        reachable.assert_called_once_with("Flash intel alert", "amber")

    def test_a_manual_source_is_saved_with_its_existing_server_hint(self):
        self.alert(SimpleNamespace(uuid="p", owner_uuid="", distribution=[]), manual=True)
        self.assertEqual(self.created["source_event_hints"], {"e" * 36: "webapp"})

    def test_a_restricted_source_is_not_downgraded(self):
        _audience, reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="", distribution=[]),
                                          manual=True, tlp="red")
        self.assertEqual(self.created["tlp"], "red")
        self.assertIn(mock.call("Flash intel alert", "red"), reachable.call_args_list)


class AdvisoryForACoveredCve(unittest.TestCase):
    def run_vea(self, cves_by_title, open_veas=(), manual=False, tlp=""):
        tags = [SimpleNamespace(name=misp_store.TAG_MANUAL_ENTRY)] if manual else []
        if tlp:
            tags.append(SimpleNamespace(name=f"tlp:{tlp}"))
        events = [SimpleNamespace(uuid=f"{i}" * 36, info=title, tags=tags)
                  for i, title in enumerate(cves_by_title, start=1)]
        self.created, self.logged = [], []

        def create(data):
            self.created.append(data)
            return "u" * 36, f"VEA-0010{len(self.created)}"
        with mock.patch.object(analyser_pipeline, "_common_candidate_events",
                               return_value=(None, events, {}, {}, {e.uuid: [] for e in events})), \
             mock.patch.object(analyser_pipeline.collection_cache, "event_cves",
                               side_effect=lambda e: cves_by_title[e.info]), \
             mock.patch.object(analyser_pipeline, "fetch_cve_info", return_value={}), \
             mock.patch.object(analyser_pipeline.llm, "draft_vea_sections", return_value={}), \
             mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="SOC"), \
             mock.patch.object(analyser_pipeline.misp_store, "list_veas", return_value=list(open_veas)), \
             mock.patch.object(analyser_pipeline.misp_store, "create_vea", side_effect=create), \
             mock.patch.object(analyser_pipeline, "_log",
                               side_effect=lambda e, outcome, detail=None: self.logged.append((e.info, detail))):
            return analyser_pipeline.run_vea_action()

    def test_an_updated_article_gets_no_second_advisory(self):
        """Unit 42 retitled a post "(Updated October 25)", and the PHP CVEs got a second draft."""
        draft = SimpleNamespace(vea_id="VEA-00589", review_state="draft", cve_id="CVE-2026-109618\nCVE-2026-109619")
        self.run_vea({"PHP (Updated October 25)": ["CVE-2026-109618", "CVE-2026-109619"]}, [draft])
        self.assertEqual(self.created, [])
        self.assertIn(("PHP (Updated October 25)", "already in an advisory: "
                       "CVE-2026-109618 in VEA-00589, CVE-2026-109619 in VEA-00589"), self.logged)

    def test_one_already_made_in_the_run_counts_too(self):
        self.run_vea({"PHP": ["CVE-2026-109618"], "PHP again": ["CVE-2026-109618"]})
        self.assertEqual([v["title"] for v in self.created], ["PHP"])

    def test_only_its_new_cves_go_in_the_advisory(self):
        draft = SimpleNamespace(vea_id="VEA-00589", review_state="pending-review", cve_id="CVE-2026-109618")
        self.run_vea({"PHP and NetScaler": ["CVE-2026-109618", "CVE-2026-88771"]}, [draft])
        self.assertEqual([(v["cve_id"], v["analyser_reason"]) for v in self.created],
                         [("CVE-2026-88771", "The event names CVE-2026-88771.")])

    def test_an_approved_advisory_does_not_count(self):
        """One already sent says nothing about a new article."""
        done = SimpleNamespace(vea_id="VEA-00388", review_state="approved", cve_id="CVE-2026-110936")
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, [done])
        self.assertEqual([v["cve_id"] for v in self.created], ["CVE-2026-110936"])

    def test_a_rejected_advisory_does(self):
        """An analyst who turned a CVE down got a new draft with every new article about it."""
        rejected = SimpleNamespace(vea_id="VEA-00388", review_state="rejected", cve_id="CVE-2026-110936")
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, [rejected])
        self.assertEqual(self.created, [])
        self.assertIn(("Siemens", "already in an advisory: CVE-2026-110936 in VEA-00388 (rejected)"), self.logged)

    def test_a_manual_source_is_saved_with_its_existing_server_hint(self):
        self.run_vea({"A manual entry": ["CVE-2026-110936"]}, manual=True)
        self.assertEqual(self.created[0]["source_event_hints"], {"1" * 36: "webapp"})

    def test_a_restricted_source_is_not_downgraded(self):
        self.run_vea({"A manual entry": ["CVE-2026-110936"]}, manual=True, tlp="amber+strict")
        self.assertEqual(self.created[0]["tlp"], "amber+strict")


class OneFailedCall(unittest.TestCase):
    def test_a_summary_that_fails_leaves_the_other_events_alone(self):
        """On Saturday a dropped connection ended an advisory run at summary 7 of 12."""
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[]) for c in "abc"]
        article = [SimpleNamespace(name="Article", content="An article")]

        def summarise(misp, event, reports, galaxy_lookup):
            if event.info == "Event b":
                raise ConnectionError("Connection error.")
            return f"Summary of {event.info}", True
        with mock.patch.object(analyser_pipeline, "_refresh_scraper_cache"), \
             mock.patch.object(analyser_pipeline, "_incomplete_scraper_events", return_value=(None, events)), \
             mock.patch.object(analyser_pipeline, "read_event_reports", return_value=article), \
             mock.patch.object(analyser_pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(analyser_pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(analyser_pipeline, "_ensure_ai_summary", side_effect=summarise), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            _misp, kept, summaries, stats, _reports = analyser_pipeline._common_candidate_events()
        self.assertEqual([e.info for e in kept], ["Event a", "Event b", "Event c"])
        self.assertEqual(summaries, {"a" * 36: "Summary of Event a", "b" * 36: "", "c" * 36: "Summary of Event c"})
        self.assertEqual((stats["summary_created"], stats["summary_failed"]), (2, 1))

    def test_a_relevance_check_that_fails_leaves_the_story_for_another_run(self):
        """It was kept, so every story the model could not answer about was briefed."""
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[], galaxies=[]) for c in "abc"]
        created = []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events", return_value=(
                {e.uuid: "misp" for e in events}, events, {}, {"event_decisions": []},
                {e.uuid: [SimpleNamespace(name="Article", content="An article")] for e in events})), \
             mock.patch.object(analyser_pipeline, "daily_briefing_title_exclusions", return_value=[]), \
             mock.patch.object(analyser_pipeline.req_matching, "get_requirements", return_value=([], [])), \
             mock.patch.object(analyser_pipeline.llm, "review_briefing_relevance",
                               side_effect=[ConnectionError("Connection error."), None, {"include": True}]), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_story", return_value=("A story", "")), \
             mock.patch.object(analyser_pipeline.llm, "detect_story_overlaps", return_value={"overlaps": []}), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_summary", return_value="The day"), \
             mock.patch.object(analyser_pipeline, "galaxy_names_with_commas", return_value=frozenset()), \
             mock.patch.object(analyser_pipeline.tagger, "get_source_feed", return_value="feed"), \
             mock.patch.object(analyser_pipeline.tagger, "set_workflow_state") as state, \
             mock.patch.object(analyser_pipeline.misp_store, "extract_source_url", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "briefing_scope_summary", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "create_briefing",
                               side_effect=lambda data: created.append(data) or "u" * 36), \
             mock.patch.object(analyser_pipeline, "log_event"), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            result = analyser_pipeline.run_daily_briefing_action()
        self.assertEqual([s["title"] for s in created[0]["stories"]], ["Event c"])
        state.assert_not_called()
        self.assertEqual([(d["title"], d["outcome"]) for d in result["event_decisions"]],
                         [("Event a", "left open"), ("Event b", "left open"), ("Event c", "included")])


if __name__ == "__main__":
    unittest.main()
