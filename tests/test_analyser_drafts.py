"""What the analyser's drafts start with, and a run one model call fails on.

An alert or advisory cannot be published without an audience, and the analyser
left it empty on every draft. An alert from a PIR or GIR now takes the roles of
the requirement's owner and of the stakeholders it is distributed to, and falls
back, as an alert from the focus points and an advisory do, to the roles of
everyone the product can reach: its subscribers cleared for its TLP.

Each draft also says why the analyser made it, for the list to show under its
title: the requirement and the scope items it matched on, or the CVEs. A CVE
that a draft or an advisory in review already covers gets no second advisory:
the scraper reads an updated article again as a new event.

One event the model or MISP fails on no longer ends the run: its summary is
left out, and a briefing relevance check that fails keeps the story, as an
answer that cannot be read already did.

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
    def alert(self, pir, manual=False, tlp=""):
        tags = [SimpleNamespace(name=misp_store.TAG_MANUAL_ENTRY)] if manual else []
        if tlp:
            tags.append(SimpleNamespace(name=f"tlp:{tlp}"))
        event = SimpleNamespace(uuid="e" * 36, info="Phishing against Belgian banks", tags=tags, galaxies=[])
        created = []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events",
                               return_value=(None, [event], {}, {}, {})), \
             mock.patch.object(analyser_pipeline.misp_store, "flash_intel_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline, "requirement_matches",
                               return_value={event.uuid: [{"id": "PIR-0003", "uuid": "p", "type": "pir",
                                                           "matched_terms": ["Belgium (Geography)", "Bank (Sector)"]},
                                                          {"id": "GIR-0001", "uuid": "g", "type": "gir",
                                                           "matched_terms": ["Belgium (Geography)"]}]}), \
             mock.patch.object(analyser_pipeline.req_matching, "get_requirements", return_value=([pir], [])), \
             mock.patch.object(analyser_pipeline.misp_store, "list_stakeholders", return_value=STAKEHOLDERS), \
             mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="SOC") as reachable, \
             mock.patch.object(analyser_pipeline.misp_store, "create_fia", side_effect=created.append), \
             mock.patch.object(analyser_pipeline, "_log"):
            analyser_pipeline.run_flash_intel_action()
        self.reason = created[0]["analyser_reason"]
        self.created = created[0]
        return created[0]["audience"], reachable

    def test_it_is_for_the_requirement_s_stakeholders(self):
        audience, _reachable = self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=["ir"]))
        self.assertEqual(audience, "Cyber Threat Intelligence, Incident Response")

    def test_it_says_what_it_matched_on(self):
        self.alert(SimpleNamespace(uuid="p", owner_uuid="owner", distribution=[]))
        self.assertEqual(self.reason, "Matches PIR-0003 on Belgium (Geography), Bank (Sector); "
                                      "GIR-0001 on Belgium (Geography)")

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
        self.assertIn(("PHP (Updated October 25)", "already in an open advisory: "
                       "CVE-2026-109618 in VEA-00589, CVE-2026-109619 in VEA-00589"), self.logged)

    def test_one_already_made_in_the_run_counts_too(self):
        self.run_vea({"PHP": ["CVE-2026-109618"], "PHP again": ["CVE-2026-109618"]})
        self.assertEqual([v["title"] for v in self.created], ["PHP"])

    def test_only_its_new_cves_go_in_the_advisory(self):
        draft = SimpleNamespace(vea_id="VEA-00589", review_state="pending-review", cve_id="CVE-2026-109618")
        self.run_vea({"PHP and NetScaler": ["CVE-2026-109618", "CVE-2026-88771"]}, [draft])
        self.assertEqual([(v["cve_id"], v["analyser_reason"]) for v in self.created],
                         [("CVE-2026-88771", "The event names CVE-2026-88771.")])

    def test_an_approved_or_rejected_advisory_does_not_count(self):
        """One already sent, or turned down, says nothing about a new article."""
        done = [SimpleNamespace(vea_id="VEA-00388", review_state=state, cve_id="CVE-2026-110936")
                for state in ("approved", "rejected")]
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, done)
        self.assertEqual([v["cve_id"] for v in self.created], ["CVE-2026-110936"])

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

    def test_a_relevance_check_that_fails_keeps_the_story(self):
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[], galaxies=[]) for c in "ab"]
        created = []
        with mock.patch.object(analyser_pipeline, "_common_candidate_events", return_value=(
                None, events, {}, {"event_decisions": []},
                {e.uuid: [SimpleNamespace(name="Article", content="An article")] for e in events})), \
             mock.patch.object(analyser_pipeline, "daily_briefing_title_exclusions", return_value=[]), \
             mock.patch.object(analyser_pipeline, "requirement_matches", return_value={}), \
             mock.patch.object(analyser_pipeline.llm, "review_briefing_relevance",
                               side_effect=[ConnectionError("Connection error."), {"include": True}]), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_story", return_value=("A story", "")), \
             mock.patch.object(analyser_pipeline.llm, "detect_story_overlaps", return_value={"overlaps": []}), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_summary", return_value="The day"), \
             mock.patch.object(analyser_pipeline, "galaxy_names_with_commas", return_value=frozenset()), \
             mock.patch.object(analyser_pipeline.tagger, "get_source_feed", return_value="feed"), \
             mock.patch.object(analyser_pipeline.misp_store, "extract_source_url", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "briefing_scope_summary", return_value=""), \
             mock.patch.object(analyser_pipeline.misp_store, "create_briefing",
                               side_effect=lambda data: created.append(data) or "u" * 36), \
             mock.patch.object(analyser_pipeline, "log_event"), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            analyser_pipeline.run_daily_briefing_action()
        self.assertEqual([s["title"] for s in created[0]["stories"]], ["Event a", "Event b"])


if __name__ == "__main__":
    unittest.main()
