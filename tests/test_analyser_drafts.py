"""What the analyser's products start with, and what decides they are made.

An alert or advisory cannot be published without an audience, and the analyser
left it empty on every draft. An alert for PIRs or GIRs takes the roles of
their owners and of the stakeholders they are distributed to, and falls back,
as an alert from the focus points and an advisory do, to the roles of everyone
the product can reach: its subscribers cleared for its TLP.

An alert is made for an event whose verdict wants one (tests.test_relevance
pins the verdict), once per event. A story an alert of the last month already
tells, one made earlier in the run included, gets none and is linked to that
alert; one that adds facts becomes an update that names it, unless that alert
was rejected (tests.test_similarity pins how the earlier story is found).

An advisory goes by the event's CVEs. A CVE an advisory of the lookback names,
in any state, gets no new one, unless it changed since: it is on the CISA KEV
list now, or its CVSS score rose enough. A rejected advisory blocks even that.
A CVE has to be in scope: in the asset inventory, or a product or vendor of the
focus points or of an active PIR or GIR. One whose record names no product yet
is matched on the article, and failing that passes, flagged as not checked; with
nothing to check against, every CVE passes. An event without one records why,
which is what lets the briefing close it.

The briefing puts its best stories first and keeps at most so many, listing
the rest under "Also seen"; a day's second run adds to that day's draft. A
story an earlier briefing told is left out in the same way, and one that adds
facts says which story it updates. A comparison that fails leaves the story in,
saying it was not compared, and a rescan compares again what an earlier run
found told before. Only the stories kept are drafted. The events no product
wants are closed, a story told before counting as declined unless an analyst
pushed it, but never one a product was made from, one without a current
verdict, or one with a CVE the advisories have not seen yet. What became of an
event for the alerts or the briefing holds while the event is what it was
decided on. The advisories' outcome only says they looked at its CVEs: those
are decided again, on the records and advisories of now, before the event is
closed. An event with a CVE that could not be looked up waits for all of them,
and each CVE of an advisory keeps its score and KEV status, which a later
change of it is measured against.

One event the model or MISP fails on no longer ends the run: its summary, its
alert or its advisory is left out, and it is read again by the next run. A
problem publishing an alert to the subscribers on automated mode is logged on
its event.

MISP and the model are stubbed.

    python -m unittest tests.test_analyser_drafts
"""
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

from analyser import relevance
from analyser.sources import Reading, Source
from core.asset_inventory import Asset
from webapp import analyser_pipeline, misp_store

SCRAPER = Source("scraper", "scraper", "MISP scraper", None, True)
MANUAL = Source("manual", "manual", "Manual entries", None, True)


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
        self.assertEqual(misp_store.requirement_audience([pir], STAKEHOLDERS), "Cyber Threat Intelligence, SOC")

    def test_several_requirements_take_all_their_stakeholders_once(self):
        pir = SimpleNamespace(owner_uuid="owner", distribution=["soc"])
        gir = SimpleNamespace(owner_uuid="", distribution=["ir", "soc2"])
        self.assertEqual(misp_store.requirement_audience([pir, gir], STAKEHOLDERS),
                         "Cyber Threat Intelligence, SOC, Incident Response")

    def test_everyone_a_product_can_reach(self):
        subscribed = [_stakeholder("a", "SOC", products=["Flash intel alert"]),
                      _stakeholder("b", "Management", products=["Flash intel alert"], tlp="green"),
                      _stakeholder("c", "Incident Response", products=["Daily threat briefing"])]
        with mock.patch.object(misp_store, "list_stakeholders", return_value=subscribed):
            self.assertEqual(misp_store.subscriber_audience("Flash intel alert", "amber"), "SOC")


PUSHED = 'cti-evaluation:relevance="very-high"'


def _event(uuid, title="An event", tags=(), date="2026-10-30"):
    return SimpleNamespace(uuid=uuid, info=title, tags=[SimpleNamespace(name=t) for t in tags], date=date, id="1")


def _found(events, source=SCRAPER, excluded=(), summaries=None):
    """What _common_candidate_events gives an action."""
    events = list(events)
    return SimpleNamespace(sources={e.uuid: source for e in [*events, *excluded]}, events=events,
                           excluded=list(excluded), summaries=summaries or {},
                           reports={e.uuid: [SimpleNamespace(name="Article", content="An article")]
                                    for e in [*events, *excluded]},
                           stats={"event_decisions": []})


def _verdict(alert=False, briefing=False, major=False, alert_reason="Off", priority_grounds=()):
    grounds = [{"focus_point": "Energy", "quote": "a grid operator"}]
    return {"version": "v1",
            "alert": {"relevant": alert, "grounds": grounds if alert else [], "major_development": False,
                      "reason": alert_reason},
            "briefing": {"relevant": briefing, "grounds": [] if major else list(priority_grounds) or grounds,
                         "major_development": major, "reason": "In scope" if briefing else "Off"},
            "scores": {}, "published": None}


def _outcomes(given: dict, decided_on: str) -> dict:
    """Outcomes as event_state keeps them, {product: text} given, decided on
    an event's evidence."""
    return {product: {"outcome": text, "decided_on": decided_on} for product, text in given.items()}


def _stored(events, outcomes=None, changed=()):
    """event_state.load for these events: what became of them before, as
    ``outcomes`` by uuid, decided on the evidence they have now, unless their
    uuid is in ``changed``: then on the article they had before. The verdict
    is current either way, as another action judged them again since."""
    now = {e.uuid: relevance.evidence(e, "An article", "") for e in events}
    then = {e.uuid: relevance.evidence(e, "A new article" if e.uuid in changed else "An article", "")
            for e in events}
    return lambda sid, uuid: {"verdict": {"evidence": now[uuid]}, "attempts": 0,
                              "outcomes": _outcomes((outcomes or {}).get(uuid, {}), then[uuid])}


class _Judge:
    """Stands in for analyser.relevance.Judge with verdicts given per event."""

    version = "v1"

    def __init__(self, verdicts):
        self.verdicts = verdicts

    def verdict(self, event, source, article, summary):
        return self.verdicts.get(event.uuid)

    def wants(self, verdict, product, event):
        if relevance.pushed(event, product):
            return True, "Pushed by an analyst"
        return verdict[product]["relevant"], verdict[product]["reason"]

    def pir_priority(self, verdict):
        return min((g["priority"] for g in verdict["briefing"]["grounds"] if "priority" in g), default=3)


class Alerts(unittest.TestCase):
    def alert(self, verdicts, alerted=(), same=None, drafted=True, briefing_on=True, outcomes=None,
              pushed=(), failing=(), changed=(), problem="", rescan_hours=None, progress=None):
        """``same`` is what the similarity check finds for each event, by uuid,
        or the exception it raises; ``pushed`` the events an analyst scored
        very high; ``failing`` those MISP refuses the alert of; ``problem``
        what went wrong publishing each alert."""
        events = [_event(uuid, f"Event {uuid[0]}", [PUSHED] if uuid in pushed else []) for uuid in verdicts]
        self.made, self.logged, self.compared = [], [], []
        self.reading = mock.create_autospec(Reading, instance=True)
        self.reading.rescan_hours = rescan_hours

        def draft(event, source, verdict, judge, article, summary, why, update_of=""):
            return {"update_of": update_of} if drafted else None

        def file(data, event, source, verdict):
            if event.uuid in failing:
                raise RuntimeError("MISP refused the alert")
            self.made.append((event.uuid, data["update_of"]))
            return f"FIA-0060{len(self.made)}", problem

        def compare(candidate, earlier):
            self.compared.append([s["id"] for s in earlier])
            found = (same or {}).get(candidate["id"])
            if isinstance(found, Exception):
                raise found
            return found
        with mock.patch.object(analyser_pipeline, "_common_candidate_events", return_value=_found(events)), \
             mock.patch.object(analyser_pipeline, "Judge", return_value=_Judge(verdicts)), \
             mock.patch.object(analyser_pipeline.misp_store, "flash_intel_source_uuids", return_value=set(alerted)), \
             mock.patch.object(analyser_pipeline.event_state, "load",
                               side_effect=_stored(events, outcomes, changed)), \
             mock.patch.object(analyser_pipeline.event_state, "save_outcome") as self.outcome, \
             mock.patch.object(analyser_pipeline.similarity, "recent_alerts", return_value=[]), \
             mock.patch.object(analyser_pipeline.similarity, "same_story", side_effect=compare), \
             mock.patch.object(analyser_pipeline.flash_intel, "draft_alert", side_effect=draft), \
             mock.patch.object(analyser_pipeline.flash_intel, "file_alert", side_effect=file), \
             mock.patch.object(analyser_pipeline, "_close_declined", return_value=0) as self.closed, \
             mock.patch.object(analyser_pipeline.config, "ANALYSER_DAILY_BRIEFING", briefing_on, create=True), \
             mock.patch.object(analyser_pipeline, "_log",
                               side_effect=lambda e, source, outcome, detail=None: self.logged.append((e.uuid, outcome))):
            return analyser_pipeline.run_flash_intel_action(self.reading, progress)

    @staticmethod
    def found(product_id="FIA-00517", new_facts=False, rejected=False):
        return {"story": {"id": product_id, "title": "Earlier", "rejected": rejected}, "new_facts": new_facts,
                "reason": "Same CVEs."}

    def test_an_event_whose_verdict_wants_one_gets_an_alert(self):
        result = self.alert({"a" * 36: _verdict(alert=True), "b" * 36: _verdict()})
        self.assertEqual(self.made, [("a" * 36, "")])
        self.assertEqual(result["source_event_uuids"], ["a" * 36])
        self.assertIn(("b" * 36, "not_relevant"), self.logged)
        # Tagged as the alert's source by the run, which is no news for the next.
        self.reading.wrote.assert_called_once_with("a" * 36)

    def test_an_event_an_alert_was_made_from_gets_no_second_one(self):
        """Whichever run made it and whatever became of it."""
        self.alert({"a" * 36: _verdict(alert=True)}, alerted={"a" * 36})
        self.assertEqual(self.made, [])

    def test_an_event_without_a_verdict_is_left_open(self):
        self.alert({"a" * 36: None})
        self.assertEqual(self.logged, [("a" * 36, "error")])

    def test_a_story_an_earlier_alert_tells_is_linked_to_it_and_gets_none(self):
        """The PHP CVEs got six alerts, one per article about them."""
        self.alert({"a" * 36: _verdict(alert=True)}, same={"a" * 36: self.found()})
        self.assertEqual(self.made, [])
        self.assertEqual(self.outcome.call_args.args[1:4], ("a" * 36, "flash-intel", "The same story as FIA-00517"))
        # Decided on the event as it is now.
        self.assertEqual(self.outcome.call_args.args[4], relevance.evidence(_event("a" * 36, "Event a"), "An article", ""))

    def test_one_linked_before_is_not_proposed_again(self):
        self.alert({"a" * 36: _verdict(alert=True)}, outcomes={"a" * 36: {"flash-intel": "The same story as X"}})
        self.assertEqual((self.made, self.compared), ([], []))

    def test_a_rescan_compares_one_linked_before_again(self):
        """It is for the settings of now, and the alert it repeated may have
        been deleted since."""
        self.alert({"a" * 36: _verdict(alert=True)}, outcomes={"a" * 36: {"flash-intel": "The same story as X"}},
                   rescan_hours=24)
        self.assertEqual(self.made, [("a" * 36, "")])

    def test_a_comparison_that_fails_is_drafted_saying_so(self):
        with self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            self.alert({"a" * 36: _verdict(alert=True)}, same={"a" * 36: TimeoutError("no answer")})
        self.assertEqual(self.made, [("a" * 36, "Not compared with the earlier alerts, as the comparison failed")])

    def test_a_run_that_lost_its_lock_during_the_model_call_files_nothing(self):
        """Its process was suspended long enough for another run to take the
        lock over, and it filed an alert beside that run."""
        def progress(step, state, message=""):
            if message.startswith("Filing"):
                raise analyser_pipeline.run_lock.Lost("taken over")
        with self.assertRaises(analyser_pipeline.run_lock.Lost):
            self.alert({"a" * 36: _verdict(alert=True)}, progress=progress)
        self.assertEqual(self.made, [])

    def test_a_problem_publishing_it_is_logged_on_its_event(self):
        """The alert is made all the same; the analysts see it was not sent."""
        result = self.alert({"a" * 36: _verdict(alert=True)}, problem="MISP did not publish it")
        self.assertEqual(result["source_event_uuids"], ["a" * 36])
        self.assertIn(("a" * 36, "error"), self.logged)

    def test_one_linked_before_whose_article_changed_is_compared_again(self):
        """It was a repeat; it may report active exploitation now. Also when
        the briefing judged it again since, which made its verdict current."""
        self.alert({"a" * 36: _verdict(alert=True)}, outcomes={"a" * 36: {"flash-intel": "The same story as X"}},
                   changed={"a" * 36})
        self.assertEqual(self.made, [("a" * 36, "")])

    def test_one_that_adds_facts_is_an_update_that_names_the_earlier_alert(self):
        self.alert({"a" * 36: _verdict(alert=True)}, same={"a" * 36: self.found(new_facts=True)})
        self.assertEqual(self.made, [("a" * 36, "Update of FIA-00517: Same CVEs.")])

    def test_but_not_of_a_rejected_one(self):
        self.alert({"a" * 36: _verdict(alert=True)}, same={"a" * 36: self.found(new_facts=True, rejected=True)})
        self.assertEqual(self.made, [])
        self.assertEqual(self.outcome.call_args.args[3], "The same story as FIA-00517, rejected")

    def test_an_alert_made_earlier_in_the_run_is_compared_too(self):
        self.alert({"a" * 36: _verdict(alert=True), "b" * 36: _verdict(alert=True)})
        self.assertEqual(self.compared, [[], ["FIA-00601"]])

    def test_one_an_analyst_pushed_is_drafted_with_what_it_repeats_marked(self):
        """The analyst asked for it."""
        self.alert({"a" * 36: _verdict()}, same={"a" * 36: self.found()}, pushed={"a" * 36},
                   outcomes={"a" * 36: {"flash-intel": "The same story as FIA-00517"}})
        self.assertEqual(self.made, [("a" * 36, "The same story as FIA-00517: Same CVEs.")])

    def test_one_pushed_before_the_model_answered_is_drafted_too(self):
        self.alert({"a" * 36: None}, pushed={"a" * 36})
        self.assertEqual(self.made, [("a" * 36, "")])

    def test_an_empty_draft_leaves_the_event_open_for_the_next_run(self):
        self.alert({"a" * 36: _verdict(alert=True)}, drafted=False)
        self.assertIn(("a" * 36, "error"), self.logged)
        self.reading.retry.assert_called_once_with("a" * 36)

    def test_one_draft_that_fails_does_not_stop_the_others(self):
        """Raised, it ended the run every hour, and the events after it never got their alert."""
        with self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            result = self.alert({"a" * 36: _verdict(alert=True), "b" * 36: _verdict(alert=True)},
                                failing={"a" * 36})
        self.assertEqual(result["source_event_uuids"], ["b" * 36])
        self.reading.retry.assert_called_once_with("a" * 36)

    def test_with_the_briefing_on_the_alerts_close_nothing(self):
        """The briefing closes the events, as the last product to deal with them."""
        self.alert({"a" * 36: _verdict()})
        self.closed.assert_not_called()
        self.alert({"a" * 36: _verdict()}, briefing_on=False)
        self.closed.assert_called_once()


class Advisories(unittest.TestCase):
    def run_vea(self, cves_by_title, veas=(), records=None, assets=None, terms=(), manual=False, tlp="",
                refused=(), progress=None):
        """``records`` the CVE database's records by CVE; None for one it
        could not be asked about. MISP refuses the advisories titled in
        ``refused``."""
        tags = [misp_store.TAG_MANUAL_ENTRY] if manual else []
        self.reading = mock.create_autospec(Reading, instance=True)
        if tlp:
            tags.append(f"tlp:{tlp}")
        events = [_event(f"{i}" * 36, title, tags) for i, title in enumerate(cves_by_title, start=1)]
        self.created, self.logged = [], []

        def create(data):
            if data["title"] in refused:
                raise RuntimeError("MISP refused the advisory")
            self.created.append(data)
            return "u" * 36, f"VEA-0010{len(self.created)}"

        def lookup(cve):
            record = (records or {}).get(cve, {})
            return None if record is None else dict(record)
        with mock.patch.object(analyser_pipeline, "_common_candidate_events",
                               return_value=_found(events, MANUAL if manual else SCRAPER)), \
             mock.patch.object(analyser_pipeline.misp_store, "vea_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline.collection_cache, "event_cves",
                               side_effect=lambda e: cves_by_title[e.info]), \
             mock.patch.object(analyser_pipeline, "lookup_cve", side_effect=lookup), \
             mock.patch.object(analyser_pipeline.asset_inventory, "enabled", return_value=assets is not None), \
             mock.patch.object(analyser_pipeline.asset_inventory, "assets", return_value=assets or []), \
             mock.patch.object(analyser_pipeline, "_scope_terms", return_value=list(terms)), \
             mock.patch.object(analyser_pipeline.llm, "draft_vea_sections", return_value={}), \
             mock.patch.object(analyser_pipeline.misp_store, "subscriber_audience", return_value="SOC"), \
             mock.patch.object(analyser_pipeline.misp_store, "list_veas", return_value=list(veas)), \
             mock.patch.object(analyser_pipeline.misp_store, "create_vea", side_effect=create), \
             mock.patch.object(analyser_pipeline.event_state, "save_outcome") as self.outcome, \
             mock.patch.object(analyser_pipeline, "_log",
                               side_effect=lambda e, source, outcome, detail=None: self.logged.append((e.info, detail))):
            return analyser_pipeline.run_vea_action(self.reading, progress)

    @staticmethod
    def vea(cve, state="draft", days_ago=5, cvss="7.5 HIGH", kev="No", baselines=None):
        made = datetime.now() - timedelta(days=days_ago)
        return SimpleNamespace(vea_id="VEA-00589", review_state=state, cve_id=cve, cvss=cvss, cisa_kev=kev,
                               created_at=made, cve_baselines=baselines or {})

    def test_an_updated_article_gets_no_second_advisory(self):
        """Unit 42 retitled a post "(Updated October 25)", and the PHP CVEs got a second draft."""
        self.run_vea({"PHP (Updated October 25)": ["CVE-2026-109618"]}, [self.vea("CVE-2026-109618")])
        self.assertEqual(self.created, [])
        self.assertEqual(self.outcome.call_args.args[2:], ("vea", "No CVE to advise on: CVE-2026-109618 in VEA-00589"))

    def test_one_already_made_in_the_run_counts_too(self):
        self.run_vea({"PHP": ["CVE-2026-109618"], "PHP again": ["CVE-2026-109618"]})
        self.assertEqual([v["title"] for v in self.created], ["PHP"])

    def test_only_its_new_cves_go_in_the_advisory(self):
        self.run_vea({"PHP and NetScaler": ["CVE-2026-109618", "CVE-2026-88771"]}, [self.vea("CVE-2026-109618")])
        self.assertEqual([v["cve_id"] for v in self.created], ["CVE-2026-88771"])

    def test_an_approved_advisory_of_the_lookback_counts_too(self):
        """It used to give a new draft for every article on the same CVE."""
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, [self.vea("CVE-2026-110936", state="approved")])
        self.assertEqual(self.created, [])

    def test_one_older_than_the_lookback_does_not(self):
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, [self.vea("CVE-2026-110936", days_ago=120)])
        self.assertEqual([v["cve_id"] for v in self.created], ["CVE-2026-110936"])

    def test_a_cve_on_the_kev_list_now_gets_an_update_that_names_the_earlier_one(self):
        self.run_vea({"Exploited": ["CVE-2026-110936"]}, [self.vea("CVE-2026-110936", state="approved")],
                     records={"CVE-2026-110936": {"cisa_kev": "Yes"}})
        self.assertTrue(self.created[0]["analyser_reason"].startswith(
            "Update of VEA-00589: it is on the CISA KEV list now."))

    def test_a_cvss_rise_counts_only_from_the_setting_up(self):
        for score, made in (("8.4", True), ("8.0", False)):
            with self.subTest(score=score):
                self.run_vea({"Rescored": ["CVE-2026-110936"]}, [self.vea("CVE-2026-110936", cvss="7.4 HIGH")],
                             records={"CVE-2026-110936": {"cvss_score": score}})
                self.assertEqual(bool(self.created), made)

    def test_each_event_has_its_decision_in_the_run(self):
        """The advisory runs listed none, so they never opened on the Pipeline page."""
        result = self.run_vea({"No CVE": [], "Covered": ["CVE-2026-109618"], "New": ["CVE-2026-88771"],
                               "Unknown": ["CVE-2026-1"]}, [self.vea("CVE-2026-109618")],
                              records={"CVE-2026-1": None})
        self.assertEqual([(d["title"], d["outcome"]) for d in result["event_decisions"]],
                         [("No CVE", "declined"), ("Covered", "declined"), ("New", "included"),
                          ("Unknown", "left open")])

    def test_a_rejected_advisory_blocks_even_a_change(self):
        """An analyst who turned a CVE down got a new draft with every new article about it."""
        self.run_vea({"Siemens": ["CVE-2026-110936"]}, [self.vea("CVE-2026-110936", state="rejected")],
                     records={"CVE-2026-110936": {"cisa_kev": "Yes"}})
        self.assertEqual(self.created, [])
        self.assertIn("rejected", self.outcome.call_args.args[3])

    def test_with_scope_a_cve_must_concern_it(self):
        records = {"CVE-1": {"affected": [("Fortinet", "FortiOS")]}, "CVE-2": {"affected": [("Acme", "Widget")]}}
        self.run_vea({"Fortinet": ["CVE-1"], "Acme": ["CVE-2"]}, records=records,
                     terms=[("Fortinet", "the focus point Fortinet")])
        self.assertEqual([v["cve_id"] for v in self.created], ["CVE-1"])
        self.assertEqual(self.created[0]["exposure"], "Fortinet FortiOS is in the scope of the focus point Fortinet.")

    def test_a_cve_in_the_asset_inventory_is_in_scope(self):
        self.run_vea({"Exchange": ["CVE-1"]}, records={"CVE-1": {"affected": [("Microsoft", "Exchange Server")]}},
                     assets=[Asset("Microsoft", "Exchange Server 2019", "CU14")])
        self.assertEqual(self.created[0]["exposure"], "In the asset inventory: Microsoft Exchange Server 2019 CU14")

    def test_a_record_without_a_product_is_matched_on_the_article(self):
        self.run_vea({"A FortiGate flaw": ["CVE-1"], "Something else": ["CVE-2"]},
                     terms=[("FortiGate", "the focus point FortiGate")])
        self.assertEqual([v["exposure"] for v in self.created],
                         ["The article names FortiGate, in the scope of the focus point FortiGate.",
                          analyser_pipeline._NOT_CHECKED])

    def test_with_nothing_to_check_against_every_cve_passes(self):
        self.run_vea({"Acme": ["CVE-2"]}, records={"CVE-2": {"affected": [("Acme", "Widget")]}})
        self.assertEqual(len(self.created), 1)

    def test_a_manual_source_is_saved_with_its_existing_server_hint(self):
        self.run_vea({"A manual entry": ["CVE-2026-110936"]}, manual=True)
        self.assertEqual(self.created[0]["source_event_hints"], {"1" * 36: "webapp"})

    def test_a_restricted_source_is_not_downgraded(self):
        self.run_vea({"A manual entry": ["CVE-2026-110936"]}, manual=True, tlp="amber+strict")
        self.assertEqual(self.created[0]["tlp"], "amber+strict")

    def test_a_cve_that_could_not_be_looked_up_is_left_for_the_next_run(self):
        """With KEV only on, it was declined as below the severity asked for,
        and the briefing closed the event on that."""
        with mock.patch.object(analyser_pipeline.config, "ANALYSER_ADVISORY_KEV_ONLY", True, create=True):
            self.run_vea({"An outage": ["CVE-2026-1"]}, records={"CVE-2026-1": None})
        self.assertEqual(self.created, [])
        self.outcome.assert_not_called()
        self.reading.retry.assert_called_once_with("1" * 36)

    def test_one_that_could_be_looked_up_waits_for_the_one_that_could_not(self):
        """The first got an advisory naming the second as not looked up, and
        the event, having one, was never read for the second again."""
        self.run_vea({"Two CVEs": ["CVE-2026-1001", "CVE-2026-1002"]}, records={"CVE-2026-1002": None})
        self.assertEqual(self.created, [])
        self.outcome.assert_not_called()
        self.reading.retry.assert_called_once_with("1" * 36)
        self.run_vea({"Two CVEs": ["CVE-2026-1001", "CVE-2026-1002"]})
        self.assertEqual(self.created[0]["cve_id"], "CVE-2026-1001\nCVE-2026-1002")

    def test_each_cve_keeps_what_it_was_when_the_draft_was_made(self):
        self.run_vea({"Two CVEs": ["CVE-2026-1001", "CVE-2026-1002"]},
                     records={"CVE-2026-1001": {"cvss_score": "9.8", "cisa_kev": "Yes"},
                              "CVE-2026-1002": {"cvss_score": "5.0", "cisa_kev": "No"}})
        self.assertEqual(self.created[0]["cve_baselines"], {"CVE-2026-1001": {"cvss": "9.8", "cisa_kev": "Yes"},
                                                            "CVE-2026-1002": {"cvss": "5.0", "cisa_kev": "No"}})

    def test_another_cve_of_an_advisory_is_measured_against_what_it_was(self):
        """Its advisory has the main CVE's 9.8 and KEV status: against those,
        the second CVE's rise to 6.5 and onto the KEV list went unseen."""
        earlier = self.vea("CVE-2026-1001\nCVE-2026-1002", cvss="9.8 CRITICAL", kev="Yes",
                           baselines={"CVE-2026-1001": {"cvss": "9.8", "cisa_kev": "Yes"},
                                      "CVE-2026-1002": {"cvss": "5.0", "cisa_kev": "No"}})
        self.run_vea({"Exploited now": ["CVE-2026-1002"]}, [earlier],
                     records={"CVE-2026-1002": {"cvss_score": "6.5", "cisa_kev": "Yes"}})
        self.assertTrue(self.created[0]["analyser_reason"].startswith(
            "Update of VEA-00589: it is on the CISA KEV list now."))

    def test_without_what_it_was_another_cve_is_covered_as_it_is(self):
        """An advisory an analyst wrote has the main CVE's 5.0 only: the
        second CVE's 9.8 and KEV status are no rise from it."""
        earlier = self.vea("CVE-2026-1001\nCVE-2026-1002", cvss="5.0 MEDIUM", kev="No")
        self.run_vea({"Again": ["CVE-2026-1002"]}, [earlier],
                     records={"CVE-2026-1002": {"cvss_score": "9.8", "cisa_kev": "Yes"}})
        self.assertEqual(self.created, [])
        self.assertIn("CVE-2026-1002 in VEA-00589", self.outcome.call_args.args[3])

    def test_a_run_that_lost_its_lock_during_the_model_call_writes_nothing(self):
        def progress(step, state, message=""):
            if message.startswith("Writing"):
                raise analyser_pipeline.run_lock.Lost("taken over")
        with self.assertRaises(analyser_pipeline.run_lock.Lost):
            self.run_vea({"PHP": ["CVE-2026-109618"]}, progress=progress)
        self.assertEqual(self.created, [])

    def test_one_misp_refuses_does_not_stop_the_others(self):
        """Raised, it held up every event after it, on every run."""
        with self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            result = self.run_vea({"Refused": ["CVE-2026-1001"], "Fine": ["CVE-2026-1002"]}, refused={"Refused"})
        self.assertEqual(result["source_event_uuids"], ["2" * 36])
        self.reading.retry.assert_called_once_with("1" * 36)
        self.assertIn(("Refused", "No advisory could be written: MISP refused the advisory; left for the next run"),
                      self.logged)

    def test_one_past_the_limit_is_named_as_not_looked_up(self):
        with mock.patch.object(analyser_pipeline.config, "ANALYSER_ADVISORY_MAX_CVES", 1, create=True):
            self.run_vea({"Patch day": ["CVE-2026-1", "CVE-2026-2"]}, terms=[("Fortinet", "the focus point")],
                         records={"CVE-2026-1": {"affected": [("Siemens", "SIMATIC")]}})
        self.assertIn("1 more not looked up, past the limit of 1", self.outcome.call_args.args[3])


def _draft(stories=(), **fields):
    """Today's draft briefing as misp_store reads it back."""
    blank = {f: "" for f in analyser_pipeline.misp_store.BRIEFING_FIELDS}
    return SimpleNamespace(**{**blank, "uuid": "d" * 36, "tlp": "clear", "vendor": [], "also_seen": [],
                              "stories": list(stories), **fields})


class Briefing(unittest.TestCase):
    def brief(self, verdicts, draft=None, cap=15, overlaps=(), outcomes=None, same=None, pushed=(), listed=()):
        """``listed`` the events under Also seen of a briefing; ``same`` what
        the similarity check finds for each event, or the exception it raises."""
        events = [_event(uuid, f"Event {uuid[0]}", [PUSHED] if uuid in pushed else []) for uuid in verdicts]
        self.created, self.updated = [], []
        reading = mock.create_autospec(Reading, instance=True)
        reading.rescan_hours = None

        def compare(candidate, earlier):
            found = (same or {}).get(candidate["id"])
            if isinstance(found, Exception):
                raise found
            return found
        with mock.patch.object(analyser_pipeline, "_common_candidate_events", return_value=_found(events)), \
             mock.patch.object(analyser_pipeline, "Judge", return_value=_Judge(verdicts)), \
             mock.patch.multiple(analyser_pipeline.misp_store, briefing_source_uuids=mock.Mock(return_value=set()),
                                 briefing_also_seen_uuids=mock.Mock(return_value=set(listed))), \
             mock.patch.object(analyser_pipeline.event_state, "load", side_effect=_stored(events, outcomes)), \
             mock.patch.object(analyser_pipeline.event_state, "save_outcome") as self.outcome, \
             mock.patch.object(analyser_pipeline, "todays_draft", return_value=draft), \
             mock.patch.object(analyser_pipeline.config, "ANALYSER_BRIEFING_MAX_STORIES", cap, create=True), \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_story",
                               return_value=("A story", "")) as self.drafted, \
             mock.patch.object(analyser_pipeline.llm, "detect_story_overlaps",
                               return_value={"overlaps": list(overlaps)}) as self.overlap, \
             mock.patch.object(analyser_pipeline.llm, "draft_briefing_summary", return_value="The day"), \
             mock.patch.object(analyser_pipeline, "galaxy_names_with_commas", return_value=frozenset()), \
             mock.patch.object(analyser_pipeline, "focus_points", return_value={}), \
             mock.patch.object(analyser_pipeline.misp_store, "extract_source_url",
                               side_effect=lambda e: f"https://example.org/{e.uuid[0]}"), \
             mock.patch.object(analyser_pipeline.misp_store, "briefing_scope_summary", return_value=[]), \
             mock.patch.object(analyser_pipeline.misp_store, "create_briefing",
                               side_effect=lambda data: self.created.append(data) or "n" * 36), \
             mock.patch.object(analyser_pipeline.misp_store, "update_briefing",
                               side_effect=lambda uuid, data, expected_state: self.updated.append(data)), \
             mock.patch.object(analyser_pipeline, "_close_declined", return_value=0) as self.closed, \
             mock.patch.object(analyser_pipeline.similarity, "recent_stories", return_value=[]) as self.history, \
             mock.patch.object(analyser_pipeline.similarity, "same_story", side_effect=compare) as self.same, \
             mock.patch.object(analyser_pipeline, "_log") as self.logged:
            return analyser_pipeline.run_daily_briefing_action(reading)

    def titles(self):
        return [s["title"] for s in (self.created or self.updated)[0]["stories"]]

    def test_the_best_stories_come_first(self):
        """Alert-worthy, then the PIR with the highest priority, and those in
        only as a major development last."""
        self.brief({"m" * 36: _verdict(briefing=True, major=True),
                    "b" * 36: _verdict(briefing=True),
                    "s" * 36: _verdict(briefing=True, priority_grounds=[{"requirement": "p", "id": "PIR-1",
                                                                         "quote": "q", "priority": 1}]),
                    "a" * 36: _verdict(alert=True, briefing=True, alert_reason="In")})
        self.assertEqual(self.titles(), ["Event a", "Event s", "Event b", "Event m"])

    def test_past_the_cap_the_rest_are_listed_under_also_seen(self):
        self.brief({c * 36: _verdict(briefing=True) for c in "abc"}, cap=2)
        self.assertEqual(self.titles(), ["Event a", "Event b"])
        self.assertEqual(self.created[0]["also_seen"], [{"title": "Event c", "source_url": "https://example.org/c",
                                                         "source_event_uuid": "c" * 36, "source_id": "scraper"}])
        # Not in the notes, which go out with the briefing.
        self.assertEqual(self.created[0]["notes"], "")

    def test_only_the_stories_it_keeps_are_drafted(self):
        """Duplicates and the cap are settled first: each story is a model call."""
        self.brief({c * 36: _verdict(briefing=True) for c in "abcd"}, cap=2,
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "Same story"}])
        self.assertEqual(self.titles(), ["Event a", "Event c"])
        self.assertEqual(self.drafted.call_count, 2)

    def test_a_story_dropped_as_duplicate_coverage_is_not_proposed_again(self):
        """And the closing step closes it. Without an outcome it stayed open."""
        self.brief({c * 36: _verdict(briefing=True) for c in "ab"},
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "Same story"}])
        self.assertEqual(self.outcome.call_args.args[1:4],
                         ("b" * 36, "daily-briefing", "Duplicate coverage of another story"))

    def test_a_story_dropped_is_in_the_pipeline_activity(self):
        """The alerts logged a story told before; the briefing left it out of
        the activity, which then showed nothing for the event."""
        self.brief({c * 36: _verdict(briefing=True) for c in "ab"},
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "Same story"}])
        self.assertIn(("not_relevant", "Duplicate coverage of another story"),
                      [call.args[2:] for call in self.logged.call_args_list])
        earlier = {"story": {"id": "the briefing of 2026-10-30", "title": "Earlier", "rejected": False},
                   "new_facts": False, "reason": "Same breach"}
        self.brief({"a" * 36: _verdict(briefing=True)}, same={"a" * 36: earlier})
        self.assertIn(("not_relevant", "The same story as one in the briefing of 2026-10-30."),
                      [call.args[2:] for call in self.logged.call_args_list])

    def test_an_event_under_also_seen_is_not_proposed_again_until_its_briefing_is_deleted(self):
        """A draft deleted to be made again by a rescan takes its Also seen with it."""
        self.brief({"a" * 36: _verdict(briefing=True)}, listed={"a" * 36})
        self.assertEqual(self.created, [])
        self.brief({"a" * 36: _verdict(briefing=True)})
        self.assertEqual(self.titles(), ["Event a"])

    def test_a_second_run_of_the_day_adds_to_its_draft(self):
        draft = _draft([SimpleNamespace(title="Earlier", source_event_uuid="x" * 36, _report_id="9")], tlp="green",
                       summary="Before")
        self.brief({"a" * 36: _verdict(briefing=True)}, draft=draft, cap=2)
        self.assertEqual(self.created, [])
        written = self.updated[0]
        self.assertEqual([s["title"] for s in written["stories"]], ["Earlier", "Event a"])
        self.assertNotIn("_report_id", written["stories"][0])
        self.assertEqual((written["story_count"], written["tlp"], written["summary"]), (2, "green", "The day"))

    def test_one_an_analyst_pushed_is_kept_with_the_overlap_marked(self):
        """It overlapped a story already in the day's draft, and was dropped."""
        draft = _draft([SimpleNamespace(title="Earlier", source_event_uuid="x" * 36)])
        self.brief({"a" * 36: _verdict()}, draft=draft, pushed={"a" * 36},
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "Same breach"}])
        added = self.updated[0]["stories"][1]
        self.assertEqual((added["title"], added["correlation"]),
                         ("Event a", "Overlaps with another story of this briefing"))

    def test_a_pushed_story_does_not_let_the_one_it_overlaps_through(self):
        """It overlapped a story of the draft and a later story; the later one
        survived as well, as the pushed one had been taken for dropped."""
        draft = _draft([SimpleNamespace(title="Earlier", source_event_uuid="x" * 36)])
        self.brief({"p" * 36: _verdict(), "b" * 36: _verdict(briefing=True)}, draft=draft, pushed={"p" * 36},
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "x"}, {"a": 2, "b": 3, "score": 0.8,
                                                                             "reason": "y"}])
        stories = self.updated[0]["stories"]
        self.assertEqual([s["title"] for s in stories], ["Earlier", "Event p"])
        self.assertEqual(stories[1]["correlation"], "Overlaps with another story of this briefing")

    def test_its_stories_count_against_the_cap_and_are_never_dropped_as_duplicates(self):
        draft = _draft([SimpleNamespace(title="Earlier", source_event_uuid="x" * 36),
                        SimpleNamespace(title="Earlier too", source_event_uuid="y" * 36)])
        self.brief({"a" * 36: _verdict(briefing=True), "b" * 36: _verdict(briefing=True)}, draft=draft, cap=3,
                   overlaps=[{"a": 1, "b": 2, "score": 0.9, "reason": "x"}, {"a": 2, "b": 3, "score": 0.9,
                                                                             "reason": "y"}])
        self.assertEqual([s["title"] for s in self.updated[0]["stories"]], ["Earlier", "Earlier too", "Event b"])

    def test_a_story_an_earlier_briefing_told_is_left_out_and_linked(self):
        same = {"story": {"id": "the briefing of 2026-10-29", "title": "Earlier", "rejected": False},
                "new_facts": False, "reason": "Same breach."}
        self.brief({"a" * 36: _verdict(briefing=True), "b" * 36: _verdict(briefing=True)}, same={"a" * 36: same})
        self.assertEqual(self.titles(), ["Event b"])
        self.assertEqual(self.outcome.call_args.args[1:4], ("a" * 36, "daily-briefing",
                                                            "The same story as one in the briefing of 2026-10-29"))

    def test_one_that_adds_facts_says_which_story_it_updates(self):
        same = {"story": {"id": "the briefing of 2026-10-29", "title": "Earlier", "rejected": False},
                "new_facts": True, "reason": "A second victim."}
        self.brief({"a" * 36: _verdict(briefing=True)}, same={"a" * 36: same})
        self.assertEqual(self.created[0]["stories"][0]["correlation"],
                         'Update of "Earlier" in the briefing of 2026-10-29: A second victim.')

    def test_a_comparison_that_fails_keeps_the_story_saying_so(self):
        with self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            self.brief({"a" * 36: _verdict(briefing=True)}, same={"a" * 36: ValueError("Unreadable")})
        self.assertEqual(self.created[0]["stories"][0]["correlation"],
                         "Not compared with the earlier briefings, as the comparison failed")

    def test_a_pushed_story_comes_first_and_goes_past_the_cap(self):
        self.brief({"a" * 36: _verdict(briefing=True), "b" * 36: _verdict(briefing=True),
                    "p" * 36: _verdict()}, cap=1, pushed={"p" * 36})
        self.assertEqual(self.titles(), ["Event p"])
        self.brief({"a" * 36: _verdict(briefing=True)}, cap=1, draft=_draft([SimpleNamespace(title="Earlier", source_event_uuid="x" * 36)]),
            pushed={"a" * 36})
        self.assertEqual([s["title"] for s in self.updated[0]["stories"]], ["Earlier", "Event a"])

    def test_a_pushed_story_an_earlier_briefing_told_is_kept_and_marked(self):
        same = {"story": {"id": "the briefing of 2026-10-29", "title": "Earlier", "rejected": False},
                "new_facts": False, "reason": "Same breach."}
        self.brief({"p" * 36: _verdict()}, same={"p" * 36: same}, pushed={"p" * 36},
                   outcomes={"p" * 36: {"daily-briefing": "Over the cap of a briefing"}})
        self.assertEqual(self.created[0]["stories"][0]["correlation"],
                         'The same story as "Earlier" in the briefing of 2026-10-29: Same breach.')

    def test_past_the_cap_nothing_more_is_compared(self):
        """Each comparison is a model call."""
        self.brief({c * 36: _verdict(briefing=True) for c in "abc"}, cap=1)
        self.assertEqual(self.same.call_count, 1)

    def test_today_s_draft_is_left_to_the_overlap_check(self):
        draft = _draft()
        self.brief({"a" * 36: _verdict(briefing=True)}, draft=draft)
        self.history.assert_called_once_with(but=draft)

    def test_it_closes_the_events_no_product_wants(self):
        self.brief({"a" * 36: _verdict()})
        self.closed.assert_called_once()


class Closing(unittest.TestCase):
    SWITCHED_ON = {"ANALYSER_FLASH_INTEL": True, "ANALYSER_DAILY_BRIEFING": True,
                   "ANALYSER_VULNERABILITY_ADVISORIES": True}

    def close(self, verdict, excluded=False, cves=(), outcomes=None, in_products=(), source=SCRAPER,
              running="briefing", refused=False, records=None, terms=(("Cisco", "the focus point Cisco"),),
              coverage=None, tags=(), followed=(), **switches):
        """The CVEs are decided again on ``records``, the CVE database's by
        CVE, by default a product out of the scope of ``terms``, and on
        ``coverage``, the advisories that cover them now. ``outcomes`` are
        decided on the event as it is."""
        event = _event("a" * 36, "An event", tags)
        found = _found([] if excluded else [event], source, excluded=[event] if excluded else [])
        self.reading = mock.create_autospec(Reading, instance=True)
        check = SimpleNamespace(checking_assets=False, terms=list(terms), coverage=dict(coverage or {}), records={})
        with mock.patch.multiple(analyser_pipeline.config, create=True, **{**self.SWITCHED_ON, **switches}), \
             mock.patch.object(analyser_pipeline, "_advisory_check", return_value=check), \
             mock.patch.object(analyser_pipeline, "lookup_cve",
                               side_effect=lambda cve: (records or {}).get(cve, {"affected": [("Acme", "Widget")]})), \
             mock.patch.object(analyser_pipeline.event_state, "save_outcome") as self.outcome, \
             mock.patch.object(analyser_pipeline.misp_store, "flash_intel_source_uuids", return_value=set(in_products)), \
             mock.patch.object(analyser_pipeline.misp_store, "briefing_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline.misp_store, "vea_source_uuids", return_value=set()), \
             mock.patch.object(analyser_pipeline.event_state, "load",
                               return_value={"verdict": verdict, "attempts": 0,
                                             "outcomes": _outcomes(outcomes or {},
                                                                   relevance.evidence(event, "An article", ""))}), \
             mock.patch.object(analyser_pipeline.collection_cache, "event_cves", return_value=list(cves)), \
             mock.patch.object(analyser_pipeline.collection_cache, "get_flagged_uuids", return_value=set(followed)), \
             mock.patch.object(analyser_pipeline.event_state, "reject", return_value=not refused) as self.rejected, \
             mock.patch.object(analyser_pipeline, "_add_rejection_note") as self.noted:
            self.found = found
            return analyser_pipeline._close_declined(found, _Judge({}), self.reading, running)

    def test_an_event_an_analyst_follows_up_is_left_open(self):
        """Reopened for review by hand, the next run closed it again."""
        self.assertEqual(self.close(_verdict(), followed=["a" * 36]), 0)
        self.rejected.assert_not_called()

    def test_an_event_every_product_declined_is_rejected_with_why(self):
        self.assertEqual(self.close(_verdict()), 1)
        self.assertEqual(self.rejected.call_args.args[2], "alert: Off; briefing: Off; advisory: no CVE")
        self.noted.assert_called_once()
        self.reading.wrote.assert_called_once_with("a" * 36)

    def test_one_a_product_wants_stays_open(self):
        self.assertEqual(self.close(_verdict(briefing=True)), 0)
        self.rejected.assert_not_called()

    def test_a_story_a_product_told_before_is_declined_by_it(self):
        """Its verdict wants an alert, which an earlier one gave: it stayed
        incomplete for good."""
        self.assertEqual(self.close(_verdict(alert=True), outcomes={"flash-intel": "The same story as FIA-00517"}), 1)
        self.assertEqual(self.rejected.call_args.args[2],
                         "alert: The same story as FIA-00517; briefing: Off; advisory: no CVE")
        self.assertEqual(self.close(_verdict(briefing=True),
                                    outcomes={"daily-briefing": "Duplicate coverage of another story"}), 1)

    def test_but_not_one_an_analyst_pushed(self):
        self.assertEqual(self.close(_verdict(alert=True), outcomes={"flash-intel": "The same story as FIA-00517"},
                                    tags=[PUSHED]), 0)

    def test_one_without_a_current_verdict_stays_open(self):
        stale = {**_verdict(), "version": "v0"}
        for verdict in (None, stale):
            with self.subTest(verdict=verdict):
                self.assertEqual(self.close(verdict), 0)

    def test_one_a_product_was_made_from_stays_open(self):
        self.assertEqual(self.close(_verdict(), in_products={"a" * 36}), 0)

    def test_an_excluded_event_needs_no_verdict(self):
        self.assertEqual(self.close(None, excluded=True), 1)
        self.assertTrue(self.rejected.call_args.args[2].startswith("alert: excluded by title"))

    def test_a_cve_the_advisories_have_not_seen_waits_for_them(self):
        """A briefing from the dashboard can read an event the hourly run has
        not reached yet; it is read again by the next one."""
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234"]), 0)
        self.reading.retry.assert_called_once_with("a" * 36)
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234"],
                                    outcomes={"vea": "No CVE to advise on: CVE-2026-1234 out of scope"}), 1)

    def test_so_does_one_added_to_the_event_since_they_declined_it(self):
        outcomes = {"vea": "No CVE to advise on: CVE-2026-1234 out of scope"}
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234", "CVE-2026-5678"], outcomes=outcomes), 0)

    def test_what_the_advisories_declined_is_decided_again_on_what_there_is_now(self):
        """The event was closed on their old outcome, although an advisory
        would be made for it now."""
        declined = {"vea": "No CVE to advise on: CVE-2026-1234 in VEA-00589"}
        then = {"affected": [("Fortinet", "FortiOS")], "cvss_score": "7.0", "cisa_kev": "No"}
        covered = {"CVE-2026-1234": analyser_pipeline._covered(
            SimpleNamespace(vea_id="VEA-00589", review_state="draft"), "7.0", "No")}
        fortinet = [("Fortinet", "PIR-00002 (Fortinet)")]
        for case, record, terms, coverage in (
                ("its CVSS score rose", dict(then, cvss_score="9.8"), fortinet, covered),
                ("the advisory that covered it was deleted", then, fortinet, {}),
                ("a PIR took its product into scope", then, fortinet, {})):
            with self.subTest(case):
                self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234"], outcomes=declined,
                                            records={"CVE-2026-1234": record}, terms=terms, coverage=coverage), 0)
                self.rejected.assert_not_called()
                self.reading.retry.assert_not_called()
        # Covered still, and as it was: closed.
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234"], outcomes=declined,
                                    records={"CVE-2026-1234": then}, terms=fortinet, coverage=covered), 1)
        self.assertTrue(self.rejected.call_args.args[2].endswith(
            "advisory: No CVE to advise on: CVE-2026-1234 in VEA-00589"))
        self.outcome.assert_not_called()

    def test_a_cve_that_cannot_be_looked_up_now_keeps_it_for_the_next_run(self):
        outcomes = {"vea": "No CVE to advise on: CVE-2026-1234 out of scope"}
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1234"], outcomes=outcomes,
                                    records={"CVE-2026-1234": None}), 0)
        self.reading.retry.assert_called_once_with("a" * 36)

    def test_the_cves_past_the_limit_do_not_keep_it_open(self):
        """They are never looked up, so the advisories have declined the event
        once they declined the ones they looked up."""
        outcomes = {"vea": "No CVE to advise on: CVE-2026-1001 out of scope, 1 more not looked up, past the limit of 1"}
        self.assertEqual(self.close(_verdict(), cves=["CVE-2026-1001", "CVE-2026-1002"], outcomes=outcomes,
                                    ANALYSER_ADVISORY_MAX_CVES=1), 1)

    def test_a_product_switched_off_has_declined_it(self):
        """With the briefing off, the alerts close the events."""
        self.assertEqual(self.close(_verdict(briefing=True), cves=["CVE-2026-1234"], running="alert",
                                    ANALYSER_DAILY_BRIEFING=False, ANALYSER_VULNERABILITY_ADVISORIES=False), 1)

    def test_the_product_of_the_run_is_never_switched_off(self):
        """The scheduled briefing is off by default, and a briefing started
        from the dashboard rejected the events it had just listed under Also
        seen."""
        self.assertEqual(self.close(_verdict(briefing=True), ANALYSER_DAILY_BRIEFING=False), 0)
        self.assertEqual(self.close(_verdict(alert=True), running="alert", ANALYSER_FLASH_INTEL=False,
                                    ANALYSER_DAILY_BRIEFING=False), 0)

    def test_one_misp_refused_to_reject_is_closed_by_the_next_run(self):
        self.assertEqual(self.close(_verdict(), refused=True), 0)
        self.reading.retry.assert_called_once_with("a" * 36)
        [decision] = self.found.stats["event_decisions"]
        self.assertEqual(decision["outcome"], "left open")
        self.assertTrue(decision["reason"].endswith("MISP refused the rejection"))

    def test_another_server_s_event_gets_no_note(self):
        """It is closed in zsazsa; writing to it is not zsazsa's to do."""
        self.close(_verdict(), source=Source("partner", "misp", "Partner", None, False))
        self.rejected.assert_called_once()
        self.noted.assert_not_called()


class OneFailedCall(unittest.TestCase):
    def setUp(self):
        # Nothing is flagged for follow-up, and this install's cache is left unread.
        self.enterContext(mock.patch.object(analyser_pipeline.collection_cache, "get_flagged_uuids", return_value=set()))

    def test_a_summary_that_fails_leaves_the_other_events_alone(self):
        """On Saturday a dropped connection ended an advisory run at summary 7 of 12."""
        events = [SimpleNamespace(uuid=c * 36, info=f"Event {c}", tags=[]) for c in "abc"]
        article = [SimpleNamespace(name="Article", content="An article")]

        def summarise(source, event, reports, galaxy_lookup, progress=None):
            if event.info == "Event b":
                raise ConnectionError("Connection error.")
            return f"Summary of {event.info}", True
        reading = mock.create_autospec(Reading, instance=True)
        reading.read.return_value = [(e, SCRAPER) for e in events]
        reading.counts, reading.errors = {"MISP scraper": 3}, []
        with mock.patch.object(analyser_pipeline, "read_event_reports", return_value=article), \
             mock.patch.object(analyser_pipeline, "_event_http_error", return_value=False), \
             mock.patch.object(analyser_pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(analyser_pipeline, "_ensure_ai_summary", side_effect=summarise), \
             self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            found = analyser_pipeline._common_candidate_events(reading)
        self.assertEqual([e.info for e in found.events], ["Event a", "Event b", "Event c"])
        self.assertEqual(found.summaries,
                         {"a" * 36: "Summary of Event a", "b" * 36: "", "c" * 36: "Summary of Event c"})
        self.assertEqual((found.stats["summary_created"], found.stats["summary_failed"]), (2, 1))
        # Read again by the next run, for its summary.
        reading.retry.assert_called_once_with("b" * 36)

    def common(self, events, reports, http_error=False, rejected=True):
        reading = mock.create_autospec(Reading, instance=True)
        reading.read.return_value = [(e, SCRAPER) for e in events]
        reading.counts, reading.errors = {"MISP scraper": len(events)}, []
        with mock.patch.object(analyser_pipeline, "read_event_reports", return_value=reports), \
             mock.patch.object(analyser_pipeline, "_event_http_error", return_value=http_error), \
             mock.patch.object(analyser_pipeline, "_build_galaxy_lookup", return_value={}), \
             mock.patch.object(analyser_pipeline.event_state, "reject", return_value=rejected), \
             mock.patch.object(analyser_pipeline.collection_cache, "mark_ai_summary"), \
             mock.patch.object(analyser_pipeline.misp_store, "add_ai_summary_report"), \
             mock.patch.object(analyser_pipeline.llm, "summarise_report", return_value=""), \
             mock.patch.object(analyser_pipeline, "_log"):
            return analyser_pipeline._common_candidate_events(reading), reading

    def test_an_empty_summary_is_asked_for_again(self):
        """A model out of tokens answers with nothing."""
        event = SimpleNamespace(uuid="a" * 36, info="Event a", tags=[], id="1")
        with self.assertLogs("webapp.analyser_pipeline", level="WARNING"):
            found, reading = self.common([event], [SimpleNamespace(name="Article", content="An article")])
        self.assertEqual(found.stats["summary_failed"], 1)
        reading.retry.assert_called_once_with("a" * 36)

    def test_a_rejection_misp_refused_is_not_counted_and_is_tried_again(self):
        event = SimpleNamespace(uuid="a" * 36, info="Event a", tags=[], id="1")
        found, reading = self.common([event], [], http_error=True, rejected=False)
        self.assertEqual(found.stats["hard_rejected"], 0)
        self.assertEqual(found.stats["event_decisions"][0]["outcome"], "left open")
        reading.retry.assert_called_once_with("a" * 36)

    def test_an_event_an_analyst_follows_up_is_not_rejected_for_its_missing_article(self):
        """Reopened for review by hand, the next run rejected it again."""
        event = SimpleNamespace(uuid="a" * 36, info="Event a", tags=[], id="1")
        with mock.patch.object(analyser_pipeline.collection_cache, "get_flagged_uuids", return_value={"a" * 36}):
            found, _reading = self.common([event], [], http_error=True)
        self.assertEqual(found.stats["hard_rejected"], 0)
        self.assertEqual(found.stats["event_decisions"][0]["outcome"], "left open")
        self.assertIn("an analyst follows it up", found.stats["event_decisions"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
