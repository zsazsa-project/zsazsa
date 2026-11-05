"""A flash intel alert drafted by the analyser from one source event.

The relevance verdict (analyser.relevance) has already said the event is worth
an alert and on what grounds. The model drafts the alert with the prompt the
Build with AI button uses, and parse_fia_draft() reads that draft into the
fields of the alert, for both of them. The alert is addressed to the
stakeholders of every PIR and GIR in its grounds, or with focus points alone to
its subscribers, and published at once to the subscribers on automated mode.

Drafting and filing are two steps, so that a run can check it still holds the
analyser lock after the model call and before it writes.
"""

import logging
import re

from analyser import llm, tagger

logger = logging.getLogger(__name__)

# Must be the product type as PRODUCT_TYPES spells it: stakeholder subscriptions
# and delivery modes are keyed by that string, so a near miss matches nobody.
_FLASH_INTEL_PRODUCT_NAME = "Flash intel alert"
# Default classification, raised when the source is more restricted.
_AUTO_TLP = "amber"


def draft_alert(event, source, verdict: dict, judge, article: str, summary: str, why: str,
                update_of: str = "") -> dict | None:
    """The fields of an alert the model drafted from an event, or None when it
    gave no draft to file, which leaves the event as it is for the next run.
    ``why`` is the reason it is made, the verdict's or an analyst's push;
    ``update_of`` names the earlier alert it tells again."""
    from webapp import misp_store

    grounds = verdict["alert"]["grounds"]
    requirements = judge.requirements_of(grounds)
    names = [g.get("focus_point") or g["id"] for g in grounds]
    reliability = tagger.tag_value(event, "admiralty-scale:source-reliability=")
    draft = llm.generate_fia_draft(
        article or summary, event_info=event.info or "", event_date=str(event.date or ""),
        source_reliability=reliability or "unknown", matched_points=names, feature="generate_flash_intel")
    fields = parse_fia_draft(draft)
    if not fields["summary"] and not fields["what_happened"]:
        # A model out of tokens answers with nothing, and one that declines
        # with a sentence of its own. Filed, either would be an alert holding
        # only its heading, sent at once to the subscribers on automated mode.
        logger.error("Flash intel draft for %s has no summary and nothing on what happened: %r",
                     event.uuid, draft.strip()[:200])
        return None

    tlp = misp_store.source_events_tlp([event], _AUTO_TLP)
    # A requirement whose stakeholders have no role takes everyone the alert
    # can reach, as an alert from focus points alone does.
    audience = misp_store.requirement_audience(requirements, misp_store.list_stakeholders()) if requirements else ""
    pirs = [r.uuid for r in requirements if getattr(r, "pir_id", "")]
    quoted = "; ".join(f'{g.get("focus_point") or g["id"]}: "{g["quote"]}"' for g in grounds)
    return {
        **fields,
        "title": event.info or "Untitled",
        "tlp": tlp,
        "audience": audience or misp_store.subscriber_audience(_FLASH_INTEL_PRODUCT_NAME, tlp),
        "source_reliability": reliability.upper(),
        "information_credibility": tagger.tag_value(event, "admiralty-scale:information-credibility="),
        "author": "analyser",
        "source_event_uuids": [event.uuid],
        "source_event_hints": {event.uuid: source.hint},
        "linked_requirement_uuids": [r.uuid for r in requirements],
        # The form edits one PIR; it shows the first.
        "linked_pir_uuid": pirs[0] if pirs else "",
        "context_tags": [f"match:{g['id']}" for g in grounds if g.get("id")],
        "analyser_reason": " ".join(part for part in (update_of and f"{update_of.rstrip('.')}.", why,
                                                      f"Grounds: {quoted}" if quoted else "") if part),
        "review_state": misp_store.FIA_REVIEW_DRAFT,
    }


def file_alert(data: dict, event, source, verdict: dict) -> tuple[str, str]:
    """File a drafted alert, and publish it at once to the subscribers on
    automated mode. Returns its id, and what went wrong in publishing it, or ""."""
    from webapp import misp_store

    uuid, fia_id = misp_store.create_fia(data)
    # MISP cannot tag an event report (it answers Invalid Target), so the
    # source type goes on the event, when the event is ours to tag.
    if source.own and verdict.get("source_type"):
        tagger.add_tag(source.client, event, f'osint:source-type="{verdict["source_type"]}"')
    return fia_id, _publish_to_automated_subscribers(uuid, fia_id, data["tlp"])


def _publish_to_automated_subscribers(uuid: str, fia_id: str, tlp: str) -> str:
    """Approve, publish and deliver an alert to the stakeholders who asked for
    alerts with nobody reviewing them, when there are any. Returns what went
    wrong, for the run to show, or ""."""
    from notifier import dispatcher
    from webapp import misp_store

    try:
        recipients = misp_store.stakeholders_on_automated_mode(_FLASH_INTEL_PRODUCT_NAME, tlp)
    except Exception as exc:
        logger.warning("Could not query stakeholders: %s", exc)
        return f"the subscribers on automated mode could not be read, so it was not sent: {exc}"
    if not recipients:
        return ""
    problems = []
    try:
        if not misp_store.publish_fia(uuid):
            # Sent all the same, as from the alert's page: it is approved now.
            problems.append("MISP did not publish it")
        fia = misp_store.get_fia(uuid)
        content = misp_store.render_fia_markdown(fia, fia_id, include_source_links=True)
        # A channel that could not be reached is already logged by the
        # dispatcher, so this only has to say who the alert was for.
        ok, detail = dispatcher.delivery_outcome(dispatcher.send_flash_intel(fia, content, recipients))
        logger.info("%s auto-published to %d subscriber(s): %s", fia_id, len(recipients), detail)
        if not ok:
            problems.append(f"its delivery to the subscribers on automated mode: {detail}")
    except Exception as exc:
        logger.warning("Auto-publish failed for %s: %s", fia_id, exc)
        problems.append(f"publishing it to the subscribers on automated mode failed: {exc}")
    return "; ".join(problems)


def _csv(value: str) -> list[str]:
    """A comma-separated value as a list, without the template's placeholders."""
    return [v.strip() for v in (value or "").split(",") if v.strip() and not v.strip().startswith("<")]


# The labelled lines of the draft, by section, and the field each fills.
_LINE_FIELDS = {
    "what_happened": (("**Source reliability:**", "source_reliability"),
                      ("**Information credibility justification:**", "credibility_justification"),
                      ("**Information credibility:**", "information_credibility"),
                      ("**Source:**", "source_description")),
    "why_matters": (("- **Likely impact:**", "likely_impact"), ("- **Affected assets:**", "affected_assets"),
                    ("- **Threat actor types:**", "actor_types"), ("- **Threat actor context:**", "actor_context")),
    "scope": (("- **Geographic scope:**", "geographic_scope"), ("- **Sectors:**", "sectors"),
              ("- **Threat types:**", "threat_types"), ("- **Technology:**", "technology"),
              ("- **Vendor:**", "vendor"), ("- **Incident:**", "incident"), ("- **Campaign:**", "campaign")),
}
_LIST_FIELDS = {"actor_types", "geographic_scope", "sectors", "threat_types", "technology", "vendor", "incident",
                "campaign"}
# Sections whose bullets are a list field of their own.
_BULLET_SECTIONS = {"what_happened", "actions_immediate", "actions_near_term", "mitre_techniques",
                    "hunting_hypotheses"}


def parse_fia_draft(text: str) -> dict:
    """The fields of an alert from a draft the flash_intel_generate prompt wrote.

    The narrative fields with one entry per line (what happened, the actions,
    the techniques, the hunting hypotheses) are lists.
    """
    fields = {
        "title": "", "summary": "", "action_required": "", "what_happened": [], "source_description": "",
        "likely_impact": "", "affected_assets": "", "actor_types": [], "actor_context": "",
        "geographic_scope": [], "sectors": [], "threat_types": [], "technology": [], "vendor": [],
        "incident": [], "campaign": [], "actions_immediate": [], "actions_near_term": [],
        "mitre_techniques": [], "hunting_hypotheses": [], "source_reliability": "",
        "information_credibility": "", "credibility_justification": "",
    }
    section = None
    for line in text.split("\n"):
        s = line.strip()
        if not s or s == "---":
            continue
        heading = re.match(r"^#\s+Flash intel alert:\s*(.*)", s, re.IGNORECASE)
        if heading:
            fields["title"] = heading.group(1).strip()
            continue
        if s.startswith("## "):
            section = _section(s[3:].lower())
            continue
        if s.startswith("### "):
            sub = s[4:].lower()
            section = "actions_immediate" if "immediate" in sub else "actions_near_term" if "near" in sub else section
            continue
        if section in ("detection", "mitre_techniques", "hunting_hypotheses"):
            if s.startswith("**Relevant MITRE"):
                section = "mitre_techniques"
                continue
            if s.startswith("**Hunting"):
                section = "hunting_hypotheses"
                continue
        if section == "summary":
            if s.startswith("**Action required:**"):
                fields["action_required"] = s[len("**Action required:**"):].strip()
            elif not s.startswith(("**", "#")):
                fields["summary"] = f"{fields['summary']}\n{s}".strip()
            continue
        labelled = next(((label, name) for label, name in _LINE_FIELDS.get(section, ()) if s.startswith(label)), None)
        if labelled:
            label, name = labelled
            value = s[len(label):].strip()
            fields[name] = _csv(value) if name in _LIST_FIELDS else value
        elif section in _BULLET_SECTIONS and s.startswith("- ") and not s.startswith("- <"):
            fields[section].append(s[2:].strip())
    reliability = fields["source_reliability"][:1].upper()
    fields["source_reliability"] = reliability if reliability in "ABCDEF" else ""
    credibility = fields["information_credibility"][:1]
    fields["information_credibility"] = credibility if credibility in "123456" else ""
    return fields


def _section(heading: str) -> str | None:
    if "summary" in heading:
        return "summary"
    if "what happened" in heading:
        return "what_happened"
    if "why it matters" in heading:
        return "why_matters"
    if heading.strip() == "scope":
        return "scope"
    if "recommended" in heading:
        return "actions"
    if "detection" in heading:
        return "detection"
    return None
