import logging
from datetime import datetime, timezone
from types import SimpleNamespace

from pymisp import MISPEvent, MISPEventReport

import config
from analyser import llm, tagger
from analyser.reader import read_event_reports

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
# Must be the product type as PRODUCT_TYPES spells it: stakeholder subscriptions
# and delivery modes are keyed by that string, so a near miss matches nobody.
_FLASH_INTEL_PRODUCT_NAME = "Flash intel alert"
# Default classification, raised when the source is more restricted.
_AUTO_TLP = "amber"


def _get_http_error(event) -> str | None:
    for tag in event.tags:
        if tag.name.startswith(_HTTP_ERROR_PREFIX):
            return tag.name[len(_HTTP_ERROR_PREFIX):]
    return None


def _get_source_reliability(event) -> str:
    for tag in event.tags:
        if tag.name.startswith("admiralty-scale:source-reliability="):
            return tag.name.split("=")[1].strip('"')
    return "f"


def _get_reports(misp, event) -> tuple[str | None, list]:
    from webapp.analyser_pipeline import _first_non_empty_report_content

    reports = read_event_reports(misp, event)
    return _first_non_empty_report_content(reports) or None, reports


def _event_date(event) -> str:
    if event.date:
        return str(event.date)
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def process(misp, misp_webapp, event, focus_points: dict, keep_open_for: str = "", open_alerts=()) -> dict:
    """Make a flash intel alert from an event whose article matches a focus point.

    An event that matches none, or whose story one of ``open_alerts`` already
    tells, is rejected, unless ``keep_open_for`` says what it is left open
    for: the daily briefing only reads the events nobody rejected.
    """
    from webapp import misp_store
    from webapp.analyser_pipeline import covering_alert

    source_feed = tagger.get_source_feed(event)
    tlp = misp_store.source_events_tlp([event], _AUTO_TLP)

    http_error = _get_http_error(event)
    if http_error:
        logger.info("Event %s skipped: HTTP %s from feed %s", event.uuid, http_error, source_feed)
        tagger.set_workflow_state(misp, event, "rejected")
        return {"outcome": "http_error", "source_feed": source_feed, "detail": f"HTTP={http_error}"}

    article_content, reports = _get_reports(misp, event)
    if not article_content:
        logger.warning("Event %s has no report content", event.uuid)
        tagger.set_workflow_state(misp, event, "rejected")
        return {"outcome": "no_content", "source_feed": source_feed, "detail": None}

    source_reliability = _get_source_reliability(event)

    relevance = llm.check_relevance(article_content, focus_points, source_reliability)
    if relevance is None:
        # No verdict on the article, so it is not rejected for one.
        return {"outcome": "error", "source_feed": source_feed, "detail": "The model's answer could not be read"}
    matched = relevance.get("matched_focus_points") or []
    if relevance.get("relevant") and matched:
        covered_by = covering_alert(event.info or "", article_content, list(open_alerts))
        reason = f"The same story as {covered_by}." if covered_by else ""
    else:
        reason = relevance.get("reason", "") or "Not relevant to the focus points."
        if relevance.get("relevant"):
            # The prompt asks for the focus points a relevant article matches.
            reason = f"Relevant, but no focus point matched. {relevance.get('reason', '')}".strip()
    if reason:
        logger.info("Event %s gets no alert: %s", event.uuid, reason)
        if keep_open_for:
            return {"outcome": "not_relevant", "source_feed": source_feed,
                    "detail": f"{reason} Kept open for {keep_open_for}."}
        tagger.set_workflow_state(misp, event, "rejected")
        return {"outcome": "not_relevant", "source_feed": source_feed, "detail": reason}

    source_type = relevance.get("source_type", "blog-post")
    logger.info("Event %s relevant, matched: %s", event.uuid, matched)

    # MISP cannot tag an event report (it answers Invalid Target), so the source type goes on the event.
    tagger.add_tag(misp, event, f'osint:source-type="{source_type}"')

    fia_content = llm.generate_flash_intel(
        article_content,
        focus_points,
        matched,
        source_reliability,
        _event_date(event),
    )
    if not fia_content.strip():
        # A model that runs out of tokens answers with nothing rather than an
        # error. Carrying on would file an alert holding only its own heading,
        # mark the source event as handled so it is never looked at again, and
        # send that to any subscriber on automated mode. Leave the event alone
        # for the daily briefing or a run from the dashboard to try again.
        logger.error("Flash intel generation returned nothing for %s", event.uuid)
        return {"outcome": "error", "source_feed": source_feed,
                "detail": "The model returned an empty flash intel draft"}

    product_event = MISPEvent()
    product_event.info = f"[zsazsa:fia] {event.info}"
    product_event.distribution = 0
    product_event.threat_level_id = 2
    product_event.analysis = 2
    product_event.extends_uuid = event.uuid
    product_event.add_tag(f"tlp:{tlp}")
    product_event.add_tag("curation:source:OSINT")

    product_event = misp_webapp.add_event(product_event, pythonify=True)
    if isinstance(product_event, dict):
        err = product_event.get("errors", "unknown error")
        logger.error("Failed to create product event: %s", err)
        return {"outcome": "error", "source_feed": source_feed, "detail": str(err)}

    event_id = getattr(product_event, "id", None)
    if not event_id:
        logger.error("Created product event has no id")
        return {"outcome": "error", "source_feed": source_feed, "detail": "missing event id"}

    # zsazsa-namespace and workflow tags are applied locally via the tag endpoint;
    # tags embedded in add_event are attached globally even when flagged local.
    misp_webapp.tag(product_event.uuid, config.TAG_FLASH_INTEL, local=True)
    misp_webapp.tag(product_event.uuid, 'workflow:state="draft"', local=True)
    fia_id = f"FIA-{int(event_id):05d}"
    if "FIA-#####" in fia_content:
        fia_content = fia_content.replace("FIA-#####", fia_id)
    else:
        fia_content = f"# {fia_id}\n\n{fia_content}"

    # Store the LLM-rendered markdown as the primary report.
    report = MISPEventReport()
    report.name = fia_id
    report.content = fia_content
    report.distribution = 0
    misp_webapp.add_event_report(product_event, report)

    # Add a minimal zsazsa-flash-intel object so the webapp wizard can edit
    # the draft. The summary seeds with the LLM body; analyst refines fields
    # before approving and publishing.
    object_saved = _add_flash_intel_object(misp_webapp, product_event, fia_id, event, fia_content, matched,
                                           relevance.get("reason", ""), tlp)

    # Mark the source event as routed for review (not yet complete). If that
    # does not take, the event still reads as incomplete and the next run makes
    # a second draft for it, so the activity log has to say so.
    routed = tagger.set_workflow_state(misp, event, "ongoing")
    # As an alert made from the dashboard does, so the collection page shows
    # the event went into one.
    tagger.add_tag(misp, event, 'zsazsa:product="flash-intel"')
    detail = fia_id if routed else f"{fia_id} (source event still marked incomplete)"
    if not object_saved:
        detail += " (draft object not saved)"

    recipients = _automated_subscribers(tlp)
    auto = bool(recipients)
    if auto:
        try:
            _auto_publish(misp_webapp, product_event, fia_id, fia_content, recipients, tlp=tlp)
        except Exception as exc:
            logger.warning("Auto-publish failed for %s: %s", fia_id, exc)
            auto = False

    logger.info(
        "Created %s draft for source event %s (%s)",
        fia_id, event.uuid,
        "auto-published" if auto else "a draft to review",
    )
    return {
        "outcome": "product_created",
        "source_feed": source_feed,
        "detail": detail,
        "product": product_event,
        "fia_id": fia_id,
        "content": fia_content,
        "auto_published": auto,
    }


def _automated_subscribers(tlp=_AUTO_TLP) -> list:
    """The stakeholders an alert may be published to without an analyst."""
    from webapp import misp_store

    try:
        return misp_store.stakeholders_on_automated_mode(_FLASH_INTEL_PRODUCT_NAME, tlp)
    except Exception as exc:
        logger.warning("Could not query stakeholders: %s", exc)
        return []


def _auto_publish(misp_webapp, product_event, fia_id, content, recipients, tlp=_AUTO_TLP):
    """Mark the FIA approved, publish, and deliver it to the automated subscribers."""
    from notifier import dispatcher
    from webapp import misp_store

    # Re-fetch so newly attached objects are present with server IDs.
    fresh = misp_webapp.get_event(product_event.uuid, pythonify=True)
    if not isinstance(fresh, dict) and fresh is not None:
        object_found = False
        state_updated = False
        for obj in getattr(fresh, "objects", []) or []:
            if obj.name != "zsazsa-flash-intel":
                continue
            object_found = True
            for a in obj.attributes:
                if a.object_relation == "review-state":
                    a.value = "approved"
                    misp_webapp.update_attribute(a)
                    state_updated = True
                    break
            break
        if not object_found:
            logger.warning("Auto-publish %s: zsazsa-flash-intel object not found", fia_id)
        elif not state_updated:
            logger.warning("Auto-publish %s: review-state attribute not found", fia_id)

    tagger.set_workflow_state(misp_webapp, product_event, "complete")
    misp_store.publish_event(misp_webapp, product_event.uuid, fia_id)

    # The analyser has no FIA namespace of its own, so the fields the senders read
    # are named directly; `id` carries the MISP link Mattermost puts under the
    # message. A channel that could not be reached is already logged by the
    # dispatcher, so the summary here only has to say who the alert was for.
    fia = SimpleNamespace(fia_id=fia_id, tlp=tlp, id=product_event.id)
    _ok, detail = dispatcher.delivery_outcome(dispatcher.send_flash_intel(fia, content, recipients))
    logger.info("%s auto-published to %d subscriber(s): %s", fia_id, len(recipients), detail)


def _add_flash_intel_object(misp_webapp, product_event, fia_id, source_event, content, matched, reason, tlp):
    """Attach a draft zsazsa-flash-intel object to the product event. False when MISP refused it."""
    from webapp import misp_store

    # Built from the template, which has the meta-category MISP needs for an object it does not know.
    obj = misp_store._build_obj("zsazsa-flash-intel")

    def add(rel, value):
        if value:
            obj.add_attribute(rel, type="text", value=str(value), disable_correlation=True)

    add("fia-id", fia_id)
    add("title", source_event.info)
    add("tlp", tlp)
    add("summary", _extract_section(content, "Summary"))
    add("source-description", f"OSINT feed: {tagger.get_source_feed(source_event)}")
    add("source-reliability", _get_source_reliability(source_event).upper())
    add("review-state", "draft")
    add("source-event-uuid", source_event.uuid)
    misp_store._oa_json(obj, "source-event-hints",
                        {source_event.uuid: misp_store.analyser_source_id(source_event)})
    add("author", "analyser")
    if matched:
        add("affected-assets", ", ".join(matched))
        # The model's own words, for the analyst to judge the match by.
        add("analyser-reason", f"Focus points: {', '.join(matched)}. {reason}".strip())
    try:
        # Everyone the alert can reach, for the analyst to narrow down.
        add("audience", misp_store.subscriber_audience(_FLASH_INTEL_PRODUCT_NAME, tlp))
    except Exception as exc:
        logger.warning("Could not read the stakeholders for the audience of %s: %s", fia_id, exc)
    reply = misp_webapp.add_object(product_event, obj)
    if isinstance(reply, dict) and reply.get("errors"):
        logger.error("Could not add the flash intel object to %s: %s", fia_id, reply["errors"])
        return False
    return True


def _extract_section(content, heading):
    """Return the first paragraph under '## <heading>' from a markdown body."""
    if not content:
        return ""
    target = f"## {heading}"
    lines = content.splitlines()
    collected = []
    in_section = False
    for line in lines:
        if line.strip() == target:
            in_section = True
            continue
        if in_section:
            if line.startswith("##"):
                break
            collected.append(line)
    return "\n".join(collected).strip()
