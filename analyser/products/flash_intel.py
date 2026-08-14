import logging
from datetime import datetime
from types import SimpleNamespace

from pymisp import MISPEvent, MISPEventReport

import config
from analyser import llm, tagger

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
# Must be the product type as PRODUCT_TYPES spells it: stakeholder subscriptions
# and delivery modes are keyed by that string, so a near miss matches nobody.
_FLASH_INTEL_PRODUCT_NAME = "Flash intel alert"
# Classification stamped on every auto-generated alert, and the one its
# notifications are sent under.
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
    reports = misp.get_event_reports(event.id, pythonify=True)
    if not isinstance(reports, list) or not reports:
        return None, []
    return getattr(reports[0], "content", None), reports


def _event_date(event) -> str:
    if event.date:
        return str(event.date)
    return datetime.utcnow().strftime("%Y-%m-%d")


def process(misp, misp_webapp, event, focus_points: dict) -> dict:
    source_feed = tagger.get_source_feed(event)

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
    if not relevance.get("relevant"):
        reason = relevance.get("reason", "")
        logger.info("Event %s not relevant: %s", event.uuid, reason)
        tagger.set_workflow_state(misp, event, "rejected")
        return {"outcome": "not_relevant", "source_feed": source_feed, "detail": reason}

    matched = relevance.get("matched_focus_points", [])
    source_type = relevance.get("source_type", "blog-post")
    logger.info("Event %s relevant, matched: %s", event.uuid, matched)

    if reports:
        tagger.add_tag(misp, reports[0], f'osint:source-type="{source_type}"')

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
        # and let the next run try it again.
        logger.error("Flash intel generation returned nothing for %s", event.uuid)
        return {"outcome": "error", "source_feed": source_feed,
                "detail": "The model returned an empty flash intel draft"}

    product_event = MISPEvent()
    product_event.info = f"[zsazsa:fia] {event.info}"
    product_event.distribution = 0
    product_event.threat_level_id = 2
    product_event.analysis = 2
    product_event.extends_uuid = event.uuid
    product_event.add_tag(f"tlp:{_AUTO_TLP}")
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
    misp_webapp.tag(product_event.uuid, 'workflow:state="ongoing"', local=True)
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
    _add_flash_intel_object(misp_webapp, product_event, fia_id, event, fia_content, matched)

    # Mark the source event as routed for review (not yet complete). If that
    # does not take, the event still reads as incomplete and the next run makes
    # a second draft for it, so the activity log has to say so.
    routed = tagger.set_workflow_state(misp, event, "ongoing")
    detail = fia_id if routed else f"{fia_id} (source event still marked incomplete)"

    recipients = _automated_subscribers()
    auto = bool(recipients)
    if auto:
        try:
            _auto_publish(misp_webapp, product_event, fia_id, fia_content, recipients)
        except Exception as exc:
            logger.warning("Auto-publish failed for %s: %s", fia_id, exc)
            auto = False

    logger.info(
        "Created %s draft for source event %s (%s)",
        fia_id, event.uuid,
        "auto-published" if auto else "pending review",
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


def _automated_subscribers() -> list:
    """The stakeholders an alert may be published to without an analyst."""
    from webapp import misp_store

    try:
        return misp_store.stakeholders_on_automated_mode(_FLASH_INTEL_PRODUCT_NAME, _AUTO_TLP)
    except Exception as exc:
        logger.warning("Could not query stakeholders: %s", exc)
        return []


def _auto_publish(misp_webapp, product_event, fia_id, content, recipients):
    """Mark the FIA approved, publish, and deliver it to the automated subscribers."""
    from notifier import dispatcher

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
    misp_webapp.publish(product_event.uuid)

    # The analyser has no FIA namespace of its own, so the fields the senders read
    # are named directly; `id` carries the MISP link Mattermost puts under the
    # message. A channel that could not be reached is already logged by the
    # dispatcher, so the summary here only has to say who the alert was for.
    fia = SimpleNamespace(fia_id=fia_id, tlp=_AUTO_TLP, id=product_event.id)
    _ok, detail = dispatcher.delivery_outcome(dispatcher.send_flash_intel(fia, content, recipients))
    logger.info("%s auto-published to %d subscriber(s): %s", fia_id, len(recipients), detail)


def _add_flash_intel_object(misp_webapp, product_event, fia_id, source_event, content, matched):
    """Attach a draft zsazsa-flash-intel object to the product event."""
    from pymisp import MISPObject

    obj = MISPObject("zsazsa-flash-intel", strict=False)

    def add(rel, value):
        if value:
            obj.add_attribute(rel, type="text", value=str(value), disable_correlation=True)

    add("fia-id", fia_id)
    add("title", source_event.info)
    add("tlp", _AUTO_TLP)
    add("summary", _extract_section(content, "Summary"))
    add("source-description", f"OSINT feed: {tagger.get_source_feed(source_event)}")
    add("source-reliability", _get_source_reliability(source_event).upper())
    add("review-state", "pending-review")
    add("source-event-uuid", source_event.uuid)
    add("author", "analyser")
    if matched:
        add("affected-assets", ", ".join(matched))
    misp_webapp.add_object(product_event, obj)


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
