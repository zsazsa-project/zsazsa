import json
import logging
from datetime import datetime
from types import SimpleNamespace

from pymisp import MISPEvent, MISPEventReport

import config
from analyser import llm, tagger

logger = logging.getLogger(__name__)

_HTTP_ERROR_PREFIX = "misp-scraper:HTTP="
_FLASH_INTEL_PRODUCT_NAME = "Flash intel"
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

    product_event = MISPEvent()
    product_event.info = f"[zsazsa:fia] {event.info}"
    product_event.distribution = 0
    product_event.threat_level_id = 2
    product_event.analysis = 2
    product_event.extends_uuid = event.uuid
    product_event.add_tag("tlp:amber")
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

    # Mark the source event as routed for review (not yet complete).
    tagger.set_workflow_state(misp, event, "ongoing")

    auto = _has_automated_subscriber(misp_webapp, _FLASH_INTEL_PRODUCT_NAME)
    if auto:
        try:
            _auto_publish(misp_webapp, product_event, fia_id, fia_content)
            logger.info("%s auto-published (subscriber on automated mode)", fia_id)
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
        "detail": fia_id,
        "product": product_event,
        "fia_id": fia_id,
        "content": fia_content,
        "auto_published": auto,
    }


def _has_automated_subscriber(misp_webapp, product_name: str) -> bool:
    """True if at least one stakeholder is subscribed to ``product_name``
    with delivery mode ``automated``."""
    try:
        events = misp_webapp.search(tags=[config.TAG_STAKEHOLDER], pythonify=True)
    except Exception as exc:
        logger.warning("Could not query stakeholders: %s", exc)
        return False
    if not events or isinstance(events, dict):
        return False
    for ev in events:
        for obj in getattr(ev, "objects", []) or []:
            if obj.name != "zsazsa-stakeholder":
                continue
            modes_attr = next(
                (a for a in obj.attributes if a.object_relation == "product-modes"),
                None,
            )
            if not modes_attr or not modes_attr.value:
                continue
            try:
                modes = json.loads(modes_attr.value)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(modes, dict) and modes.get(product_name) == "automated":
                return True
    return False


def _auto_publish(misp_webapp, product_event, fia_id, content):
    """Mark the FIA approved, publish, and send Mattermost and email alerts."""
    from notifier.mattermost import send_flash_intel_alert
    from notifier import email

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
    send_flash_intel_alert(product_event, fia_id, content)
    # The e-mail sender takes the alert itself so the subject carries the id and
    # classification; the analyser has no FIA namespace, so name them directly.
    email.send_flash_intel_alert(SimpleNamespace(fia_id=fia_id, tlp=_AUTO_TLP), content)


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
