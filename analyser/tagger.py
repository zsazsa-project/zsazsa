import logging

logger = logging.getLogger(__name__)

_WORKFLOW_PREFIX = "workflow:state="
_FEED_TAG_PREFIX = "scraper:data-collection-source:"


def source_feed_from_tags(tag_names) -> str:
    """Return the collection-source feed from a list of tag name strings."""
    for name in tag_names or []:
        if name and name.startswith(_FEED_TAG_PREFIX):
            return name[len(_FEED_TAG_PREFIX):]
    return "unknown"


def get_source_feed(event) -> str:
    return source_feed_from_tags(
        [getattr(t, "name", "") for t in (getattr(event, "tags", []) or [])]
    )


def _failed(reply) -> str:
    """The error MISP reported for a tag call, or "" when it went through.

    PyMISP answers a refused tag with a dict rather than raising, so a caller
    that does not look at the reply cannot tell the two apart.
    """
    if isinstance(reply, dict) and "errors" in reply:
        return str(reply["errors"])
    return ""


def set_workflow_state(misp, event, state: str) -> bool:
    """Replace the event's workflow state tag. False when MISP refused a part.

    Both halves matter. An event that keeps its old state alongside the new one
    still answers the analyser's "incomplete" search, so it is picked up and
    processed again on every run, producing a second product each time.
    """
    ok = True
    for tag in event.tags:
        if tag.name.startswith(_WORKFLOW_PREFIX):
            error = _failed(misp.untag(event, tag.name))
            if error:
                logger.error("Could not remove %s from %s: %s", tag.name, event.uuid, error)
                ok = False
    error = _failed(misp.tag(event, f'{_WORKFLOW_PREFIX}"{state}"', local=True))
    if error:
        logger.error("Could not set workflow state %s on %s: %s", state, event.uuid, error)
        ok = False
    return ok


def add_tag(misp, entity, tag_name: str) -> bool:
    """Attach a local tag. False when MISP refused it."""
    error = _failed(misp.tag(entity, tag_name, local=True))
    if error:
        logger.error("Could not add tag %s: %s", tag_name, error)
        return False
    return True
