"""Lightweight JSON API endpoints used by the webapp UI.

All endpoints require the CSRF token (POST methods are covered by the global
before_request hook). Results are returned as JSON.
"""

import logging
import re
import threading

import config
from flask import Blueprint, jsonify, url_for

from core.net_safety import is_safe_public_url
from core.rulezet_lookup import (get_rule, search_rules_by_attack, search_rules_by_cve,
                                 validate_rule)
from core.vuln_lookup import fetch_cve_info
from webapp import audit, job_store, misp_session, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX
from webapp.rate_limit import rate_limited
from webapp.utils import json_body as _json_object, scraper_enabled

_TECH_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

logger = logging.getLogger(__name__)
bp = Blueprint("api", __name__, url_prefix="/api")


def _focus_points() -> dict:
    """What the organisation cares about, as the story prompt wants it."""
    return {
        "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
        "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
        "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
        "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
        "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
    }


def _threat_actor_types() -> list:
    return list(getattr(config, "THREAT_ACTOR_TYPES", []) or [])


def _get_event_content_and_scope(event_uuid: str, source_id: str = ""):
    """Fetch report content and scope tags from a source MISP event.

    The event is looked up on whichever configured MISP instance holds it (the
    scraper, an external MISP_SERVERS instance, or the webapp MISP), trying the
    given source hint first.

    Returns (content: str | None, scope: dict) where scope has keys
    sectors, geo, techniques - each a list of strings.
    """
    empty_scope = {"sectors": [], "geo": [], "techniques": []}
    if not event_uuid:
        return None, empty_scope
    try:
        event, _client, _sid = misp_store.resolve_source_event(event_uuid, source_id)
    except Exception as exc:
        logger.warning("api: resolve_source_event %s failed: %s", event_uuid, exc)
        return None, empty_scope
    if event is None:
        return None, empty_scope
    # Extract content
    reports = getattr(event, "event_reports", []) or []
    content = None
    for r in reports:
        if not (getattr(r, "name", "") or "").startswith(AI_SUMMARY_PREFIX):
            c = getattr(r, "content", None)
            if c:
                content = c
                break
    if not content:
        for r in reports:
            c = getattr(r, "content", None)
            if c:
                content = c
                break
    # Extract scope from galaxy tags already on the event
    sectors, geo, techniques = [], [], []
    for t in getattr(event, "tags", []) or []:
        name = getattr(t, "name", "") or ""
        if name.startswith('misp-galaxy:sector='):
            v = name.split('=', 1)[1].strip('"')
            if v:
                sectors.append(v)
        elif name.startswith('misp-galaxy:country='):
            v = name.split('=', 1)[1].strip('"')
            if v:
                geo.append(v)
        elif name.startswith('misp-galaxy:mitre-attack-pattern='):
            v = name.split('=', 1)[1].strip('"')
            m = _TECH_RE.search(v)
            if m:
                techniques.append(m.group(0))
    return content, {"sectors": sectors, "geo": geo, "techniques": techniques}


def _get_event_content(event_uuid: str) -> str | None:
    """Fetch the first event report content from the MISP instance holding the event."""
    content, _ = _get_event_content_and_scope(event_uuid)
    return content


@bp.route("/misp-status", methods=["GET"])
def misp_status():
    """Return webapp MISP connectivity status. No CSRF required (GET)."""
    result = misp_store.test_webapp_misp()
    return jsonify(result)


@bp.route("/draft-story", methods=["POST"])
@rate_limited("api_draft_story", limit=30, window_s=60)
def draft_story():
    """Draft a 5-line daily briefing story from a scraper event.

    POST JSON: {"event_uuid": "...", "source_id": "optional source hint",
                "context_hint": "optional extra context"}
    Returns: {"story": "...", "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"story": "", "scope": {}, "error": "Invalid JSON payload."}), 400
    event_uuid = (body.get("event_uuid") or "").strip()
    source_id = (body.get("source_id") or "").strip()
    context_hint = (body.get("context_hint") or "").strip()

    content, scope = _get_event_content_and_scope(event_uuid, source_id)
    if not content and not context_hint:
        return jsonify({"story": "", "scope": {}, "error": "No content found for this event."})

    try:
        from analyser import llm

        story, suggested_actor_type = llm.draft_briefing_story(
            content or context_hint, _focus_points(), _threat_actor_types())
        return jsonify({"story": story, "scope": scope, "threat_actor_type": suggested_actor_type, "error": None})
    except Exception as exc:
        logger.warning("draft_story LLM call failed: %s", exc)
        return jsonify({"story": "", "scope": scope, "threat_actor_type": "", "error": "Failed to generate story."}), 502


@bp.route("/event-attributes-text", methods=["POST"])
@rate_limited("api_event_attributes_text", limit=30, window_s=60)
def event_attributes_text():
    """Render a source event's attributes (and report, if any) as story text.

    Useful for events that carry no scraper-style article report - the analyst
    can pull the indicators straight into the briefing story instead.

    POST JSON: {"event_uuid": "...", "source_id": "optional source hint"}
    Returns: {"text": "...", "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"text": "", "error": "Invalid JSON payload."}), 400
    event_uuid = (body.get("event_uuid") or "").strip()
    source_id = (body.get("source_id") or "").strip()
    if not event_uuid:
        return jsonify({"text": "", "error": "event_uuid is required"}), 400

    event, _misp_client, _source_id = misp_store.resolve_source_event(event_uuid, source_id)
    if event is None:
        return jsonify({"text": "", "error": "Event not found."}), 404

    text = misp_store.format_event_attributes_text(event)
    if not text:
        return jsonify({"text": "", "error": "This event has no attributes or report content."})
    return jsonify({"text": text, "error": None})


@bp.route("/event-reports", methods=["POST"])
@rate_limited("api_event_reports", limit=60, window_s=60)
def event_reports():
    """Return the MISP reports attached to a source event, for viewing in the UI.

    POST JSON: {"event_uuid": "...", "source_id": "optional source hint"}
    Returns: {"reports": [{"name": "...", "content": "...", "date": "..."}],
              "event_info": "...", "event_url": "...", "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"reports": [], "error": "Invalid JSON payload."}), 400
    event_uuid = (body.get("event_uuid") or "").strip()
    source_id = (body.get("source_id") or "").strip()
    if not event_uuid:
        return jsonify({"reports": [], "error": "event_uuid is required"}), 400

    event, misp_client, _sid = misp_store.resolve_source_event(event_uuid, source_id)
    if event is None:
        return jsonify({"reports": [], "error": "Event not found on any configured MISP instance."}), 404

    reports = [
        {"name": getattr(r, "name", "") or "(untitled report)",
         "content": getattr(r, "content", "") or "",
         "date": misp_store.report_date(r)}
        for r in misp_store.live_reports(event)
    ]
    base_url = (getattr(misp_client, "root_url", "") or "").rstrip("/")
    return jsonify({
        "reports": reports,
        "event_info": getattr(event, "info", "") or "",
        "event_url": f"{base_url}/events/view/{event.uuid}" if base_url else "",
        "error": None,
    })


@bp.route("/event-report-count", methods=["POST"])
@rate_limited("api_event_report_count", limit=60, window_s=60)
def event_report_count():
    """How many MISP reports a source event has, for the briefing story button.

    Separate from /event-reports because the button only needs the number and a
    scraped article report runs to tens of kilobytes.

    POST JSON: {"event_uuid": "...", "source_id": "optional source hint"}
    Returns: {"count": 0, "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"count": 0, "error": "Invalid JSON payload."}), 400
    event_uuid = (body.get("event_uuid") or "").strip()
    source_id = (body.get("source_id") or "").strip()
    if not event_uuid:
        return jsonify({"count": 0, "error": "event_uuid is required"}), 400

    event, _misp_client, _sid = misp_store.resolve_source_event(event_uuid, source_id)
    if event is None:
        return jsonify({"count": 0, "error": "Event not found on any configured MISP instance."}), 404
    return jsonify({"count": len(misp_store.live_reports(event)), "error": None})


def _run_overlap_job(job_id: str, stories: list[dict]) -> None:
    """Compare the briefing stories with the LLM and store the answer on the job."""
    from analyser import llm

    job_store.update_job(job_id, status="running",
                         message=f"Comparing {len(stories)} stories...")
    try:
        # One call covering every story: it reports nothing until it is done, so
        # keep the job visibly alive rather than letting it age into "stalled".
        with job_store.heartbeat(job_id, f"Comparing {len(stories)} stories"):
            result = llm.detect_story_overlaps(stories)
        overlaps = result["overlaps"]
        job_store.update_job(
            job_id, status="completed",
            result={"overlaps": overlaps, "summary": result["summary"]},
            message=(f"{len(overlaps)} overlapping pair(s) found" if overlaps
                     else "No meaningful overlap found"),
        )
    except Exception as exc:
        job_store.update_job(job_id, status="failed", error=str(exc),
                             message=f"Failed: {exc}")
        logger.exception("Overlap job %s failed", job_id)


@bp.route("/briefing-overlap-check", methods=["POST"])
@rate_limited("api_briefing_overlap_check", limit=20, window_s=60)
def briefing_overlap_check():
    """Start the check for briefing stories that cover the same event.

    The comparison is one LLM call over every story in the briefing, which takes
    long enough to lose a request to a proxy timeout, so it runs on a background
    thread like the other AI work and this only hands back the job to follow.

    POST JSON: {"stories": [{"title": "...", "content": "...", "source_url": "..."}, ...]}
    Returns: {"ok": true, "job_id": "..."}
    """
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    stories = body.get("stories")
    if not isinstance(stories, list):
        return jsonify({"ok": False, "error": "Stories must be a list."}), 400

    normalized = []
    for s in stories:
        if not isinstance(s, dict):
            continue
        normalized.append({
            "title": (s.get("title") or "").strip(),
            "content": (s.get("content") or "").strip(),
            "source_url": (s.get("source_url") or "").strip(),
        })

    if len(normalized) < 2:
        return jsonify({"ok": False, "error": "Add at least two stories to compare."}), 400
    if any(not s["content"] for s in normalized):
        return jsonify({"ok": False, "error": "All stories need text before running overlap check."}), 400

    job = job_store.create_job("briefing-overlap", label="Briefing overlap check")
    threading.Thread(
        target=_run_overlap_job, args=(job["id"], normalized),
        daemon=True, name=job_store.thread_name(job["id"]),
    ).start()
    return jsonify({"ok": True, "job_id": job["id"]})


def _run_briefing_summary_job(job_id: str, stories: list[dict], date: str) -> None:
    """Write the briefing's summary from its stories, on a worker thread."""
    from analyser import llm

    job_store.update_job(job_id, status="running",
                         message=f"Summarising {len(stories)} stories...")
    try:
        with job_store.heartbeat(job_id, f"Summarising {len(stories)} stories"):
            summary = llm.draft_briefing_summary(
                stories, misp_store.briefing_scope_summary(stories), date)
        if not summary:
            empty = "The model returned an empty summary."
            job_store.update_job(job_id, status="failed", error=empty, message=empty)
            return
        job_store.update_job(job_id, status="completed", result={"summary": summary},
                             message="Briefing summary drafted")
    except Exception as exc:
        job_store.update_job(job_id, status="failed", error=str(exc),
                             message=f"Failed: {exc}")
        logger.exception("Briefing summary job %s failed", job_id)


def _run_briefing_draft_job(job_id: str, briefing_uuid: str, with_summary: bool, user: str) -> None:
    """Draft every story on a saved briefing, and its summary when asked.

    Runs against the briefing in MISP rather than the compose form, which is
    what lets the analyst close the page: the stories are drafted one at a time
    and written back in a single update at the end, so a briefing is never left
    half rewritten if the job dies partway.
    """
    from analyser import llm

    try:
        briefing = misp_store.get_briefing(briefing_uuid)
        if briefing is None:
            gone = "The briefing could not be loaded."
            job_store.update_job(job_id, status="failed", error=gone, message=gone)
            return
        # Published between the save that started this job and now: what was
        # approved stays as it is.
        if briefing.review_state != misp_store.BRIEFING_REVIEW_DRAFT:
            published = "The briefing was published before drafting began, so nothing was drafted."
            job_store.update_job(job_id, status="failed", error=published, message=published)
            return

        stories = [dict(vars(s)) for s in briefing.stories]
        total = len(stories)
        job_store.update_job(job_id, status="running", message=f"Drafting {total} stories...")
        focus_points, actor_types = _focus_points(), _threat_actor_types()
        drafted = 0

        with job_store.heartbeat(job_id, f"Drafting {total} stories"):
            for index, story in enumerate(stories, 1):
                job_store.update_job(job_id, message=f"Drafting story {index} of {total}...")
                content, _scope = _get_event_content_and_scope(
                    story.get("source_event_uuid", ""), story.get("source_id", ""))
                if not content:
                    job_store.append_log(job_id, f"Story {index}: no source content, left as it was.")
                    continue
                try:
                    text, actor_type = llm.draft_briefing_story(content, focus_points, actor_types)
                except Exception as exc:
                    # One story per model call, so a call that fails costs that
                    # story and not the seven already drafted. The story button
                    # on the form treats a failure the same way.
                    logger.warning("Briefing draft job %s: story %d failed: %s", job_id, index, exc)
                    job_store.append_log(job_id, f"Story {index}: the model call failed ({exc}).")
                    continue
                if not text:
                    job_store.append_log(job_id, f"Story {index}: the model returned nothing.")
                    continue
                story["content"] = text
                story["drafted_by"] = "ai"
                # Only when the analyst has not picked one: the suggestion is a
                # starting point, and the story button leaves an existing choice
                # alone for the same reason.
                if actor_type and not story.get("threat_actor_types"):
                    story["threat_actor_types"] = [actor_type]
                drafted += 1

            summary = briefing.summary
            rewrote_summary = False
            if with_summary:
                job_store.update_job(job_id, message="Drafting the briefing summary...")
                written = llm.draft_briefing_summary(
                    stories, misp_store.briefing_scope_summary(stories), briefing.date or "")
                if written:
                    summary, rewrote_summary = written, True
                else:
                    job_store.append_log(job_id, "The model returned an empty summary.")

        # update_briefing rebuilds the whole object, so start from everything it
        # holds and replace what the job wrote.
        data = {field: getattr(briefing, field) for field in misp_store.BRIEFING_FIELDS}
        data["stories"] = stories
        data["story_count"] = len(stories)
        data["summary"] = summary
        # A summary describes the stories it was written from, so redrafting
        # them dates it unless this run wrote a new one. Asking for a summary
        # and getting nothing back still leaves the old one out of date.
        data["summary_stale"] = (briefing.summary_stale or bool(drafted)) and not rewrote_summary
        try:
            # Only if it is still in the state it was read in: publishing it while
            # the model was drafting must not be undone by this write.
            misp_store.update_briefing(briefing_uuid, data, expected_state=briefing.review_state)
        except misp_store.BriefingStateChanged:
            moved = ("The briefing was published while the stories were being drafted, "
                     "so the drafts were not saved over it.")
            job_store.update_job(job_id, status="failed", error=moved, message=moved)
            return
        audit.record("update", "daily-briefing", entity_id=briefing_uuid,
                     entity_label=f"Daily briefing {briefing.date}",
                     details=f"AI drafted {drafted} of {total} stories"
                             + (" and the summary" if with_summary else ""),
                     user=user)
        done = f"Drafted {drafted} of {total} stories"
        job_store.update_job(job_id, status="completed", message=done + ", saved to the briefing.",
                             result={"briefing_uuid": briefing_uuid, "drafted": drafted, "total": total})
    except Exception as exc:
        job_store.update_job(job_id, status="failed", error=str(exc), message=f"Failed: {exc}")
        logger.exception("Briefing draft job %s failed", job_id)


# Two submits landing together would both pass the in-flight test and start a
# job, and both would write the briefing. The same guard notify_jobs puts around
# its own start, for the same reason.
_start_lock = threading.Lock()


def start_briefing_draft_job(briefing_uuid: str, label: str, with_summary: bool, user: str) -> dict:
    """Start the drafting job for one briefing, or return the one already running.

    Called from the briefing routes once the form has been saved, because the
    job writes to the stored briefing rather than to the page.
    """
    with _start_lock:
        running = job_store.in_flight_for(briefing_uuid, "briefing-draft")
        if running is not None:
            return running
        job = job_store.create_job("briefing-draft", label=label)
        job_store.update_job(job["id"], entity=briefing_uuid)
    threading.Thread(
        target=_run_briefing_draft_job,
        args=(job["id"], briefing_uuid, with_summary, user),
        daemon=True, name=job_store.thread_name(job["id"]),
    ).start()
    return job


@bp.route("/draft-briefing-summary", methods=["POST"])
@rate_limited("api_draft_briefing_summary", limit=20, window_s=60)
def draft_briefing_summary():
    """Start writing the summary that opens a daily briefing.

    The stories come from the form rather than from a saved briefing, so the
    summary can be drafted on a briefing that has not been saved yet and covers
    the edits the analyst has just made. Like the overlap check this is one LLM
    call over every story, long enough to lose a request to a proxy timeout, so
    it runs on a background thread and this hands back the job to follow.

    POST JSON: {"date": "...", "stories": [{"title", "content", scope lists}, ...]}
    Returns: {"ok": true, "job_id": "..."}
    """
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    stories = body.get("stories")
    if not isinstance(stories, list):
        return jsonify({"ok": False, "error": "Stories must be a list."}), 400

    def _scope(story, key):
        return [v.strip() for v in (story.get(key) or []) if isinstance(v, str) and v.strip()]

    normalized = []
    for s in stories:
        if not isinstance(s, dict):
            continue
        normalized.append({
            "title": (s.get("title") or "").strip(),
            "content": (s.get("content") or "").strip(),
            "sectors": _scope(s, "sectors"),
            "geographic_scope": _scope(s, "geographic_scope"),
            "threat_actors": _scope(s, "threat_actors"),
            "techniques": _scope(s, "techniques"),
            "vendor": _scope(s, "vendor"),
            "threat_actor_types": _scope(s, "threat_actor_types"),
        })

    if not normalized:
        return jsonify({"ok": False, "error": "Add at least one story before writing the summary."}), 400
    if any(not s["content"] for s in normalized):
        return jsonify({"ok": False, "error": "All stories need text before the summary can cover them."}), 400

    job = job_store.create_job("briefing-summary", label="Briefing summary")
    threading.Thread(
        target=_run_briefing_summary_job,
        args=(job["id"], normalized, (body.get("date") or "").strip()),
        daemon=True, name=job_store.thread_name(job["id"]),
    ).start()
    return jsonify({"ok": True, "job_id": job["id"]})


# The QA review audits what would actually be published, so it reads the same
# markdown the notifier and the published report use.
_QA_PRODUCTS = {
    "fia": {"label": "Flash intel alert", "id_attr": "fia_id",
            "get": misp_store.get_fia, "render": misp_store.render_fia_markdown},
    "vea": {"label": "Vulnerability advisory", "id_attr": "vea_id",
            "get": misp_store.get_vea, "render": misp_store.render_vea_markdown},
}


@bp.route("/qa-review", methods=["POST"])
@rate_limited("api_qa_review", limit=20, window_s=60)
def qa_review():
    """Audit a product draft against its source events before publication.

    POST JSON: {"kind": "fia" | "vea", "uuid": "..."}
    Returns: {"review": {...}, "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"review": {}, "error": "Invalid JSON payload."}), 400
    kind = (body.get("kind") or "").strip()
    uuid = (body.get("uuid") or "").strip()
    if kind not in _QA_PRODUCTS or not uuid:
        return jsonify({"review": {}, "error": "Unknown product."}), 400
    product_type = _QA_PRODUCTS[kind]

    product = product_type["get"](uuid)
    if product is None:
        return jsonify({"review": {}, "error": "Product not found."}), 404

    hints = dict(getattr(product, "source_event_hints", {}) or {})
    source_material = []
    for source_uuid in (getattr(product, "source_event_uuids", []) or []):
        hint = hints.get(source_uuid, "")
        content, _scope = _get_event_content_and_scope(source_uuid, hint)
        if not content:
            # An advisory often has attributes and no article report.
            event, _client, _sid = misp_store.resolve_source_event(source_uuid, hint)
            content = misp_store.format_event_attributes_text(event) if event else ""
        if content:
            source_material.append(content)
    if not source_material:
        return jsonify({"review": {}, "error": "No source event content to review the draft against."})

    try:
        from analyser import llm
        draft = product_type["render"](product)
        review = llm.review_product_draft(product_type["label"], draft, "\n\n---\n\n".join(source_material))
    except Exception as exc:
        logger.warning("qa_review LLM call failed: %s", exc)
        return jsonify({"review": {}, "error": "Failed to run the QA review."}), 502

    if not review:
        return jsonify({"review": {}, "error": "The model returned no usable review. Check the LLM settings and the analyser log."}), 502
    audit.record("generate", "ai_qa_review", entity_id=uuid,
                 entity_label=getattr(product, product_type["id_attr"], ""),
                 details=review.get("verdict", ""))
    return jsonify({"review": review, "error": None})


@bp.route("/draft-tap", methods=["POST"])
@rate_limited("api_draft_tap", limit=30, window_s=60)
def draft_tap():
    """Draft threat actor profile fields from the actors and context on the form.

    POST JSON: {"actors": ["APT29"], "context": {"summary": "...", "capabilities": "..."}}
    Returns: {"sections": {...}, "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"sections": {}, "error": "Invalid JSON payload."}), 400
    actors = [str(a).strip() for a in (body.get("actors") or []) if str(a).strip()]
    context = body.get("context")
    if not isinstance(context, dict):
        context = {}
    context = {str(k): str(v).strip() for k, v in context.items() if str(v).strip()}
    if not actors and not context:
        return jsonify({"sections": {}, "error": "Select a threat actor or add some notes first."})

    try:
        from analyser import llm
        sections = llm.draft_tap_sections(actors, context)
        if not sections:
            return jsonify({"sections": {}, "error": "The model returned no usable draft. Check the LLM settings and the analyser log."}), 502
        # It lands in a select, which takes only the values it offers.
        confidence = str(sections.get("assessment_confidence") or "").strip().lower()
        offered = {value for value, _label, _help in misp_store.ESTIMATIVE_CONFIDENCE}
        sections["assessment_confidence"] = confidence if confidence in offered else ""
        return jsonify({"sections": sections, "error": None})
    except Exception as exc:
        logger.warning("draft_tap LLM call failed: %s", exc)
        return jsonify({"sections": {}, "error": "Failed to draft the profile."}), 502


@bp.route("/draft-vea", methods=["POST"])
@rate_limited("api_draft_vea", limit=30, window_s=60)
def draft_vea():
    """Draft VEA section content from CVE info and optional article content.

    POST JSON: {"cve_id": "CVE-...", "product_info": "...", "article_content": "..."}
    Returns: {"sections": {...}, "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"sections": {}, "error": "Invalid JSON payload."}), 400
    cve_id = (body.get("cve_id") or "").strip()
    product_info = (body.get("product_info") or "").strip()
    article_content = (body.get("article_content") or "").strip()

    if not cve_id and not article_content:
        return jsonify({"sections": {}, "error": "CVE ID or article content required."})

    try:
        from analyser import llm
        sections = llm.draft_vea_sections(cve_id, product_info, article_content)
        return jsonify({"sections": sections, "error": None})
    except Exception as exc:
        logger.warning("draft_vea LLM call failed: %s", exc)
        return jsonify({"sections": {}, "error": "Failed to draft VEA content."}), 502


@bp.route("/event-preview", methods=["POST"])
def event_preview():
    """Return event info and report content for the triage preview panel.

    POST JSON: {"uuid": "..."}
    Returns: {"uuid", "info", "date", "tags",
              "reports": [{"name", "content", "date"}], "error"}
    """
    body, err = _json_object()
    if err:
        return jsonify({"error": "Invalid JSON payload."}), 400
    uuid = (body.get("uuid") or "").strip()
    if not uuid:
        return jsonify({"error": "UUID required"})

    if not scraper_enabled():
        return jsonify({"error": "No MISP scraper is configured."}), 502

    misp = misp_store._scraper_misp()
    try:
        event = misp.get_event(uuid, pythonify=True)
    except Exception as exc:
        logger.warning("event_preview: get_event %s failed: %s", uuid, exc)
        return jsonify({"error": "Could not fetch event."}), 502

    if not event or isinstance(event, dict):
        return jsonify({"error": "Event not found"})

    reports = []
    for r in getattr(event, "event_reports", []) or []:
        content = getattr(r, "content", None)
        name = getattr(r, "name", "") or ""
        if content and not getattr(r, "deleted", False):
            reports.append({"name": name, "content": content,
                            "date": misp_store.report_date(r)})

    return jsonify({
        "uuid": event.uuid,
        "info": event.info or "",
        "date": str(event.date) if event.date else "",
        "tags": [t.name for t in getattr(event, "tags", []) or []],
        "reports": reports,
        "error": None,
    })


@bp.route("/correlate", methods=["POST"])
def correlate():
    """Find scraper MISP events matching a keyword or indicator.

    POST JSON: {"query": "CVE-2024-1234 or keyword", "limit": 20}
    Returns: {"matches": [...], "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"matches": [], "error": "Invalid JSON payload."}), 400
    query = (body.get("query") or "").strip()
    try:
        limit = max(1, min(int(body.get("limit", 20)), 100))
    except (TypeError, ValueError):
        limit = 20

    if not query or len(query) < 3:
        return jsonify({"matches": [], "error": "Query must be at least 3 characters."})

    if not scraper_enabled():
        return jsonify({"matches": [], "error": None})

    try:
        misp = misp_store._scraper_misp()
        events = misp.search(
            tags=[config.SCRAPER_MARKER_TAG],
            limit=getattr(config, "MISP_SCRAPER_LIMIT", 500),
            page=1,
            metadata=False,
            pythonify=True,
        )
        if not events or isinstance(events, dict):
            return jsonify({"matches": [], "error": None})

        ql = query.lower()
        matches = []
        for e in events:
            text = misp_store._event_text(e).lower()
            if ql in text:
                matches.append({
                    "uuid": e.uuid,
                    "info": e.info or "",
                    "date": str(e.date) if e.date else "",
                })
            if len(matches) >= limit:
                break

        return jsonify({"matches": matches, "error": None})
    except Exception as exc:
        logger.warning("correlate search failed: %s", exc)
        return jsonify({"matches": [], "error": "Search failed."}), 502


@bp.route("/fetch-url", methods=["POST"])
@rate_limited("api_fetch_url", limit=20, window_s=60)
def fetch_url():
    """Fetch a URL and return its content as Markdown.

    POST JSON: {"url": "https://..."}
    Returns: {"title": "...", "content": "...", "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"title": "", "content": "", "error": "Invalid JSON payload."}), 400
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"title": "", "content": "", "error": "URL required."})
    if not is_safe_public_url(url):
        logger.warning("fetch_url rejected non-public or invalid URL: %s", url)
        return jsonify({
            "title": "", "content": "",
            "error": "URL must be a public http(s) address.",
        }), 400
    try:
        from curl_cffi import requests as cf_requests
        from bs4 import BeautifulSoup
        from markdownify import markdownify as md

        # allow_redirects=False so a public URL cannot 30x-redirect the fetch
        # to an internal target that bypasses the pre-fetch validation above.
        response = cf_requests.get(url, impersonate="chrome124", timeout=20, allow_redirects=False)
        rawhtml = response.text

        soup = BeautifulSoup(rawhtml, "html.parser")

        title = ""
        if soup.title:
            title = soup.title.get_text(strip=True)

        for tag in soup.find_all(["script", "head", "header", "footer", "meta", "nav", "style"]):
            tag.decompose()

        content = md(str(soup), heading_style="ATX", strip=["a", "img"])
        content = "\n".join(
            line for line in content.splitlines()
            if line.strip()
        )
        return jsonify({"title": title, "content": content, "error": None})
    except Exception as exc:
        logger.warning("fetch_url failed for %s: %s", url, exc)
        return jsonify({"title": "", "content": "", "error": "Could not fetch URL content."}), 502


def _parse_fia_markdown(text: str) -> dict:
    """Parse flash_intel_generate.md LLM output into form field values."""
    def _csv(s):
        """Split a comma-separated value string into a clean list, drop placeholders."""
        return [v.strip() for v in (s or '').split(',') if v.strip() and not v.strip().startswith('<')]

    fields = {
        'title': '', 'summary': '', 'action_required': '',
        'what_happened': [], 'source_description': '',
        'likely_impact': '', 'affected_assets': '',
        'actor_types': [], 'actor_context': '',
        'geographic_scope': [], 'sectors': [],
        'threat_types': [], 'technology': [], 'vendor': [], 'incident': [], 'campaign': [],
        'actions_immediate': [], 'actions_near_term': [],
        'mitre_techniques': [], 'hunting_hypotheses': [],
        'source_reliability': '', 'information_credibility': '', 'credibility_justification': '',
    }
    section = None
    for line in text.split('\n'):
        s = line.strip()
        if not s or s == '---':
            continue
        m = re.match(r'^#\s+Flash intel alert:\s*(.*)', s, re.IGNORECASE)
        if m:
            fields['title'] = m.group(1).strip()
            continue
        if s.startswith('## '):
            sl = s[3:].lower()
            if 'summary' in sl: section = 'summary'
            elif 'what happened' in sl: section = 'what_happened'
            elif 'why it matters' in sl: section = 'why_matters'
            elif sl.strip() == 'scope': section = 'scope'
            elif 'recommended' in sl: section = 'actions'
            elif 'detection' in sl: section = 'detection'
            else: section = None
            continue
        if s.startswith('### '):
            sl = s[4:].lower()
            if 'immediate' in sl: section = 'actions_immediate'
            elif 'near' in sl: section = 'actions_near_term'
            continue
        if section in ('detection', 'mitre', 'hunting'):
            if s.startswith('**Relevant MITRE'):
                section = 'mitre'; continue
            if s.startswith('**Hunting'):
                section = 'hunting'; continue
        if section == 'summary':
            if s.startswith('**Action required:**'):
                fields['action_required'] = s[len('**Action required:**'):].strip()
            elif not s.startswith('**') and not s.startswith('#'):
                fields['summary'] = (fields['summary'] + '\n' + s).strip() if fields['summary'] else s
        elif section == 'what_happened':
            if s.startswith('**Source reliability:**'):
                val = s[len('**Source reliability:**'):].strip()
                fields['source_reliability'] = val[:1].upper() if val and val[:1].upper() in 'ABCDEF' else ''
            elif s.startswith('**Information credibility:**'):
                val = s[len('**Information credibility:**'):].strip()
                fields['information_credibility'] = val[:1] if val and val[:1] in '123456' else ''
            elif s.startswith('**Information credibility justification:**'):
                fields['credibility_justification'] = s[len('**Information credibility justification:**'):].strip()
            elif s.startswith('**Source:**'):
                fields['source_description'] = s[len('**Source:**'):].strip()
            elif s.startswith('- ') and not s.startswith('- <'):
                fields['what_happened'].append(s[2:].strip())
        elif section == 'why_matters':
            if s.startswith('- **Likely impact:**'):
                fields['likely_impact'] = s[len('- **Likely impact:**'):].strip()
            elif s.startswith('- **Affected assets:**'):
                fields['affected_assets'] = s[len('- **Affected assets:**'):].strip()
            elif s.startswith('- **Threat actor types:**'):
                fields['actor_types'] = _csv(s[len('- **Threat actor types:**'):])
            elif s.startswith('- **Threat actor context:**'):
                fields['actor_context'] = s[len('- **Threat actor context:**'):].strip()
        elif section == 'scope':
            if s.startswith('- **Geographic scope:**'):
                fields['geographic_scope'] = _csv(s[len('- **Geographic scope:**'):])
            elif s.startswith('- **Sectors:**'):
                fields['sectors'] = _csv(s[len('- **Sectors:**'):])
            elif s.startswith('- **Threat types:**'):
                fields['threat_types'] = _csv(s[len('- **Threat types:**'):])
            elif s.startswith('- **Technology:**'):
                fields['technology'] = _csv(s[len('- **Technology:**'):])
            elif s.startswith('- **Vendor:**'):
                fields['vendor'] = _csv(s[len('- **Vendor:**'):])
            elif s.startswith('- **Incident:**'):
                fields['incident'] = _csv(s[len('- **Incident:**'):])
            elif s.startswith('- **Campaign:**'):
                fields['campaign'] = _csv(s[len('- **Campaign:**'):])
        elif section == 'actions_immediate':
            if s.startswith('- ') and not s.startswith('- <'):
                fields['actions_immediate'].append(s[2:].strip())
        elif section == 'actions_near_term':
            if s.startswith('- ') and not s.startswith('- <'):
                fields['actions_near_term'].append(s[2:].strip())
        elif section == 'mitre':
            if s.startswith('- ') and not s.startswith('- <'):
                fields['mitre_techniques'].append(s[2:].strip())
        elif section == 'hunting':
            if s.startswith('- ') and not s.startswith('- <'):
                fields['hunting_hypotheses'].append(s[2:].strip())
    # Convert narrative list fields to newline-joined strings (wizard textarea fields)
    for f in ('what_happened', 'actions_immediate', 'actions_near_term', 'mitre_techniques', 'hunting_hypotheses'):
        if isinstance(fields[f], list):
            fields[f] = '\n'.join(fields[f])
    return fields


@bp.route("/build-fia", methods=["POST"])
@rate_limited("api_build_fia", limit=10, window_s=60)
def build_fia():
    """Generate FIA draft content using the flash_intel_generate prompt.

    POST JSON: {"source_uuids": ["uuid1", ...]}
    Returns {"fields": {...}, "error": null}
    """
    body, err = _json_object()
    if err:
        return jsonify({"fields": {}, "error": "Invalid JSON payload."}), 400
    source_uuids = [u.strip() for u in (body.get("source_uuids") or []) if u.strip()]
    if not source_uuids:
        return jsonify({"fields": {}, "error": "No source event UUIDs provided."})

    try:
        source_events = misp_store.fetch_source_events(source_uuids)
    except Exception as exc:
        logger.warning("build_fia: fetch_source_events failed: %s", exc)
        source_events = []

    report_mode = body.get("report_mode", "both")
    content_parts, all_tags, info_parts, dates = [], [], [], []
    for ev in source_events:
        if ev.get('info'): info_parts.append(ev['info'])
        if ev.get('date'): dates.append(str(ev['date']))
        all_tags.extend(ev.get('tags', []))
        for r in ev.get('reports', []):
            if report_mode == 'raw_only' and (r.get('name') or '').startswith('[AI-Summary]'):
                continue
            c = (r.get('content') or '').strip()
            if c: content_parts.append(c)

    content = '\n\n---\n\n'.join(content_parts)
    if not content:
        return jsonify({"fields": {}, "error": "No report content found in source events."})

    def _extract_galaxy_values(tags, prefixes):
        seen, result = set(), []
        for tag in tags:
            for prefix in prefixes:
                if tag.startswith(prefix):
                    val = tag[len(prefix):].strip().strip('"')
                    if val and val not in seen:
                        seen.add(val); result.append(val)
                    break
        return result

    geo_values = _extract_galaxy_values(all_tags, ['misp-galaxy:country=', 'misp-galaxy:target-information='])
    sector_values = _extract_galaxy_values(all_tags, ['misp-galaxy:sector='])
    actor_values = _extract_galaxy_values(all_tags, ['misp-galaxy:threat-actor='])

    reliability_letters, credibility_numbers = [], []
    for t in all_tags:
        if t.startswith('admiralty-scale:source-reliability='):
            v = t.split('"')[1] if '"' in t else ''
            if v: reliability_letters.append(v.upper())
        elif t.startswith('admiralty-scale:information-credibility='):
            v = t.split('"')[1] if '"' in t else ''
            if v.isdigit(): credibility_numbers.append(int(v))

    worst_reliability = max(reliability_letters) if reliability_letters else ""
    worst_credibility = str(max(credibility_numbers)) if credibility_numbers else ""

    try:
        from analyser import llm
        raw = llm.generate_fia_draft(
            content[:12000],
            event_info=' | '.join(info_parts[:2]) if info_parts else "",
            event_date=dates[0] if dates else "",
            source_reliability=worst_reliability,
        )
    except Exception as exc:
        logger.warning("build_fia: LLM call failed: %s", exc)
        return jsonify({"fields": {}, "error": "Failed to generate FIA draft."}), 502

    if not raw.strip():
        # Parsing nothing yields a wizard full of empty fields and no clue why.
        return jsonify({"fields": {}, "error": "The model returned an empty draft. "
                                               "Check the LLM settings and the analyser log."}), 502

    fields = _parse_fia_markdown(raw)
    if worst_reliability: fields['source_reliability'] = worst_reliability
    if worst_credibility: fields['information_credibility'] = worst_credibility

    # Infer sectors and geo from LLM-generated text when tags alone don't cover it
    scope_text = ' '.join([
        fields.get('summary', ''), fields.get('actor_context', ''),
        fields.get('likely_impact', ''), fields.get('affected_assets', ''), raw,
    ]).lower()

    def _infer_scope(known, candidates):
        existing = {v.lower() for v in known}
        extra = []
        for item in (candidates or []):
            if item.lower() not in existing and item.lower() in scope_text:
                existing.add(item.lower())
                extra.append(item)
        return known + extra

    # Remove LLM-parsed geo/sector from fields; _infer_scope will re-derive them
    # from scope_text (which already includes the full LLM output) against the galaxy.
    fields.pop('geographic_scope', None)
    fields.pop('sectors', None)

    try:
        sector_values = _infer_scope(sector_values, misp_store.galaxy_sectors())
    except Exception as exc:
        logger.warning("build_fia: sector scope inference failed: %s", exc)
    try:
        geo_values = _infer_scope(geo_values, misp_store.galaxy_geography())
    except Exception as exc:
        logger.warning("build_fia: geo scope inference failed: %s", exc)

    fields['geographic_scope'] = geo_values
    fields['sectors'] = sector_values
    fields['threat_actors'] = actor_values
    audit.record("generate", "ai_fia_draft", details=f"sources: {', '.join(source_uuids[:5])}")
    return jsonify({"fields": fields, "error": None})


# A whole technique ID, nothing around it: the same pattern the forms use to
# pick IDs out of the checked techniques, anchored because here it is a
# gatekeeper for what gets forwarded to Rulezet, not a search.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _id_list(body: dict, key: str) -> tuple[list[str], str]:
    """The list of IDs posted under key, stripped and upper-cased.

    Returns (ids, "") or ([], error). The forms always post a list of strings,
    but anything can reach this endpoint: a bare string would otherwise be
    iterated one character at a time, and a number in the list would reach
    .strip() and turn a bad request into a 500.
    """
    raw = body.get(key)
    if raw is None:
        return [], ""
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        return [], f"{key} must be a list of strings."
    return [v.strip().upper() for v in raw if v.strip()], ""


@bp.route("/cve-lookup", methods=["POST"])
@rate_limited("api_cve_lookup", limit=20, window_s=60)
def cve_lookup():
    """Proxy CVE details from vulnerability.circl.lu.

    POST JSON: {"cve_ids": ["CVE-2024-1234", ...]}
    Returns: {"ok": true, "results": [{...}, ...]}
    """
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    raw_ids, bad = _id_list(body, "cve_ids")
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    cve_ids = [c for c in raw_ids if c.startswith("CVE-")][:10]
    if not cve_ids:
        return jsonify({"ok": False, "error": "No valid CVE IDs provided"})

    results = []
    for cve_id in cve_ids:
        info = fetch_cve_info(cve_id)
        if info:
            results.append({"cve_id": cve_id, "ok": True, **info})
        else:
            results.append({"cve_id": cve_id, "ok": False, "error": "Lookup failed"})

    return jsonify({"ok": True, "results": results})


@bp.route("/rulezet-lookup", methods=["POST"])
@rate_limited("api_rulezet_lookup", limit=20, window_s=60)
def rulezet_lookup():
    """Proxy detection-rule matches from a Rulezet instance (config.RULEZET_URL).

    POST JSON: {"cve_ids": ["CVE-2024-1234", ...]}
    Returns: {"ok": true, "rules": [{...}, ...]}
    """
    if not getattr(config, "RULEZET_URL", ""):
        return jsonify({"ok": False, "error": "Rulezet integration is not configured."})

    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    raw_ids, bad = _id_list(body, "cve_ids")
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    cve_ids = [c for c in raw_ids if c.startswith("CVE-")][:10]
    if not cve_ids:
        return jsonify({"ok": False, "error": "No valid CVE IDs provided"})

    rules = search_rules_by_cve(cve_ids)
    return jsonify({"ok": True, "rules": rules})


@bp.route("/rulezet-rule", methods=["POST"])
# Higher than the searches allow: this is one cheap read per rule an analyst
# opens, not a lookup that returns hundreds at once, and a product can list a
# dozen rules to click through.
@rate_limited("api_rulezet_rule", limit=60, window_s=60)
def rulezet_rule():
    """Proxy one rule, with its content, from a Rulezet instance by its id.

    A saved product keeps only a rule's title and URL, so this is what the
    "view rule" button on a product page reads to show the rule itself.

    POST JSON: {"rule_id": "740025"}
    Returns: {"ok": true, "rule": {...}}
    """
    if not getattr(config, "RULEZET_URL", ""):
        return jsonify({"ok": False, "error": "Rulezet integration is not configured."})

    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    rule_id = str(body.get("rule_id") or "").strip()
    # Digits only: this goes into the path of the URL called on the Rulezet side.
    if not rule_id.isdigit():
        return jsonify({"ok": False, "error": "A numeric rule id is required."}), 400

    rule = get_rule(rule_id)
    if not rule:
        return jsonify({"ok": False, "error": "Rulezet did not return that rule."}), 502
    return jsonify({"ok": True, "rule": rule})


@bp.route("/rulezet-attack-lookup", methods=["POST"])
@rate_limited("api_rulezet_attack_lookup", limit=20, window_s=60)
def rulezet_attack_lookup():
    """Proxy detection-rule matches from Rulezet by MITRE ATT&CK technique ID.

    POST JSON: {"technique_ids": ["T1071", "T1566.001", ...]}
    Returns: {"ok": true, "rules": [{...}, ...]}
    """
    if not getattr(config, "RULEZET_URL", ""):
        return jsonify({"ok": False, "error": "Rulezet integration is not configured."})

    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    raw_ids, bad = _id_list(body, "technique_ids")
    if bad:
        return jsonify({"ok": False, "error": bad}), 400
    technique_ids = [t for t in raw_ids if _TECHNIQUE_ID_RE.match(t)][:20]
    if not technique_ids:
        return jsonify({"ok": False, "error": "No valid technique IDs provided"})

    rules = search_rules_by_attack(technique_ids)
    return jsonify({"ok": True, "rules": rules})


@bp.route("/rulezet-validate", methods=["POST"])
@rate_limited("api_rulezet_validate", limit=20, window_s=60)
def rulezet_validate():
    """Proxy a dry-run rule-syntax check to Rulezet — nothing is ever saved.

    POST JSON: {"format": "sigma", "content": "..."}
    Returns: {"ok": true, "valid": bool, "errors": [...], "warnings": [...]}
    """
    if not getattr(config, "RULEZET_URL", ""):
        return jsonify({"ok": False, "error": "Rulezet integration is not configured."})

    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    rule_format = body.get("format") or ""
    content = body.get("content") or ""
    if not isinstance(rule_format, str) or not isinstance(content, str):
        return jsonify({"ok": False, "error": "format and content must be strings."}), 400
    rule_format, content = rule_format.strip(), content.strip()
    if not rule_format:
        return jsonify({"ok": False, "error": "No format provided."})
    if not content:
        return jsonify({"ok": False, "error": "No content to validate."})

    result = validate_rule(rule_format, content)
    if result is None:
        return jsonify({"ok": False, "error": "Rulezet is unreachable."})
    if "error" in result:
        return jsonify({"ok": False, "error": result["error"]})
    return jsonify({"ok": True, **result})


@bp.route("/collection/<string:uuid>/used-in", methods=["GET"])
@rate_limited("api_collection_used_in", limit=30, window_s=60)
def collection_used_in(uuid):
    products = misp_store.find_products_using_source(uuid)
    # Build links here, via url_for, so they honour the app's mount path (e.g. /zsazsa).
    endpoints = {
        "daily-briefing": "daily_briefing.detail",
        "flash-intel": "flash_intel.detail",
        "vea": "vea.detail",
    }
    for product in products:
        endpoint = endpoints.get(product["type"])
        if endpoint:
            product["url"] = url_for(endpoint, id=product["uuid"])
    return jsonify({"ok": True, "products": products})


def _run_summarise_content_job(job_id: str, content: str, title: str, user: str) -> None:
    """Summarise pasted content on a worker thread, for a form that has no event yet."""
    from analyser import llm

    job_store.update_job(job_id, status="running", message="Generating summary...")
    try:
        with job_store.heartbeat(job_id, "Generating summary"):
            summary = llm.summarise_report(content[:12000], event_info=title)
        if not summary.strip():
            empty = ("The model returned an empty summary. Check the LLM settings "
                     "and the analyser log.")
            job_store.update_job(job_id, status="failed", error=empty, message=empty)
            return
        audit.record("generate", "ai_summary", details=title or f"{len(content)} chars",
                     user=user)
        job_store.update_job(job_id, status="completed", result={"summary": summary},
                             message="Summary generated")
    except Exception as exc:
        job_store.update_job(job_id, status="failed", error=str(exc),
                             message=f"Failed: {exc}")
        logger.exception("Summarise content job %s failed", job_id)


@bp.route("/summarise-content", methods=["POST"])
@rate_limited("api_summarise_content", limit=15, window_s=60)
def summarise_content():
    """Start an AI summary of raw text content, on a background thread.

    The manual collection entry form has no MISP event yet, so the content comes
    from the form rather than from a report. One LLM call is long enough to lose
    the request to a proxy timeout, so this hands back a job to follow instead;
    it also puts the work in the top bar's job list like every other AI run.

    POST JSON: {"content": "...", "title": "optional event title"}
    Returns: {"ok": true, "job_id": "..."}
    """
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    content = (body.get("content") or "").strip()
    title = (body.get("title") or "").strip()
    if not content:
        return jsonify({"ok": False, "error": "Content required."}), 400

    job = job_store.create_job("summarise-content", label="AI summary")
    threading.Thread(
        target=_run_summarise_content_job,
        args=(job["id"], content, title, misp_session.current_user_email()),
        daemon=True, name=job_store.thread_name(job["id"]),
    ).start()
    return jsonify({"ok": True, "job_id": job["id"]})
