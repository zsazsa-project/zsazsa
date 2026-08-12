"""Lightweight JSON API endpoints used by the webapp UI.

All endpoints require the CSRF token (POST methods are covered by the global
before_request hook). Results are returned as JSON.
"""

import ipaddress
import json
import logging
import re
import socket
import threading
from urllib.parse import urlsplit

import config
from flask import Blueprint, jsonify, request, url_for

from core.vuln_lookup import fetch_cve_info
from webapp import audit, job_store, misp_session, misp_store
from webapp.collection_cache import AI_SUMMARY_PREFIX, filter_events_by_org
from webapp.rate_limit import rate_limited
from webapp.utils import json_body as _json_object, parse_bool as _parse_bool

_TECH_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

logger = logging.getLogger(__name__)
bp = Blueprint("api", __name__, url_prefix="/api")


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

        focus_points = {
            "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
            "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
            "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
            "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
            "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
        }

        threat_actor_types = list(getattr(config, "THREAT_ACTOR_TYPES", []) or [])
        story, suggested_actor_type = llm.draft_briefing_story(content or context_hint, focus_points, threat_actor_types)
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


def _is_safe_public_url(url: str) -> bool:
    """Return True only for http(s) URLs whose host resolves to public IPs.

    Guards the server-side fetch against SSRF: rejects non-web schemes and any
    host that resolves to a loopback, link-local, private, reserved or
    multicast address (e.g. cloud metadata at 169.254.169.254, internal
    services on 127.0.0.1 or RFC1918 ranges). Every resolved address must be
    global, so a hostname with a mix of public and private records is rejected.

    Note: this validates the host at check time. DNS rebinding between this
    check and the actual fetch remains a residual risk; authentication and
    authorization on this endpoint are the primary control.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global or ip.is_multicast:
            return False
    return True


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
    if not _is_safe_public_url(url):
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


@bp.route("/pull-estimate", methods=["POST"])
@rate_limited("api_pull_estimate", limit=20, window_s=60)
def pull_estimate():
    """Estimate how many events a MISP server would return with the current filter settings.

    POST JSON: {misp_url, misp_key, verify_tls, tags, tags_and, tags_not,
                since_days, org_filter_type, org_filter}
    Returns {"count": N, "error": null}.
    """
    import datetime as _dt
    from pymisp import PyMISP
    from webapp.collection_cache import _split_tags

    body, err = _json_object()
    if err:
        return jsonify({"count": None, "error": "Invalid JSON payload."}), 400
    misp_url = (body.get("misp_url") or "").strip()
    misp_key = (body.get("misp_key") or "").strip()
    if not misp_url or not misp_key:
        return jsonify({"count": None, "error": "URL and API key required."})

    try:
        verify_tls = _parse_bool(body.get("verify_tls", False), default=False)
    except ValueError as exc:
        return jsonify({"count": None, "error": str(exc)}), 400
    tags_or = _split_tags(body.get("tags") or "")
    tags_and = _split_tags(body.get("tags_and") or "")
    tags_not = _split_tags(body.get("tags_not") or "")
    since_days = int(body.get("since_days") or 0)
    org_filter_type = (body.get("org_filter_type") or "").strip()
    org_filter = {u.lower() for u in _split_tags(body.get("org_filter") or "")}
    try:
        limit = max(1, int(body.get("limit") or 500))
    except (ValueError, TypeError):
        limit = 500

    try:
        m = PyMISP(misp_url, misp_key, verify_tls)
        use_published = body.get("published", True)
        kwargs = dict(limit=limit, page=1, metadata=True, pythonify=True)
        if use_published:
            kwargs["published"] = True
        if tags_and or tags_not:
            kwargs["tags"] = m.build_complex_query(
                or_parameters=tags_or or None,
                and_parameters=tags_and or None,
                not_parameters=tags_not or None,
            )
        elif tags_or:
            kwargs["tags"] = tags_or
        if since_days:
            cutoff = (_dt.date.today() - _dt.timedelta(days=since_days)).isoformat()
            kwargs["date_from"] = cutoff
        events = m.search(**kwargs)
        if not events or isinstance(events, dict):
            return jsonify({"count": 0, "error": None})

        events = filter_events_by_org(events, org_filter_type, org_filter)

        return jsonify({"count": len(events), "error": None})
    except Exception as exc:
        logger.warning("pull_estimate failed: %s", exc)
        return jsonify({"count": None, "error": "Pull estimate failed."}), 502


@bp.route("/lookup-org", methods=["POST"])
@rate_limited("api_lookup_org", limit=60, window_s=60)
def lookup_org():
    """Look up a MISP organisation name by UUID.

    POST JSON: {"uuid": "...", "misp_url": "...", "misp_key": "..."}
    The misp_url / misp_key fields are optional; if omitted the configured
    webapp and scraper MISP instances are tried instead.
    Returns {"name": "Org Name", "error": null} or {"name": null, "error": "..."}.
    """
    from pymisp import PyMISP
    body, err = _json_object()
    if err:
        return jsonify({"name": None, "error": "Invalid JSON payload."}), 400
    uuid = (body.get("uuid") or "").strip()
    if not uuid:
        return jsonify({"name": None, "error": "UUID required."})

    misp_url = (body.get("misp_url") or "").strip()
    misp_key = (body.get("misp_key") or "").strip()

    servers = []
    if misp_url and misp_key:
        servers.append((misp_url, misp_key, False))
    servers.append((config.MISP_WEBAPP_URL, config.MISP_WEBAPP_KEY, config.MISP_WEBAPP_VERIFYCERT))
    if config.MISP_URL != config.MISP_WEBAPP_URL:
        servers.append((config.MISP_URL, config.MISP_KEY, config.MISP_VERIFYCERT))

    for url, key, verify in servers:
        try:
            m = PyMISP(url, key, verify)
            result = m.get_organisation(uuid, pythonify=True)
            if result and not isinstance(result, dict):
                return jsonify({"name": result.name, "error": None})
        except Exception as exc:
            logger.debug("lookup_org failed against %s: %s", url, exc)
            continue

    return jsonify({"name": None, "error": "Not found."})


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
    raw_ids = [c.strip().upper() for c in (body.get("cve_ids") or []) if c.strip()]
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
