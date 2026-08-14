"""Daily Threat Briefing routes.

Workflow: analyst opens the triage page (shows recent scraper events),
selects relevant stories, drafts a 5-line summary per story (optionally
with LLM assistance), then publishes the briefing.
"""

import json
import logging
from datetime import datetime

import config
import weasyprint
from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from webapp import (audit, branding, collection_cache, misp_session, misp_store,
                    notify_jobs, product_log)
from webapp.collection_cache import AI_SUMMARY_PREFIX
from webapp.utils import dedup_lower, md_to_html, mute_lead_labels, sort_products
from webapp.routes.source_event_utils import parse_source_tokens, source_id_from_event_ref

logger = logging.getLogger(__name__)
bp = Blueprint("daily_briefing", __name__, url_prefix="/briefing")


def _scope_keys(values):
    """Scope values as a lowercase set, for comparing them across sources."""
    return {(v or "").strip().lower() for v in values} - {""}


def _render_briefing_form(
    *,
    stories,
    date: str,
    title: str,
    author: str,
    tlp: str,
    escalations: str,
    notes: str,
    mode: str,
    form_action: str,
    cancel_url: str,
    summary: str = "",
    summary_stale: bool = False,
    geographic_scope=None,
    sectors=None,
    threat_actors=None,
    mitre_attack_techniques=None,
    threat_types=None,
    technology=None,
    vendor=None,
    incident=None,
    campaign=None,
    created_at=None,
    starts_unsaved=False,
):
    is_edit = mode == "edit"
    story_uuids = [
        (story.get("source_event_uuid") if isinstance(story, dict) else getattr(story, "source_event_uuid", ""))
        for story in stories
    ]
    # The cache also knows how many reports each source event has, which is what
    # the "MISP reports" button shows. A story seeded from triage brings its own
    # count; one loaded from a saved briefing has none until this fills it in.
    cached = {
        row["uuid"]: row
        for row in collection_cache.get_events_by_uuids([uuid for uuid in story_uuids if uuid])
    }
    for story in stories:
        if isinstance(story, dict):
            source_event_uuid = story.get("source_event_uuid", "")
            row = cached.get(source_event_uuid) or {}
            if not story.get("source_id"):
                story["source_id"] = row.get("source_id") or source_id_from_event_ref(story.get("source_url", ""))
            if story.get("report_count") is None:
                story["report_count"] = row.get("report_count")
        else:
            source_event_uuid = getattr(story, "source_event_uuid", "")
            row = cached.get(source_event_uuid) or {}
            if not getattr(story, "source_id", ""):
                setattr(story, "source_id", row.get("source_id") or source_id_from_event_ref(getattr(story, "source_url", "")))
            if getattr(story, "report_count", None) is None:
                setattr(story, "report_count", row.get("report_count"))
    gathered = misp_store.briefing_story_scope_values(stories)
    own_scope = {
        "geographic_scope": list(geographic_scope or []),
        "sectors": list(sectors or []),
        "threat_actors": list(threat_actors or []),
        "mitre_attack_techniques": list(mitre_attack_techniques or []),
    }
    # Which briefing-level values no story accounts for. Removing a story takes
    # the scope items it brought in with it, and these are what has to survive
    # that: they were picked for the briefing itself, not reused from a story.
    manual_scope = {
        field: sorted(_scope_keys(values) - _scope_keys(gathered[field]))
        for field, values in own_scope.items()
    }
    return render_template(
        "daily_briefing/form.html",
        stories=stories,
        briefing_date=date,
        briefing_title=title,
        briefing_author=author,
        briefing_tlp=tlp,
        briefing_escalations=escalations,
        briefing_notes=notes,
        briefing_summary=summary,
        briefing_summary_stale=summary_stale,
        page_mode=mode,
        page_title_text=(f"Edit briefing {date or '(no date)'}" if is_edit else "Compose daily briefing"),
        browser_title=(f"Edit briefing {date or '(no date)'}" if is_edit else "Compose briefing"),
        form_action=form_action,
        save_label=("Save changes" if is_edit else "Save draft"),
        cancel_url=cancel_url,
        cancel_label=("Cancel" if is_edit else "Back to triage"),
        story_title_exclusions=(getattr(config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", []) or []),
        threat_actor_types=(getattr(config, "THREAT_ACTOR_TYPES", []) or []),
        story_scope_summary=misp_store.briefing_scope_summary(stories),
        briefing_geographic_scope=dedup_lower(own_scope["geographic_scope"] + gathered["geographic_scope"]),
        briefing_sectors=dedup_lower(own_scope["sectors"] + gathered["sectors"]),
        briefing_threat_actors=dedup_lower(own_scope["threat_actors"] + gathered["threat_actors"]),
        briefing_mitre_attack_techniques=dedup_lower(own_scope["mitre_attack_techniques"] + gathered["mitre_attack_techniques"]),
        briefing_manual_scope=manual_scope,
        briefing_threat_types=threat_types or [],
        briefing_technology=technology or [],
        briefing_vendor=vendor or [],
        briefing_incident=incident or [],
        briefing_campaign=campaign or [],
        galaxy_countries=misp_store.galaxy_geography(),
        galaxy_sectors=misp_store.galaxy_sectors(),
        galaxy_threat_actors=misp_store.galaxy_threat_actors(),
        galaxy_mitre_attack=misp_store.galaxy_mitre_attack_patterns(),
        briefing_created_at=created_at,
        starts_unsaved=starts_unsaved,
    )



def _extract_ai_summary(event) -> str:
    """Return the AI-generated summary report content if one exists on this event."""
    for r in (getattr(event, "event_reports", []) or []):
        if (getattr(r, "name", "") or "").startswith(AI_SUMMARY_PREFIX):
            return (getattr(r, "content", "") or "").strip()
    return ""


def _seed_story_from_event(ev_uuid, source_hint=""):
    """Build a story stub dict from a MISP event, for pre-loading into a briefing draft.

    Resolves the event from whichever MISP instance it actually lives on (the
    scraper, an external MISP_SERVERS instance, or the webapp MISP), trying the
    given source hint first. Scraper events carry an article URL that
    extract_source_url() picks out of their link attributes; events from any
    other source have no such article link (their URL-typed attributes are
    indicators, not "the source"), so the story links to the MISP event page
    itself instead.
    """
    ev, misp_client, source_id = misp_store.resolve_source_event(ev_uuid, source_hint)
    if ev is None:
        return None
    source_url = misp_store.extract_source_url(ev) if source_id == "scraper" else ""
    if not source_url:
        base_url = (getattr(misp_client, "root_url", "") or "").rstrip("/")
        if base_url:
            source_url = f"{base_url}/events/view/{ev.uuid}"
    story = {
        "title": ev.info or "",
        "content": "",
        "source_url": source_url,
        "source_event_uuid": ev.uuid,
        "source_id": source_id,
        "ai_summary": _extract_ai_summary(ev),
        "report_count": len(misp_store.live_reports(ev)),
    }
    story.update(misp_store.extract_story_context(ev))
    return story


def _parse_scope_field(form, key):
    """Read a story scope list out of a hidden form field.

    The field carries JSON, so a value containing a comma ("UNC3753 (also known
    as Luna Moth, Chatty Spider)") stays one value; the earlier comma-joined
    field tore it into two, and those fragments were what the next save wrote to
    MISP. A form rendered before the change still posts the comma-joined string,
    which is read the old way rather than lost.
    """
    raw = (form.get(key) or "").strip()
    if raw.startswith("["):
        try:
            return [str(v).strip() for v in json.loads(raw) if str(v).strip()]
        except ValueError:
            logger.warning("Briefing form field %s is not valid JSON; dropping it", key)
            return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _parse_briefing_scope_from_form(form):
    """Extract briefing-level scope element fields from a POST form.

    Mirrors the PIR form's scope parsing: galaxy-backed multiselect fields
    (geographic_scope, sectors, threat_actors) are deduplicated case-insensitively,
    the rest are taken as-is from the submitted checkbox/tag-input values.
    """
    return {
        "geographic_scope": dedup_lower(form.getlist("geographic_scope")),
        "sectors": dedup_lower(form.getlist("sectors")),
        "threat_actors": dedup_lower(form.getlist("threat_actors")),
        "mitre_attack_techniques": form.getlist("mitre_attack_techniques"),
        "threat_types": form.getlist("threat_types"),
        "technology": form.getlist("technology"),
        "vendor": form.getlist("vendor"),
        "incident": form.getlist("incident"),
        "campaign": form.getlist("campaign"),
    }


# How a story's text came to be, as the compose form reports it. Anything else
# posted under that name is read as hand-written.
_STORY_ORIGINS = ("ai", "ai-edited")


def _parse_stories_from_form(form):
    """Extract story dicts from a POST form with indexed story fields."""
    stories = []
    i = 1
    while True:
        title = form.get(f"story_{i}_title", "").strip()
        if not title and not form.get(f"story_{i}_source_event_uuid", "").strip():
            break
        drafted_by = form.get(f"story_{i}_drafted_by", "").strip()
        cti_eval_raw = form.get(f"story_{i}_cti_evaluation", "").strip()
        try:
            cti_evaluation = json.loads(cti_eval_raw) if cti_eval_raw else {}
        except Exception:
            cti_evaluation = {}
        stories.append({
            "title": title,
            "content": form.get(f"story_{i}_content", "").strip(),
            "source_url": form.get(f"story_{i}_source_url", "").strip(),
            "source_event_uuid": form.get(f"story_{i}_source_event_uuid", "").strip(),
            "source_id": form.get(f"story_{i}_source_id", "").strip(),
            "geographic_scope": _parse_scope_field(form, f"story_{i}_geographic_scope"),
            "sectors": _parse_scope_field(form, f"story_{i}_sectors"),
            "threat_actors": _parse_scope_field(form, f"story_{i}_threat_actors"),
            "techniques": _parse_scope_field(form, f"story_{i}_techniques"),
            "vendor": _parse_scope_field(form, f"story_{i}_vendor"),
            "source_reliability": form.get(f"story_{i}_source_reliability", "").strip(),
            "information_credibility": form.get(f"story_{i}_information_credibility", "").strip(),
            "cti_evaluation": cti_evaluation,
            "threat_actor_types": [v.strip() for v in form.getlist(f"story_{i}_threat_actor_types") if v.strip()],
            "drafted_by": drafted_by if drafted_by in _STORY_ORIGINS else "",
        })
        i += 1
    return stories


def _start_briefing_delivery(uuid, date_label, preview_url, reason):
    """Hand a briefing's delivery to a background job.

    The briefing is re-read on the job thread; only the preview URL and the
    analyst's identity have to be resolved while the request is still alive.
    """
    def deliver(log):
        from notifier import dispatcher

        briefing = misp_store.get_briefing(uuid)
        if briefing is None:
            return False, "the briefing could not be loaded"
        stakeholders = misp_store.stakeholders_cleared_for("Daily threat briefing", briefing.tlp)
        markdown = misp_store.render_briefing_markdown(briefing, preview_url=preview_url)
        log(f"{reason}: {len(stakeholders)} eligible recipient(s).")
        summary = dispatcher.send_daily_briefing(briefing, markdown, stakeholders,
                                                 preview_url=preview_url)
        ok, detail = dispatcher.delivery_outcome(summary)
        log(f"Channels: {detail}.")
        return ok, detail

    return notify_jobs.start(
        "notify-briefing",
        f"Daily briefing {date_label} delivery",
        deliver,
        entity_type="daily-briefing",
        entity_id=uuid,
        entity_label=f"Daily briefing {date_label}",
        user=misp_session.current_user_email(),
    )


@bp.route("/")
def list_briefings():
    state_filter = (request.args.get("state") or "").strip() or None
    sort = (request.args.get("sort") or "").strip()
    direction = (request.args.get("dir") or "asc").strip()
    briefings = misp_store.list_briefings()
    if state_filter:
        briefings = [b for b in briefings if b.review_state == state_filter]
    sort_products(briefings, sort, direction)
    return render_template(
        "daily_briefing/list.html",
        briefings=briefings,
        scope_summaries={b.uuid: misp_store.briefing_combined_scope_summary(b) for b in briefings},
        state_filter=state_filter or "",
        review_states=misp_store.BRIEFING_REVIEW_STATES,
        sort=sort,
        dir=direction,
    )


@bp.route("/triage")
def triage():
    """Redirect to the collection page in briefing mode."""
    return redirect(url_for("data_collection.index", briefing_mode=1))


@bp.route("/compose", methods=["GET", "POST"])
def compose():
    """Build the briefing: one text area per selected story, with LLM draft buttons."""
    if request.method == "POST":
        # Submitted from the triage page: create a blank briefing shell with
        # selected events pre-loaded as story stubs, then redirect to edit.
        selected_uuids, source_hints, _pairs = parse_source_tokens(request.form.getlist("selected_events"))
        bdate = request.form.get("date", "").strip() or datetime.utcnow().strftime("%Y-%m-%d")
        btitle = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip()
        tlp = request.form.get("tlp", "clear")

        stories = []
        for ev_uuid in selected_uuids[:8]:
            try:
                story = _seed_story_from_event(ev_uuid, source_hints.get(ev_uuid, ""))
                if story:
                    stories.append(story)
            except Exception as exc:
                logger.warning("Could not fetch event %s for briefing: %s", ev_uuid, exc)

        return _render_briefing_form(
            stories=stories,
            date=bdate,
            title=btitle,
            author=author,
            tlp=tlp,
            escalations="",
            notes="",
            mode="create",
            form_action=url_for("daily_briefing.save"),
            cancel_url=url_for("daily_briefing.triage"),
        )

    # GET: show empty compose form, optionally pre-seeded with one source event
    today = datetime.utcnow().strftime("%Y-%m-%d")
    stories = []
    seed_token = (request.args.get("source") or "").strip()
    if seed_token:
        seed_ref, _, seed_sid = seed_token.partition("|")
        seed_uuid = (seed_ref or "").strip()
        source_hint = seed_sid.strip() or source_id_from_event_ref(seed_ref)
        try:
            story = _seed_story_from_event(seed_uuid, source_hint)
            if story:
                stories = [story]
        except Exception as exc:
            logger.warning("Could not seed briefing from event %s: %s", seed_uuid, exc)
    return _render_briefing_form(
        stories=stories,
        date=today,
        title="",
        author="",
        tlp="clear",
        escalations="",
        notes="",
        mode="create",
        form_action=url_for("daily_briefing.save"),
        cancel_url=url_for("daily_briefing.triage"),
    )


@bp.route("/save", methods=["POST"])
def save():
    """Save the composed briefing draft to MISP."""
    stories = _parse_stories_from_form(request.form)
    data = {
        "date": request.form.get("date", "").strip() or datetime.utcnow().strftime("%Y-%m-%d"),
        "title": request.form.get("title", "").strip(),
        "author": request.form.get("author", "").strip(),
        "tlp": request.form.get("tlp", "clear"),
        "escalations": request.form.get("escalations", "").strip(),
        "notes": request.form.get("notes", "").strip(),
        "summary": request.form.get("summary", "").strip(),
        # The form tracks this while the analyst works: it knows a story was
        # deleted or rewritten after the summary was drafted, which nothing on
        # this side can tell from the posted values alone.
        "summary_stale": request.form.get("summary_stale") == "true",
        "review_state": misp_store.BRIEFING_REVIEW_DRAFT,
        "stories": stories,
        **_parse_briefing_scope_from_form(request.form),
    }
    if not stories:
        flash("Add at least one story before saving.", "warning")
        return redirect(url_for("daily_briefing.compose"))
    try:
        uuid = misp_store.create_briefing(data)
        product_log.log_product_sources([s.get("source_event_uuid") for s in stories], "daily-briefing")
        label = data["title"] or f"Daily briefing {data['date']}"
        audit.record("create", "daily-briefing", entity_id=uuid, entity_label=label)
        flash(f"{label} saved as draft.", "success")
        return redirect(url_for("daily_briefing.detail", id=uuid))
    except Exception as exc:
        flash(f"Could not save briefing: {exc}", "warning")
        return redirect(url_for("daily_briefing.compose"))


@bp.route("/<string:id>")
def detail(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    feedback = misp_store.list_product_feedback(briefing.uuid)
    recipients = misp_store.stakeholders_cleared_for("Daily threat briefing", briefing.tlp)
    notify_status = audit.latest_notify_status("daily-briefing", id)

    # Enrich story source-event references with cache metadata (date, org, title)
    source_uuids = [
        getattr(s, "source_event_uuid", "")
        for s in briefing.stories
        if getattr(s, "source_event_uuid", "")
    ]
    source_meta = {}
    if source_uuids:
        try:
            for ev in collection_cache.get_events_by_uuids(source_uuids):
                source_meta[ev["uuid"]] = ev
        except Exception:
            pass

    return render_template(
        "daily_briefing/detail.html",
        briefing=briefing,
        feedback=feedback,
        recipients=recipients,
        notify_status=notify_status,
        source_meta=source_meta,
        scope_summary=misp_store.briefing_combined_scope_summary(briefing),
        misp_webapp_url=config.MISP_WEBAPP_URL.rstrip("/"),
    )


# weasyprint has no JS engine to run marked.js like the HTML views do, so
# story content is rendered to HTML server-side before going into the PDF.


@bp.route("/<string:id>/pdf")
def pdf(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    for story in briefing.stories:
        story.html = mute_lead_labels(md_to_html(getattr(story, "content", "")))
    document_html = render_template(
        "daily_briefing/pdf.html",
        briefing=briefing,
        css_url=branding.pdf_css_url(),
        brand=branding.brand(),
        scope_summary=misp_store.briefing_combined_scope_summary(briefing),
    )
    pdf_bytes = weasyprint.HTML(string=document_html).write_pdf()
    filename = f"briefing-{briefing.date or 'draft'}.pdf"
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.route("/<string:id>/feedback", methods=["POST"])
def add_feedback(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    author = request.form.get("author", "").strip()
    rating = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        misp_store.add_product_feedback(briefing.uuid, author, rating, comment)
        audit.record("create", "briefing_feedback", entity_id=id,
                     entity_label=f"Daily briefing {briefing.date}")
        flash("Feedback recorded.", "success")
    except Exception as exc:
        logger.warning("add_feedback briefing %s failed: %s", id, exc)
        flash(f"Could not record feedback: {exc}", "warning")
    return redirect(url_for("daily_briefing.detail", id=id))


@bp.route("/<string:id>/edit", methods=["GET", "POST"])
def edit(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    if request.method == "POST":
        stories = _parse_stories_from_form(request.form)
        data = {
            "date": request.form.get("date", briefing.date).strip(),
            "title": request.form.get("title", briefing.title).strip(),
            "author": request.form.get("author", briefing.author).strip(),
            "tlp": request.form.get("tlp", briefing.tlp),
            "escalations": request.form.get("escalations", "").strip(),
            "notes": request.form.get("notes", "").strip(),
            "summary": request.form.get("summary", "").strip(),
            "summary_stale": request.form.get("summary_stale") == "true",
            "review_state": briefing.review_state,
            "stories": stories,
            **_parse_briefing_scope_from_form(request.form),
        }
        try:
            misp_store.update_briefing(id, data)
            audit.record("update", "daily-briefing", entity_id=id,
                         entity_label=f"Daily briefing {data['date']}")
            flash("Briefing updated.", "success")
            return redirect(url_for("daily_briefing.detail", id=id))
        except Exception as exc:
            flash(f"Could not update briefing: {exc}", "warning")
    return _render_briefing_form(
        stories=briefing.stories,
        date=briefing.date,
        title=briefing.title or "",
        author=briefing.author or "",
        tlp=briefing.tlp or "clear",
        escalations=briefing.escalations or "",
        notes=briefing.notes or "",
        summary=briefing.summary or "",
        summary_stale=briefing.summary_stale,
        mode="edit",
        form_action=url_for("daily_briefing.edit", id=briefing.uuid),
        cancel_url=url_for("daily_briefing.detail", id=briefing.uuid),
        geographic_scope=briefing.geographic_scope,
        sectors=briefing.sectors,
        threat_actors=briefing.threat_actors,
        mitre_attack_techniques=briefing.mitre_attack_techniques,
        threat_types=briefing.threat_types,
        technology=briefing.technology,
        vendor=briefing.vendor,
        incident=briefing.incident,
        campaign=briefing.campaign,
        created_at=briefing.created_at,
    )


@bp.route("/<string:id>/add-stories", methods=["POST"])
def add_stories(id):
    """Seed new stories from selected data-collection events onto an existing draft briefing.

    Renders the edit form pre-loaded with the existing stories plus the new
    stubs, so the analyst can review/draft them before saving.
    """
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    if briefing.review_state != misp_store.BRIEFING_REVIEW_DRAFT:
        flash("Only draft briefings can receive additional stories.", "warning")
        return redirect(url_for("daily_briefing.detail", id=id))

    selected_uuids, source_hints, _pairs = parse_source_tokens(request.form.getlist("selected_events"))
    new_stories = []
    for ev_uuid in selected_uuids[:8]:
        try:
            story = _seed_story_from_event(ev_uuid, source_hints.get(ev_uuid, ""))
            if story:
                new_stories.append(story)
        except Exception as exc:
            logger.warning("Could not fetch event %s for briefing: %s", ev_uuid, exc)

    if not new_stories:
        flash("No stories could be added from the selected events.", "warning")
        return redirect(url_for("daily_briefing.edit", id=id))

    return _render_briefing_form(
        stories=list(briefing.stories) + new_stories,
        date=briefing.date,
        title=briefing.title or "",
        author=briefing.author or "",
        tlp=briefing.tlp or "clear",
        escalations=briefing.escalations or "",
        notes=briefing.notes or "",
        summary=briefing.summary or "",
        # The story set is changing right here, so a summary written for the
        # earlier one no longer covers the briefing.
        summary_stale=bool(briefing.summary),
        mode="edit",
        form_action=url_for("daily_briefing.edit", id=briefing.uuid),
        cancel_url=url_for("daily_briefing.detail", id=briefing.uuid),
        geographic_scope=briefing.geographic_scope,
        sectors=briefing.sectors,
        threat_actors=briefing.threat_actors,
        mitre_attack_techniques=briefing.mitre_attack_techniques,
        threat_types=briefing.threat_types,
        technology=briefing.technology,
        vendor=briefing.vendor,
        incident=briefing.incident,
        campaign=briefing.campaign,
        created_at=briefing.created_at,
        # The new stories exist in this page only until it is saved, which the
        # unsaved-changes warning cannot see for itself: they are there from the
        # first render, so nothing about the form has changed yet.
        starts_unsaved=True,
    )


@bp.route("/<string:id>/publish", methods=["POST"])
def publish(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    try:
        misp_store.publish_briefing(id)
        audit.record("publish", "daily-briefing", entity_id=id,
                     entity_label=f"Daily briefing {briefing.date}")
        _start_briefing_delivery(id, briefing.date,
                                 url_for("daily_briefing.detail", id=id, _external=True), "publish")
        flash(f"Daily briefing {briefing.date} published.", "success")
        flash("Notifications are being sent in the background; the job badge reports the result.", "info")
    except Exception as exc:
        flash(f"Could not publish briefing: {exc}", "warning")
    return redirect(url_for("daily_briefing.detail", id=id))


@bp.route("/<string:id>/resend", methods=["POST"])
def resend(id):
    briefing = misp_store.get_briefing(id)
    if briefing is None:
        return "Briefing not found", 404
    if request.form.get("next") == "detail":
        redirect_target = url_for("daily_briefing.detail", id=id)
    else:
        redirect_target = url_for("daily_briefing.list_briefings")
    if getattr(briefing, "review_state", None) != misp_store.BRIEFING_REVIEW_PUBLISHED:
        flash("Only published briefings can be resent.", "warning")
        return redirect(redirect_target)
    _start_briefing_delivery(id, briefing.date,
                             url_for("daily_briefing.detail", id=id, _external=True), "resend")
    flash(f"Briefing {briefing.date} resend started; the job badge reports the result.", "info")
    return redirect(redirect_target)


@bp.route("/<string:id>/delete", methods=["POST"])
def delete(id):
    briefing = misp_store.get_briefing(id)
    label = f"Daily briefing {briefing.date}" if briefing else id
    if briefing and getattr(briefing, "review_state", None) == misp_store.BRIEFING_REVIEW_PUBLISHED:
        flash(f"{label} is published and cannot be deleted.", "warning")
        return redirect(url_for("daily_briefing.list_briefings"))
    try:
        misp_store.delete_briefing(id)
        audit.record("delete", "daily-briefing", entity_id=id, entity_label=label)
        flash(f"{label} deleted.", "success")
    except Exception as exc:
        flash(f"Could not delete briefing: {exc}", "warning")
    return redirect(url_for("daily_briefing.list_briefings"))
