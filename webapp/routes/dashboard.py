import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template

import config
from analyser import llm
from analyser.reader import load_last_action, load_last_run
from webapp import analyser_pipeline, audit, collection_cache
from webapp import job_store, misp_session, misp_store
from webapp.routes import setup_wizard
from webapp.models import MOSCOW_PRIORITIES, REVIEW_CYCLES
from webapp.utils import json_body as _json_object, ordered_counts, scraper_enabled

logger = logging.getLogger(__name__)
bp = Blueprint("dashboard", __name__)


def _pipeline_status():
    """Return scraper / analyser pipeline status for the dashboard panel.

    - ``last_run`` (datetime | None): when the analyser last completed a run,
      from ``data/state.json``.
    - ``minutes_since`` (int | None): age in minutes of that timestamp.
    - ``stale`` (bool): True if the last run is older than 90 minutes.
    - ``processed_24h`` (dict): counts per outcome from ``event_log`` over
      the last 24h.
    - ``pending`` (int | None): scraper events still tagged
      ``workflow:state="incomplete"`` and waiting for the analyser.
    """
    status = {
        "last_run": None, "minutes_since": None, "stale": True,
        "processed_24h": {}, "total_24h": 0, "pending": None,
    }

    # Last analyser run: whichever ran more recently, the scheduled analyser or
    # an action started from here. They are two entries because only the first
    # of them may move the analyser's watermark.
    try:
        stamps = [ts for ts in (load_last_run(), load_last_action()) if ts]
        if stamps:
            dt = datetime.fromtimestamp(int(max(stamps)), tz=timezone.utc)
            status["last_run"] = dt
            age = (datetime.now(tz=timezone.utc) - dt).total_seconds() / 60
            status["minutes_since"] = int(age)
            status["stale"] = age > 90
    except Exception:
        logger.exception("Failed to read pipeline state from %s", config.STATE_FILE)

    # Outcomes over the last 24h from analyser DB
    try:
        with sqlite3.connect(config.DB_FILE) as conn:
            rows = conn.execute(
                "SELECT outcome, COUNT(*) FROM event_log "
                "WHERE processed_at >= datetime('now', '-1 day') "
                "GROUP BY outcome"
            ).fetchall()
        status["processed_24h"] = {outcome: n for outcome, n in rows}
        status["total_24h"] = sum(status["processed_24h"].values())
    except Exception:
        logger.exception("Failed to query analyser DB for 24h event counts")

    # Pending scraper events: the marker and the incomplete workflow state as
    # one AND query, so MISP sends only those, and all of them. Without a
    # scraper there is nothing to count, and "pending" stays None, which the
    # dashboard renders as "-".
    if not scraper_enabled():
        return status
    try:
        misp = misp_store._scraper_misp()
        query = misp.build_complex_query(
            and_parameters=[config.SCRAPER_MARKER_TAG, 'workflow:state="incomplete"'])
        pending = misp_store._search_all(misp, tags=query, metadata=True, pythonify=False)
        if isinstance(pending, dict):
            logger.warning("pending scraper events: MISP refused the search: %s", pending.get("errors") or pending)
        else:
            status["pending"] = len(pending)
    except Exception:
        logger.exception("Failed to query pending scraper events from MISP")

    return status


@bp.route("/")
def index():
    # Render only the static shell (action bar + placeholders). All the
    # MISP-backed widgets are loaded afterwards via /dashboard/widgets so the
    # page paints immediately instead of waiting on a chain of MISP queries.
    return render_template("dashboard.html")


@bp.route("/dashboard/widgets")
def widgets():
    """Render the data-heavy dashboard sections as an HTML fragment plus the
    pipeline status, fetched asynchronously by the dashboard shell."""
    try:
        pirs = misp_store.list_pirs()
        girs = misp_store.list_girs()
        # Only the number is shown, so the stakeholders' metadata is enough.
        stakeholder_count = misp_store.count_records(config.TAG_STAKEHOLDER)
        rfi_count = misp_store.count_records(config.TAG_RFI)
        pir_count = len(pirs)
        gir_count = len(girs)
        active_pirs = [
            p for p in pirs
            if p.status in ("Active", "In Development", "Under Evaluation")
        ]
        active_girs = [g for g in girs if g.status == "Active"]
    except Exception:
        logger.exception("Failed to load requirements for dashboard")
        pir_count = gir_count = stakeholder_count = rfi_count = 0
        active_pirs = active_girs = []

    try:
        pending_email_sources = len(misp_store.list_pending_newsletters())
    except Exception:
        pending_email_sources = 0

    # Awaiting feedback and the products to review read the alerts and the
    # advisories, and the threat actor chart the alerts, so each is fetched once.
    try:
        fias = misp_store.list_fias()
    except Exception:
        logger.exception("Failed to load flash intel alerts for the dashboard")
        fias = []
    try:
        veas = misp_store.list_veas()
    except Exception:
        logger.exception("Failed to load vulnerability advisories for the dashboard")
        veas = []

    try:
        pending_feedback = misp_store.list_pending_feedback_products(fias, veas)
    except Exception:
        logger.exception("Failed to load pending-feedback products")
        pending_feedback = []

    try:
        to_review = misp_store.products_to_review(fias, veas)
    except Exception:
        logger.exception("Failed to load the products to review")
        to_review = []

    # Both summary charts show the eight busiest entries, most active first.
    try:
        actor_type_products = sorted(
            misp_store.product_counts_by_threat_actor_type(fias),
            key=lambda r: r["total"], reverse=True,
        )[:8]
    except Exception:
        logger.exception("Failed to load product counts by threat actor type")
        actor_type_products = []
    try:
        # Live per-source counts from MISP (the authoritative store), not the local log.
        throughput_by_source = misp_store.data_collection_source_counts()[:8]
    except Exception:
        logger.exception("Failed to load throughput by collection source")
        throughput_by_source = []
    try:
        configured_sources = collection_cache.cached_event_counts()[:8]
    except Exception:
        logger.exception("Failed to load event counts per configured source")
        configured_sources = []

    html = render_template(
        "_dashboard_content.html",
        setup_needed=setup_wizard.needs_setup(),
        pir_count=pir_count,
        gir_count=gir_count,
        stakeholder_count=stakeholder_count,
        rfi_count=rfi_count,
        active_pirs=active_pirs,
        active_girs=active_girs,
        priority_counts=ordered_counts((p.priority for p in active_pirs), MOSCOW_PRIORITIES),
        cycle_counts=ordered_counts((g.review_cycle for g in active_girs), REVIEW_CYCLES),
        pending_email_sources=pending_email_sources,
        pending_feedback=pending_feedback,
        to_review=to_review,
        actor_type_products=actor_type_products,
        throughput_by_source=throughput_by_source,
        configured_sources=configured_sources,
    )

    pl = _pipeline_status()
    pipeline = {
        "has_run": pl["last_run"] is not None,
        "stale": pl["stale"],
        "minutes_since": pl["minutes_since"],
        "last_run_title": pl["last_run"].strftime("%d-%m-%Y %H:%M UTC") if pl["last_run"] else "never",
        "pending": pl["pending"],
        "total_24h": pl["total_24h"],
        "processed_24h": pl["processed_24h"],
    }

    return jsonify({"html": html, "pipeline": pipeline})


@bp.route("/pipeline/run", methods=["POST"])
def run_pipeline_action():
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    action = (body.get("action") or "").strip().lower()
    if action not in {"daily-briefing", "flash-intel", "vea"}:
        return jsonify({"ok": False, "error": "Unknown pipeline action."}), 400

    job = job_store.create_job(action, label=analyser_pipeline.ACTION_LABELS[action],
                               steps=analyser_pipeline.action_steps(action))
    t = threading.Thread(target=analyser_pipeline.run_action, args=(job["id"], misp_session.current_user_email()),
                         daemon=True, name=job_store.thread_name(job["id"]))
    t.start()
    return jsonify({"ok": True, "job_id": job["id"], "action": action})


@bp.route("/pipeline/run/<string:job_id>", methods=["GET"])
def pipeline_job_status(job_id: str):
    job = job_store.get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found."}), 404
    return jsonify({"ok": True, "job": job})


# Which AI feature to report on when an unfinished job is probed. A job that is
# not listed here does not call a model, so there is nothing to ask about, and
# the feature matters because each one can be pointed at its own provider and
# model in the AI settings.
_AI_FEATURE_BY_ACTION = {
    "summarise": "summarise_report",
    "bulk-summarise": "summarise_report",
    "daily-briefing": "draft_briefing_story",
    "briefing-overlap": "detect_story_overlaps",
    "briefing-summary": "draft_briefing_summary",
    # Drafting a whole briefing calls draft_briefing_story once per story, so
    # that is the endpoint it spends its time on even when it writes a summary too.
    "briefing-draft": "draft_briefing_story",
    "flash-intel": "generate_flash_intel",
    "vea": "draft_vea_sections",
    # The scheduled analyser calls check_relevance for every event before it
    # drafts anything, so that is the endpoint one of its runs waits on.
    "analyser": "check_relevance",
}


@bp.route("/pipeline/jobs", methods=["GET"])
def pipeline_jobs():
    """Jobs this instance knows about, for the indicator in the top bar.

    Only what the indicator needs: the steps and the log stay behind
    /pipeline/run/<id> so this stays cheap enough to poll from every page.
    """
    now = time.time()
    jobs = []
    for job in job_store.list_jobs():
        status = job.get("status", "")
        # Age is measured here rather than in the browser: how long ago a job
        # was touched should not depend on how well a laptop keeps time.
        age = max(0, int(now - job.get("updated_at", 0)))
        jobs.append({
            "id": job["id"],
            "action": job.get("action", ""),
            "label": job.get("label") or job.get("action", ""),
            "status": status,
            "message": job.get("message", ""),
            "with_errors": status == "completed" and bool((job.get("result") or {}).get("errors")),
            "stale": job_store.stalled(job),
            "age": age,
        })
    running = [j for j in jobs if j["status"] in job_store.IN_FLIGHT and not j["stale"]]
    return jsonify({"ok": True, "jobs": jobs[:20], "running": len(running)})


@bp.route("/pipeline/jobs/<string:job_id>/probe", methods=["GET"])
def probe_job(job_id: str):
    """Answer "is this job stuck, or just slow?" for one unfinished job.

    Neither LLM provider can be asked how far along a call is, so the answer is
    assembled from what can be known: whether this instance still has a live
    worker thread for the job, how long ago it last reported, and whether the
    AI endpoint it depends on is responding.
    """
    job = job_store.get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "No such job."}), 404

    alive = job_store.worker_alive(job_id)
    unfinished = job.get("status") in job_store.IN_FLIGHT

    if not unfinished:
        verdict = f"Finished {job.get('status')}, nothing to check."
    elif alive:
        verdict = "Still working in this instance. Its thread is alive, so give it time."
    else:
        verdict = ("No worker for this job in this instance. Either another instance is "
                   "running it, or the process that started it is gone and it will never finish.")

    answer = {"ok": True, "status": job.get("status", ""), "message": job.get("message", ""),
              "worker_alive": alive, "verdict": verdict, "ai": None}

    feature = _AI_FEATURE_BY_ACTION.get(job.get("action", ""))
    if unfinished and feature:
        try:
            answer["ai"] = llm.service_status(feature)
        except Exception as exc:
            logger.warning("AI service probe failed: %s", exc)
            answer["ai"] = {"error": str(exc)}
    return jsonify(answer)


@bp.route("/pipeline/jobs/clear", methods=["POST"])
def clear_jobs():
    """Drop job entries from the list in the top bar.

    POST JSON: {"scope": "completed"} for the runs that succeeded, {"scope":
    "abandoned"} for entries left behind by a worker that died with its process,
    or {"scope": "all"} for both and the failed runs. This removes the record,
    not the work.
    """
    body, err = _json_object()
    if err:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    scope = (body.get("scope") or "").strip()
    if scope not in ("completed", "all", "abandoned"):
        return jsonify({"ok": False, "error": "Unknown scope."}), 400

    if scope == "completed":
        removed = job_store.forget_finished(("completed",))
    else:
        removed = job_store.forget_abandoned()
        if scope == "all":
            removed += job_store.forget_finished()
    audit.record("clear", "background-jobs", details=f"scope={scope} removed={removed}")
    return jsonify({"ok": True, "removed": removed})
