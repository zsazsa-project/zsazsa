import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, render_template

import config
from analyser.reader import save_last_run
from core.db import log_pipeline_run_start, log_pipeline_run_end
from webapp import analyser_pipeline, audit
from webapp import job_store, misp_session, misp_store
from webapp.utils import json_body as _json_object

logger = logging.getLogger(__name__)
bp = Blueprint("dashboard", __name__)


_ACTION_LABELS = {
    "daily-briefing": "Daily briefing",
    "flash-intel": "Flash intel alert",
    "vea": "Vulnerability advisory",
}


def _steps_for_action(action: str) -> list[dict]:
    common = [
        {"id": "refresh-cache", "label": "Refresh scraper cache", "state": "pending"},
        {"id": "collect-events", "label": "Load today's incomplete events", "state": "pending"},
        {"id": "filter-events", "label": "Filter hard negatives", "state": "pending"},
        {"id": "generate-summaries", "label": "Generate missing LLM summaries", "state": "pending"},
    ]
    if action == "daily-briefing":
        common.extend([
            {"id": "review-relevance", "label": "Review relevance and usefulness", "state": "pending"},
            {"id": "build-briefing", "label": "Build briefing story set", "state": "pending"},
            {"id": "check-overlap", "label": "Check overlap and remove duplicates", "state": "pending"},
            {"id": "create-drafts", "label": "Create daily briefing draft", "state": "pending"},
        ])
    elif action == "flash-intel":
        common.extend([
            {"id": "match-requirements", "label": "Match events to PIR/GIR", "state": "pending"},
            {"id": "create-drafts", "label": "Create flash intel draft(s)", "state": "pending"},
        ])
    elif action == "vea":
        common.extend([
            {"id": "detect-cves", "label": "Detect CVE matches", "state": "pending"},
            {"id": "create-drafts", "label": "Create vulnerability advisory draft(s)", "state": "pending"},
        ])
    return common


def _run_pipeline_job(job_id: str, user: str) -> None:
    """Run one analyser action. ``user`` is the analyst who started it, read
    from the request before this thread began, for the audit entries."""
    job = job_store.get_job(job_id)
    if not job:
        return
    action = job["action"]
    handlers = {
        "daily-briefing": analyser_pipeline.run_daily_briefing_action,
        "flash-intel": analyser_pipeline.run_flash_intel_action,
        "vea": analyser_pipeline.run_vea_action,
    }
    handler = handlers.get(action)
    if handler is None:
        job_store.update_job(job_id, status="failed", error="Unknown pipeline action.",
                             message="Unknown pipeline action.")
        return

    run_id = log_pipeline_run_start(action, triggered_by="dashboard")
    audit.record("run-start", "pipeline", entity_label=action, details="triggered by dashboard", user=user)
    job_store.update_job(job_id, status="running", message="Running...")
    job_store.append_log(job_id, f"Started action '{action}'.")

    def _progress(*, step: str, state: str, message: str = ""):
        job_store.set_step(job_id, step=step, state=state, message=message)

    try:
        result = handler(progress=_progress)
        # Keep dashboard pipeline freshness in sync with manual runs.
        save_last_run(int(time.time()))
        log_pipeline_run_end(run_id, "completed", result)
        audit.record("run-complete", "pipeline", entity_label=action,
                     details=(result or {}).get("message") or "", user=user)
        job_store.complete_open_steps(job_id)
        job_store.update_job(
            job_id,
            status="completed",
            result=result,
            message=(result or {}).get("message") or "Completed.",
            error=None,
        )
        job_store.append_log(job_id, "Action completed.")
    except Exception as exc:
        log_pipeline_run_end(run_id, "failed")
        audit.record("run-failed", "pipeline", entity_label=action, details=str(exc), user=user)
        job_store.update_job(job_id, status="failed", error=str(exc), message=f"Failed: {exc}")
        job_store.append_log(job_id, f"Action failed: {exc}")
        logger.exception("Pipeline job %s failed", job_id)


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

    # Last analyser run
    try:
        state = json.loads(Path(config.STATE_FILE).read_text())
        ts = state.get("analyser_last_run")
        if ts:
            dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            status["last_run"] = dt
            age = (datetime.now(tz=timezone.utc) - dt).total_seconds() / 60
            status["minutes_since"] = int(age)
            status["stale"] = age > 90
    except FileNotFoundError:
        pass
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

    # Pending scraper events (workflow incomplete). MISP tag filters are OR,
    # so search by the scraper marker and AND-filter the workflow tag locally.
    # pythonify=False keeps this to plain dicts instead of building up to 500
    # MISPEvent objects, which is the bulk of the cost for this count.
    try:
        misp = misp_store._scraper_misp()
        pending = misp.search(
            tags=[config.SCRAPER_MARKER_TAG],
            limit=getattr(config, "MISP_SCRAPER_LIMIT", 500), metadata=True, pythonify=False,
        )
        if isinstance(pending, dict):
            pending = pending.get("response", [])
        if isinstance(pending, list):
            needed = 'workflow:state="incomplete"'
            count = 0
            for item in pending:
                event = item.get("Event", item) if isinstance(item, dict) else {}
                tags = event.get("Tag") or []
                if any(t.get("name") == needed for t in tags):
                    count += 1
            status["pending"] = count
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
        stakeholder_count = len(misp_store.list_stakeholders())
        pir_count = len(pirs)
        gir_count = len(girs)
        active_pirs = [
            p for p in pirs
            if p.status in ("Active", "In Development", "Under Evaluation")
        ]
        active_girs = [g for g in girs if g.status == "Active"]
    except Exception:
        logger.exception("Failed to load requirements for dashboard")
        pir_count = gir_count = stakeholder_count = 0
        active_pirs = active_girs = []

    try:
        pending_email_sources = len(misp_store.list_pending_newsletters())
    except Exception:
        pending_email_sources = 0

    try:
        pending_feedback = misp_store.list_pending_feedback_products()
    except Exception:
        logger.exception("Failed to load pending-feedback products")
        pending_feedback = []

    # Both summary charts show the eight busiest entries, most active first.
    try:
        actor_type_products = sorted(
            misp_store.product_counts_by_threat_actor_type(),
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

    html = render_template(
        "_dashboard_content.html",
        pir_count=pir_count,
        gir_count=gir_count,
        stakeholder_count=stakeholder_count,
        active_pirs=active_pirs,
        active_girs=active_girs,
        pending_email_sources=pending_email_sources,
        pending_feedback=pending_feedback,
        actor_type_products=actor_type_products,
        throughput_by_source=throughput_by_source,
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

    job = job_store.create_job(action, label=_ACTION_LABELS.get(action, action),
                               steps=_steps_for_action(action))
    t = threading.Thread(target=_run_pipeline_job, args=(job["id"], misp_session.current_user_email()),
                         daemon=True, name=f"pipeline-{action}")
    t.start()
    return jsonify({"ok": True, "job_id": job["id"], "action": action})


@bp.route("/pipeline/run/<string:job_id>", methods=["GET"])
def pipeline_job_status(job_id: str):
    job = job_store.get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found."}), 404
    return jsonify({"ok": True, "job": job})


# A job whose worker died with the process keeps its "running" status until it
# expires, so anything silent for this long is reported as stalled instead of
# spinning in the top bar for the rest of the day. Well above the slowest step
# an analyser run takes between two progress messages.
_JOB_STALE_AFTER_SECONDS = 1800


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
        unfinished = status in ("queued", "running")
        # Age is measured here rather than in the browser: how long ago a job
        # was touched should not depend on how well a laptop keeps time.
        age = max(0, int(now - job.get("updated_at", 0)))
        jobs.append({
            "id": job["id"],
            "action": job.get("action", ""),
            "label": job.get("label") or job.get("action", ""),
            "status": status,
            "message": job.get("message", ""),
            "stale": unfinished and age > _JOB_STALE_AFTER_SECONDS,
            "age": age,
        })
    running = [j for j in jobs if j["status"] in ("queued", "running") and not j["stale"]]
    return jsonify({"ok": True, "jobs": jobs[:20], "running": len(running)})
