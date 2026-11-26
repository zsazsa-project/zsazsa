"""Import a threat report, a long CTI report such as a vendor's yearly one:
Data collection > Threat report.

The analyst uploads a PDF or gives its address, and picks the manual source
its stories go under and the provider who published it. A background job
downloads the PDF when needed, reads it with core.report_document in a child
process, and stores it as a zsazsa record with the stories drafted from its
structure. When asked, the same job has the model name, classify and read the
stories (webapp.report_stories); "Continue with AI" goes on where it stopped.

The analyst then reviews the stories, moving where they start and correcting
their context, and has them made into collection events, which go to the
threat landscape queue.
"""

import hashlib
import io
import logging
import threading

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file, url_for

from core import report_document
from core.db import log_pipeline_run_end, log_pipeline_run_start
from core.report_document import ReportError
from webapp import audit, collection_cache, job_store, misp_session, misp_store, report_stories
from webapp.models import TLP_LEVELS
from webapp.rate_limit import rate_limited
from webapp.utils import iso_day

logger = logging.getLogger(__name__)

bp = Blueprint("report_import", __name__, url_prefix="/collection/reports")

JOB_ACTION = "report-import"
AI_ACTION = "report-ai"
CREATE_ACTION = "report-create"
ANALYSE_ACTION = "report-story-context"
# The jobs that write a report's manifest. While one runs, the review of the
# report is read only.
_WRITING = (JOB_ACTION, AI_ACTION, CREATE_ACTION)
_AI_STEPS = [{"id": "split", "label": "Name and classify the stories", "state": "pending"},
             {"id": "context", "label": "Read the context of each story", "state": "pending"}]
# A request this much over the PDF's limit is refused before it is read: the
# rest of the form is a few fields.
_FORM_SLACK = 1024 * 1024


def _manual_sources() -> list:
    try:
        return [s for s in misp_store.list_collection_sources() if s.enabled and (s.name or "").strip()]
    except Exception as exc:
        logger.warning("Could not load manual collection sources: %s", exc)
        return []


def _reports() -> list:
    try:
        return misp_store.list_report_documents()
    except Exception as exc:
        logger.warning("Could not list the imported reports: %s", exc)
        return []


def _in_flight(job) -> bool:
    return job.get("status") in job_store.IN_FLIGHT and not job_store.stalled(job)


def _running_import():
    return next((j for j in job_store.list_jobs() if j.get("action") == JOB_ACTION and _in_flight(j)), None)


def _last_job(uuid: str):
    """The most recent job that wrote, or writes, this report's manifest."""
    return next((j for j in job_store.list_jobs() if j.get("entity") == uuid and j.get("action") in _WRITING), None)


def _busy(uuid: str):
    """The job writing this report's manifest now, if there is one."""
    job = _last_job(uuid)
    return job if job and _in_flight(job) else None


def _similar(report, reports) -> list:
    """Earlier imports of another file that look like the same threat report:
    from the same provider, with the same title or file name. A new version of
    a report, or the same one saved again, comes back that way."""
    norm = report_document._norm
    return [r for r in reports if r.uuid != report.uuid and norm(r.provider) == norm(report.provider)
            and (norm(r.title) == norm(report.title) or (r.filename and r.filename == report.filename))]


def _known(reports) -> list:
    """The earlier imports, as the form checks a file against them before it is sent."""
    return [{"uuid": r.uuid, "title": r.title, "provider": r.provider, "filename": r.filename, "sha256": r.sha256,
             "published": r.published, "url": url_for(".detail", uuid=r.uuid)} for r in reports]


_STATES = {"drafted": "Drafted", "reviewed": "Reviewed", "created": "Made into events"}


@bp.route("/")
def index():
    """Every imported threat report."""
    reports = _reports()
    # The reports a job writes to now, which the delete route refuses.
    busy = {j.get("entity") for j in job_store.list_jobs() if j.get("action") in _WRITING and _in_flight(j)}
    return render_template("data_collection/report_list.html", reports=reports, states=_STATES,
                           providers=misp_store.report_providers(reports), busy=busy)


@bp.route("/new", methods=["GET", "POST"])
def new():
    sources = _manual_sources()
    if not sources:
        flash("No enabled manual sources configured. Add them under Settings > Collection sources > Manual sources.",
              "warning")
        return redirect(url_for("data_collection.index"))
    if request.method == "POST":
        started = _start_import({s.name.strip(): s for s in sources})
        if started:
            return started
    job_id = request.args.get("job", "")
    job = job_store.get_job(job_id) if job_id else None
    reports = _reports()
    return render_template(
        "data_collection/report_new.html",
        sources=sources, reports=reports[:6], report_count=len(reports), known=_known(reports),
        providers=misp_store.report_providers(reports),
        job=job if job and job.get("action") == JOB_ACTION else None,
        form=request.form if request.method == "POST" else {},
        tlp_levels=TLP_LEVELS, reliabilities=misp_store.FIA_RELIABILITIES,
        max_mb=report_document.max_mb(),
    )


def _start_import(sources: dict):
    """Check the form and start the import job. Returns the redirect to the
    job's progress, or None after flashing what is wrong."""
    limit = report_document.max_mb()
    if (request.content_length or 0) > limit * 1024 * 1024 + _FORM_SLACK:
        flash(f"The PDF is larger than {limit} MB.", "warning")
        return None
    form = request.form
    source = (form.get("source") or "").strip()
    provider = " ".join((form.get("provider") or "").split())[:120]
    reliability = (form.get("source_reliability") or "").strip().upper()
    tlp = (form.get("tlp") or "document").strip()
    published = (form.get("published") or "").strip()
    url = (form.get("url") or "").strip()
    upload = request.files.get("document")
    pdf, filename = None, ""
    if upload and upload.filename:
        pdf = upload.read(limit * 1024 * 1024 + 1)
        filename = report_document.pdf_filename(upload.filename)
        url = ""

    problem = ""
    if source not in sources:
        problem = "Pick the manual source the threat report's stories go under."
    elif not provider:
        problem = "Name the provider who published the threat report."
    elif reliability and reliability not in misp_store.FIA_RELIABILITIES:
        problem = "Pick a source reliability from A to F, or leave it unrated."
    elif tlp != "document" and tlp not in TLP_LEVELS:
        problem = "Pick a TLP."
    elif published and not iso_day(published):
        problem = "The publication date is not a date."
    elif pdf is not None and len(pdf) > limit * 1024 * 1024:
        problem = f"The PDF is larger than {limit} MB."
    elif pdf is not None and not report_document.looks_like_pdf(pdf):
        problem = "The file is not a PDF."
    elif pdf is None and not url:
        problem = "Choose a PDF, or give the address of one."
    elif pdf is None and not url.lower().startswith(("http://", "https://")):
        problem = "The address must start with http:// or https://."
    elif _running_import():
        problem = "Another threat report is being imported. Start this one when it is done."
    if problem:
        flash(problem, "warning")
        return None
    if pdf is not None:
        # The same file opens the import it already has, before a job reads it
        # again. A link is only known after its download, which the job checks.
        try:
            earlier = misp_store.find_report_document(hashlib.sha256(pdf).hexdigest())
        except Exception as exc:
            logger.warning("Could not look for an earlier import of %s: %s", filename, exc)
            earlier = None
        if earlier:
            return redirect(url_for(".detail", uuid=earlier, earlier=1))

    details = {"title": " ".join((form.get("title") or "").split())[:200], "provider": provider,
               "published": published, "collection_source": source,
               "source_reliability": reliability,
               "tlp": tlp, "filename": filename, "source_url": url}
    with_ai = form.get("with_ai") == "1"
    steps = ([{"id": "fetch", "label": "Download the PDF", "state": "pending"}] if url else []) + [
        {"id": "read", "label": "Read the text", "state": "pending"},
        {"id": "draft", "label": "Draft the stories", "state": "pending"},
        {"id": "store", "label": "Save the threat report in MISP", "state": "pending"},
    ] + ([dict(step) for step in _AI_STEPS] if with_ai else [])
    job = job_store.create_job(JOB_ACTION, label=f"Import a threat report from {provider}", steps=steps)
    threading.Thread(target=_run_import, args=(job["id"], pdf, details, misp_session.current_user_email(), with_ai),
                     daemon=True, name=job_store.thread_name(job["id"])).start()
    return redirect(url_for(".new", job=job["id"]))


def _note(job_id: str, step: str, text: str) -> None:
    """A line under a step on the progress panel, such as what was read."""
    job = job_store.get_job(job_id) or {}
    job_store.update_job(job_id, notes={**(job.get("notes") or {}), step: text})


def _run_import(job_id: str, pdf, details: dict, user: str, with_ai: bool = False) -> None:
    job_store.update_job(job_id, status="running", message="Starting the import")
    run_id = log_pipeline_run_start(JOB_ACTION, triggered_by="data collection")
    try:
        if pdf is None:
            job_store.set_step(job_id, "fetch", "in_progress", "Downloading the PDF")
            pdf, details["filename"] = report_document.fetch_pdf(details["source_url"])
            job_store.set_step(job_id, "fetch", "completed", f"Downloaded {details['filename']}")
            _note(job_id, "fetch", f"{details['filename']}, {len(pdf) / 1024 / 1024:.1f} MB")
        sha256 = hashlib.sha256(pdf).hexdigest()
        earlier = misp_store.find_report_document(sha256)
        if earlier:
            job_store.complete_open_steps(job_id)
            job_store.update_job(job_id, entity=earlier, result={"uuid": earlier, "earlier": True})
            _finish(job_id, run_id, "This PDF was imported before")
            return

        job_store.set_step(job_id, "read", "in_progress", "Reading the text")
        reading = report_document.read_pdf(pdf)
        job_store.set_step(job_id, "read", "completed", f"Read {reading['pages']} pages")
        _note(job_id, "read", f"{reading['characters']:,} characters in {len(reading['blocks']):,} blocks"
              + (f", without {len(reading['running'])} running header and footer lines" if reading["running"] else ""))
        entries = len(reading["outline"])
        source = {"outline": f"{entries} entr{'y' if entries == 1 else 'ies'} of the outline", "headings": "its headings",
                  "size": "its length", "document": "a short document, one story"}[reading["structure"]]
        job_store.set_step(job_id, "draft", "completed", f"Drafted {len(reading['drafts'])} stories")
        _note(job_id, "draft", f"From {source}")

        job_store.set_step(job_id, "store", "in_progress", "Saving the threat report in MISP")
        data = {**details, "sha256": sha256, "pages": reading["pages"], "characters": reading["characters"],
                "structure": reading["structure"], "import_state": "drafted", "version": 1,
                "title": details["title"] or reading["title"] or details["filename"],
                "published": details["published"] or reading["created"],
                "tlp": details["tlp"] if details["tlp"] != "document" else (reading["tlp"] or "amber")}
        uuid = misp_store.create_report_document(data, pdf, reading, report_stories.new_manifest(reading))
        job_store.set_step(job_id, "store", "completed", "Saved in MISP")
        audit.record("create", "report-import", entity_id=uuid, entity_label=data["title"], user=user)
        # The page can open the import from here on, also when the AI fails.
        job_store.update_job(job_id, entity=uuid, result={"uuid": uuid})
    except ReportError as exc:
        _finish(job_id, run_id, error=str(exc))
        return
    except Exception:
        logger.exception("report import %s failed", job_id[:8])
        _finish(job_id, run_id, error="The threat report could not be imported. The log says why.")
        return
    imported = f"Imported {data['title']}, {len(reading['drafts'])} stories drafted"
    if not with_ai:
        _finish(job_id, run_id, imported)
        return
    stopped = _run_ai(job_id, uuid)
    _finish(job_id, run_id, f"{imported} and read by the AI", error=f"The threat report is imported, but {stopped}"
            if stopped else "")


def _run_continue(job_id: str, uuid: str) -> None:
    """The AI going on with a report imported before, as a job of its own."""
    job_store.update_job(job_id, status="running")
    run_id = log_pipeline_run_start(AI_ACTION, triggered_by="data collection")
    stopped = _run_ai(job_id, uuid)
    _finish(job_id, run_id, "The stories are ready to review", error=stopped[:1].upper() + stopped[1:])


def _run_ai(job_id: str, uuid: str) -> str:
    """The model's part of an import, as the job's last two steps. Returns
    why it stopped, or "". What it answered is kept, and "Continue with AI"
    goes on from there."""
    try:
        job_store.set_step(job_id, "split", "in_progress", "Naming and classifying the stories")
        report_stories.run_split(job_id, uuid)
        job_store.set_step(job_id, "split", "completed", "Named and classified the stories")
        job_store.set_step(job_id, "context", "in_progress", "Reading the context of each story")
        report_stories.run_context(job_id, uuid)
        job_store.set_step(job_id, "context", "completed", "Read the context of each story")
    except misp_store.ReportChanged:
        return ("someone saved it while the AI was working. What the AI did is kept; continue with AI on the "
                "threat report's page to go on.")
    except Exception:
        logger.exception("the AI of report %s stopped", uuid)
        return ("the AI stopped before it was done. What it answered is kept; continue with AI on the threat report's "
                "page to go on. The log says why it stopped.")
    return ""


def _finish(job_id: str, run_id: int, message: str = "", error: str = "") -> None:
    """End a job, and its line in the Pipeline page's run history: completed
    with its message, or failed with why, its unfinished step marked so."""
    if error:
        job = job_store.get_job(job_id) or {}
        for step in job.get("steps", []):
            if step.get("state") == "in_progress":
                job_store.set_step(job_id, step["id"], "failed")
        job_store.update_job(job_id, status="failed", error=error, message=error)
    else:
        job_store.update_job(job_id, status="completed", message=message)
    log_pipeline_run_end(run_id, "failed" if error else "completed", {"message": error or message})


def _report_or_404(uuid: str):
    report = misp_store.get_report_document(uuid)
    if report is None:
        abort(404)
    return report


def _deleted(uuid: str):
    """What a story's "From threat report" badge opens once its threat report
    is deleted: the stories made from it are collection events of their own
    and stay. Without a deletion in the audit log or a story left, it is a 404.
    """
    uuid = uuid.lower()
    if not misp_store._UUID_RE.fullmatch(uuid):
        abort(404)
    deletion = audit.latest_event("delete", "report-import", entity_id=uuid)
    stories = collection_cache.get_events(collection_cache.cached_source_ids(), [misp_store.report_tag(uuid)],
                                          limit=500)
    if deletion is None and not stories:
        abort(404)
    tags = [t for ev in stories for t in ev["tags"]]
    provider = next((t[len(misp_store.PROVIDER_TAG_PREFIX):].strip('"') for t in tags
                     if t.startswith(misp_store.PROVIDER_TAG_PREFIX)), "")
    # Each run makes its stories in the order of the report, so their event ids follow it.
    stories.sort(key=lambda ev: int(ev["id"] or 0))
    for ev in stories:
        ev["kind"] = misp_store.story_kind(ev["tags"])
    return render_template("data_collection/report_deleted.html", deletion=deletion, stories=stories,
                           provider=provider, report_tag=misp_store.report_tag(uuid)), 410


@bp.route("/<string:uuid>")
def detail(uuid):
    report = misp_store.get_report_document(uuid)
    if report is None:
        return _deleted(uuid)
    manifest = misp_store.report_manifest(report)
    reports = _reports()
    return render_template("data_collection/report_detail.html", report=report,
                           read=manifest.get("read", {}), stories=manifest["stories"],
                           calls_left=report_stories.calls_left(manifest), busy=_busy(uuid), last_job=_last_job(uuid),
                           made=sum(1 for s in manifest["stories"] if s.get("event")),
                           providers=misp_store.report_providers(reports), earlier=request.args.get("earlier") == "1",
                           similar=_similar(report, reports),
                           report_tag=misp_store.report_tag(report.uuid), tlp_levels=TLP_LEVELS)


@bp.route("/<string:uuid>/details", methods=["POST"])
def save_details(uuid):
    form = request.form
    details = {"title": " ".join((form.get("title") or "").split())[:200],
               "provider": " ".join((form.get("provider") or "").split())[:120],
               "published": (form.get("published") or "").strip(), "tlp": (form.get("tlp") or "").strip()}
    try:
        version = int(form.get("version") or "")
    except ValueError:
        version = -1
    if _busy(uuid):
        # A save now would move the version from under the job writing the report.
        flash("Something is still being done to this threat report. Save its details when it is done.", "warning")
    elif not details["title"] or not details["provider"]:
        flash("A threat report needs a title and a provider.", "warning")
    elif details["published"] and not iso_day(details["published"]):
        flash("The publication date is not a date.", "warning")
    elif details["tlp"] not in TLP_LEVELS:
        flash("Pick a TLP.", "warning")
    else:
        try:
            misp_store.update_report_details(uuid, details, version)
        except misp_store.ReportChanged:
            flash("Someone saved this threat report after you opened it. It shows their change now; make yours again.",
                  "warning")
        except ValueError:
            abort(404)
        except Exception:
            logger.exception("could not save the details of report %s", uuid)
            flash("Could not save the details. The log says why.", "warning")
        else:
            audit.record("update", "report-import", entity_id=uuid, entity_label=details["title"])
            flash("Details saved.", "success")
    return redirect(url_for(".detail", uuid=uuid))


@bp.route("/<string:uuid>/delete", methods=["POST"])
def delete(uuid):
    """Delete a threat report. The stories made from it are collection events
    of their own, and stay."""
    report = _report_or_404(uuid)
    if _busy(uuid):
        flash("Something is still being done to this threat report. Delete it when it is done.", "warning")
        return redirect(url_for(".detail", uuid=uuid))
    try:
        made = sum(1 for s in misp_store.report_manifest(report)["stories"] if s.get("event"))
    except Exception as exc:
        logger.warning("threat report %s: could not count the stories made from it: %s", uuid, exc)
        made = 0
    try:
        misp_store.delete_report_document(report.uuid)
    except Exception:
        logger.exception("could not delete threat report %s", uuid)
        flash("Could not delete the threat report. The log says why.", "warning")
        return redirect(url_for(".detail", uuid=uuid))
    audit.record("delete", "report-import", entity_id=report.uuid, entity_label=report.title)
    kept = (f" The {made} stor{'y' if made == 1 else 'ies'} made from it stay on Data collection and in the threat "
            "landscape queue." if made else "")
    flash(f'"{report.title}" is deleted.{kept}', "success")
    return redirect(url_for(".index"))


@bp.route("/<string:uuid>/pdf")
def pdf(uuid):
    report = misp_store.get_report_document(uuid)
    if report is None or not report.pdf:
        abort(404)
    return send_file(io.BytesIO(misp_store.report_pdf(report)), mimetype="application/pdf",
                     as_attachment=True, download_name=report.filename or "report.pdf")


def _start(action: str, uuid: str, label: str, target, *args, steps=None) -> dict:
    job = job_store.create_job(action, label=label, steps=steps)
    job_store.update_job(job["id"], entity=uuid)
    threading.Thread(target=target, args=(job["id"], uuid, *args), daemon=True,
                     name=job_store.thread_name(job["id"])).start()
    return job


@bp.route("/<string:uuid>/ai", methods=["POST"])
def continue_ai(uuid):
    """Have the model go on with the stories where it stopped, or start."""
    report = _report_or_404(uuid)
    if _busy(uuid):
        flash("Something is still being done to this threat report. Wait until it is done.", "warning")
    elif not report_stories.calls_left(misp_store.report_manifest(report)):
        flash("The AI has nothing left to do for this threat report.", "info")
    else:
        _start(AI_ACTION, uuid, f"AI for {report.title}", _run_continue, steps=[dict(s) for s in _AI_STEPS])
        audit.record("update", "report-import", entity_id=uuid, entity_label=report.title, details="asked the AI")
    return redirect(url_for(".detail", uuid=uuid))


def _galaxy_lists() -> dict:
    return {"sectors": misp_store.galaxy_sectors(), "geographic_scope": misp_store.galaxy_geography(),
            "threat_actors": misp_store.galaxy_threat_actors(),
            "techniques": misp_store.galaxy_mitre_attack_patterns()}


@bp.route("/<string:uuid>/review")
def review(uuid):
    report = _report_or_404(uuid)
    manifest = misp_store.report_manifest(report)
    blocks = [{k: b[k] for k in ("id", "page", "text", "kind")} for b in misp_store.report_reading(report)["blocks"]]
    return render_template("data_collection/report_review.html", report=report, busy=_busy(uuid),
                           data={"version": report.version, "blocks": blocks, "stories": manifest["stories"],
                                 "skipped": manifest.get("skipped", []),
                                 "kinds": report_stories.kind_names(), "kind_notes": report_stories.kind_notes(),
                                 "threat_types": misp_store.tlr_threat_types(),
                                 "lists": _galaxy_lists()})


@bp.route("/<string:uuid>/review", methods=["POST"])
def save_review(uuid):
    """Save the stories as the analyst left them. JSON in and out."""
    report = misp_store.get_report_document(uuid)
    if report is None:
        return jsonify({"ok": False, "error": "This threat report no longer exists."}), 404
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or type(body.get("version")) is not int:
        return jsonify({"ok": False, "error": "The review could not be read."}), 400
    if _busy(uuid):
        return jsonify({"ok": False, "error": "Something is still being done to this threat report, so the review "
                                              "cannot be saved yet. Wait until it is done."}), 409
    manifest = misp_store.report_manifest(report)
    blocks = misp_store.report_reading(report)["blocks"]
    try:
        skipped = report_stories.review_skipped(manifest, body.get("skipped", []), blocks)
        manifest["stories"] = report_stories.review(manifest, body.get("stories"), blocks, report_stories.galaxies(),
                                                    set(skipped))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    manifest["skipped"] = skipped
    manifest["ai"]["closed"] = True
    try:
        made = any(s["event"] for s in manifest["stories"])
        version = misp_store.save_report_manifest(uuid, manifest, body["version"], import_state="created"
                                                  if made and not report_stories.to_create(manifest) else "reviewed")
    except misp_store.ReportChanged:
        return jsonify({"ok": False, "error": "Someone saved this threat report after you opened it. Reload the page to "
                                              "see their change; what you changed here is not saved."}), 409
    audit.record("update", "report-import", entity_id=uuid, entity_label=report.title, details="reviewed the stories")
    return jsonify({"ok": True, "version": version, "stories": manifest["stories"], "skipped": skipped})


def _run_analyse(job_id: str, uuid: str, story: dict, skipped: set) -> None:
    job_store.update_job(job_id, status="running", message=f"Reading the context of {story['title']}")
    try:
        with job_store.heartbeat(job_id, f"Reading the context of {story['title']}"):
            result = report_stories.analyse_one(uuid, story, skipped)
    except ValueError as exc:
        job_store.update_job(job_id, status="failed", error=str(exc), message=str(exc))
        return
    except Exception:
        logger.exception("the context of a story of report %s could not be read", uuid)
        message = "The AI could not read the story. The log says why."
        job_store.update_job(job_id, status="failed", error=message, message=message)
        return
    job_store.update_job(job_id, status="completed", message="Read the story's context",
                         result={"story": story["id"], **result})


@bp.route("/<string:uuid>/analyse", methods=["POST"])
@rate_limited("report_analyse", limit=20, window_s=60)
def analyse(uuid):
    """Ask the model for the context of one story, as the analyst has cut it.
    The page follows the job and applies what it gives."""
    report = misp_store.get_report_document(uuid)
    if report is None:
        return jsonify({"ok": False, "error": "This threat report no longer exists."}), 404
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "The story could not be read."}), 400
    story = {k: body.get(k) for k in ("id", "start", "end", "title", "kind", "path")}
    if not (type(story["start"]) is int and type(story["end"]) is int and 0 <= story["start"] < story["end"]
            and story["end"] <= misp_store.report_manifest(report)["read"]["blocks"]):
        return jsonify({"ok": False, "error": "The story's blocks are not in the threat report."}), 400
    story["title"] = " ".join(str(story["title"] or "").split())[:200] or "Untitled story"
    story["path"] = [str(p) for p in story["path"]] if isinstance(story["path"], list) else []
    skipped = body.get("skipped") if isinstance(body.get("skipped"), list) else []
    job = _start(ANALYSE_ACTION, uuid, f"AI context of {story['title']}", _run_analyse, story,
                 {b for b in skipped if type(b) is int})
    return jsonify({"ok": True, "job": job["id"]})


def _run_create(job_id: str, uuid: str, user: str) -> None:
    job_store.update_job(job_id, status="running", message="Making the stories")
    run_id = log_pipeline_run_start(CREATE_ACTION, triggered_by="data collection")
    try:
        result = report_stories.run_create(job_id, uuid)
    except Exception:
        logger.exception("the stories of report %s could not all be made", uuid)
        _finish(job_id, run_id, error="Not every story could be made. Those that were are kept and queued; make "
                                      "the stories again to go on. The log says why.")
        return
    for problem in result["problems"]:
        job_store.append_log(job_id, problem)
    audit.record("create", "report-story", entity_id=uuid, user=user,
                 details=f"made {result['made']} stories, queued {result['queued']} for the threat landscape")
    job_store.update_job(job_id, result=result)
    _finish(job_id, run_id, f"Made {result['made']} stories and queued {result['queued']} for the threat landscape"
                            + (f"; {len(result['problems'])} could not be queued" if result["problems"] else ""))


@bp.route("/<string:uuid>/create", methods=["POST"])
def create_stories(uuid):
    """Make the reviewed stories collection events and queue them."""
    report = _report_or_404(uuid)
    manifest = misp_store.report_manifest(report)
    todo = report_stories.to_create(manifest)
    unkind = [s for s in todo if not s["kind"]]
    try:
        version = int(request.form.get("version") or "")
    except ValueError:
        version = -1
    if version != report.version:
        flash("The stories were saved after this page was opened. Look them over again before you make them.",
              "warning")
    elif _busy(uuid):
        flash("Something is still being done to this threat report. Wait until it is done.", "warning")
    elif not todo:
        flash("Every story to make is made already.", "info")
    elif unkind:
        flash(f"Give every story a kind before you make them: {len(unkind)} have none yet, starting with "
              f'"{unkind[0]["title"]}".', "warning")
    else:
        _start(CREATE_ACTION, uuid, f"Make the stories of {report.title}", _run_create,
               misp_session.current_user_email())
        return redirect(url_for(".detail", uuid=uuid))
    return redirect(url_for(".review", uuid=uuid))
