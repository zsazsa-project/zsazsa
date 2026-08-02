"""Deliver product notifications on a background thread.

Publishing a product fans out to e-mail, Mattermost and Flowintel, and every hop
carries its own timeout. One unreachable recipient used to hold the analyst's
browser until that connection gave up, which on a dead SMTP host is twenty
seconds before anything appears on screen.

Delivery now runs as a background job, the same mechanism the analyser runs and
the AI summaries use, so the page comes straight back and the outcome shows up
in the job badge. The product itself is still published in the request: what
moves to the background is the sending, not the state change.

The worker has no request context, so anything request-scoped (the analyst's
identity, external URLs) must be resolved by the caller and closed over.
"""

import logging
import threading

from webapp import audit, job_store

logger = logging.getLogger(__name__)

# Guards the check-then-create below, so two quick clicks on Publish cannot both
# get past the in-flight test and mail every stakeholder twice.
_start_lock = threading.Lock()

_IN_FLIGHT = ("queued", "running")


def _in_flight_for(entity_id: str):
    """A delivery already running for this product, if there is one."""
    for job in job_store.list_jobs():
        if job.get("entity") == entity_id and job.get("status") in _IN_FLIGHT:
            return job
    return None


def start(action: str, label: str, deliver, *, entity_type: str, entity_id: str,
          entity_label: str, user: str) -> dict:
    """Run `deliver` on a worker thread, reporting through the job store.

    `deliver(log)` is given a callable for progress lines and returns an
    (ok, detail) pair, the same shape dispatcher.delivery_outcome() produces.

    A product already being delivered is not sent again: the job in flight is
    returned instead, so a double-clicked Publish button cannot notify every
    stakeholder twice.
    """
    with _start_lock:
        running = _in_flight_for(entity_id)
        if running is not None:
            logger.info("Delivery for %s already running; not starting a second", entity_label)
            return running
        job = job_store.create_job(action, label=label)
        job_store.update_job(job["id"], entity=entity_id)

    threading.Thread(
        target=_deliver,
        args=(job["id"], deliver, entity_type, entity_id, entity_label, user),
        daemon=True,
        name=f"notify-{action}",
    ).start()
    return job


def start_preview(action: str, label: str, send, *, entity_type: str, entity_id: str,
                  entity_label: str, user: str) -> dict:
    """Background job for a requirement or RFI preview send.

    `send()` returns a dispatcher summary; the wording comes from the shared
    delivery_outcome(), so a preview reads like any other delivery instead of
    each caller phrasing "sent"/"nothing sent" its own way.
    """
    def deliver(log):
        from notifier import dispatcher

        summary = send()
        ok, detail = dispatcher.delivery_outcome(summary)
        log(f"{summary.get('recipients', 0)} recipient(s): {detail}.")
        return ok, detail

    return start(action, label, deliver, entity_type=entity_type, entity_id=entity_id,
                 entity_label=entity_label, user=user)


def to_channels(send, log):
    """Dispatch to the message channels and report (ok, detail).

    For deliveries that carry on afterwards (Flowintel), where a dead SMTP host
    must not cost the product its case. Deliveries with nothing following let the
    exception reach the job runner, which words the failure more precisely.
    """
    from notifier import dispatcher

    try:
        ok, detail = dispatcher.delivery_outcome(send())
        log(f"Channels: {detail}.")
        return ok, detail
    except Exception as exc:
        logger.warning("Channel delivery failed: %s", exc)
        log(f"Channel delivery failed: {exc}")
        return False, "delivery error (see the application log)"


def to_flowintel(stakeholders, product_name: str, send_fn, log) -> None:
    """Create a Flowintel case on every eligible instance, logging each outcome."""
    from core import flowintel_client

    try:
        for instance, result in flowintel_client.send_to_eligible_instances(
                stakeholders, product_name, send_fn):
            name = instance.get("name") or instance.get("id")
            if result["ok"]:
                log(f"Flowintel case {result['case_id']} created on {name}.")
            else:
                log(f"Flowintel case creation on {name} failed: "
                    f"{result.get('error', 'unknown error')}")
    except Exception as exc:
        logger.warning("Flowintel delivery failed for %s: %s", product_name, exc)
        log(f"Flowintel delivery failed: {exc}")


def _deliver(job_id: str, deliver, entity_type: str, entity_id: str,
             entity_label: str, user: str) -> None:
    job_store.update_job(job_id, status="running", message="Sending notifications...")

    # The job log expires with the job; the audit entry is the permanent record,
    # so it carries the same trail (which Flowintel case, which channel failed).
    trail = []

    def log(message: str) -> None:
        trail.append(message)
        job_store.append_log(job_id, message)

    try:
        ok, detail = deliver(log)
    except Exception as exc:
        logger.exception("Notification job %s (%s) failed", job_id, entity_label)
        job_store.update_job(job_id, status="failed", error=str(exc),
                             message=f"Delivery failed: {exc}")
        _record(entity_type, entity_id, entity_label, f"delivery failed: {exc}", user)
        return

    job_store.update_job(
        job_id,
        status="completed" if ok else "failed",
        message=detail,
        error=None if ok else detail,
    )
    _record(entity_type, entity_id, entity_label, "; ".join(trail) or detail, user)


def _record(entity_type: str, entity_id: str, entity_label: str, detail: str, user: str) -> None:
    """Audit the delivery. A failed audit write must not fail the delivery."""
    try:
        audit.record("notify", entity_type, entity_id=entity_id,
                     entity_label=entity_label, details=detail, user=user)
    except Exception:
        logger.exception("Could not audit notification for %s", entity_label)
