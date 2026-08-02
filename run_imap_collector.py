"""Poll configured IMAP mailboxes for newsletter e-mails and ingest them.

For each enabled mailbox in config.IMAP_SOURCES, fetch unprocessed messages that
match the mailbox's subject/sender criteria, parse them with the configured
newsletter parser, and archive each as a MISP event. In 'auto' mode the article
URLs are pushed to the misp-scraper queue immediately; in 'manual' mode the
newsletter is left in the pending-review queue for a human to approve. A message
is only marked processed in the mailbox once it has been archived, so a failure
simply retries on the next run.

Run from cron, e.g. every 15 minutes:
    */15 * * * * cd /path/to/zsazsa && venv/bin/python run_imap_collector.py
"""

import logging

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import config
from core.logging_setup import setup_logging
from core import imap_collector
from core.db import init_db, log_pipeline_run_start, log_pipeline_run_end
from webapp import job_store, misp_store, newsletter_ingest, newsletter_parsers

logger = logging.getLogger(__name__)




def _ingest_message(source: dict, body: str) -> None:
    """Parse and archive one e-mail for a collection source; push in auto mode.

    The source's name becomes the scraper feed, so the events created from its
    articles carry it as their data-collection-source and stay countable.
    """
    feed = source["name"]
    parser = source["parser"]
    parsed = newsletter_parsers.parse(parser, body)
    report_title = parsed.get("report_title", "")
    tlp = parsed.get("tlp") or ""
    reliability = source.get("reliability", "")
    articles = newsletter_ingest.articles_from_parsed(parsed)

    # Manual mode, or nothing parsed, leaves the newsletter for human review.
    if source.get("mode", "auto") == "manual" or not articles:
        misp_store.create_newsletter_event(
            feed, body, report_title=report_title, tlp=tlp,
            reliability=reliability, parser=parser, status="pending-review",
        )
        logger.info("%s: archived newsletter for review (%d article(s))",
                    feed, len(articles))
        return

    uuid = misp_store.create_newsletter_event(
        feed, body, report_title=report_title, tlp=tlp, reliability=reliability,
        parser=parser, article_urls=[a["url"] for a in articles],
    )
    counts = newsletter_ingest.publish_articles(feed, articles)
    # Redis pub/sub is fire-and-forget: if no subscriber received the push, fall
    # back to the review queue so nothing is silently lost.
    if counts["published"] == 0 or counts["no_subscriber"] == counts["published"]:
        misp_store.mark_newsletter_pending(uuid)
        logger.warning("%s: scraper not listening, left newsletter %s for review",
                       feed, uuid)
    else:
        logger.info("%s: pushed %d/%d article(s) to scraper",
                    feed, counts["published"], len(articles))


def _match_source(msg, sources: list) -> dict | None:
    """Return the first collection source whose criteria match the message."""
    for source in sources:
        if imap_collector.matches(msg, source.get("subjects") or [], source.get("senders") or []):
            return source
    return None


def _poll_mailbox(mailbox: dict) -> dict:
    """Poll one mailbox; return {"processed", "status", "message"} for reporting."""
    name = mailbox.get("name") or mailbox.get("id") or "mailbox"
    available = newsletter_parsers.available_sources()
    sources = [s for s in (mailbox.get("sources") or [])
               if s.get("enabled", True) and s.get("parser") in available]
    if not sources:
        logger.warning("%s: no usable collection sources, skipping", name)
        return {"processed": 0, "status": "skipped", "message": "no usable collection sources"}
    handled = 0
    for conn, uid, msg in imap_collector.fetch_unprocessed(mailbox):
        source = _match_source(msg, sources)
        if source is None:
            continue  # not for any source in this mailbox; leave it untouched
        body = imap_collector.extract_body(msg)
        if not body.strip():
            logger.warning("%s: a matched message had no readable body, skipping", name)
            imap_collector.mark_processed(conn, uid)
            continue
        try:
            _ingest_message(source, body)
        except Exception:
            logger.exception("%s: failed to ingest a message, will retry next run", name)
            continue
        imap_collector.mark_processed(conn, uid)
        handled += 1
    logger.info("%s: processed %d new message(s)", name, handled)
    return {"processed": handled, "status": "ok", "message": f"{handled} message(s) ingested"}


def main() -> None:
    setup_logging()
    logger.info("IMAP collector started")
    init_db()
    run_id = log_pipeline_run_start("imap-collector", triggered_by="cli")

    mailboxes = [m for m in getattr(config, "IMAP_SOURCES", []) or [] if m.get("enabled")]
    if not mailboxes:
        logger.info("No enabled IMAP mailboxes configured")
        log_pipeline_run_end(run_id, "completed", {"message": "No enabled mailboxes configured", "mailboxes": []})
        return

    # Registered as a job as well, so a scheduled poll is visible in the web app
    # while it is going, not only in the history once it has finished.
    job = job_store.create_job("imap-collector", label="Mailbox poll")
    job_store.update_job(job["id"], status="running", message=f"Polling {len(mailboxes)} mailbox(es)")

    records = []
    for mailbox in mailboxes:
        record = {"id": mailbox.get("id"), "name": mailbox.get("name") or mailbox.get("id")}
        job_store.update_job(job["id"], message=f"Polling {record['name']}")
        try:
            record.update(_poll_mailbox(mailbox))
        except Exception as exc:
            record.update({"processed": 0, "status": "failed", "message": str(exc)})
            logger.error("Mailbox %s failed: %s", record["name"], exc)
        records.append(record)

    processed = sum(r["processed"] for r in records)
    failures = sum(1 for r in records if r["status"] == "failed")
    message = f"{processed} message(s) ingested from {len(mailboxes)} mailbox(es)"
    if failures:
        message += f", {failures} mailbox(es) failed"
    result = {"message": message, "mailboxes": records}
    log_pipeline_run_end(run_id, "failed" if failures else "completed", result)
    if processed or failures:
        job_store.update_job(job["id"], status="failed" if failures else "completed",
                             result=result, message=message)
    else:
        # Most polls find an empty mailbox. Those are in the run history, but
        # they have nothing to say to someone watching the job badge.
        job_store.forget_job(job["id"])
    logger.info("IMAP collector finished: %s", message)


if __name__ == "__main__":
    main()
