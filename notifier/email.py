import logging
import smtplib
import ssl
from contextlib import contextmanager
from email.message import EmailMessage

import config
from notifier import product_email
from webapp import branding
from webapp.utils import normalize_notification_channels

logger = logging.getLogger(__name__)


@contextmanager
def _smtp_session(host: str, port: int, use_tls: bool, username: str, password: str):
    """Open an authenticated SMTP session, closed automatically on exit.

    starttls() defaults to ssl._create_stdlib_context(), which checks neither the
    certificate nor the hostname, and the login below would hand the credentials
    straight to whoever answered. Pass a verifying context instead.
    """
    with smtplib.SMTP(host, port or 587, timeout=20) as server:
        if use_tls:
            server.starttls(context=ssl.create_default_context())
        if username:
            server.login(username, password)
        yield server


def _settings() -> dict:
    """SMTP server settings, shared by all email channels."""
    return {
        "host": (getattr(config, "SMTP_HOST", "") or "").strip(),
        "port": int(getattr(config, "SMTP_PORT", 587) or 587),
        "use_tls": bool(getattr(config, "SMTP_USE_TLS", True)),
        "username": (getattr(config, "SMTP_USERNAME", "") or "").strip(),
        "password": getattr(config, "SMTP_PASSWORD", "") or "",
        "sender": (getattr(config, "SMTP_FROM", "") or "").strip(),
    }


def _recipients(channel_ids: list | None = None) -> list[str]:
    """Resolve enabled email channels to recipient addresses.

    If channel_ids is given, only those channels are considered; otherwise all
    enabled email channels are used. Addresses are de-duplicated.
    """
    channels = normalize_notification_channels(getattr(config, "NOTIFICATION_CHANNELS", []))
    seen: set[str] = set()
    recipients: list[str] = []
    for ch in channels:
        if (ch.get("type") or "").strip().lower() != "email" or not ch.get("enabled"):
            continue
        if channel_ids is not None and ch.get("id") not in channel_ids:
            continue
        addr = (ch.get("recipient") or "").strip()
        if addr and addr not in seen:
            seen.add(addr)
            recipients.append(addr)
    return recipients


def test_connection(host: str, port: int, use_tls: bool, username: str, password: str) -> dict:
    """Check SMTP connectivity and, if a username is given, authentication.

    Does not send any mail. Returns {"ok": bool, "error": str} for the UI.
    """
    if not host:
        return {"ok": False, "error": "SMTP host is required"}
    try:
        with _smtp_session(host, port, use_tls, username, password):
            pass
        return {"ok": True}
    except (smtplib.SMTPException, OSError) as e:
        return {"ok": False, "error": str(e)}


def _attach_logo(msg: EmailMessage, body_html: str) -> None:
    """Attach the brand logo as a related part when the HTML body references it.

    Mail clients block data: URIs in images, so the header logo travels as a
    Content-ID part alongside the HTML alternative.
    """
    if f"cid:{product_email.LOGO_CID}" not in body_html:
        return
    logo = branding.logo_bytes()
    if not logo:
        return
    data, maintype, subtype = logo
    msg.get_payload()[-1].add_related(
        data, maintype=maintype, subtype=subtype, cid=f"<{product_email.LOGO_CID}>"
    )


def _subject(tlp: str, rest: str) -> str:
    """Build the subject line for a product notification.

    Recipients (and their mail rules) should be able to tell how a product may be
    handled without opening it, so the TLP sits in the subject next to the tag.
    Requirements carry no TLP and get the tag alone.
    """
    tlp = (tlp or "").strip()
    return f"[CTI] TLP:{tlp.upper()} - {rest}" if tlp else f"[CTI] {rest}"


def send_email(recipients: list[str], subject: str, markdown: str, label: str,
               attachments: list[tuple] | None = None, html_body: str | None = None) -> bool:
    """Send one multipart (plaintext + HTML) email to the given recipients.

    `markdown` is the plaintext alternative; `html_body` is the branded HTML the
    product senders build, and falls back to a rendering of the markdown for
    callers that have none (the config page's channel test).
    `attachments` is an optional list of (filename, bytes, maintype, subtype)
    tuples, e.g. ("feed.csv", b"...", "text", "csv") or ("d.png", b"...", "image", "png").
    """
    if not recipients:
        logger.debug("No email recipients for %s", label)
        return False
    cfg = _settings()
    if not cfg["host"] or not cfg["sender"]:
        logger.error("SMTP not configured (host/from missing) - cannot send %s", label)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["sender"]
    # With several recipients, keep their addresses private from one another: the
    # visible To is the sender and delivery happens via the explicit list below.
    msg["To"] = recipients[0] if len(recipients) == 1 else cfg["sender"]
    msg.set_content(markdown or "")
    body_html = html_body or product_email.markdown_html(markdown, "Notification")
    msg.add_alternative(body_html, subtype="html")
    _attach_logo(msg, body_html)
    for filename, data, maintype, subtype in attachments or []:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    try:
        with _smtp_session(cfg["host"], cfg["port"], cfg["use_tls"], cfg["username"], cfg["password"]) as server:
            server.send_message(msg, to_addrs=recipients)
        logger.info("Email notification sent (%s) to %d recipient(s)", label, len(recipients))
        return True
    except (smtplib.SMTPException, OSError) as e:
        logger.error("Email notification failed (%s): %s", label, e)
        return False


# Per-product senders. The markdown already carries the product content (and any
# preview link); each builds a subject line and the branded HTML body for its
# product type. Signatures match the calls the dispatcher makes.

def send_pir_notification(pir, markdown: str, channel_ids: list[str] | None = None) -> bool:
    subject = _subject("", f"{pir.pir_id}: {(getattr(pir, 'question', '') or '')[:80]}")
    html = product_email.markdown_html(markdown, "Priority Intelligence Requirement")
    return send_email(_recipients(channel_ids), subject, markdown, f"PIR {pir.pir_id}", html_body=html)


def send_gir_notification(gir, markdown: str, channel_ids: list[str] | None = None) -> bool:
    subject = _subject("", f"{gir.gir_id}: {(getattr(gir, 'topic', '') or '')[:80]}")
    html = product_email.markdown_html(markdown, "General Intelligence Requirement")
    return send_email(_recipients(channel_ids), subject, markdown, f"GIR {gir.gir_id}", html_body=html)


def send_rfi_notification(rfi, markdown: str, channel_ids: list[str] | None = None) -> bool:
    tlp = getattr(rfi, "deliverable_tlp", "") or ""
    subject = _subject(tlp, f"{rfi.rfi_id}: {(getattr(rfi, 'question', '') or '')[:80]}")
    html = product_email.markdown_html(markdown, "Request for Information", tlp)
    return send_email(_recipients(channel_ids), subject, markdown, f"RFI {rfi.rfi_id}", html_body=html)


def send_daily_briefing_notification(briefing, markdown: str, channel_ids: list[str] | None = None,
                                     preview_url: str = "") -> bool:
    date = getattr(briefing, "date", "")
    title = getattr(briefing, "title", "") or ""
    rest = f"Daily briefing {date}" + (f": {title}" if title else "")
    subject = _subject(getattr(briefing, "tlp", ""), rest)
    html = product_email.briefing_html(briefing, preview_url)
    return send_email(_recipients(channel_ids), subject, markdown, f"Daily briefing {date}", html_body=html)


def send_vea_notification(vea, markdown: str, channel_ids: list[str] | None = None) -> bool:
    vea_id = getattr(vea, "vea_id", "")
    descriptor = ", ".join(p for p in (getattr(vea, "cve_id", ""), getattr(vea, "title", "")) if p)
    tlp = getattr(vea, "tlp", "")
    subject = _subject(tlp, f"{vea_id}: {descriptor}" if descriptor else vea_id)
    html = product_email.markdown_html(markdown, "Vulnerability Advisory", tlp)
    return send_email(_recipients(channel_ids), subject, markdown, f"VEA {vea_id}", html_body=html)


def send_threat_actor_profile_notification(tap, markdown: str, channel_ids: list[str] | None = None,
                                           diamond_png: bytes | None = None) -> bool:
    tap_id = getattr(tap, "tap_id", "")
    title = getattr(tap, "title", "")
    tlp = getattr(tap, "tlp", "")
    subject = _subject(tlp, f"{tap_id}: {title}" if title else tap_id)
    html = product_email.markdown_html(markdown, "Threat Actor Profile", tlp)
    attachments = [("diamond-model.png", diamond_png, "image", "png")] if diamond_png else None
    return send_email(_recipients(channel_ids), subject, markdown,
                      f"threat actor profile {tap_id}", attachments, html_body=html)


def send_flash_intel_alert(fia, content: str, channel_ids: list[str] | None = None,
                           attachments: list[tuple] | None = None) -> bool:
    """Send a flash intel alert e-mail using the FIA object as source of truth.

    Subject and badge both come from the product metadata rather than from parsing
    the markdown, which the analyser has a model write and which may leave the
    classification line out. Files attached to the alert ride along with the
    e-mail; the content already names them for the channels that cannot carry files.
    """
    fia_id = getattr(fia, "fia_id", "") or "FIA"
    tlp = getattr(fia, "tlp", "") or ""
    subject = _subject(tlp, f"{fia_id}: Flash Intel Alert")
    html = product_email.markdown_html(content, "Flash Intel Alert", tlp)
    return send_email(_recipients(channel_ids), subject, content, fia_id,
                      attachments, html_body=html)


def send_indicator_feed_notification(feed, markdown: str, channel_ids: list[str] | None = None,
                                     csv_bytes: bytes | None = None) -> bool:
    feed_id = getattr(feed, "feed_id", "")
    name = getattr(feed, "name", "") or ""
    tlp = getattr(feed, "tlp", "")
    subject = _subject(tlp, f"{feed_id}: {name}" if name else feed_id)
    html = product_email.markdown_html(markdown, "Indicator Feed", tlp)
    attachments = None
    if csv_bytes:
        slug = (name or feed_id or "indicator-feed").lower().replace(" ", "-")
        attachments = [(f"{slug}.csv", csv_bytes, "text", "csv")]
    return send_email(_recipients(channel_ids), subject, markdown,
                      f"Indicator feed {feed_id}", attachments, html_body=html)
