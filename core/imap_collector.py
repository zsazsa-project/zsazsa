"""Read newsletter e-mails from an IMAP mailbox.

Connects to a configured mailbox, finds unprocessed messages that match the
mailbox's subject or sender criteria, and returns their plain-text body for the
newsletter parser. Processed messages are marked with a dedicated IMAP keyword
(plus Seen and Flagged as a visible cue) so they are never picked up twice.

Only stdlib imaplib/email are used. Nothing here deletes mail.
"""

import email
import imaplib
import logging
import re
import ssl as ssl_module
from email.header import decode_header, make_header
from email.message import Message

from markdownify import markdownify

logger = logging.getLogger(__name__)

# imaplib's default IMAP4_SSL context is ssl._create_stdlib_context(), which
# verifies neither the certificate nor the hostname. The collector logs in with
# stored mailbox credentials, so it builds a verifying context instead.
_TIMEOUT_SECONDS = 30


def _imap_connect(host: str, port: int, use_ssl: bool) -> imaplib.IMAP4:
    if use_ssl:
        return imaplib.IMAP4_SSL(host, port, ssl_context=ssl_module.create_default_context(),
                                 timeout=_TIMEOUT_SECONDS)
    return imaplib.IMAP4(host, port, timeout=_TIMEOUT_SECONDS)

# Authoritative "already ingested" marker. A dedicated keyword is used instead of
# \Seen so that a human opening the mailbox cannot cause messages to be skipped
# or reprocessed.
PROCESSED_KEYWORD = "zsazsaProcessed"

_FORWARD_RE = re.compile(r"^\s*-+\s*Forwarded message\s*-+\s*$", re.IGNORECASE | re.MULTILINE)
_FORWARD_HEADER_RE = re.compile(r"^(From|Date|Subject|To|Sent|Cc|Reply-To):", re.IGNORECASE)
_BODY_FROM_RE = re.compile(r"^\s*From:\s*(.+)$", re.IGNORECASE)
# Leading e-mail quote marker, as Apple Mail and others add when forwarding ("> ").
_QUOTE_RE = re.compile(r"^>+ ?")


def _decode_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except (ValueError, UnicodeDecodeError):
        return value


def _part_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _strip_forward_preamble(text: str) -> str:
    """Remove a forwarded-message header block, keeping the original newsletter body.

    Gmail (and most clients) prefix a forwarded mail with a
    "---------- Forwarded message ----------" line followed by From/Date/Subject/To.
    Those belong to the forward, not the newsletter, so they are dropped.
    """
    match = _FORWARD_RE.search(text)
    if not match:
        return text
    lines = text[match.end():].splitlines()
    i = 0
    while i < len(lines) and (not lines[i].strip() or _FORWARD_HEADER_RE.match(lines[i].strip())):
        i += 1
    return "\n".join(lines[i:])


def _body_text(msg: Message) -> str:
    """Return the message's text, preferring text/plain, else HTML converted to text.

    This is the raw body, including any forwarded-message preamble; use it for
    matching. extract_body() strips that preamble for parsing.
    """
    plain = None
    html = None
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        if "attachment" in (part.get("Content-Disposition") or "").lower():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and plain is None:
            plain = _part_text(part)
        elif ctype == "text/html" and html is None:
            html = _part_text(part)

    if plain and plain.strip():
        return plain
    if html and html.strip():
        return markdownify(html)
    return ""


def extract_body(msg: Message) -> str:
    """Return the newsletter body for parsing, with any forward preamble removed."""
    return _strip_forward_preamble(_body_text(msg))


def _candidate_senders(msg: Message) -> list[str]:
    """Sender strings to match against: the From header plus any From: line in the
    forwarded body (the original sender is there once a mail has been forwarded)."""
    candidates = [_decode_header(msg.get("From", ""))]
    for line in _body_text(msg).splitlines()[:40]:
        m = _BODY_FROM_RE.match(_QUOTE_RE.sub("", line))
        if m:
            candidates.append(m.group(1).strip())
    return [c for c in candidates if c]


def matches(msg: Message, subjects: list[str], senders: list[str]) -> bool:
    """True if the message matches any configured subject or sender substring.

    Matching is case-insensitive substring. With no criteria set at all, every
    message matches (the folder itself is the filter).
    """
    subjects = [s.strip().lower() for s in subjects if s.strip()]
    senders = [s.strip().lower() for s in senders if s.strip()]
    if not subjects and not senders:
        return True
    subject = _decode_header(msg.get("Subject", "")).lower()
    if any(s in subject for s in subjects):
        return True
    candidates = [c.lower() for c in _candidate_senders(msg)]
    return any(any(s in c for c in candidates) for s in senders)


def _connect(mailbox: dict) -> imaplib.IMAP4:
    host = (mailbox.get("host") or "").strip()
    use_ssl = bool(mailbox.get("ssl", True))
    port = int(mailbox.get("port") or (993 if use_ssl else 143))
    conn = _imap_connect(host, port, use_ssl)
    conn.login(mailbox.get("username") or "", mailbox.get("password") or "")
    return conn


def _search_unprocessed(conn: imaplib.IMAP4) -> list[bytes]:
    """UIDs of messages without the processed keyword.

    Falls back to UNSEEN on servers that do not support keyword searches.
    """
    typ, data = "NO", None
    try:
        typ, data = conn.uid("search", None, "UNKEYWORD", PROCESSED_KEYWORD)
    except imaplib.IMAP4.error:
        typ = "NO"
    if typ != "OK":
        typ, data = conn.uid("search", None, "UNSEEN")
    if typ != "OK" or not data or not data[0]:
        return []
    return data[0].split()


def fetch_unprocessed(mailbox: dict):
    """Yield (conn, uid, msg) for every unprocessed message in the mailbox.

    Matching is left to the caller: a mailbox holds several collection sources,
    each with its own criteria, so the caller decides which source (if any) a
    message belongs to. The connection is kept open and yielded so the caller can
    mark each message processed only after it has been ingested successfully.
    """
    conn = _connect(mailbox)
    try:
        conn.select(mailbox.get("folder") or "INBOX")
        for uid in _search_unprocessed(conn):
            typ, data = conn.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not data or not data[0]:
                continue
            yield conn, uid, email.message_from_bytes(data[0][1])
    finally:
        try:
            conn.close()
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass


def mark_processed(conn: imaplib.IMAP4, uid: bytes) -> None:
    """Flag a message as ingested: processed keyword, plus Seen and Flagged."""
    conn.uid("store", uid, "+FLAGS", f"({PROCESSED_KEYWORD} \\Seen \\Flagged)")


def test_connection(host: str, port, ssl: bool, username: str, password: str,
                    folder: str = "INBOX") -> dict:
    """Check that the mailbox can be opened. Returns {"ok": bool, "error": str}."""
    if not host:
        return {"ok": False, "error": "IMAP host is required"}
    try:
        port = int(port or (993 if ssl else 143))
        conn = _imap_connect(host, port, ssl)
        try:
            conn.login(username, password)
            typ, _ = conn.select(folder or "INBOX", readonly=True)
            if typ != "OK":
                return {"ok": False, "error": f"Cannot open folder {folder!r}"}
            return {"ok": True}
        finally:
            try:
                conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
    except (imaplib.IMAP4.error, OSError) as e:
        return {"ok": False, "error": str(e)}
