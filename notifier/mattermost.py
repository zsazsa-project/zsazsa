import logging
from urllib.parse import urlsplit

import requests
import urllib3

import config
from webapp.utils import normalize_notification_channels

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _notification_channels() -> list[dict]:
    return normalize_notification_channels(
        getattr(config, "NOTIFICATION_CHANNELS", []),
        legacy_url=getattr(config, "MATTERMOST_WEBHOOK_URL", ""),
        legacy_enabled=getattr(config, "MATTERMOST_ENABLED", False),
    )


def _active_webhooks(channel_ids: list | None = None) -> list[dict]:
    """Return webhook URLs for enabled Mattermost channels.

    If channel_ids is provided, only return URLs for those IDs.
    Falls back to the legacy MATTERMOST_WEBHOOK_URL if NOTIFICATION_CHANNELS is absent.
    """
    channels = _notification_channels()
    if channels:
        targets = []
        for ch in channels:
            if ch.get("type") != "mattermost" or not ch.get("enabled"):
                continue
            if channel_ids is not None and ch.get("id") not in channel_ids:
                continue
            url = (ch.get("url") or "").strip()
            if url:
                targets.append({"url": url, "verify_tls": bool(ch.get("verify_tls", True))})
        return targets
    # Legacy fallback
    if getattr(config, "MATTERMOST_ENABLED", False) and getattr(config, "MATTERMOST_WEBHOOK_URL", ""):
        return [{"url": config.MATTERMOST_WEBHOOK_URL, "verify_tls": True}]
    return []


def _webhook_host(url: str) -> str:
    """Name a webhook by its host: the path is the shared secret."""
    parts = urlsplit(url or "")
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else "webhook"


def _without_secret(message: str, url: str) -> str:
    """Strip a webhook's secret path out of a message.

    requests puts the failing URL in its exception text, which for a Mattermost
    webhook is the token itself, and that text goes to the log file.
    """
    path = urlsplit(url or "").path
    for secret in (url, path):
        if secret and len(secret) > 1:
            message = message.replace(secret, "/...")
    return message


def _post(targets: list[dict], payload: dict, label: str) -> bool:
    sent_any = False
    for target in targets:
        url = target.get("url")
        verify_tls = bool(target.get("verify_tls", True))
        try:
            r = requests.post(url, json=payload, timeout=10, verify=verify_tls)
            r.raise_for_status()
            logger.info("Mattermost notification sent (%s) to %s", label, _webhook_host(url))
            sent_any = True
        except requests.RequestException as e:
            logger.error("Mattermost notification failed (%s) to %s: %s",
                         label, _webhook_host(url), _without_secret(str(e), url))
    return sent_any


def send_text(text: str, label: str, channel_ids: list[str] | None = None) -> bool:
    targets = _active_webhooks(channel_ids)
    if not targets:
        return False
    payload = {"text": text}
    return bool(_post(targets, payload, label))


# Room for the "**Part 12/34**\n\n" heading a split message carries, so the
# pieces still fit the budget once it is prepended.
_PART_PREFIX_ALLOWANCE = 24


def _chunk_and_send(urls, body: str, label: str, max_chars: int = 3500) -> bool:
    """Send body to all urls, splitting into chunks if it exceeds max_chars."""
    if len(body) <= max_chars:
        return bool(_post(urls, {"text": body}, label))
    max_chars -= _PART_PREFIX_ALLOWANCE
    paragraphs = body.split("\n\n")
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        candidate = para if not current else f"{current}\n\n{para}"
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            chunks.append(current)
        if len(para) > max_chars:
            start = 0
            while start < len(para):
                chunks.append(para[start:start + max_chars])
                start += max_chars
            current = ""
        else:
            current = para
    if current:
        chunks.append(current)
    all_sent = True
    total = len(chunks)
    for idx, chunk in enumerate(chunks, start=1):
        prefix = f"**Part {idx}/{total}**\n\n" if total > 1 else ""
        ok = _post(urls, {"text": prefix + chunk}, f"{label} part {idx}/{total}")
        all_sent = all_sent and bool(ok)
    return all_sent


def send_product_published(product_type: str, product_id: str, description: str,
                           stakeholders: list) -> bool:
    """Notify that a product has been published. Sends to each subscribed stakeholder's channels."""
    # Collect the union of channel IDs from stakeholders that have preferences set.
    channel_ids = None
    if stakeholders:
        ids: set[str] = set()
        for s in stakeholders:
            for cid in (getattr(s, "notification_channels", None) or []):
                ids.add(cid)
        if ids:
            channel_ids = list(ids)

    urls = _active_webhooks(channel_ids)
    if not urls:
        logger.debug("No active notification channels for product %s", product_id)
        return False

    if stakeholders:
        names = ", ".join(getattr(s, "name", str(s)) for s in stakeholders)
        delivery_line = f"\n**Subscribed stakeholders:** {names}"
    else:
        delivery_line = "\n_No stakeholders currently subscribed to this product type._"

    payload = {
        "text": (
            f"### :page_facing_up: {product_id} published\n"
            f"**Type:** {product_type}\n"
            f"**{description}**"
            f"{delivery_line}"
        )
    }
    return bool(_post(urls, payload, f"product {product_id}"))


def send_pir_notification(
    pir,
    markdown: str,
    preview_url: str = "",
    channel_ids: list[str] | None = None,
    stakeholder_names: list[str] | None = None,
) -> bool:
    """Notify that a PIR has been shared with stakeholders."""
    recipients_line = ""
    if stakeholder_names:
        recipients_line = "\n**Recipients:** " + ", ".join(stakeholder_names)
    preview_line = f"\n[Open PIR preview]({preview_url})" if preview_url else ""
    text = (
        f"### :clipboard: {pir.pir_id} shared\n"
        f"**{pir.question[:120]}**\n\n"
        f"Status: {pir.status} | Priority: {pir.priority}"
        f"{recipients_line}"
        f"{preview_line}"
    )
    return send_text(text, f"PIR {pir.pir_id}", channel_ids=channel_ids)


def send_pir_intake_notification(pir, new_status: str, reason: str = None) -> None:
    """Notify that a PIR's intake status has changed."""
    urls = _active_webhooks()
    if not urls:
        return
    icons = {
        "acknowledged": ":white_check_mark:",
        "triaged": ":mag:",
        "approved": ":tada:",
        "rejected": ":x:",
        "deferred": ":hourglass:",
        "merged": ":twisted_rightwards_arrows:",
    }
    icon = icons.get(new_status, ":clipboard:")
    text = (
        f"### {icon} {pir.pir_id} intake: {new_status}\n"
        f"**{pir.question[:120]}**"
    )
    if reason:
        text += f"\n**Reason:** {reason}"
    _post(urls, {"text": text}, f"PIR intake {pir.pir_id}")


def send_gir_notification(
    gir,
    markdown: str,
    preview_url: str = "",
    channel_ids: list[str] | None = None,
    stakeholder_names: list[str] | None = None,
) -> bool:
    """Notify that a GIR has been shared with stakeholders."""
    recipients_line = ""
    if stakeholder_names:
        recipients_line = "\n**Recipients:** " + ", ".join(stakeholder_names)
    preview_line = f"\n[Open GIR preview]({preview_url})" if preview_url else ""
    text = (
        f"### :clipboard: {gir.gir_id} shared\n"
        f"**{gir.topic[:120]}**\n\n"
        f"Status: {gir.status} | Review cycle: {gir.review_cycle}"
        f"{recipients_line}"
        f"{preview_line}"
    )
    return send_text(text, f"GIR {gir.gir_id}", channel_ids=channel_ids)


def send_daily_briefing_notification(briefing, markdown: str, stakeholders: list | None = None,
                                     channel_ids: list[str] | None = None) -> bool:
    """Send the full Daily Briefing content to the given Mattermost channels.

    `channel_ids` selects the channels directly (used by the dispatcher, which
    owns channel-type routing). When omitted, the Mattermost channels are
    derived from the stakeholders' channel preferences for backwards compatibility.
    """
    if channel_ids is None and stakeholders:
        ids: set[str] = set()
        for s in stakeholders:
            for cid in (getattr(s, "notification_channels", None) or []):
                if cid:
                    ids.add(cid)
        if ids:
            channel_ids = sorted(ids)

    headline = f"### :newspaper: Daily briefing {getattr(briefing, 'date', '')}"
    title = getattr(briefing, "title", "") or ""
    body = f"{headline}\n"
    if title:
        body += f"**{title}**\n\n"
    body += markdown

    label = f"Daily briefing {getattr(briefing, 'date', '')}"
    targets = _active_webhooks(channel_ids)
    return _chunk_and_send(targets, body, label)


def send_indicator_feed_notification(feed, markdown: str, channel_ids: list[str] | None = None) -> bool:
    """Post an indicator feed (summary + values) to the given Mattermost channels."""
    headline = f"### :satellite: {getattr(feed, 'feed_id', '')}: {getattr(feed, 'name', '') or 'Indicator feed'}"
    body = f"{headline}\n{markdown}"
    label = f"Indicator feed {getattr(feed, 'feed_id', '')}"
    targets = _active_webhooks(channel_ids)
    return _chunk_and_send(targets, body, label)


def send_vea_notification(vea, markdown: str, stakeholders: list | None = None,
                          channel_ids: list[str] | None = None) -> bool:
    """Send a detailed VEA notification to subscribed stakeholders.

    `channel_ids` selects the Mattermost channels directly (used by the
    dispatcher). When omitted, they are derived from the stakeholders.
    """
    if channel_ids is None and stakeholders:
        ids: set[str] = set()
        for s in stakeholders:
            for cid in (getattr(s, "notification_channels", None) or []):
                if cid:
                    ids.add(cid)
        if ids:
            channel_ids = sorted(ids)

    headline = f"### :shield: {getattr(vea, 'vea_id', '')}: Vulnerability advisory"
    subtitle = f"**{getattr(vea, 'cve_id', '')}: {getattr(vea, 'title', '')}**".strip()
    body = f"{headline}\n"
    if subtitle and subtitle != "**: **":
        body += f"{subtitle}\n\n"
    body += markdown

    targets = _active_webhooks(channel_ids)
    return _chunk_and_send(targets, body, f"VEA {getattr(vea, 'vea_id', '')}")


def send_threat_actor_profile_notification(tap, markdown: str, stakeholders: list | None = None,
                                           channel_ids: list[str] | None = None,
                                           diamond_url: str | None = None) -> bool:
    """Send a threat actor profile notification to subscribed stakeholders.

    When `diamond_url` is given, the Diamond Model image is posted as a webhook
    message attachment (Mattermost fetches it by URL, so the URL must be reachable
    from the Mattermost server)."""
    if channel_ids is None and stakeholders:
        ids: set[str] = set()
        for s in stakeholders:
            for cid in (getattr(s, "notification_channels", None) or []):
                if cid:
                    ids.add(cid)
        if ids:
            channel_ids = sorted(ids)

    headline = f"### :detective: {getattr(tap, 'tap_id', '')}: Threat actor profile"
    subtitle = f"**{getattr(tap, 'title', '')}**".strip()
    body = f"{headline}\n"
    if subtitle and subtitle != "****":
        body += f"{subtitle}\n\n"
    body += markdown

    label = f"threat actor profile {getattr(tap, 'tap_id', '')}"
    targets = _active_webhooks(channel_ids)
    ok = _chunk_and_send(targets, body, label)
    if diamond_url:
        payload = {"attachments": [{"title": "Diamond Model", "image_url": diamond_url}]}
        ok = bool(_post(targets, payload, f"{label} diamond")) and ok
    return ok


def send_rfi_notification(
    rfi,
    markdown: str,
    preview_url: str = "",
    channel_ids: list[str] | None = None,
    stakeholder_names: list[str] | None = None,
) -> bool:
    recipients_line = ""
    if stakeholder_names:
        recipients_line = "\n**Recipients:** " + ", ".join(stakeholder_names)
    preview_line = f"\n[Open RFI preview]({preview_url})" if preview_url else ""
    requester = getattr(rfi, "requester_name", "") or "Unknown requester"
    text = (
        f"### :incoming_envelope: {rfi.rfi_id} received\n"
        f"**{(getattr(rfi, 'question', '') or '')[:120]}**\n\n"
        f"Requester: {requester} | Priority: {rfi.priority} | Status: {rfi.status}"
        f"{recipients_line}"
        f"{preview_line}"
    )
    return send_text(text, f"RFI {rfi.rfi_id}", channel_ids=channel_ids)


def send_flash_intel_alert(product_event, fia_id: str, fia_content: str,
                           stakeholders: list | None = None,
                           channel_ids: list[str] | None = None) -> bool:
    """Send the full Flash Intel Alert report to subscribed stakeholders' Mattermost channels.

    `channel_ids` selects the Mattermost channels directly (used by the
    dispatcher). When omitted, they are derived from the stakeholders.
    """
    if channel_ids is None and stakeholders:
        ids: set[str] = set()
        for s in stakeholders:
            for cid in (getattr(s, "notification_channels", None) or []):
                if cid:
                    ids.add(cid)
        if ids:
            channel_ids = sorted(ids)

    urls = _active_webhooks(channel_ids)
    if not urls:
        return False
    misp_url = f"{config.MISP_WEBAPP_URL}/events/view/{product_event.id}"
    body = (
        f":rotating_light: **{fia_id}: Flash Intel Alert**\n\n"
        + fia_content
        + f"\n\n---\n[Open in MISP]({misp_url})"
    )
    return _chunk_and_send(urls, body, fia_id)
