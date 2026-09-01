"""Shared request-parsing and config-normalization utilities."""

import ast
import re
from datetime import datetime

import config
from flask import jsonify, request
from markdown_it import MarkdownIt
from werkzeug.routing import BuildError

# breaks=True renders single newlines as <br>, matching the client-side preview
# (marked with breaks:true) so multi-line fields like observed facts look the same
# in the on-screen preview, the PDF and e-mail.
_md = MarkdownIt("commonmark", {"breaks": True}).enable("table")

# A label opening a line, as briefing stories write them ("What happened: ...").
# Only plain words count, so a colon inside a sentence or an indicator such as
# "CVE-2024-1234:" is left alone.
_LEAD_LABEL_RE = re.compile(r"(<p>|<br\s*/?>)(\s*)([A-Za-z][A-Za-z ]{1,33}:)(?=\s)")


def md_to_html(text: str) -> str:
    """Render Markdown to HTML for server-side contexts (e.g. PDF generation)."""
    return _md.render(text or "")


def md_to_html_inline(text: str) -> str:
    """Render Markdown to inline HTML (no wrapping block element).

    For short, single-value fields shown inside a sentence or list item, where a
    wrapping <p> would break the layout but inline markdown (links, bold, code,
    line breaks) should still render.
    """
    return _md.renderInline(text or "")


def mute_lead_labels(html: str, open_tag: str = '<span class="pretext">') -> str:
    """Set the "Label:" opening a line back from the content it introduces.

    Briefing stories write those labels as plain prose, so unlike the bold
    labels in product markdown there is no tag to match; the substitution runs
    on the rendered HTML instead. E-mail passes an inline-styled span, having no
    stylesheet to carry the class.
    """
    return _LEAD_LABEL_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{open_tag}{m.group(3)}</span>", html or "")


def human_size(size) -> str:
    """Format a byte count for a reader, e.g. 20841 -> "20.4 KB"."""
    try:
        value = float(size)
    except (TypeError, ValueError):
        return "unknown size"
    if value < 1024:
        return f"{value:.0f} B"
    for unit in ("KB", "MB"):
        value /= 1024
        if value < 1024:
            return f"{value:.1f} {unit}"
    return f"{value / 1024:.1f} GB"


def dedup_lower(values: list) -> list:
    """Deduplicate strings case-insensitively, keeping first-occurrence casing.

    Galaxy-backed scope fields arrive from the form with whatever casing the
    picker used, so the same country can appear twice.
    """
    seen = set()
    result = []
    for value in values:
        key = (value or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            result.append(value.strip())
    return result


def json_body():
    """Parse the request body as a JSON object.

    Returns (dict, None) on success, or (None, flask-response-tuple) on failure.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, (jsonify({"ok": False, "error": "Invalid JSON payload."}), 400)
    return body, None


def parse_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value in (0, 1):
            return bool(value)
        raise ValueError("Boolean values must be true/false.")
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "on"}:
            return True
        if v in {"false", "0", "no", "off"}:
            return False
    raise ValueError("Boolean values must be true/false.")


def normalize_notification_channels(
    raw_channels,
    *,
    legacy_url: str = "",
    legacy_enabled: bool = False,
) -> list[dict]:
    """Return notification channel config in a consistent list-of-dicts form."""
    channels = []

    if isinstance(raw_channels, dict):
        channels = [raw_channels]
    elif isinstance(raw_channels, (list, tuple)):
        channels = [c for c in raw_channels if isinstance(c, dict)]
    elif isinstance(raw_channels, str) and raw_channels.strip():
        try:
            parsed = ast.literal_eval(raw_channels)
        except (SyntaxError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            channels = [parsed]
        elif isinstance(parsed, list):
            channels = [c for c in parsed if isinstance(c, dict)]

    if not channels and legacy_url:
        channels = [{
            "id": "mattermost-default",
            "name": "Mattermost",
            "type": "mattermost",
            "url": legacy_url,
            "enabled": bool(legacy_enabled),
        }]

    normalized = []
    for channel in channels:
        item = dict(channel)
        item.setdefault("verify_tls", True)
        normalized.append(item)
    return normalized


_PRODUCT_SORT_KEYS = {
    "title": lambda p: (getattr(p, "title", "") or "").lower(),
    "state": lambda p: (getattr(p, "review_state", "") or getattr(p, "status", "") or ""),
    "date": lambda p: getattr(p, "published_at", None) or datetime.min,
    "bdate": lambda p: (getattr(p, "date", "") or ""),
    # Product id: FIAs, VEAs and TAPs use a zero-padded "<TYPE>-NNNNN" so a plain
    # string sort orders them numerically.
    "id": lambda p: (getattr(p, "fia_id", "") or getattr(p, "vea_id", "") or getattr(p, "tap_id", "") or ""),
    "cve": lambda p: (getattr(p, "cve_id", "") or "").upper(),
}


def sort_products(items: list, sort: str, direction: str) -> list:
    """Sort a product list in place by 'title', 'state', 'date' (published) or
    'bdate' (briefing date). Unknown keys leave the existing order untouched."""
    key = _PRODUCT_SORT_KEYS.get(sort)
    if key:
        items.sort(key=key, reverse=(direction == "desc"))
    return items


_PRODUCT_TAG_PREFIX = 'zsazsa:ctiproduct='
_PRODUCT_TYPE_CONFIG = {
    "Flash intel alert": {"config_attr": "TAG_FLASH_INTEL", "fallback": "flash-intel", "endpoint": "flash_intel.detail"},
    "Vulnerability advisory": {"config_attr": "TAG_VEA", "fallback": "vea", "endpoint": "vea.detail"},
    "Daily threat briefing": {"config_attr": "TAG_BRIEFING", "fallback": "daily-briefing", "endpoint": "daily_briefing.detail"},
    "Threat landscape report": {"config_attr": "TAG_TLR", "fallback": "threat-landscape-report", "endpoint": "threat_landscape.detail"},
    "Indicator feed": {"config_attr": "TAG_INDICATOR_FEED", "fallback": "indicator-feed", "endpoint": "indicator_feed.detail"},
    "Threat actor profile": {"config_attr": "TAG_THREAT_ACTOR_PROFILE", "fallback": "threat-actor-profile", "endpoint": "threat_actor_profile.detail"},
}
_PRODUCT_TYPE_ALIASES = {
    "flash-intel": "Flash intel alert",
    "vea": "Vulnerability advisory",
    "vulnerability exploitation advisory": "Vulnerability advisory",
    "daily-briefing": "Daily threat briefing",
    "threat-landscape-report": "Threat landscape report",
    "indicator-feed": "Indicator feed",
    "threat-actor-profile": "Threat actor profile",
}


def _normalized_product_type(value: str) -> str:
    return (value or "").strip().lower()


def _configured_product_tag_value(config_attr: str, fallback: str) -> str:
    raw = str(getattr(config, config_attr, "") or "").strip()
    if raw.startswith(_PRODUCT_TAG_PREFIX):
        return raw.split("=", 1)[1].strip().strip('"')
    return fallback


def product_type_tag_value(product_type: str) -> str:
    value = (product_type or "").strip()
    if not value:
        return ""
    wanted = _normalized_product_type(value)
    for label, meta in _PRODUCT_TYPE_CONFIG.items():
        tag_value = _configured_product_tag_value(meta["config_attr"], meta["fallback"])
        if wanted in {_normalized_product_type(label), _normalized_product_type(tag_value)}:
            return tag_value
    return value


def product_type_label(product_type: str) -> str:
    value = (product_type or "").strip()
    if not value:
        return ""
    wanted = _normalized_product_type(value)
    wanted = _normalized_product_type(_PRODUCT_TYPE_ALIASES.get(wanted, wanted))
    for label, meta in _PRODUCT_TYPE_CONFIG.items():
        tag_value = _configured_product_tag_value(meta["config_attr"], meta["fallback"])
        if wanted in {_normalized_product_type(label), _normalized_product_type(tag_value)}:
            return label
    return value


def product_detail_url(product_type: str, entity_id: str, fallback_url: str = "") -> str:
    """Return the app-detail URL for a known CTI product type.

    Falls back to the provided URL (typically the MISP event URL) when no
    dedicated app detail page exists for that product type.
    """
    from flask import url_for

    endpoint = None
    wanted = _normalized_product_type(product_type)
    wanted = _normalized_product_type(_PRODUCT_TYPE_ALIASES.get(wanted, wanted))
    for label, meta in _PRODUCT_TYPE_CONFIG.items():
        tag_value = _configured_product_tag_value(meta["config_attr"], meta["fallback"])
        if wanted in {_normalized_product_type(label), _normalized_product_type(tag_value)}:
            endpoint = meta["endpoint"]
            break

    if not endpoint:
        return fallback_url
    try:
        return url_for(endpoint, id=entity_id)
    except BuildError:
        return fallback_url
