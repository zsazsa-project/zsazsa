"""Shared request-parsing and config-normalization utilities."""

import ast
import html
import re
from collections import Counter, namedtuple
from datetime import date, datetime

import config
from webapp.models import TLP_LEVELS
from flask import jsonify, request
from markdown_it import MarkdownIt
from werkzeug.routing import BuildError

# breaks=True renders single newlines as <br>, matching the client-side preview
# (marked with breaks:true) so multi-line fields like observed facts look the same
# in the on-screen preview, the PDF and e-mail. html=False escapes raw HTML in
# the source: the commonmark preset passes it through, and this text comes from
# ingested articles and model output, so a <script> in it would end up in the
# page (the md filters mark their output safe).
_md = MarkdownIt("commonmark", {"breaks": True, "html": False}).enable("table")

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


def mark_lead_labels(html: str, open_tag: str = '<span class="pretext">') -> str:
    """Wrap the "Label:" opening a line in ``open_tag``, so it is shown like the
    bold labels of product markdown.

    Briefing stories write those labels as plain prose, so there is no tag to
    match; the substitution runs on the rendered HTML instead. E-mail passes an
    inline-styled span, having no stylesheet for the class.
    """
    return _LEAD_LABEL_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{open_tag}{m.group(3)}</span>", html or "")


# The same label at the start of a source line, before it is rendered.
_LEAD_LABEL_LINE_RE = re.compile(r"^( {0,3})([A-Za-z][A-Za-z ]{1,33}:)(?=[ \t])")
_FENCE_RE = re.compile(r"^ {0,3}(```|~~~)")


def bold_lead_labels(text: str) -> str:
    """Write the labels mark_lead_labels() would set in bold as **Label:** in
    the Markdown itself, so the editor shows the text as it will look.

    For story drafts and for what a briefing stored before the labels were
    written this way. Lines in a fenced code block are left as they are.
    """
    return _outside_code(text, lambda line: _LEAD_LABEL_LINE_RE.sub(r"\1**\2**", line))


def _outside_code(text: str, change) -> str:
    """The text with ``change`` made to each line that is not in fenced code."""
    lines = (text or "").split("\n")
    fence = None
    for i, line in enumerate(lines):
        opening = _FENCE_RE.match(line)
        if fence:
            if opening and opening.group(1) == fence:
                fence = None
        elif opening:
            fence = opening.group(1)
        else:
            lines[i] = change(line)
    return "\n".join(lines)


# A line that is already Markdown of its own: a list item, heading, quote,
# table row or code fence.
_MARKDOWN_BLOCK_RE = re.compile(r"^\s*([-*+]\s|\d+[.)]\s|#|>|\||```|~~~)")


def markdown_list(lines) -> str:
    """The text of a field that used to keep one item per line, for its editor.

    Saved before the field was Markdown, the lines are bare items, which the
    products showed as bullets; they open as a "- " list so they still read as
    one. Text with a blank line or a line that is Markdown already is left as
    it was written.
    """
    lines = list(lines or [])
    if any(not line.strip() or _MARKDOWN_BLOCK_RE.match(line) for line in lines):
        return "\n".join(lines)
    return "\n".join(f"- {line}" for line in lines)


_LIST_ITEM_RE = re.compile(r"^(?:[-*+]|\d+[.)])\s", re.M)


def list_item_count(lines) -> int:
    """How many items such a field has: the items of its top-level list, or
    one for text that is not a list."""
    text = markdown_list(lines)
    return len(_LIST_ITEM_RE.findall(text)) or int(bool(text.strip()))


_HEADING_RE = re.compile(r"^( {0,3})(#{1,6})(?=[ \t]|$)")


def nest_headings(text: str, levels: int = 2) -> str:
    """Move the headings an analyst wrote ``levels`` down, under the "## "
    sections of the product the text goes into, so a heading in a field does
    not start a section of the mail of its own. Fenced code is left alone."""
    return _outside_code(text, lambda line: _HEADING_RE.sub(
        lambda m: m.group(1) + "#" * min(6, len(m.group(2)) + levels), line))


def md_to_text(text: str) -> str:
    """Markdown as plain text, for a place that shows no formatting, such as
    the Diamond Model."""
    plain = html.unescape(re.sub(r"<[^>]+>", "", md_to_html(text)))
    return re.sub(r"\n{2,}", "\n", plain).strip()


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


def age_text(seconds: float) -> str:
    """Same wording as the ago() helper the pages use client-side."""
    minutes = round(seconds / 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    if minutes < 1440:
        return f"{round(minutes / 60)}h ago"
    return f"{round(minutes / 1440)}d ago"


def iso_day(raw: str) -> str:
    """A day to filter on, as YYYY-MM-DD, or "" for one that is no date."""
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return ""


def long_day(day: str) -> str:
    """A day, YYYY-MM-DD, as "Thursday 5 November 2026"."""
    parsed = date.fromisoformat(day)
    return f"{parsed.strftime('%A')} {parsed.day} {parsed.strftime('%B %Y')}"


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


def ordered_counts(values, order=()) -> list:
    """[(value, how often)] for the bars above a list: the values of ``order``
    first, in that order, then any others, most frequent first."""
    counts = Counter(values)
    return [(v, counts.pop(v)) for v in order if v in counts] + counts.most_common()


# The TLP levels as the product lists show them and filter on them.
TLP_NAMES = [t.upper() for t in TLP_LEVELS]


def tlp_of(product) -> str:
    return product.tlp.upper()


def tlp_counts(products) -> list:
    """[(TLP, how many)] for the bar above a product list, from CLEAR to RED."""
    return ordered_counts(map(tlp_of, products), TLP_NAMES)


def matching(items, tests, skip=None) -> list:
    """The items that pass every test in ``tests`` but the one named ``skip``.

    A bar beside a list counts what the other filters let through, so that it
    still offers every choice of the filter it sets.
    """
    return [i for i in items if all(test(i) for name, test in tests.items() if name != skip)]


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


def scraper_enabled() -> bool:
    """True when zsazsa has a misp-scraper to collect from.

    The scraper is optional, like the other MISP servers: switch it off with
    MISP_SCRAPER_ENABLED, or leave MISP_URL and MISP_KEY empty, and everything
    that would have read it leaves it out instead. Switching off keeps the
    credentials, which is the difference that makes it worth having both.
    """
    if not getattr(config, "MISP_SCRAPER_ENABLED", True):
        return False
    return bool((getattr(config, "MISP_URL", "") or "").strip()
                and (getattr(config, "MISP_KEY", "") or "").strip())


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


PRODUCT_TAG_PREFIX = 'zsazsa:ctiproduct='

# What zsazsa puts before the title of each record it files in MISP.
_INFO_PREFIX = re.compile(r"^\[zsazsa:[^\]]*\]\s*")


def record_title(info: str) -> str:
    """A MISP event title without zsazsa's "[zsazsa:fia]" marker, for a page
    that already says what kind of record it lists."""
    return _INFO_PREFIX.sub("", info or "")


# The CTI products that have their own pages, by display name: the config tag
# holding the tag value, the built-in value, the detail endpoint and the list endpoint.
_PRODUCT_TYPES = {
    "Flash intel alert": ("TAG_FLASH_INTEL", "flash-intel", "flash_intel.detail", "flash_intel.review"),
    "Vulnerability advisory": ("TAG_VEA", "vea", "vea.detail", "vea.review"),
    "Daily threat briefing": ("TAG_BRIEFING", "daily-briefing", "daily_briefing.detail", "daily_briefing.list_briefings"),
    "Threat landscape report": ("TAG_TLR", "threat-landscape-report", "threat_landscape.detail",
                                "threat_landscape.review"),
    "Indicator feed": ("TAG_INDICATOR_FEED", "indicator-feed", "indicator_feed.detail", "indicator_feed.index"),
    "Threat actor profile": ("TAG_THREAT_ACTOR_PROFILE", "threat-actor-profile", "threat_actor_profile.detail",
                             "threat_actor_profile.review"),
    "Detection engineering request": ("TAG_DETECTION_ENG", "detection-eng-request", "detection_eng.detail",
                                      "detection_eng.review"),
}

# Names used before the product was renamed, still stored on older events.
_PRODUCT_TYPE_ALIASES = {"vulnerability exploitation advisory": "vulnerability advisory"}

_ProductType = namedtuple("_ProductType", "label tag_value endpoint list_endpoint")


def fill_product_tag_defaults():
    """Give config a tag setting for every product that lacks one.

    A config file written before a product existed has no setting for its tag,
    and saving the Settings page is what adds it. Until then every page that
    reads the setting would fail, so the product gets the tag zsazsa ships with.
    """
    for config_attr, builtin, _endpoint, _list_endpoint in _PRODUCT_TYPES.values():
        if not getattr(config, config_attr, ""):
            setattr(config, config_attr, f'{PRODUCT_TAG_PREFIX}"{builtin}"')


def _configured_tag_value(config_attr: str, builtin: str) -> str:
    """Return the value inside a configured product tag, e.g. 'flash-intel'.

    An admin can rename the tag in config/__init__.py; anything that is not a
    usable zsazsa:ctiproduct tag falls back to the value zsazsa ships with.
    """
    tag = str(getattr(config, config_attr, "") or "").strip()
    if not tag.startswith(PRODUCT_TAG_PREFIX):
        return builtin
    return tag.split("=", 1)[1].strip().strip('"') or builtin


def _find_product_type(product_type: str):
    """Look up a product type given as a display name or as a tag value.

    Returns None when it is not one of ours: the config page lets an admin add
    product types that have no page of their own.
    """
    wanted = (product_type or "").strip().lower()
    wanted = _PRODUCT_TYPE_ALIASES.get(wanted, wanted)
    for label, (config_attr, builtin, endpoint, list_endpoint) in _PRODUCT_TYPES.items():
        tag_value = _configured_tag_value(config_attr, builtin)
        if wanted in (label.lower(), tag_value.lower()):
            return _ProductType(label, tag_value, endpoint, list_endpoint)
    return None


def product_type_tag_value(product_type: str) -> str:
    """Return the zsazsa:ctiproduct tag value for a product type."""
    found = _find_product_type(product_type)
    return found.tag_value if found else (product_type or "").strip()


def product_type_label(product_type: str) -> str:
    """Return the display name for a product type given by its tag value."""
    found = _find_product_type(product_type)
    return found.label if found else (product_type or "").strip()


def product_list_url(product_type: str) -> str:
    """Return the URL of a product type's own list, or "" when it has none."""
    from flask import url_for

    found = _find_product_type(product_type)
    return url_for(found.list_endpoint) if found else ""


def product_detail_url(product_type: str, entity_id: str, fallback_url: str = "") -> str:
    """Return the app-detail URL for a known CTI product type.

    Falls back to the provided URL (typically the MISP event URL) when no
    dedicated app detail page exists for that product type.
    """
    from flask import url_for

    found = _find_product_type(product_type)
    if not found:
        return fallback_url
    try:
        return url_for(found.endpoint, id=entity_id)
    except BuildError:
        return fallback_url
