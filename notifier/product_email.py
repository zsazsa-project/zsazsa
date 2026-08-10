"""Branded HTML rendering for CTI products sent by e-mail.

The PDF is the reference layout: a coloured header carrying the logo and the TLP,
a title block, a meta grid, then boxed sections. This module reproduces that
layout in the subset of HTML that mail clients agree on (tables and inline
styles), so a product reads the same whether it arrives as a PDF or in a mailbox.

Two entry points:
    briefing_html() is built from the briefing object, so stories keep the
    numbered badge and per-story scope rows the PDF shows.
    markdown_html() is built from rendered markdown for products that follow a
    title + metadata + section-body layout.
"""

import html
import re

from webapp import branding
from webapp.misp_store import (
    briefing_combined_scope_summary,
    briefing_story_scope_rows,
)
from webapp.utils import md_to_html, mute_lead_labels

LOGO_CID = "brandlogo"

# TLP -> (background, text, background when sitting on the dark header).
_TLP_COLOURS = {
    "red": ("#fee2e2", "#991b1b", "#991b1b"),
    "amber": ("#fef3c7", "#92400e", "#92400e"),
    "amber+strict": ("#fed7aa", "#7c2d12", "#7c2d12"),
    "green": ("#dcfce7", "#166534", "#166534"),
    "clear": ("#f1f5f9", "#334155", "rgba(255,255,255,0.15)"),
}

# Products name their classification line either "Classification: tlp:x" or
# "TLP: TLP:X"; both mean the same thing.
_TLP_KEYS = ("classification", "tlp")

_META_RE = re.compile(r"^\*\*(?P<key>[^*]+?):\*\*\s*(?P<value>.*)$")
# Field labels in the markdown are written as bold "Label:". They introduce the
# content rather than being content, so they get the muted pretext treatment.
_LABEL_RE = re.compile(r"<strong>([^<]{1,60}:)</strong>")


def _esc(value) -> str:
    return html.escape(str(value or ""))


def _pretext(text: str, brand: dict) -> str:
    """A field label: one step back from the content it introduces."""
    return f'<span style="font-size:12px;color:{brand["color3"]};">{_esc(text)}</span>'


def _body_html(markdown: str, brand: dict) -> str:
    """Render markdown for the mail body, muting "Label:" pretext.

    The muting deliberately happens after rendering, against the <strong> that
    CommonMark guarantees for **bold**. Substituting the span into the markdown
    beforehand reads tidier but only works while md_to_html keeps html=True: the
    day that is turned off, every product mail would show escaped tag text.
    Briefing stories write their labels as plain prose instead of bold, which
    mute_lead_labels picks up from the same rendered HTML.
    """
    muted = f'<span style="font-size:12px;color:{brand["color3"]};">'
    rendered = _LABEL_RE.sub(lambda m: f"{muted}{m.group(1)}</span>", md_to_html(markdown or ""))
    return mute_lead_labels(rendered, muted)


def _tlp_badge(tlp: str, *, on_dark: bool) -> str:
    key = (tlp or "clear").strip().lower()
    background, colour, dark_background = _TLP_COLOURS.get(key, _TLP_COLOURS["clear"])
    if on_dark:
        background, colour = dark_background, "#ffffff"
    return (
        f'<span style="display:inline-block;padding:3px 9px;border-radius:3px;'
        f'font-size:11px;font-weight:700;background:{background};color:{colour};'
        f'white-space:nowrap;">TLP:{_esc(key.upper())}</span>'
    )


def _header(brand: dict, tlp: str) -> str:
    logo_cell = ""
    if brand["logo_uri"]:
        logo_cell = (
            f'<td width="1" valign="middle" style="padding-right:16px;">'
            f'<img src="cid:{LOGO_CID}" height="40" alt="" '
            f'style="display:block;max-height:40px;border:0;"></td>'
        )
    identity = ""
    if brand["company"]:
        identity += (
            f'<div style="font-size:17px;font-weight:700;color:#ffffff;'
            f'letter-spacing:.03em;">{_esc(brand["company"])}</div>'
        )
    if brand["department"]:
        identity += (
            f'<div style="font-size:11px;color:rgba(255,255,255,.65);'
            f'text-transform:uppercase;letter-spacing:.04em;margin-top:2px;">'
            f'{_esc(brand["department"])}</div>'
        )
    # Products without a classification (PIR, GIR) carry no badge rather than a
    # misleading default.
    badge_cell = ""
    if tlp:
        badge_cell = f'<td valign="middle" align="right">{_tlp_badge(tlp, on_dark=True)}</td>'
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="background:{brand["color1"]};">'
        f'<tr><td style="padding:18px 24px 16px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
        f"{logo_cell}"
        f'<td valign="middle" width="100%" style="width:100%;">{identity}</td>'
        f"{badge_cell}"
        f"</tr></table></td></tr>"
        f'<tr><td style="height:4px;line-height:4px;font-size:0;'
        f'background:{brand["color2"]};">&nbsp;</td></tr>'
        f"</table>"
    )


def _title_block(brand: dict, doc_label: str, title: str) -> str:
    if not doc_label and not title:
        return ""
    label = ""
    if doc_label:
        label = (
            f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
            f'letter-spacing:.1em;color:{brand["color2"]};margin-bottom:4px;">'
            f"{_esc(doc_label)}</div>"
        )
    return (
        f'<div style="padding:20px 24px 12px;border-bottom:1px solid #e2e8f0;">'
        f"{label}"
        f'<h1 style="font-size:22px;font-weight:700;color:{brand["color1"]};'
        f'margin:0;line-height:1.25;">{_esc(title)}</h1>'
        f"</div>"
    )


def _meta_block(brand: dict, meta: list, tlp: str) -> str:
    """The date/author/… grid under the title, in rows of at most four cells.

    The classification is always the last cell, so every product carries its TLP
    on its face whether or not the caller's metadata mentioned one.
    """
    items = [(label, _esc(value)) for label, value in meta if value]
    if tlp:
        items.append(("Classification", _tlp_badge(tlp, on_dark=False)))
    if not items:
        return ""
    rows = ""
    for start in range(0, len(items), 4):
        cells = ""
        for label, value in items[start:start + 4]:
            cells += (
                f'<td valign="top" style="padding:4px 16px 4px 0;">'
                f'<div style="font-size:10px;font-weight:700;text-transform:uppercase;'
                f'letter-spacing:.06em;color:{brand["color3"]};">{_esc(label)}</div>'
                f'<div style="font-size:13px;font-weight:600;color:#1e293b;'
                f'margin-top:2px;">{value}</div></td>'
            )
        rows += f"<tr>{cells}</tr>"
    return (
        f'<div style="margin:16px 24px 20px;background:#f8fafc;'
        f'border-left:3px solid {brand["color1"]};padding:10px 14px;">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'width="100%">{rows}</table></div>'
    )


def _section(heading: str, inner_html: str, brand: dict) -> str:
    """A section heading with its content in a bordered box, as in the PDF."""
    head = ""
    if heading:
        head = (
            f'<div style="font-size:14px;font-weight:700;color:{brand["color1"]};'
            f'border-bottom:1px solid {brand["color2"]};padding-bottom:4px;'
            f'margin:0 24px 8px;">{_esc(heading)}</div>'
        )
    return (
        f"{head}"
        f'<div style="margin:0 24px 14px;border:1px solid #e2e8f0;border-radius:4px;'
        f'padding:10px 14px;font-size:14px;line-height:1.55;color:#1e293b;">'
        f"{inner_html}</div>"
    )


def _story_block(brand: dict, number: int, title: str, body_html: str, footer_html: str) -> str:
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="border:1px solid #e2e8f0;border-radius:4px;margin:0 0 12px;">'
        f'<tr><td style="background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:8px 12px;">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td width="22" valign="top">'
        f'<div style="width:22px;height:22px;line-height:22px;text-align:center;'
        f'background:{brand["color2"]};color:#ffffff;font-size:11px;font-weight:700;'
        f'border-radius:11px;">{number}</div></td>'
        f'<td valign="middle" style="padding-left:10px;font-size:15px;font-weight:700;'
        f'color:{brand["color1"]};">{_esc(title)}</td>'
        f"</tr></table></td></tr>"
        f'<tr><td style="padding:10px 12px;font-size:14px;line-height:1.55;">'
        f"{body_html}{footer_html}</td></tr></table>"
    )


def _scope_tags(values: list) -> str:
    return "".join(
        f'<span style="display:inline-block;font-size:11px;border:1px solid #cbd5e1;'
        f'border-radius:3px;padding:1px 6px;margin:2px 4px 2px 0;color:#334155;">'
        f"{_esc(v)}</span>"
        for v in values
    )


def _document(brand: dict, doc_label: str, title: str, tlp: str, meta: list, body: str) -> str:
    # Products without a classification (PIR, GIR) get no handling footer.
    footer = ""
    if tlp:
        footer = (
            '<div style="padding:12px 24px 20px;font-size:11px;color:#94a3b8;">'
            f"TLP:{_esc(tlp.upper())} - handle according to the classification above."
            "</div>"
        )
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        '<body style="margin:0;padding:0;background:#eef2f6;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="background:#eef2f6;"><tr><td align="center" style="padding:16px 8px;">'
        '<table role="presentation" width="720" cellpadding="0" cellspacing="0" border="0" '
        'style="width:100%;max-width:720px;background:#ffffff;'
        'font-family:Arial,Helvetica,sans-serif;color:#1e293b;">'
        "<tr><td>"
        f"{_header(brand, tlp)}"
        f"{_title_block(brand, doc_label, title)}"
        f"{_meta_block(brand, meta, tlp)}"
        f"{body}"
        f"{footer}"
        "</td></tr></table></td></tr></table></body></html>"
    )


# ── Generic product mail (flash intel, advisory, profile, requirements, …) ────

def _split_markdown(markdown: str):
    """Split product markdown into (title, meta rows, remaining body).

    This parser is intentionally narrow: it reads leading "**Key:** value"
    metadata rows after a top-level title and stops at the first non-metadata
    line. Products with a different layout should pass explicit metadata to
    their e-mail renderer instead of relying on this split.
    """
    lines = (markdown or "").splitlines()

    def skip_blanks(i):
        while i < len(lines) and not lines[i].strip():
            i += 1
        return i

    index = skip_blanks(0)
    title = ""
    if index < len(lines) and lines[index].startswith("# "):
        title = lines[index][2:].strip()
        index += 1
    # The metadata lines run without a break; stopping at the first line that is
    # not one keeps a bold phrase further down the body out of the grid.
    index = skip_blanks(index)
    meta = []
    while index < len(lines):
        match = _META_RE.match(lines[index].strip())
        if not match:
            break
        meta.append((match.group("key").strip(), match.group("value").strip()))
        index += 1
    return title, meta, "\n".join(lines[index:])


def _sections(body: str):
    """Split a product body into (heading, markdown) pairs on '## ' headings."""
    result = []
    heading = ""
    buffer = []
    for line in (body or "").splitlines():
        if line.startswith("## "):
            result.append((heading, "\n".join(buffer)))
            heading = line[3:].strip()
            buffer = []
        elif line.strip() == "---":
            continue
        else:
            buffer.append(line)
    result.append((heading, "\n".join(buffer)))
    return [(h, c) for h, c in result if h or c.strip()]


def _meta_tlp(meta: list) -> str:
    """The TLP named by a metadata block, as a bare level ("amber")."""
    for key, value in meta:
        if key.lower() in _TLP_KEYS:
            return value.split(":", 1)[-1].strip().lower()
    return ""


def markdown_html(markdown: str, doc_label: str, fallback_tlp: str = "") -> str:
    """Render any product's markdown as a branded HTML mail.

    `fallback_tlp` covers the products whose markdown states the classification
    somewhere other than the metadata block (threat actor profiles, feeds).
    """
    brand = branding.brand()
    title, meta, body = _split_markdown(markdown)
    tlp = _meta_tlp(meta) or fallback_tlp
    rows = [(key, value) for key, value in meta if key.lower() not in _TLP_KEYS]
    sections = "".join(_section(h, _body_html(c, brand), brand)
                       for h, c in _sections(body))
    return _document(brand, doc_label, title or doc_label, tlp, rows, sections)


# ── Daily threat briefing ─────────────────────────────────────────────────────

def _story_footer(story, brand: dict) -> str:
    """Source line plus the labelled scope rows shown under a story."""
    rows = []
    source_url = getattr(story, "source_url", "") or ""
    if source_url:
        rows.append(
            f'{_pretext("Source:", brand)} <a href="{_esc(source_url)}" '
            f'style="color:{brand["color2"]};">{_esc(source_url)}</a>'
        )
    for label, values in briefing_story_scope_rows(story):
        rows.append(f"{_pretext(label + ':', brand)} {_scope_tags(values)}")

    reliability = getattr(story, "source_reliability", "") or "-"
    credibility = getattr(story, "information_credibility", "") or "-"
    if reliability != "-" or credibility != "-":
        rows.append(_pretext("Admiralty scale:", brand) + " "
                    + _scope_tags([f"{reliability}/{credibility}"]))
    evaluation = getattr(story, "cti_evaluation", None) or {}
    if evaluation:
        rows.append(_pretext("CTI evaluation:", brand) + " "
                    + _scope_tags([f"{k}={v}" for k, v in evaluation.items()]))
    if not rows:
        return ""
    body = "".join(f'<div style="margin-top:4px;">{row}</div>' for row in rows)
    return f'<div style="margin-top:8px;padding-top:6px;border-top:1px solid #e2e8f0;">{body}</div>'


def briefing_html(briefing, preview_url: str = "") -> str:
    """Render a daily threat briefing as a branded HTML mail.

    Built from the briefing object rather than its markdown so the stories keep
    the numbered badge, boxed layout and labelled scope rows of the PDF.
    """
    brand = branding.brand()
    date_str = briefing.date or (
        briefing.created_at.strftime("%Y-%m-%d") if briefing.created_at else "unknown"
    )
    meta = [
        ("Date", date_str),
        ("Author", briefing.author or "analyst"),
        # Stringified so a briefing with no stories still shows the count cell.
        ("Stories", str(len(briefing.stories))),
    ]

    stories = "".join(
        _story_block(
            brand,
            index,
            getattr(story, "title", "") or f"Story {index}",
            _body_html(getattr(story, "content", "") or "", brand)
            or '<p style="color:#94a3b8;font-style:italic;">(no content)</p>',
            _story_footer(story, brand),
        )
        for index, story in enumerate(briefing.stories, 1)
    )
    body = ""
    if briefing.summary:
        body += _section("Briefing summary", _body_html(briefing.summary, brand), brand)
    body += _section(
        f"Today's stories ({len(briefing.stories)} items)",
        stories or '<p style="color:#94a3b8;font-style:italic;">No stories added.</p>',
        brand,
    )

    scope_summary = briefing_combined_scope_summary(briefing)
    if scope_summary:
        groups = "".join(
            f'<div style="margin-bottom:8px;">{_pretext(label + ":", brand)}<br>'
            # The tag text is escaped, so this is the character, not an entity.
            + _scope_tags([f"{value} ×{count}" if count > 1 else value
                           for value, count in ranked])
            + "</div>"
            for label, ranked in scope_summary
        )
        body += _section("Scope summary", groups, brand)

    body += _section("Escalations", _body_html(briefing.escalations or "None today.", brand), brand)
    if briefing.notes:
        body += _section("Notes", _body_html(briefing.notes, brand), brand)
    if preview_url:
        body += (
            f'<div style="margin:0 24px 16px;font-size:14px;">'
            f'<a href="{_esc(preview_url)}" style="color:{brand["color2"]};">'
            f"Open briefing</a></div>"
        )

    title = briefing.title or f"Daily threat briefing - {date_str}"
    return _document(brand, "Daily Threat Briefing", title, briefing.tlp, meta, body)
