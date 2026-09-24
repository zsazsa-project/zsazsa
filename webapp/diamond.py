"""Render a threat actor profile's Diamond Model as a PNG, so it can travel
through notification channels (email attachment, Mattermost image, PDF) where
the HTML/CSS version on the detail page is not available."""

from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

_W, _H = 760, 560
_WHITE = (255, 255, 255)
_TEXT = (29, 43, 48)
_MUTED = (118, 130, 140)
_BORDER = (200, 210, 216)
_ACCENT = (24, 146, 177)
_AMBER = (214, 118, 13)
_AMBER_BG = (252, 243, 232)

_FONT_CANDIDATES = {
    True: ["DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
    False: ["DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"],
}


def _font(bold: bool, size: int):
    for name in _FONT_CANDIDATES[bold]:
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _wrap(text: str, font, max_w: float, max_lines: int = 4):
    """Word-wrap to fit `max_w` while keeping the author's own line breaks.
    Capped at `max_lines`, with an ellipsis when content is dropped."""
    lines = []
    for segment in (text or "").split("\n"):
        words = segment.split()
        if not words:
            lines.append("")  # keep a blank line the author typed
            continue
        cur = ""
        for w in words:
            trial = (cur + " " + w).strip()
            if font.getlength(trial) <= max_w or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and font.getlength(last + "…") > max_w:
            last = last[:-1]
        lines[-1] = (last + "…") if last else "…"
    return lines or [""]


def _node(draw, box, value, label, missing, fval, flabel):
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=10,
                           fill=(_AMBER_BG if missing else _WHITE),
                           outline=(_AMBER if missing else _BORDER), width=2)
    cx = (x0 + x1) / 2
    lab = label.upper()
    draw.text((cx - flabel.getlength(lab) / 2, y1 - 20), lab, font=flabel, fill=_MUTED)
    val = (value or "").strip() or "Not set"
    color = _AMBER if missing else _TEXT
    lines = _wrap(val, fval, (x1 - x0) - 20)
    line_h = fval.getbbox("Ay")[3] - fval.getbbox("Ay")[1] + 6
    block_h = line_h * len(lines)
    y = y0 + ((y1 - 24 - y0) - block_h) / 2
    for line in lines:
        draw.text((cx - fval.getlength(line) / 2, y), line, font=fval, fill=color)
        y += line_h


def render_diamond_png(tap) -> bytes:
    """Return PNG bytes of the Diamond Model for a threat actor profile."""
    img = Image.new("RGB", (_W, _H), _WHITE)
    d = ImageDraw.Draw(img)
    fval, flabel, ftitle = _font(True, 15), _font(False, 11), _font(True, 19)

    heading = f"Diamond Model: {tap.title or tap.tap_id}"
    d.text((_W / 2 - ftitle.getlength(heading) / 2, 14), heading, font=ftitle, fill=_TEXT)

    cx, cy = 380, 295
    # Connector cross, drawn first so the nodes and centre sit on top of it.
    d.line((cx, 135, cx, 445), fill=_BORDER, width=2)
    d.line((260, cy, 500, cy), fill=_BORDER, width=2)
    r = 22
    d.polygon([(cx, cy - r), (cx + r, cy), (cx, cy + r), (cx - r, cy)],
              fill=(232, 244, 247), outline=_ACCENT)

    capability = " | ".join(p for p in (
        tap.capabilities,
        ", ".join(tap.mitre_attack_techniques) if tap.mitre_attack_techniques else "",
    ) if p)
    victim = ", ".join(list(tap.geographic_scope) + list(tap.sectors))

    _node(d, (280, 40, 480, 135), tap.title, "Adversary", not tap.title, fval, flabel)
    _node(d, (40, 247, 260, 342), tap.infrastructure, "Infrastructure", not tap.infrastructure, fval, flabel)
    _node(d, (500, 247, 720, 342), capability, "Capability", not capability, fval, flabel)
    _node(d, (280, 445, 480, 540), victim, "Victim", not victim, fval, flabel)

    buf = BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
