"""Parsers for security newsletters, whether pasted into the importer or
collected from a mailbox.

Each parser turns a newsletter into a list of article dicts so the importer can
show them for selection. The text may be a directly delivered edition or a
forwarded copy (traditional or Apple Mail style), so the ETDA parser tolerates a
forward preamble and '> ' quoting. Parsing is pure text work; nothing here
touches MISP or the network. New newsletters are added by writing a parser and
registering it in PARSERS.
"""

import re

_PRIORITY_RE = re.compile(r'^Priority:\s*(\d)\s*-\s*(.+?)\s*$', re.IGNORECASE)
_RELEVANCE_RE = re.compile(r'^Relevance:\s*(.+?)\s*$', re.IGNORECASE)
_URL_RE = re.compile(r'https?://\S+')
# A "Quick overview" row: a section name followed by three counts.
_OVERVIEW_ROW_RE = re.compile(r'^(.+?)[ \t]+\d+[ \t]+\d+[ \t]+\d+\s*$')
_TLP_RE = re.compile(r'TLP:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)', re.IGNORECASE)

_PRIORITY_KEYS = {1: "critical", 2: "urgent", 3: "important"}

_QUOTE_RE = re.compile(r'^> ?')
# Forwarded-message header lines, so the real newsletter title is not mistaken
# for the forward's Subject line.
_FWD_HEADER_RE = re.compile(
    r'^(From|Date|Subject|To|Sent|Cc|Reply-To|Delivered-To|Return-Path'
    r'|Begin forwarded message)\b', re.IGNORECASE)
# Trailing in-mail anchor link on a "Quick overview" section name,
# e.g. "Industrial Sector <x-msg://3/#ICS>".
_OVERVIEW_ANCHOR_RE = re.compile(r'\s*<[^>]*>\s*$')


def _parsed_tlp(match: re.Match | None) -> str:
    """The TLP of a newsletter header, with the retired WHITE read as CLEAR."""
    if not match:
        return ""
    tlp = match.group(1).lower()
    return "clear" if tlp == "white" else tlp


def _dequote(text: str) -> str:
    """Strip one level of '> ' e-mail quoting when the text is a quoted forward.

    Apple Mail and similar clients quote a forwarded newsletter by prefixing
    every line with '> ', which breaks the line-anchored parsing below. Only
    strip when most non-blank lines are quoted, so a pasted (unquoted)
    newsletter is left untouched.
    """
    lines = text.split("\n")
    nonblank = [ln for ln in lines if ln.strip()]
    if not nonblank:
        return text
    quoted = sum(1 for ln in nonblank if ln.startswith(">"))
    if quoted < len(nonblank) * 0.6:
        return text
    return "\n".join(_QUOTE_RE.sub("", ln) for ln in lines)


def _clean_url(token: str) -> str:
    return token.strip().strip("<>").rstrip(">.,);")


def _strip_quotes(text: str) -> str:
    return text.strip().strip('"').strip('“”').strip()


def _etda_section_names(lines: list[str]) -> list[str]:
    """Section names in order, read from the 'Quick overview' table."""
    names = []
    in_overview = False
    for line in lines:
        if line.strip().lower().startswith("quick overview"):
            in_overview = True
            continue
        if in_overview:
            match = _OVERVIEW_ROW_RE.match(line.strip())
            if match:
                names.append(_OVERVIEW_ANCHOR_RE.sub("", match.group(1)).strip())
            elif names:
                break
    return names


def _etda_body_start(lines: list[str]) -> int:
    """Index of the first line after the 'Quick overview' table."""
    seen_row = False
    for idx, line in enumerate(lines):
        if _OVERVIEW_ROW_RE.match(line.strip()):
            seen_row = True
        elif seen_row:
            return idx
    return 0


def parse_etda(text: str) -> dict:
    """Parse an ETDA CTI Robot newsletter into report metadata and articles."""
    text = _dequote(text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = text.split("\n")

    sections = set(_etda_section_names(lines))
    tlp_match = _TLP_RE.search(text)
    tlp = _parsed_tlp(tlp_match)

    report_title = ""
    for line in lines[:20]:
        if _FWD_HEADER_RE.match(line.strip()):
            continue
        if "cyber threat intelligence" in line.lower():
            report_title = line.strip()
            break

    articles = []
    current_section = ""
    pending = []  # lines gathered before a Priority line: [title, intro lines...]

    body = lines[_etda_body_start(lines):]
    i = 0
    while i < len(body):
        line = body[i].strip()
        i += 1
        if not line or line == "↑":  # blank or back-to-top arrow
            if line == "↑":
                pending = []
            continue
        if line in sections:
            current_section = line
            pending = []
            continue

        priority = _PRIORITY_RE.match(line)
        if not priority:
            pending.append(line)
            continue

        title = pending[0] if pending else ""
        intro = _strip_quotes(" ".join(pending[1:])) if len(pending) > 1 else ""
        pending = []

        relevance = ""
        urls = []
        while i < len(body):
            nxt = body[i].strip()
            rel = _RELEVANCE_RE.match(nxt)
            if rel:
                relevance = rel.group(1).strip()
                i += 1
            elif _URL_RE.search(nxt):
                urls.extend(_clean_url(u) for u in _URL_RE.findall(nxt))
                i += 1
            elif not nxt:
                i += 1
            else:
                break  # next title, section header or arrow

        if not title:
            continue
        rank = int(priority.group(1))
        articles.append({
            "section": current_section,
            "title": title,
            "intro": intro,
            "priority_rank": rank,
            "priority_label": priority.group(2).strip(),
            "priority_key": _PRIORITY_KEYS.get(rank, "important"),
            "relevance": relevance,
            "primary_url": urls[0] if urls else "",
            "related_urls": urls[1:],
        })

    return {"report_title": report_title, "tlp": tlp, "articles": articles}


# IT-ISAC lays each article out as labelled fields, separated by a rule. The
# labels wrap onto following lines, and an excerpt can run to several
# paragraphs, so a field keeps collecting until the next label, rule or title.
_ITISAC_RULE_RE = re.compile(r'^-{10,}$')
_ITISAC_FIELD_RE = re.compile(r'^(Title|Date Published|Excerpt)\s*:\s*(.*)$', re.IGNORECASE)
# The mail signature, '-- ' on its own line, which is not one of the rules above.
_ITISAC_SIGNATURE_RE = re.compile(r'^--\s*$')


def _itisac_article(block: list[str]) -> dict | None:
    """One article from one block of lines, or None if the block has no title."""
    fields = {"title": [], "excerpt": []}
    urls = []
    current = None

    for line in block:
        line = line.strip()
        label = _ITISAC_FIELD_RE.match(line)
        # The excerpt is the last field of a block, so once it starts everything
        # up to the next label is part of it: the blank lines between its
        # paragraphs, and any link in the quoted prose, which is not the
        # article's own URL and would take the rest of the sentence with it.
        if current == "excerpt" and not label:
            if line:
                fields["excerpt"].append(line)
            continue
        if not line:
            current = None
            continue
        if label:
            # "Date Published" is recognised but not kept: matching it is what
            # stops the title above from swallowing it.
            name = label.group(1).lower()
            current = name if name in fields else None
            if current:
                fields[current].append(label.group(2).strip())
            continue
        if _URL_RE.search(line):
            urls.extend(_clean_url(u) for u in _URL_RE.findall(line))
            current = None
            continue
        if current:
            fields[current].append(line)

    title = " ".join(fields["title"]).strip()
    if not title:
        return None
    return {
        "section": "",
        "title": title,
        "intro": _strip_quotes(" ".join(fields["excerpt"])),
        "priority_rank": 0,
        "priority_label": "",
        "priority_key": "",
        "relevance": "",
        "primary_url": urls[0] if urls else "",
        "related_urls": urls[1:],
    }


def parse_itisac(text: str) -> dict:
    """Parse an IT-ISAC Open Source News mail into report metadata and articles.

    IT-ISAC grades nothing, so the priority and section fields the ETDA parser
    fills stay empty rather than being invented here.
    """
    text = _dequote(text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = text.split("\n")

    report_title = ""
    for line in lines[:20]:
        if _FWD_HEADER_RE.match(line.strip()):
            continue
        if "[IT-ISAC]" in line:
            report_title = line.strip()
            break

    tlp_match = _TLP_RE.search(text)

    # A title opens an article and a rule closes one, so the mail's own header
    # and anything between two articles land in a block of their own and are
    # dropped for having no title. Splitting on the rule alone let a link above
    # the first title, a "view this online" banner, pass as that article's URL,
    # and folded two articles into one wherever an edition lost its rule.
    blocks = [[]]
    for line in lines:
        if _ITISAC_SIGNATURE_RE.match(line.rstrip()):
            break
        label = _ITISAC_FIELD_RE.match(line.strip())
        if label and label.group(1).lower() == "title":
            blocks.append([line])
        elif _ITISAC_RULE_RE.match(line.strip()):
            blocks.append([])
        else:
            blocks[-1].append(line)

    articles = [a for a in (_itisac_article(b) for b in blocks) if a]

    return {
        "report_title": report_title,
        "tlp": _parsed_tlp(tlp_match),
        "articles": articles,
    }


PARSERS = {
    "ETDA CTI Robot": parse_etda,
    "IT-ISAC Open Source News": parse_itisac,
}


def available_sources() -> list[str]:
    return sorted(PARSERS)


def parse(source_name: str, text: str) -> dict:
    parser = PARSERS.get(source_name)
    if parser is None:
        raise ValueError(f"No parser for newsletter source {source_name!r}")
    return parser(text or "")
