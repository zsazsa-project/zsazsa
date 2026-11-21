"""Read a long CTI report, a PDF, and draft where its stories start.

A report imported on Data collection is split into stories for the threat
landscape. This module turns the PDF into what the import works with:

- blocks: the text in reading order, a paragraph or a heading each, with its
  page and its font size as a share of the body text;
- the outline the PDF has, each entry placed on the block that starts it;
- drafts: where each story starts and ends, taken from that outline, else from
  the headings found by font size, else by size alone.

PyMuPDF parses the file in a child process (``python -m core.report_document``)
with a time and memory limit, so a malformed or hostile PDF cannot hang or
exhaust the web app. read_pdf() is what the web app calls.

The rules come from reading eight reports from six publishers. Each has a
comment where a report showed why.
"""

import collections
import json
import logging
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from core.net_safety import pinned_curl_options, resolve_public_url

logger = logging.getLogger(__name__)

_READ_TIMEOUT_S = 180
_MEMORY_LIMIT = 2 * 1024 ** 3
_MAX_REDIRECTS = 3

# A line repeated at the top or bottom of this share of the pages is a running
# header or footer: a report's name, its id, a page number, a chapter bar.
_EDGE_TOP, _EDGE_BOTTOM = 0.08, 0.93
_RUNNING_SHARE = 0.3
# A heading is this much larger than the body text. Sizes are compared, never
# read as points: ESET's pages are 3840 points wide and its body text is 33 pt.
_HEADING_RATIO = 1.3
# A branch of the outline longer than this is split at its next level. Below
# it, its sections stay one story; Microsoft's 323 entries come to about 65.
_DESCEND_CHARS = 15_000
# A story longer than this is cut at its own headings. Up to it a story is kept
# whole: CrowdStrike's themes are 16,000 to 18,000 characters each.
_STORY_MAX_CHARS = 30_000
# A shorter section is still split when it is made of three subsections or
# more with this much text each, by their median: Recorded Future's Section III
# is 14,800 characters on four conflicts, while Microsoft's sections of a few
# short paragraphs stay together.
_SUBSECTION_CHARS = 2_000
# A section with less text than this before its first subsection only has its
# heading, and joins the story after it.
_EMPTY_CHARS = 300
# A document this short is one story. The ENISA booklet is 6,000 characters,
# most of them labels of its graphics.
_SMALL_DOCUMENT_CHARS = 10_000
# A text this sparse is a scan, which is not read.
_SCANNED_CHARS_PER_PAGE = 40

_CAPTION = re.compile(r"(figure|fig\.|table|chart|exhibit)\s*\d", re.IGNORECASE)
_WORD = re.compile(r"[^\W\d_]{3}")
_TLP = re.compile(r"\bTLP\s*:\s*(CLEAR|WHITE|GREEN|AMBER\+STRICT|AMBER|RED)\b", re.IGNORECASE)


class ReportError(Exception):
    """Why a report cannot be imported, in words an analyst can act on."""


def max_mb() -> int:
    """The largest PDF an import takes, in MB, as Settings > System has it."""
    # Imported here rather than at the top: the child process that parses the
    # PDF has no use for the configuration and its keys.
    import config

    return getattr(config, "REPORT_IMPORT_MAX_MB", 30)


# ── Fetching ─────────────────────────────────────────────────────────────────

def looks_like_pdf(data: bytes) -> bool:
    return b"%PDF-" in data[:1024]


def pdf_filename(url: str, disposition: str = "") -> str:
    """A safe file name for a PDF, from its Content-Disposition or its address."""
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', disposition or "", re.IGNORECASE)
    name = unquote(match.group(1)) if match else unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    name = re.sub(r"[^\w.\-]+", "_", name).strip("._")
    if not name:
        return "report.pdf"
    return name if name.lower().endswith(".pdf") else f"{name}.pdf"


def fetch_pdf(url: str) -> tuple[bytes, str]:
    """Download a PDF from a public address and return it with a file name.

    Each hop of a redirect is checked and pinned as /api/fetch-url does, so a
    public address cannot send the fetch to an internal one. The type is read
    from the content: CERT-EU's address ends in /pdf, and CrowdStrike's report
    page is a viewer with the PDF inside it.
    """
    from curl_cffi import requests as cf_requests

    limit = max_mb()
    for _ in range(_MAX_REDIRECTS + 1):
        resolved = resolve_public_url(url)
        if resolved is None:
            raise ReportError("The link must be a public http or https address.")
        with cf_requests.Session(curl_options=pinned_curl_options(*resolved)) as session:
            response = session.get(url, impersonate="chrome124", timeout=60,
                                   allow_redirects=False, stream=True)
            try:
                if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                    url = urljoin(url, response.headers["location"])
                    continue
                if response.status_code != 200:
                    raise ReportError(f"The link answered with HTTP {response.status_code}.")
                data = bytearray()
                for chunk in response.iter_content():
                    data += chunk
                    if len(data) > limit * 1024 * 1024:
                        raise ReportError(f"The PDF is larger than {limit} MB.")
                disposition = response.headers.get("content-disposition", "")
            finally:
                response.close()
        if not looks_like_pdf(data):
            if b"<html" in data[:4096].lower():
                raise ReportError("The link leads to a web page, not a PDF. Download the PDF from that page "
                                  "and upload it instead.")
            raise ReportError("The link does not lead to a PDF.")
        return bytes(data), pdf_filename(url, disposition)
    raise ReportError("The link redirects too many times.")


# ── Reading, in the child process ────────────────────────────────────────────

def _clean(text: str) -> str:
    text = text.replace("\xa0", " ").replace("\u200b", "")
    text = "".join(c for c in text if c.isprintable())
    return " ".join(text.split())


def _join(lines: list[str]) -> str:
    """The lines of a paragraph as one text.

    A line that ends in a hyphen goes on without a space and keeps it: in the
    reports read, that is a compound ("third-party") or an address broken over
    two lines, and almost never a word the layout split.
    """
    out = ""
    for line in lines:
        if out.endswith("-") and line[:1].islower():
            out += line
        else:
            out = f"{out} {line}" if out else line
    return out


def _lines(doc):
    """Every line of text: (page, top, bottom, text, size, block number).

    In the order the PDF holds them, not sorted by position: sorting mixes the
    columns of Microsoft's landscape pages.
    """
    import pymupdf

    flags = pymupdf.TEXTFLAGS_DICT & ~pymupdf.TEXT_PRESERVE_LIGATURES & ~pymupdf.TEXT_PRESERVE_IMAGES
    for pno, page in enumerate(doc):
        height = page.rect.height or 1
        for block in page.get_text("dict", flags=flags)["blocks"]:
            for line in block.get("lines", []):
                spans = [s for s in line["spans"] if s["text"].strip()]
                text = _clean("".join(s["text"] for s in line["spans"]))
                if spans and text:
                    yield (pno, line["bbox"][1] / height, line["bbox"][3] / height, text,
                           round(max(s["size"] for s in spans), 1), block["number"])


def _shape(text: str) -> str:
    """A line with its numbers blanked, so "Page 3 of 26" repeats as "Page # of #"."""
    return re.sub(r"\d+", "#", text)


def _at_edge(line) -> bool:
    return line[1] < _EDGE_TOP or line[2] > _EDGE_BOTTOM


def _running(lines, page_count: int) -> set:
    pages = collections.defaultdict(set)
    for line in lines:
        if _at_edge(line):
            pages[_shape(line[3])].add(line[0])
    least = max(3, page_count * _RUNNING_SHARE)
    return {shape for shape, seen in pages.items() if len(seen) >= least}


def _blocks(lines, body_size: float) -> list[dict]:
    """Lines grouped into paragraphs and headings.

    A PyMuPDF block can hold a heading and the paragraph under it, so a change
    of font size starts a new block too.
    """
    blocks, current, last = [], [], None
    for line in lines + [None]:
        if current and (line is None or line[0] != last[0] or line[5] != last[5] or abs(line[4] - last[4]) > 0.5):
            text = _join([c[3] for c in current])
            ratio = round(max(c[4] for c in current) / body_size, 2)
            if ratio >= _HEADING_RATIO and len(text) <= 160 and _WORD.search(text):
                kind = "h"
            elif _CAPTION.match(text):
                kind = "cap"
            else:
                kind = "p"
            blocks.append({"id": len(blocks), "page": current[0][0] + 1, "text": text, "size": ratio, "kind": kind})
            current = []
        if line is not None:
            current.append(line)
            last = line
    return blocks


def _norm(text: str) -> str:
    return " ".join(re.sub(r"[^\w]+", " ", text.lower()).split())


def _usable_title(title: str) -> bool:
    """An outline entry that names a section.

    Recorded Future's outline also holds InDesign's anchors, such as
    _s3n6j2ho91kz, and Microsoft's names its figures.
    """
    return bool(title) and not title.startswith("_") and bool(re.search(r"[^\W\d_]{2}", title)) \
        and not _CAPTION.match(title)


def _place(blocks_on_page: list[dict], title: str) -> dict | None:
    """The block an outline entry starts at: the one that opens with its title.

    By title, not by the entry's coordinates: CrowdStrike's give only a page,
    and Recorded Future's are measured from the other edge. A heading is looked
    for first, so a paragraph that happens to open with the same words is not.
    """
    wanted = _norm(title)
    for headings_only in (True, False):
        for block in blocks_on_page:
            if headings_only and block["size"] < 1.05:
                continue
            have = _norm(block["text"])
            if have and (have.startswith(wanted[:60]) or (len(have) >= 4 and wanted.startswith(have))):
                return block
    return blocks_on_page[0] if blocks_on_page else None


def _outline(doc, blocks: list[dict]) -> tuple[list[dict], int]:
    """The outline entries that name a section, placed on their block, and how
    many were left out."""
    by_page = collections.defaultdict(list)
    for block in blocks:
        by_page[block["page"]].append(block)
    entries, skipped = [], 0
    for level, title, page in doc.get_toc(simple=True):
        title = " ".join(title.split())
        if not _usable_title(title) or page < 1:
            skipped += 1
            continue
        # An entry on a page without text, such as a full-page figure, starts
        # at the first text after it.
        later = next((p for p in sorted(by_page) if p >= page), None)
        block = _place(by_page[later], title) if later is not None else None
        if block is None:
            skipped += 1
            continue
        entries.append({"level": level, "title": title, "block": block["id"]})
    entries.sort(key=lambda e: e["block"])
    return entries, skipped


def _font_headings(blocks: list[dict], lo: int, hi: int) -> list[dict]:
    """The headings of one size, the size that comes back on the most pages.

    At most twice a page, so the labels of an infographic, large but many on
    one page, are not taken for headings, as in ENISA's reports. The cover is
    left out.
    """
    candidates = []
    for block in blocks[lo:hi]:
        if block["kind"] != "h" or block["page"] == 1:
            continue
        previous = candidates[-1] if candidates else None
        if previous and previous["end"] == block["id"] and previous["size"] == block["size"] \
                and previous["page"] == block["page"]:
            previous["title"] += " " + block["text"]
            previous["end"] = block["id"] + 1
        else:
            candidates.append({"title": block["text"], "block": block["id"], "end": block["id"] + 1,
                               "size": block["size"], "page": block["page"]})
    tiers = collections.defaultdict(list)
    for c in candidates:
        tiers[c["size"]].append(c)
    best, best_key = [], None
    for size, found in tiers.items():
        per_page = collections.Counter(c["page"] for c in found)
        key = (len(per_page), size)
        if len(per_page) >= 2 and max(per_page.values()) <= 2 and (best_key is None or key > best_key):
            best, best_key = found, key
    return [{"level": 1, "title": c["title"], "block": c["block"]} for c in best]


def _title(doc, lines) -> str:
    """The title in the PDF's metadata, unless it is a file name, else the
    largest text on the first page with text, read from the top down.

    Only a first guess, which the analyst confirms: a cover sets its title in
    pieces and sizes of its own.
    """
    meta = " ".join((doc.metadata or {}).get("title", "").split())
    if " " in meta and "_" not in meta and not meta.lower().endswith((".indd", ".pdf", ".docx")):
        return meta[:200]
    first = [line for line in lines if line[0] == lines[0][0]] if lines else []
    if not first:
        return ""
    largest = max(line[4] for line in first)
    title = " ".join(line[3] for line in sorted(first, key=lambda line: line[1]) if line[4] >= largest * 0.6)[:200]
    return title.title() if title.isupper() else title


def _created(doc) -> str:
    match = re.match(r"D:(\d{4})(\d{2})(\d{2})", (doc.metadata or {}).get("creationDate", ""))
    return "-".join(match.groups()) if match else ""


def _tlp(lines) -> str:
    """The TLP the document is marked with in its headers, footers or cover.

    CERT-EU's footer says TLP:CLEAR/PUBLIC.
    """
    pages = collections.defaultdict(set)
    for line in lines:
        if line[0] == 0 or _at_edge(line):
            for found in _TLP.findall(line[3]):
                pages[found.lower().replace("white", "clear")].add(line[0])
    return max(pages, key=lambda tlp: len(pages[tlp])) if pages else ""


def read_document(path: str) -> dict:
    """Everything the import keeps of a PDF. Runs in the child process."""
    import pymupdf

    try:
        doc = pymupdf.open(path, filetype="pdf")
    except Exception as exc:
        raise ReportError("The file is not a PDF zsazsa can read.") from exc
    if doc.needs_pass:
        raise ReportError("The PDF is protected with a password.")
    if not doc.page_count:
        raise ReportError("The PDF has no pages.")
    lines = list(_lines(doc))
    running = _running(lines, doc.page_count)
    body = [line for line in lines if not (_at_edge(line) and _shape(line[3]) in running)]
    chars = sum(len(line[3]) for line in body)
    if chars < _SCANNED_CHARS_PER_PAGE * doc.page_count:
        raise ReportError("The PDF has almost no text. It looks scanned, and zsazsa does not read scanned reports.")
    sizes = collections.Counter()
    for line in body:
        sizes[line[4]] += len(line[3])
    blocks = _blocks(body, sizes.most_common(1)[0][0] or 1)
    title = _title(doc, body)
    outline, skipped = _outline(doc, blocks)
    marks, structure = outline, "outline"
    if len(outline) < 2:
        marks, structure = _font_headings(blocks, 0, len(blocks)), "headings"
    if len(marks) < 2:
        marks, structure = [], "size"
    if chars <= _SMALL_DOCUMENT_CHARS:
        structure = "document"
    labels = [page.get_label() for page in doc]
    return {
        "pages": doc.page_count,
        "page_labels": labels if any(labels) else [],
        "title": title,
        "created": _created(doc),
        "tlp": _tlp(lines),
        "running": sorted(running)[:12],
        "characters": sum(len(b["text"]) for b in blocks),
        "blocks": blocks,
        "outline": outline,
        "outline_skipped": skipped,
        "structure": structure,
        "drafts": draft_stories(blocks, marks if structure != "document" else [], title),
    }


# ── Drafting the stories ─────────────────────────────────────────────────────

def _chars(blocks: list[dict], start: int, end: int) -> int:
    return sum(len(b["text"]) for b in blocks[start:end])


def _story(blocks, title, start, end, path):
    return {"title": title, "start": start, "end": end, "path": path,
            "pages": [blocks[start]["page"], blocks[end - 1]["page"]], "chars": _chars(blocks, start, end)}


def _by_pages(blocks, title, start, end, path):
    """A long text with no headings, cut where a page ends once it is long enough."""
    pieces, begin, size = [], start, 0
    for i in range(start, end):
        size += len(blocks[i]["text"])
        page_ends = i + 1 == end or blocks[i + 1]["page"] != blocks[i]["page"]
        if page_ends and (size >= _DESCEND_CHARS or i + 1 == end):
            pieces.append((begin, i + 1))
            begin, size = i + 1, 0
    if len(pieces) == 1:
        return [_story(blocks, title, start, end, path)]
    stories = []
    for a, b in pieces:
        first, last = blocks[a]["page"], blocks[b - 1]["page"]
        stories.append(_story(blocks, f"{title}, page {first}" if first == last else f"{title}, pages {first} to {last}",
                              a, b, path))
    return stories


def _cut(blocks, title, start, end, path):
    """A story, or the pieces of one too long to read as one."""
    if _chars(blocks, start, end) <= _STORY_MAX_CHARS:
        return [_story(blocks, title, start, end, path)]
    stops = [h for h in _font_headings(blocks, start, end) if h["block"] > start]
    if not stops:
        return _by_pages(blocks, title, start, end, path)
    bounds = [start] + [h["block"] for h in stops] + [end]
    titles = [title] + [f"{title}: {h['title']}" for h in stops]
    stories = []
    for piece_title, a, b in zip(titles, bounds, bounds[1:]):
        if stories and _chars(blocks, stories[-1]["start"], a) < _EMPTY_CHARS:
            stories[-1] = _story(blocks, piece_title, stories[-1]["start"], b, path)
        else:
            stories.append(_story(blocks, piece_title, a, b, path))
    return stories


def _tree(marks: list[dict], total: int) -> list[dict]:
    """The marks as a tree by level, each node with the blocks it spans.

    A node ends where the next node that is not under it starts. Built from
    positions rather than trusted as a tree of pages: CrowdStrike's outline has
    five of its six themes under the first.
    """
    roots, stack = [], []
    for m in marks:
        node = {"title": m["title"], "level": m["level"], "start": m["block"], "children": []}
        while stack and stack[-1]["level"] >= node["level"]:
            stack.pop()
        (stack[-1]["children"] if stack else roots).append(node)
        stack.append(node)

    def close(nodes, end):
        for node, after in zip(nodes, nodes[1:] + [None]):
            node["end"] = after["start"] if after else end
            close(node["children"], node["end"])

    close(roots, total)
    return roots


def _made_of_parts(blocks, children) -> bool:
    return len(children) >= 3 and statistics.median(
        _chars(blocks, c["start"], c["end"]) for c in children) >= _SUBSECTION_CHARS


def draft_stories(blocks: list[dict], marks: list[dict], title: str = "") -> list[dict]:
    """Where each story starts and ends, as block ids, contiguous and in order.

    Small stories next to each other are not merged here: which belong together
    is for the model and the analyst, who see the section whole. Folding one
    into the story before it pulled Recorded Future's Section IV opening into
    Section III.
    """
    if not blocks:
        return []
    title = title or "Report"
    if not marks:
        return _cut(blocks, title, 0, len(blocks), [])
    roots = _tree(marks, len(blocks))
    if roots[0]["start"] > 0:
        roots.insert(0, {"title": "Opening pages", "level": 0, "start": 0, "end": roots[0]["start"], "children": []})
    stories = []

    def visit(node, path):
        if node["start"] >= node["end"]:
            return
        children = [c for c in node["children"] if c["start"] < c["end"]]
        if not children or (_chars(blocks, node["start"], node["end"]) <= _DESCEND_CHARS
                            and not _made_of_parts(blocks, children)):
            stories.extend(_cut(blocks, node["title"], node["start"], node["end"], path))
            return
        first = children[0]["start"]
        intro_at = len(stories)
        if _chars(blocks, node["start"], first) >= _EMPTY_CHARS:
            stories.append(_story(blocks, node["title"], node["start"], first, path))
            intro_at = None
        for child in children:
            visit(child, path + [node["title"]])
        # The heading on its own joins the first story under it.
        if intro_at is not None and intro_at < len(stories):
            s = stories[intro_at]
            stories[intro_at] = _story(blocks, s["title"], node["start"], s["end"], s["path"])

    for root in roots:
        visit(root, [])
    return stories


# ── The child process and how the web app calls it ───────────────────────────

def read_pdf(data: bytes) -> dict:
    """Read a PDF in a child process with a time and memory limit.

    Raises ReportError with a message for the analyst when the PDF cannot be
    read, and logs what the child said when it failed some other way.
    """
    if not looks_like_pdf(data):
        raise ReportError("The file is not a PDF.")
    with tempfile.TemporaryDirectory(prefix="zsazsa-report-") as tmp:
        path, answer = Path(tmp) / "report.pdf", Path(tmp) / "reading.json"
        path.write_bytes(data)
        try:
            done = subprocess.run([sys.executable, "-m", "core.report_document", str(path), str(answer)],
                                  cwd=Path(__file__).resolve().parent.parent, capture_output=True,
                                  timeout=_READ_TIMEOUT_S, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ReportError(f"Reading the PDF took longer than {_READ_TIMEOUT_S // 60} minutes.") from exc
        if done.returncode not in (0, 2) or not answer.exists():
            logger.error("report reader exited with %s: %s", done.returncode,
                         done.stderr.decode("utf-8", "replace")[-2000:])
            raise ReportError("The PDF could not be read. The log says why.")
        reading = json.loads(answer.read_text(encoding="utf-8"))
    if done.returncode == 2:
        raise ReportError(reading["error"])
    return reading


def _main(path: str, answer: str) -> int:
    """Read the PDF at path and write what it holds, or why not, to answer.

    The answer goes to a file rather than stdout, where MuPDF may print its
    warnings.
    """
    import resource

    try:
        resource.setrlimit(resource.RLIMIT_AS, (_MEMORY_LIMIT, _MEMORY_LIMIT))
    except ValueError:
        # macOS refuses an address space limit; zsazsa runs on Linux.
        pass
    code = 0
    try:
        reading = read_document(path)
    except ReportError as exc:
        reading, code = {"error": str(exc)}, 2
    except MemoryError:
        reading, code = {"error": "The PDF needs more memory to read than zsazsa allows."}, 2
    Path(answer).write_text(json.dumps(reading), encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1], sys.argv[2]))
