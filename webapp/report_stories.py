"""The stories of an imported report: proposing them with the model, the
analyst's review, and making them collection events for the threat landscape.

A report's manifest (misp_store.report_manifest) lists its stories in the
order of the report. Each one runs from its start to the next one's, so the
starts alone say where the report is cut:

    {"read": what the import read (pages, outline, lines left out),
     "stories": [{"id", "title", "start", "end", "pages", "chars", "path",
                  "kind", "context", "context_for", "context_failed", "event"}],
     "ai": {"parts": [[start, end], ...], "split": [start of each part done],
            "closed": once the analyst has saved a review},
     "skipped": [the blocks the analyst left out of the stories]}

"context" is what the model proposed and the analyst corrected, each value
with the block that states it. "context_for" is the [start, end] it was
proposed for, so the review can say when a story has moved since. "event" is
the UUID of the story's collection event once it is made, after which the
story cannot be moved any more. A block in "skipped" is in no story's text,
length or what the model reads: a sales pitch or a reference list in the
middle of a story is left out that way rather than by editing the report's
own words.
"""

import logging
import re
from uuid import uuid4

import config
from webapp import collection_cache, job_store, misp_store

logger = logging.getLogger(__name__)

# The kinds a story can be, as Settings > Products sets them
# (REPORT_STORY_KINDS): each with what it means, which the model is told and
# the review shows, and whether select all ticks it in the threat landscape
# queue. "excluded" is always there besides them: it is what Leave out sets,
# and no event is made of a story of that kind.
LEFT_OUT = "excluded"
LEFT_OUT_NOTE = ("Left out: no event is made of it. For what a threat landscape has no use for: the contents, an "
                 "index, about the publisher, sales text such as \"How we can help\", references and legal text.")
DEFAULT_KINDS = [
    {"name": "assessment", "ticked": True,
     "description": "The publisher's analysis of a threat, an actor, a region or a trend over the period."},
    {"name": "incident", "ticked": True, "description": "One attack, breach, campaign or operation."},
    {"name": "finding", "ticked": True,
     "description": "A statistic or a result from the publisher's own data or survey."},
    {"name": "outlook", "ticked": False,
     "description": "Forecasts, predictions, looking ahead: what the publisher expects next."},
    {"name": "context", "ticked": False,
     "description": "Background without threat content of its own: a foreword, the methodology, a policy overview, "
                    "a conclusion that only repeats."},
]


def normalise_kinds(raw) -> list:
    """Kinds as Settings may store them: a name in lower case with hyphens,
    each once, never "excluded", with a description and whether it is ticked."""
    kinds, seen = [], {LEFT_OUT}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = re.sub(r"[^a-z0-9]+", "-", str(item.get("name") or "").strip().lower()).strip("-")[:40]
        if name and name not in seen:
            kinds.append({"name": name, "description": " ".join(str(item.get("description") or "").split())[:400],
                          "ticked": bool(item.get("ticked"))})
            seen.add(name)
    return kinds


def kinds() -> list:
    """The kinds Settings has, or the built-in ones when it has none."""
    return normalise_kinds(getattr(config, "REPORT_STORY_KINDS", None)) or DEFAULT_KINDS


def kind_names() -> list:
    return [k["name"] for k in kinds()] + [LEFT_OUT]


def kind_notes() -> dict:
    return {**{k["name"]: k["description"] for k in kinds()}, LEFT_OUT: LEFT_OUT_NOTE}


def unticked_kinds() -> list:
    """Kinds that are made into events and queued, but that select all does
    not tick in the queue, such as what a report expects or its background."""
    return [k["name"] for k in kinds() if not k["ticked"]]


CONTEXT_LISTS = ("sectors", "geographic_scope", "threat_actors", "techniques")
CONTEXT_TEXTS = ("affected_assets", "impact", "motivation", "mitigation")
QUEUE_LABEL = "threat-landscape-report"

# Drafts the model is shown in one call, so a long report is asked in parts
# that each fit a small model's context.
_PART_DRAFTS = 20
_OPENING_CHARS = 400
# The text of one story the model reads: as long as a draft can be
# (core.report_document), and a story the analyst merged is read that far.
_STORY_CHARS = 30_000
# The context of a story is saved every so many stories, so an import that
# stops loses little of what the model already answered.
_SAVE_EVERY = 5
_ID = re.compile(r"[a-z0-9]{4,16}")


def new_id() -> str:
    return uuid4().hex[:10]


def _measure(stories: list, blocks: list, end: int, skipped=frozenset()) -> list:
    """Each story with the end, pages and length its start and the next one's give it."""
    for story, after in zip(stories, stories[1:] + [None]):
        story["end"] = after["start"] if after else end
        story["pages"] = [blocks[story["start"]]["page"], blocks[story["end"] - 1]["page"]]
        story["chars"] = sum(len(b["text"]) for b in blocks[story["start"]:story["end"]] if b["id"] not in skipped)
    return stories


def _kept(story: dict, blocks: list, skipped) -> list:
    """The blocks of a story the analyst did not leave out."""
    return [b for b in blocks[story["start"]:story["end"]] if b["id"] not in skipped]


def _story(start: int, title: str, path: list, kind: str = "", id_: str = "") -> dict:
    return {"id": id_ or new_id(), "title": title, "start": start, "path": path, "kind": kind,
            "context": None, "context_for": None, "context_failed": False, "event": ""}


def _parts(stories: list, depth: int = 1) -> list:
    """The stories in runs under one section, at most _PART_DRAFTS each.

    A section's own story, its introduction, goes with the stories under it,
    so the model can merge the two. A run too long is cut at the next level of
    the outline, or by count at the deepest one. Runs of a single story join
    the run before them, which saves a call for each.
    """
    runs = []
    for story in stories:
        key = tuple((story["path"] + [story["title"]])[:depth])
        if runs and runs[-1][0] == key:
            runs[-1][1].append(story)
        else:
            runs.append((key, [story]))
    parts = []
    for _key, run in runs:
        if len(run) > _PART_DRAFTS and depth < 4 and any(len(s["path"]) >= depth for s in run):
            parts.extend(_parts(run, depth + 1))
        else:
            parts.extend(run[i:i + _PART_DRAFTS] for i in range(0, len(run), _PART_DRAFTS))
    joined = []
    for part in parts:
        if joined and (len(part) == 1 or len(joined[-1]) == 1) and len(joined[-1]) + len(part) <= _PART_DRAFTS:
            joined[-1] = joined[-1] + part
        else:
            joined.append(part)
    return joined


def new_manifest(reading: dict) -> dict:
    """The manifest of a report just read: its drafts as stories, not yet
    named, classified or read by the model."""
    blocks = reading["blocks"]
    stories = _measure([_story(d["start"], d["title"], d["path"]) for d in reading["drafts"]], blocks, len(blocks))
    return {
        "read": {k: reading[k] for k in ("structure", "outline_skipped", "running", "tlp", "created", "title")}
        | {"outline": len(reading["outline"]), "blocks": len(blocks)},
        "stories": stories,
        "ai": {"parts": [[p[0]["start"], p[-1]["end"]] for p in _parts(stories)], "split": [], "closed": False},
    }


def calls_left(manifest: dict) -> int:
    """The model calls the AI still has to make for this report."""
    ai = manifest.get("ai") or {}
    parts = 0 if ai.get("closed") else sum(1 for p in ai.get("parts", []) if p[0] not in ai.get("split", []))
    stories = sum(1 for s in manifest["stories"] if needs_context(s))
    return parts + stories


def needs_context(story: dict) -> bool:
    return story["kind"] != LEFT_OUT and story["context"] is None and not story.get("context_failed")


# ── Asking the model ─────────────────────────────────────────────────────────

def _headings(blocks: list, start: int, end: int) -> list:
    return [b for b in blocks[start + 1:end] if b["kind"] == "h"]


def drafts_text(part: list, blocks: list) -> str:
    """A part of the report as the split prompt reads it: per draft its first
    block, pages, length, the headings inside it and how it opens."""
    lines = []
    for n, s in enumerate(part, 1):
        opening = " ".join(b["text"] for b in blocks[s["start"]:s["end"]] if b["kind"] != "h")[:_OPENING_CHARS]
        lines.append(f"Draft {n}, first block {s['start']}, pages {s['pages'][0]} to {s['pages'][1]}, "
                     f"{s['chars']:,} characters: {s['title']}")
        if s["path"]:
            lines.append(f"Under: {' > '.join(s['path'])}")
        heads = _headings(blocks, s["start"], s["end"])
        if heads:
            lines.append("Headings inside: " + "; ".join(f"[block {h['id']}] {h['text']}" for h in heads))
        lines.append(f"Opens: {opening}\n")
    return "\n".join(lines)


def apply_split(part: list, answer: dict, blocks: list) -> list | None:
    """The stories of a part as the model cut and named them, or None when it
    named no start the part offers. A start it may not use is left out, and a
    draft it kept keeps its id."""
    offered = {s["start"] for s in part} | {h["id"] for s in part for h in _headings(blocks, s["start"], s["end"])}
    allowed = kind_names()
    chosen = {}
    for item in answer.get("stories") if isinstance(answer.get("stories"), list) else []:
        start = item.get("start") if isinstance(item, dict) else None
        if type(start) is not int or start not in offered or start in chosen:
            continue
        title = " ".join(str(item.get("title") or "").split())[:200]
        chosen[start] = (title, item.get("kind") if item.get("kind") in allowed else "")
    if not chosen:
        return None
    chosen.setdefault(part[0]["start"], (part[0]["title"], ""))
    stories = []
    for start in sorted(chosen):
        title, kind = chosen[start]
        draft = next(s for s in reversed(part) if s["start"] <= start)
        same = draft["start"] == start
        stories.append(_story(start, title or (draft["title"] if same else blocks[start]["text"]),
                              draft["path"] if same else draft["path"] + [draft["title"]], kind,
                              draft["id"] if same else ""))
    return _measure(stories, blocks, part[-1]["end"])


def story_blocks(story: dict, blocks: list, skipped=frozenset()) -> str:
    """A story's text as the context prompt reads it, each block with its number."""
    lines, size = [], 0
    for b in _kept(story, blocks, skipped):
        line = f"[{b['id']}] {'# ' if b['kind'] == 'h' else ''}{b['text']}"
        size += len(line)
        if size > _STORY_CHARS:
            lines.append("(The rest of the story is left out.)")
            break
        lines.append(line)
    return "\n".join(lines)


def galaxies() -> dict:
    """What a context value is checked against: each galaxy's names by their
    lower case, and the ATT&CK techniques by their id."""
    named = {
        "sectors": misp_store.galaxy_sectors(),
        "geographic_scope": misp_store.galaxy_geography(),
        "threat_actors": misp_store.galaxy_threat_actors(),
    }
    for key, items in named.items():
        if not items:
            logger.warning("report stories: the %s galaxy could not be read, so no value of it is kept", key)
    found = {key: {v.strip().lower(): v for v in items} for key, items in named.items()}
    found["techniques"] = {misp_store.technique_id(t): t for t in misp_store.galaxy_mitre_attack_patterns()
                           if misp_store.technique_id(t)}
    return found


def _threat_type(value) -> str:
    """The threat type of the landscape list that value names, in any case, or ""."""
    wanted = str(value or "").strip().lower()
    return next((t for t in misp_store.tlr_threat_types() if t.lower() == wanted), "")


def _known(key: str, value, known: dict) -> str:
    value = str(value or "").strip()
    if key == "techniques":
        return known["techniques"].get(misp_store.technique_id(value), "")
    return known[key].get(value.lower(), "")


_GALAXY_NAMES = {"sectors": "sector", "geographic_scope": "country and region", "threat_actors": "threat actor",
                 "techniques": "ATT&CK"}


def clean_context(answer: dict, story: dict, known: dict) -> dict:
    """The model's context of a story, with only what holds: values from the
    galaxies and the threat types, each with a block of the story.

    What it named that does not hold is listed under "left_out" with why, so
    the analyst sees it: a ransomware gang the galaxy does not know yet is
    worth knowing about, even if it cannot become a tag.
    """
    inside = range(story["start"], story["end"])
    left_out = []

    def block(item):
        b = item.get("block") if isinstance(item, dict) else None
        if isinstance(b, str) and b.strip().isdigit():
            b = int(b)
        return b if type(b) is int and b in inside else None

    def drop(field, value, why):
        if str(value or "").strip():
            left_out.append({"field": field, "value": " ".join(str(value).split())[:120], "why": why})

    context = {"summary": " ".join(str(answer.get("summary") or "").split())[:1200],
               "period": " ".join(str(answer.get("period") or "").split())[:60]}
    for key in CONTEXT_LISTS:
        values, seen = [], set()
        for item in answer.get(key) if isinstance(answer.get(key), list) else []:
            named = item.get("value") if isinstance(item, dict) else item
            value = _known(key, named, known)
            if not value:
                drop(key, named, f"not in the MISP {_GALAXY_NAMES[key]} galaxy")
            elif block(item) is None:
                drop(key, named, "no paragraph of this story says it")
            elif value not in seen:
                values.append({"value": value, "block": block(item)})
                seen.add(value)
        context[key] = values
    threat = answer.get("threat_type")
    named = threat.get("value") if isinstance(threat, dict) else threat
    value = _threat_type(named)
    context["threat_type"] = None
    if named and not value:
        drop("threat_type", named, "not one of the threat types of a threat landscape")
    elif value and block(threat) is None:
        drop("threat_type", named, "no paragraph of this story says it")
    elif value:
        context["threat_type"] = {"value": value, "block": block(threat)}
    for key in CONTEXT_TEXTS:
        item = answer.get(key)
        text = " ".join(str(item.get("text") or "").split())[:600] if isinstance(item, dict) else ""
        context[key] = {"text": text, "block": block(item)} if text and block(item) is not None else None
        if text and context[key] is None:
            drop(key, text, "no paragraph of this story says it")
    context["left_out"] = left_out
    return context


def _load(report_uuid: str):
    report = misp_store.get_report_document(report_uuid)
    if report is None:
        raise ValueError(f"report {report_uuid} not found")
    meta = {"title": report.title, "provider": report.provider, "published": report.published}
    return report, misp_store.report_manifest(report), misp_store.report_reading(report)["blocks"], meta


def run_split(job_id: str, report_uuid: str) -> None:
    """Have the model cut, name and classify the stories, part by part.

    Each part is saved as it is answered, so a run that stops goes on from the
    next part. Once the analyst has saved a review, the cut is theirs and
    nothing is asked. Raises what stopped it.
    """
    from analyser import llm

    report, manifest, blocks, meta = _load(report_uuid)
    ai, version = manifest["ai"], report.version
    todo = [] if ai["closed"] else [p for p in ai["parts"] if p[0] not in ai["split"]]
    for n, (lo, hi) in enumerate(todo, 1):
        stories = manifest["stories"]
        part = [s for s in stories if lo <= s["start"] < hi]
        message = f"Naming and classifying the stories, part {n} of {len(todo)}"
        job_store.update_job(job_id, message=message)
        with job_store.heartbeat(job_id, message):
            answer = llm.split_report_stories(meta, drafts_text(part, blocks), kinds()) if part else None
        cut = apply_split(part, answer, blocks) if answer else None
        if cut is not None:
            at = stories.index(part[0])
            manifest["stories"] = stories[:at] + cut + stories[at + len(part):]
        elif part:
            job_store.append_log(job_id, f"Part {n}: the model's answer could not be used, so its drafts stay as they are.")
        ai["split"].append(lo)
        version = misp_store.save_report_manifest(report_uuid, manifest, version)


def run_context(job_id: str, report_uuid: str) -> None:
    """Have the model read the context of each story that has none, saving
    every few stories. A story whose answer could not be used is marked so,
    and left for the analyst to ask again. Raises what stopped it."""
    from analyser import llm

    report, manifest, blocks, meta = _load(report_uuid)
    version = report.version
    skipped = set(manifest.get("skipped", []))
    todo = [s for s in manifest["stories"] if needs_context(s)]
    known = galaxies() if todo else {}
    for n, story in enumerate(todo, 1):
        message = f"Reading the context of story {n} of {len(todo)}"
        job_store.update_job(job_id, message=message)
        with job_store.heartbeat(job_id, message):
            answer = llm.analyse_report_story(meta, story, story_blocks(story, blocks, skipped), kinds(),
                                              sorted(set(known["sectors"].values())), misp_store.tlr_threat_types())
        if answer is None:
            story["context_failed"] = True
            job_store.append_log(job_id, f"{story['title']}: the model's answer could not be used.")
        else:
            set_context(story, clean_context(answer, story, known), answer.get("kind"))
        if n % _SAVE_EVERY == 0 or n == len(todo):
            version = misp_store.save_report_manifest(report_uuid, manifest, version)


def set_context(story: dict, context: dict, kind=None) -> None:
    story["context"] = context
    story["context_for"] = [story["start"], story["end"]]
    story["context_failed"] = False
    if kind in kind_names():
        story["kind"] = kind


def analyse_one(report_uuid: str, story: dict, skipped=frozenset()) -> dict:
    """The model's context of one story as the analyst has cut it, and without
    the blocks they left out, for the review to apply. Nothing is saved: the
    analyst saves it with the review."""
    from analyser import llm

    _report, _manifest, blocks, meta = _load(report_uuid)
    known = galaxies()
    answer = llm.analyse_report_story(meta, story, story_blocks(story, blocks, skipped), kinds(),
                                      sorted(set(known["sectors"].values())), misp_store.tlr_threat_types())
    if answer is None:
        raise ValueError("The model's answer could not be used. Try again, or fill in the context yourself.")
    return {"context": clean_context(answer, story, known), "context_for": [story["start"], story["end"]],
            "kind": answer.get("kind") if answer.get("kind") in kind_names() else story["kind"]}


# ── The analyst's review ─────────────────────────────────────────────────────

def _clean_values(key: str, items, known: dict) -> list:
    values, seen = [], set()
    for item in items if isinstance(items, list) else []:
        value = _known(key, item.get("value") if isinstance(item, dict) else "", known)
        b = item.get("block") if isinstance(item, dict) else None
        if value and value not in seen:
            values.append({"value": value, "block": b if type(b) is int else None})
            seen.add(value)
    return values


def _clean_review_context(context, known: dict):
    """A context as the analyst edited it. Values must still be the galaxies'
    and the threat types'; one the analyst added has no block."""
    if not isinstance(context, dict):
        return None
    clean = {"summary": " ".join(str(context.get("summary") or "").split())[:1200],
             "period": " ".join(str(context.get("period") or "").split())[:60]}
    for key in CONTEXT_LISTS:
        clean[key] = _clean_values(key, context.get(key), known)
    threat = context.get("threat_type")
    value = _threat_type(threat.get("value")) if isinstance(threat, dict) else ""
    clean["threat_type"] = ({"value": value, "block": threat.get("block") if type(threat.get("block")) is int else None}
                            if value else None)
    for key in CONTEXT_TEXTS:
        item = context.get(key)
        text = " ".join(str(item.get("text") or "").split())[:600] if isinstance(item, dict) else ""
        clean[key] = {"text": text, "block": item.get("block") if type(item.get("block")) is int else None} \
            if text else None
    left_out = context.get("left_out")
    clean["left_out"] = [{k: " ".join(str(item.get(k) or "").split())[:200] for k in ("field", "value", "why")}
                         for item in (left_out[:40] if isinstance(left_out, list) else []) if isinstance(item, dict)]
    return clean


def review_skipped(manifest: dict, sent, blocks: list) -> list:
    """The blocks the analyst left out, checked. One inside a story already
    made into an event keeps the state it was made with."""
    if not isinstance(sent, list) or not all(type(b) is int and 0 <= b < len(blocks) for b in sent):
        raise ValueError("The paragraphs left out could not be read.")
    made = [range(s["start"], s["end"]) for s in manifest["stories"] if s.get("event")]
    before = set(manifest.get("skipped", []))
    wanted = {b for b in sent if not any(b in r for r in made)}
    return sorted(wanted | {b for b in before if any(b in r for r in made)})


def review(manifest: dict, sent: list, blocks: list, known: dict, skipped=frozenset()) -> list:
    """The stories as the analyst left them on the review page, checked.

    Raises ValueError with what is wrong. A story already made into an event
    keeps its place: its event says which blocks it is made of.
    """
    if not isinstance(sent, list) or not sent:
        raise ValueError("The review has no stories.")
    before = {s["id"]: s for s in manifest["stories"]}
    allowed = kind_names()
    stories, ids = [], set()
    for n, item in enumerate(sent, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Story {n} could not be read.")
        sid, start = str(item.get("id") or ""), item.get("start")
        if not _ID.fullmatch(sid) or sid in ids:
            raise ValueError(f"Story {n} has no id of its own.")
        if type(start) is not int or not 0 <= start < len(blocks) or (stories and start <= stories[-1]["start"]):
            raise ValueError(f"Story {n} does not start after the story before it.")
        title = " ".join(str(item.get("title") or "").split())[:200]
        if not title:
            raise ValueError(f"Story {n} has no title.")
        old = before.get(sid, {})
        # A kind Settings no longer has stays on the story that has it.
        kind = item.get("kind")
        kind = kind if isinstance(kind, str) and (kind in allowed or kind == old.get("kind")) else ""
        if old.get("event"):
            # Its event is made from what it said then; the page does not edit
            # it any more, and neither does a save.
            story = {**old, "start": start}
        else:
            story = _story(start, title, old.get("path") or (stories[-1]["path"] if stories else []), kind, sid)
            span = item.get("context_for")
            story.update(context=_clean_review_context(item.get("context"), known),
                         context_failed=bool(old.get("context_failed")) and item.get("context") is None,
                         context_for=span if (isinstance(span, list) and len(span) == 2
                                              and all(type(v) is int for v in span)) else old.get("context_for"))
        stories.append(story)
        ids.add(sid)
    if stories[0]["start"] != 0:
        raise ValueError("The first story must start at the beginning of the report.")
    _measure(stories, blocks, len(blocks), skipped)
    kept = {s["id"]: s for s in stories}
    for old in manifest["stories"]:
        if old.get("event"):
            new = kept.get(old["id"])
            if new is None or (new["start"], new["end"]) != (old["start"], old["end"]):
                raise ValueError(f'"{old["title"]}" is a collection event already, so it cannot be moved '
                                 f"or merged.")
    return stories


# ── Making the events ────────────────────────────────────────────────────────

def story_markdown(report, story: dict, blocks: list, skipped=frozenset()) -> str:
    """The text of a story as its event report: where it is from, then the
    report's own text with its headings and captions."""
    first, last = story["pages"]
    pages = f"page {first}" if first == last else f"pages {first} to {last}"
    lines = [f"*From {report.title}, {report.provider}, {pages}.*"]
    for b in _kept(story, blocks, skipped):
        lines.append(f"### {b['text']}" if b["kind"] == "h" else f"*{b['text']}*" if b["kind"] == "cap" else b["text"])
    return "\n\n".join(lines)


def to_create(manifest: dict) -> list:
    return [s for s in manifest["stories"] if s["kind"] != LEFT_OUT and not s.get("event")]


def run_create(job_id: str, report_uuid: str) -> dict:
    """Make the collection event of each story left to make, and queue it for
    the threat landscape. The manifest records each event, also when a later
    one fails. Returns what was made, queued and went wrong."""
    from webapp.routes.data_collection import _refresh_cached_event

    report = misp_store.get_report_document(report_uuid)
    manifest = misp_store.report_manifest(report)
    blocks = misp_store.report_reading(report)["blocks"]
    skipped = set(manifest.get("skipped", []))
    misp = misp_store._misp()
    source_id = collection_cache.manual_source_id(report.collection_source)
    todo = to_create(manifest)
    made = queued = 0
    problems = []
    stopped = None
    try:
        for n, story in enumerate(todo, 1):
            job_store.update_job(job_id, message=f"Making story {n} of {len(todo)}: {story['title']}")
            uuid, new = misp_store.create_report_story(report, story, story_markdown(report, story, blocks, skipped))
            story["event"] = uuid
            made += new
            problem = misp_store.product_source_problem(uuid, QUEUE_LABEL, misp_client=misp)
            if problem:
                problems.append(f"{story['title']} was made but not queued: {problem}")
            else:
                queued += 1
            _refresh_cached_event(uuid, source_id, misp, context="making a report's story")
    except Exception as exc:
        stopped = exc
    if any(s.get("event") for s in todo):
        try:
            misp_store.save_report_manifest(report_uuid, manifest, report.version,
                                            import_state="" if to_create(manifest) else "created")
        except Exception:
            if stopped is None:
                raise
            # The events have the UUIDs a next try makes them with, so it
            # finds them again; what stopped this one is what to report.
            logger.exception("report %s: the events made could not be recorded", report_uuid)
    if stopped is not None:
        raise stopped
    return {"made": made, "queued": queued, "problems": problems}
