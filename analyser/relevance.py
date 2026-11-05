"""Whether an article is worth an alert and a briefing story, judged once.

One model call per event reads the article against the focus points and the
active PIRs and GIRs, and answers both questions with their grounds, the
article's cti-evaluation scores and its publication date. The verdict is kept
in zsazsa (analyser.event_state) and reused by every later run, of any action,
until its version changes, a hash of what it was judged against (the focus
points with their types, the requirements, the prompt and the model), or the
event's title, date, summary or article do.

The grounds are checked before they count. A focus point must be one in the
settings, or a synonym of a threat actor that is; a requirement must be one
that was sent; and each needs a quote, of four different words or more, from
the article or its title. A quote shortened with an ellipsis has its parts in
the order they are there, each of two words or more.
A "yes" left with no ground is a "no", except a briefing story that is in as a
major development.

Each focus point is sent with its type, from the MISP galaxy it is in: "Energy
(sector)", "Belgium (country)", "APT29 (threat actor; also known as Cozy Bear)".
"""

import hashlib
import logging
import re
from datetime import date, datetime, timezone

import config
from analyser import event_state, llm, settings
from webapp import matching, misp_store

logger = logging.getLogger(__name__)

_PRODUCTS = ("alert", "briefing")
_PRODUCT_NAMES = {"alert": "alerts", "briefing": "briefing"}


def focus_names(key: str) -> list[str]:
    """The names in a focus point setting."""
    return [str(n).strip() for n in (getattr(config, key, []) or []) if str(n).strip()]


def _galaxy_values(galaxy_uuid: str) -> dict:
    """{lower-cased value: value} of a galaxy's clusters."""
    return {value.strip().lower(): value for value in misp_store._fetch_galaxy_clusters(galaxy_uuid)}


def focus_points(synonyms: bool = True) -> list[dict]:
    """Every focus point, as {"name", "type", "synonyms", "found", "setting"}:
    its type from the galaxy it is in, "found" False for a name its galaxy does
    not have, which is sent with the type of its list, and the setting it is
    in. ``synonyms`` False leaves out the threat actors' synonyms, which cost a
    MISP call each, for the settings page."""
    countries = _galaxy_values(misp_store.GALAXY_COUNTRY)
    regions = _galaxy_values(misp_store.GALAXY_TARGET_INFORMATION)
    sectors = _galaxy_values(misp_store.GALAXY_SECTOR)
    actors = _galaxy_values(misp_store.GALAXY_THREAT_ACTOR)
    techniques = {}
    for value in misp_store.galaxy_mitre_attack_patterns():
        name, _, technique = value.rpartition(" - ")
        techniques[name.strip().lower()] = technique

    points = []

    def add(setting, name, kind, found, also_known_as=()):
        points.append({"name": name, "type": kind, "synonyms": [s for s in also_known_as if s], "found": found,
                       "setting": setting})

    for name in focus_names("FOCUS_POINTS_GEOGRAPHIES"):
        key = name.lower()
        kind = "country" if key in countries else "region" if key in regions else "geography"
        add("FOCUS_POINTS_GEOGRAPHIES", name, kind, kind != "geography")
    for name in focus_names("FOCUS_POINTS_SECTORS"):
        add("FOCUS_POINTS_SECTORS", name, "sector", name.lower() in sectors)
    for name in focus_names("FOCUS_POINTS_THREAT_ACTORS"):
        found = name.lower() in actors
        aliases = (misp_store.threat_actor_galaxy_meta(actors[name.lower()]).get("synonyms", [])
                   if found and synonyms else [])
        add("FOCUS_POINTS_THREAT_ACTORS", name, "threat actor", found, aliases)
    for name in focus_names("FOCUS_POINTS_THREAT_TYPES"):
        technique = techniques.get(name.lower())
        add("FOCUS_POINTS_THREAT_TYPES", name, f"technique, ATT&CK {technique}" if technique else "threat type",
            bool(technique))
    for setting, kind in (("FOCUS_POINTS_VENDORS", "vendor"), ("FOCUS_POINTS_TECHNOLOGIES", "technology")):
        for name in focus_names(setting):
            add(setting, name, kind, True)
    return points


def analyst_scores(event) -> dict:
    """The cti-evaluation scores on an event, {dimension: level}. They are all
    analysts': the analyser keeps its own with the verdict, not as tags."""
    found = {}
    for tag in event.tags:
        matched = misp_store._CTI_EVAL_TAG_RE.match(tag.name)
        if matched and matched.group(2) in settings.LEVELS:
            found[matched.group(1)] = matched.group(2)
    return found


def _rank(level: str) -> int:
    return settings.LEVELS.index(level)


def pushed(event, product: str) -> bool:
    """Whether an analyst's relevance score pushes an event into the alerts
    ("alert") or the briefing ("briefing"), past what the verdict says."""
    level = analyst_scores(event).get("relevance")
    threshold = settings.get("ANALYSER_PUSH_ALERT" if product == "alert" else "ANALYSER_PUSH_BRIEFING")
    return bool(level) and _rank(level) >= _rank(threshold)


def pushes(level: str) -> bool:
    """Whether a relevance score an analyst sets pushes an event into the
    alerts or the briefing."""
    return level in settings.LEVELS and _rank(level) >= min(_rank(settings.get("ANALYSER_PUSH_ALERT")),
                                                            _rank(settings.get("ANALYSER_PUSH_BRIEFING")))


def pulled(event) -> bool:
    """Whether an analyst's relevance score keeps an event out of both."""
    level = analyst_scores(event).get("relevance")
    return bool(level) and _rank(level) <= _rank(settings.get("ANALYSER_PULL"))


def unjudged() -> dict:
    """The verdict of an event an analyst pushed before the model answered:
    no grounds, and no version, so it is judged again by the next run."""
    part = {"relevant": False, "grounds": [], "major_development": False, "reason": "Not judged yet"}
    return {"version": "", "alert": dict(part), "briefing": dict(part), "scores": {}, "published": None,
            "published_from": "", "source_type": ""}


def _line(point: dict) -> str:
    if point["synonyms"]:
        return f"{point['name']} ({point['type']}; also known as {', '.join(point['synonyms'])})"
    return f"{point['name']} ({point['type']})"


def _rules() -> str:
    """The rules added after the focus points and requirements."""
    if not settings.get("ANALYSER_MAJOR_DEVELOPMENTS"):
        return ""
    return llm.read_prompt("analyser_major_development.md").strip()


class Judge:
    """What one run judges its events against, read once for the run.

    ``reading`` is the run's analyser.sources.Reading: an event whose answer
    could not be read is read again by the next runs, up to
    ANALYSER_RELEVANCE_ATTEMPTS times.
    """

    def __init__(self, reading):
        self.reading = reading
        self.focus_points = focus_points()
        pirs, girs = matching.get_requirements(strict=True)
        # A requirement nobody wants answered is never a ground.
        pirs = [r for r in pirs if r.priority != "Won't have"]
        self._pir_uuids = {r.uuid for r in pirs}
        self._requirements_by_uuid = {r.uuid: r for r in [*pirs, *girs]}
        self._requirements_by_id = {matching.requirement_id(r).upper(): r for r in self._requirements_by_uuid.values()
                                    if matching.requirement_id(r)}
        self._major_developments = settings.get("ANALYSER_MAJOR_DEVELOPMENTS")
        self._system = llm.relevance_prompt(
            [_line(p) for p in self.focus_points],
            [{"id": matching.requirement_id(r), **matching.requirement_scope(r)} for r in self._requirements_by_uuid.values()],
            _rules())
        self.model = llm.feature_model("judge_relevance")
        # What the verdict depends on is all in the prompt: the prompt file,
        # the focus points with their types and synonyms, the requirements and
        # the major development rule. With the model, that is its version.
        self.version = hashlib.sha256(f"{self._system}\n{self.model}".encode()).hexdigest()[:16]
        # Every name a ground can give, lower-cased, to the focus point it is.
        self._point_names = {}
        for point in self.focus_points:
            for name in [point["name"], *point["synonyms"]]:
                self._point_names.setdefault(name.lower(), point["name"])

    def verdict(self, event, source, article: str, summary: str) -> dict | None:
        """The event's current verdict, judged now when it has none, or one
        judged under other settings or on other evidence. None when the model's
        answer could not be read."""
        stored = event_state.load(source.id, event.uuid)["verdict"]
        seen = evidence(event, article, summary)
        if stored and stored.get("version") == self.version and stored.get("evidence") == seen:
            return stored
        title = event.info or ""
        article = article[:settings.get("ANALYSER_ARTICLE_CHARS")]
        try:
            answer = llm.judge_relevance(self._system, title, summary, article)
        except Exception as exc:
            # No answer at all, as when the model cannot be reached: one event
            # should not end the run for the others. The next run asks again,
            # and an outage does not use up its attempts.
            logger.warning("Relevance call failed for %s: %s", event.uuid, exc)
            self.reading.retry(event.uuid)
            return None
        if answer is None:
            attempts = event_state.count_failed_attempt(source.id, event.uuid)
            if attempts < settings.get("ANALYSER_RELEVANCE_ATTEMPTS"):
                self.reading.retry(event.uuid)
            else:
                logger.warning("No relevance answer for %s after %d attempts; left for the analyst",
                               event.uuid, attempts)
            return None
        # A ground is quoted from the source's own words, not from the summary
        # a model wrote of them.
        verdict = self._checked(answer, f"{title}\n{article}", event, source)
        verdict["evidence"] = seen
        event_state.save_verdict(source.id, event.uuid, verdict)
        return verdict

    def _checked(self, answer: dict, sent: str, event, source) -> dict:
        text = _normalised(sent)
        verdict = {"version": self.version, "model": self.model,
                   "judged_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        for product in _PRODUCTS:
            part = answer[product]
            grounds = self._grounds(part["grounds"], text, event)
            major = product == "briefing" and self._major_developments and part.get("major_development") is True
            reason = part["reason"].strip()
            if part["relevant"] and not grounds and not major:
                reason = "None of the grounds the model gave is quoted from the article"
            verdict[product] = {"relevant": part["relevant"] and bool(grounds or major), "grounds": grounds,
                                "major_development": major and not grounds, "reason": reason}
        verdict["scores"] = answer["scores"]
        verdict["published"], verdict["published_from"] = _publication_date(answer["publication_date"], event,
                                                                             source)
        verdict["source_type"] = answer["source_type"]
        return verdict

    def _grounds(self, grounds: list, text: str, event) -> list[dict]:
        kept, seen = [], set()
        for ground in grounds:
            name = ground["name"].strip()
            point = self._point_names.get(name.lower())
            requirement = None if point else self._requirements_by_id.get(name.upper())
            if point is None and requirement is None:
                logger.info("Ground %r for %s is no focus point or requirement; dropped", name, event.uuid)
                continue
            if not _quoted(ground["quote"], text):
                logger.info("Ground %r for %s has no quote from the article; dropped", name, event.uuid)
                continue
            key = point or requirement.uuid
            if key in seen:
                continue
            seen.add(key)
            if point:
                kept.append({"focus_point": point, "quote": ground["quote"].strip()})
            else:
                kept.append({"requirement": requirement.uuid, "id": matching.requirement_id(requirement),
                             "quote": ground["quote"].strip()})
        return kept

    def wants(self, verdict: dict, product: str, event) -> tuple[bool, str]:
        """Whether a verdict wants an event for "alert" or "briefing", and why
        or why not. An analyst's relevance score pushes or pulls it, whatever
        the verdict says, and the analyst's other scores take the model's place
        in the limits."""
        level = analyst_scores(event).get("relevance")
        if pulled(event):
            return False, f"An analyst scored its relevance {level}"
        if pushed(event, product):
            return True, f"Pushed by an analyst, who scored its relevance {level}"
        part = verdict[product]
        if not part["relevant"]:
            return False, part["reason"] or f"Not relevant for the {_PRODUCT_NAMES[product]}"
        failed = failed_limit(verdict, product, event)
        if failed:
            return False, f"Its {failed} score is under the limit for the {_PRODUCT_NAMES[product]}"
        if product == "alert" and not self._alert_allowed(part["grounds"]):
            return False, "Its only grounds are PIRs whose priority gives no alert"
        return True, part["reason"]

    def _alert_allowed(self, grounds: list) -> bool:
        """A focus point or a GIR may give an alert; a PIR only with a priority
        of ANALYSER_ALERT_MIN_PRIORITY or higher."""
        for ground in grounds:
            uuid = ground.get("requirement")
            if uuid not in self._pir_uuids or self._requirements_by_uuid[uuid].priority in _alert_priorities():
                return True
        return False

    def pir_priority(self, verdict: dict) -> int:
        """The highest MoSCoW priority among the PIRs in a verdict's briefing
        grounds: 0 for "Must have", 1 for "Should have", 2 for "Could have",
        and 3 when no PIR is among them."""
        priorities = [self._requirements_by_uuid[g["requirement"]].priority for g in verdict["briefing"]["grounds"]
                      if g.get("requirement") in self._pir_uuids]
        return min((settings.PRIORITIES.index(p) for p in priorities if p in settings.PRIORITIES), default=3)

    def requirements_of(self, grounds: list) -> list:
        """The PIRs and GIRs among grounds, as their records."""
        return [self._requirements_by_uuid[g["requirement"]] for g in grounds
                if g.get("requirement") in self._requirements_by_uuid]


def evidence(event, article: str, summary: str) -> str:
    """A fingerprint of what a verdict is judged on: the title, the date, the
    summary and the part of the article the model reads. An article fetched
    again, or replaced, is judged again, and what became of it before no longer
    holds."""
    article = article[:settings.get("ANALYSER_ARTICLE_CHARS")]
    return hashlib.sha256(f"{event.info or ''}\n{event.date}\n{summary}\n{article}".encode()).hexdigest()[:16]


def _normalised(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


# A quote of fewer different words proves nothing: "IT" or "Energy" alone, or
# repeated, is in almost any article, and the ground would be let in on the
# word itself.
_QUOTE_MIN_WORDS = 4


def _quoted(quote: str, text: str) -> bool:
    """Whether a quote is in the normalised text sent, case and whitespace
    ignored. A quote shortened with an ellipsis counts when its parts are
    there in that order, each of two words or more: "the ... market ... in
    ... city" is four words found anywhere."""
    parts = [_normalised(p).strip(" \"'") for p in re.split(r"\.\.\.|…", quote or "")]
    parts = [p for p in parts if p]
    words = {word for p in parts for word in p.split()}
    if len(words) < _QUOTE_MIN_WORDS or (len(parts) > 1 and min(len(p.split()) for p in parts) < 2):
        return False
    at = 0
    for part in parts:
        at = text.find(part, at)
        if at < 0:
            return False
        at += len(part)
    return True


def _publication_date(answer: str | None, event, source) -> tuple[str | None, str]:
    """The article's publication date, and where it came from ("article" or
    "event"), or (None, "") when there is none to go by.

    A date the model read after the event's own date is discarded: the event
    was scraped or created that day, so the article cannot be newer. Without a
    usable date, a manual entry's or another server's event date is used, as
    whoever made the event set it; a scraper event's is the day of the scrape.
    """
    event_day = event.date
    try:
        published = date.fromisoformat(answer) if answer else None
    except ValueError:
        published = None
    if published and (event_day is None or published <= event_day):
        return published.isoformat(), "article"
    if source.kind != "scraper" and event_day:
        return event_day.isoformat(), "event"
    return None, ""


def _alert_priorities() -> tuple:
    lowest = settings.get("ANALYSER_ALERT_MIN_PRIORITY")
    return settings.PRIORITIES[:settings.PRIORITIES.index(lowest) + 1]


def timeliness(verdict: dict, today: date | None = None) -> str | None:
    """The article's timeliness by its age on ``today``, or None when its
    publication date is not known."""
    if not verdict.get("published"):
        return None
    age = ((today or datetime.now(timezone.utc).date()) - date.fromisoformat(verdict["published"])).days
    for level in ("very-high", "high", "moderate", "low"):
        if age <= settings.get(f"ANALYSER_{level.replace('-', '_').upper()}_TIMELINESS_DAYS"):
            return level
    return "very-low"


def scores(verdict: dict, event=None, today: date | None = None) -> dict:
    """The event's scores, {dimension: level}: the model's, the timeliness
    calculated from the publication date, and in the place of either an
    analyst's, when the event has one."""
    found = dict(verdict.get("scores") or {})
    level = timeliness(verdict, today)
    if level:
        found["timeliness"] = level
    if event is not None:
        found.update(analyst_scores(event))
    return found


def _value(level: str) -> int:
    return _rank(level) * 25


def overall(verdict: dict, event=None, today: date | None = None) -> float | None:
    """The weighted average of usefulness, specificity and timeliness, 0 to
    100, of those that were scored; None when none was. An analyst's own
    overall score takes its place."""
    found = scores(verdict, event, today)
    if "overall-score" in found:
        return _value(found["overall-score"])
    weighted = [(_value(found[dim]), settings.get(f"ANALYSER_WEIGHT_{dim.upper()}"))
                for dim in ("usefulness", "specificity", "timeliness") if dim in found]
    total = sum(weight for _score, weight in weighted)
    return sum(value * weight for value, weight in weighted) / total if total else None


def failed_limit(verdict: dict, product: str, event=None, today: date | None = None) -> str:
    """The first dimension whose score is under the product's limit, or "".
    A dimension that was not scored, such as the timeliness of an article
    whose date is not known, does not fail."""
    found = scores(verdict, event, today)
    for dim in ("timeliness", "usefulness", "specificity", "overall"):
        minimum = settings.get(f"ANALYSER_{product.upper()}_MIN_{dim.upper()}")
        if not minimum:
            continue
        value = overall(verdict, event, today) if dim == "overall" else (_value(found[dim]) if dim in found else None)
        if value is not None and value < _value(minimum):
            return dim
    return ""
