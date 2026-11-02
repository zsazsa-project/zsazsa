"""Whether an alert or a briefing story would tell a story already told.

The scraper reads an article again as a new event when its title changes, and
several sites write up one incident, so the same story reaches the analyser
more than once over days. Each candidate is compared with the alerts, or the
briefing stories, of the last ANALYSER_SIMILARITY_DAYS days, in any state, a
rejected one included. A cheap shortlist comes first: those that share
a CVE or a threat actor with it, a threat actor tagged on one and named in the
text of the other included, or enough of the words of their titles. Only
when there is one does a model call compare them, and say whether the
candidate adds facts the earlier one does not have. Without new facts it is a
duplicate; with them, an update of the earlier one.
"""

import logging
import re
from datetime import datetime, timedelta, timezone

from analyser import llm, settings
from core.vuln_lookup import CVE_RE
from webapp import collection_cache, matching as req_matching, misp_store

logger = logging.getLogger(__name__)

_ACTOR_TAG = 'misp-galaxy:threat-actor="'


def story(product_id: str, title: str, content: str, actors=(), rejected: bool = False) -> dict:
    """A story as it is compared: an alert, a briefing story or a candidate."""
    return {"id": product_id, "title": title or "", "content": content or "",
            "cves": {cve.upper() for cve in CVE_RE.findall(f"{title}\n{content}")},
            "actors": {a.strip().lower() for a in actors if a and a.strip()}, "rejected": rejected}


def event_story(event, summary: str, article: str) -> dict:
    """An event as a candidate: its summary, or its article when it has none.
    Its CVEs are also those of its vulnerability attributes and of the
    article, which a summary can leave out."""
    actors = [t.name[len(_ACTOR_TAG):-1] for t in event.tags if t.name.startswith(_ACTOR_TAG)]
    candidate = story(event.uuid, event.info or "", summary or article, actors)
    candidate["cves"] |= {cve.upper() for cve in CVE_RE.findall(article)} | set(collection_cache.event_cves(event))
    return candidate


def _since() -> datetime:
    days = settings.get("ANALYSER_SIMILARITY_DAYS")
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)


def recent_alerts() -> list[dict]:
    """The alerts of the lookback, in any state."""
    return [story(fia.fia_id, fia.title, "\n".join([fia.summary, *fia.what_happened]), fia.threat_actors,
                  rejected=fia.review_state == misp_store.FIA_REVIEW_REJECTED)
            for fia in misp_store.list_fias(strict=True) if fia.created_at and fia.created_at >= _since()]


def recent_stories(but=None) -> list[dict]:
    """The stories of the briefings of the lookback, in any state, but those
    of ``but``, the draft the run adds to, which its overlap check covers."""
    oldest = _since().date().isoformat()
    stories = []
    for briefing in misp_store.list_briefings(strict=True):
        if briefing.date < oldest or (but is not None and briefing.uuid == but.uuid):
            continue
        rejected = briefing.review_state == misp_store.BRIEFING_REVIEW_REJECTED
        for s in briefing.stories:
            stories.append(story(f"the briefing of {briefing.date}", getattr(s, "title", ""),
                                 getattr(s, "content", ""), getattr(s, "threat_actors", None) or (),
                                 rejected=rejected))
    return stories


def _words(title: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]+", title.lower()) if len(w) > 3}


def _names_an_actor_of(one: dict, other: dict) -> bool:
    """Whether one story's text names a threat actor the other has as one: an
    article names an actor more often than its event has its galaxy tag."""
    text = f"{one['title']}\n{one['content']}"
    return any(req_matching.term_in_text(actor, text) for actor in other["actors"])


def _resembles(candidate: dict, earlier: dict) -> bool:
    if (candidate["cves"] & earlier["cves"] or candidate["actors"] & earlier["actors"]
            or _names_an_actor_of(candidate, earlier) or _names_an_actor_of(earlier, candidate)):
        return True
    a, b = _words(candidate["title"]), _words(earlier["title"])
    return bool(a | b) and len(a & b) / len(a | b) >= settings.get("ANALYSER_SHORTLIST_OVERLAP")


def same_story(candidate: dict, earlier: list[dict]) -> dict | None:
    """The earlier story the candidate tells again, as {"story", "new_facts",
    "reason"}, or None when it is a new one. Raises when the model could not
    compare them: the caller drafts the candidate all the same, and says so."""
    shortlist = [s for s in earlier if _resembles(candidate, s)]
    if not shortlist:
        return None
    compared = llm.compare_stories(candidate, shortlist)
    threshold = settings.get("ANALYSER_SAME_STORY_SCORE")
    matches = [m for m in compared if m["score"] >= threshold]
    if not matches:
        return None
    best = max(matches, key=lambda m: m["score"])
    return {"story": shortlist[best["index"] - 1], "new_facts": best["new_facts"], "reason": best["reason"]}


def repeats(found: dict | None) -> bool:
    """Whether a story found to be the same is left out: it adds nothing, or
    the earlier one was rejected and that blocks an update."""
    return found is not None and (not found["new_facts"]
                                  or (found["story"]["rejected"] and settings.get("ANALYSER_REJECTED_BLOCKS_UPDATES")))
