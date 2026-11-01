"""The settings of the analyser's workflow, under Settings > Analyser.

Each is a config key with the default given here. get() reads it from config
when it is used, so a value saved on the settings page applies to the next run
without a restart. The page, the config file it writes and the example take
their keys, defaults, labels and limits from this list.
"""

from collections import namedtuple

import config

# The values of the cti-evaluation taxonomy, lowest first. "" in a limit means
# the dimension is not checked.
LEVELS = ("very-low", "low", "moderate", "high", "very-high")
PRIORITIES = ("Must have", "Should have", "Could have")

# ``choices`` for a value picked from a list; ``minimum`` and ``maximum`` for a
# number. Booleans are a switch.
Setting = namedtuple("Setting", "key default label help choices minimum maximum",
                     defaults=(None, None, None))


def _limit(product: str, dimension: str, default: str = "") -> Setting:
    name = "overall score" if dimension == "overall" else dimension
    label, below = ((f"Lowest {name} for an alert", "An event scored lower gets no alert.") if product == "alert"
                    else (f"Lowest {name} for a briefing story", "An event scored lower is not a story."))
    return Setting(f"ANALYSER_{product.upper()}_MIN_{dimension.upper()}", default, label,
                   f"{below} Empty: not checked.", ("", *LEVELS))


# In the order of the sections of Settings > Analyser.
GROUPS = (
    ("Sources", (
        Setting("ANALYSER_READ_SCRAPER", True, "MISP scraper",
                "Articles from feeds and websites, the links sent in newsletters included: the scraper fetches "
                "those, and their events cannot be told apart from the others."),
        Setting("ANALYSER_READ_MANUAL", True, "Manual entries",
                "The entries of every manual source on Data collection, once they have a report."),
        Setting("ANALYSER_READ_MISP_SERVERS", True, "MISP communities",
                "The events with a report on the other MISP servers whose \"Analyse its events\" is on, through "
                "their own filters. Each event read costs a model call."),
        Setting("ANALYSER_MAX_EVENT_AGE_DAYS", 7, "Oldest scraper event read (days)",
                "By its MISP date, the day it was scraped. Manual entries and the other servers are not cut off.",
                minimum=1, maximum=365),
        Setting("ANALYSER_LOOKBACK_HOURS", 1, "First run of the hourly actions reads (hours)",
                "How far back the alerts and the advisories read a source they have not read before.",
                minimum=1, maximum=168),
        Setting("ANALYSER_BRIEFING_LOOKBACK_HOURS", 24, "First run of the briefing reads (hours)",
                "The same for the daily briefing.", minimum=1, maximum=168),
    )),
    ("Judging", (
        Setting("ANALYSER_MAJOR_DEVELOPMENTS", True, "Major developments make briefing stories",
                "A major threat development every organisation needs to know about becomes a story without "
                "a focus point or requirement behind it."),
        Setting("ANALYSER_ARTICLE_CHARS", 12000, "Article characters read",
                "How much of the article the relevance call reads.", minimum=1000, maximum=50000),
        Setting("ANALYSER_RELEVANCE_ATTEMPTS", 3, "Attempts for an unreadable answer",
                "After that many runs the event is left for the analyst.", minimum=1, maximum=10),
        Setting("ANALYSER_PULL", "low", "Analyst relevance that pulls out",
                "At this score or lower, the event is kept out of the alerts and the briefing.", LEVELS),
        Setting("ANALYSER_PUSH_BRIEFING", "high", "Analyst relevance that pushes to the briefing", "", LEVELS),
        Setting("ANALYSER_PUSH_ALERT", "very-high", "Analyst relevance that pushes to an alert",
                "An analyst's cti-evaluation relevance score of this or higher makes an alert of the event, "
                "whatever the verdict says.", LEVELS),
        Setting("ANALYSER_VERY_HIGH_TIMELINESS_DAYS", 1, "Very high timeliness up to (days old)", "",
                minimum=0, maximum=365),
        Setting("ANALYSER_HIGH_TIMELINESS_DAYS", 3, "High timeliness up to (days old)", "",
                minimum=0, maximum=365),
        Setting("ANALYSER_MODERATE_TIMELINESS_DAYS", 7, "Moderate timeliness up to (days old)", "",
                minimum=0, maximum=365),
        Setting("ANALYSER_LOW_TIMELINESS_DAYS", 30, "Low timeliness up to (days old)", "Older is very low.",
                minimum=0, maximum=3650),
        Setting("ANALYSER_WEIGHT_USEFULNESS", 1, "Weight of usefulness in the overall score", "",
                minimum=0, maximum=10),
        Setting("ANALYSER_WEIGHT_SPECIFICITY", 1, "Weight of specificity in the overall score", "",
                minimum=0, maximum=10),
        Setting("ANALYSER_WEIGHT_TIMELINESS", 1, "Weight of timeliness in the overall score", "",
                minimum=0, maximum=10),
    )),
    ("Alerts", (
        Setting("ANALYSER_ALERT_MIN_PRIORITY", "Should have", "Lowest PIR priority that gives an alert",
                "When PIRs are all an event's grounds. A focus point or a GIR always may; below this, the "
                "event can still be a briefing story.", PRIORITIES),
        _limit("alert", "timeliness", "high"),
        _limit("alert", "usefulness"),
        _limit("alert", "specificity"),
        _limit("alert", "overall"),
    )),
    ("Briefing", (
        Setting("ANALYSER_BRIEFING_MAX_STORIES", 15, "Most stories in a briefing",
                "The rest are listed under Also seen.", minimum=1, maximum=100),
        Setting("ANALYSER_OVERLAP_SCORE", 0.65, "Overlap score within a briefing",
                "Of two stories this alike, the later one is dropped.", minimum=0.0, maximum=1.0),
        Setting("ANALYSER_BRIEFING_WITH_ALERTS", True, "An event with an alert can also be a story", ""),
        _limit("briefing", "timeliness", "moderate"),
        _limit("briefing", "usefulness"),
        _limit("briefing", "specificity"),
        _limit("briefing", "overall"),
    )),
    ("Advisories", (
        Setting("ANALYSER_ADVISORY_DAYS", 90, "A CVE is covered by advisories of the last (days)",
                "In any state, approved and rejected ones included.", minimum=1, maximum=730),
        Setting("ANALYSER_ADVISORY_MAX_CVES", 10, "CVEs looked up per event",
                "An event listing a month of patches stops there, to spare the lookups.", minimum=1, maximum=50),
        Setting("ANALYSER_ADVISORY_CVSS_FLOOR", 0.0, "Lowest CVSS score",
                "A CVE scored lower gets no advisory. 0 for any.", minimum=0.0, maximum=10.0),
        Setting("ANALYSER_ADVISORY_UPDATES", True, "A material change gives an update",
                "A covered CVE that is on the CISA KEV list now, or whose CVSS score rose enough, gets a new "
                "advisory that names the earlier one."),
        Setting("ANALYSER_ADVISORY_CVSS_RISE", 1.0, "CVSS rise that counts as material", "",
                minimum=0.1, maximum=10.0),
        Setting("ANALYSER_ADVISORY_REJECTED_BLOCKS", True, "A rejected advisory blocks updates", ""),
        Setting("ANALYSER_ADVISORY_KEV_ONLY", False, "Only CVEs on the CISA KEV list", ""),
    )),
    ("Earlier products", (
        Setting("ANALYSER_SIMILARITY_DAYS", 30, "Compared with the products of the last (days)",
                "Alerts and briefing stories in any state, rejected ones included.", minimum=1, maximum=365),
        Setting("ANALYSER_SHORTLIST_OVERLAP", 0.35, "Title word overlap that shortlists",
                "Besides a shared CVE or threat actor. Only a shortlisted product is compared by the AI.",
                minimum=0.0, maximum=1.0),
        Setting("ANALYSER_SAME_STORY_SCORE", 0.65, "Score that counts as the same story", "",
                minimum=0.0, maximum=1.0),
        Setting("ANALYSER_REJECTED_BLOCKS_UPDATES", True, "A rejected product blocks updates",
                "The same story with new facts is not proposed again when the earlier one was rejected."),
    )),
)

ALL = tuple(setting for _group, settings in GROUPS for setting in settings)
_BY_KEY = {setting.key: setting for setting in ALL}


def setting(key: str) -> Setting:
    """A workflow setting by its key, as the settings page lays them out."""
    return _BY_KEY[key]


def get(key: str):
    """The configured value of a workflow setting, or its default."""
    return getattr(config, key, setting(key).default)


def conflict(values: dict) -> str:
    """Why these workflow values cannot be saved together, or "". A relevance
    score that pulls an event out cannot also push it in."""
    pull = LEVELS.index(values["ANALYSER_PULL"])
    if pull >= min(LEVELS.index(values["ANALYSER_PUSH_ALERT"]), LEVELS.index(values["ANALYSER_PUSH_BRIEFING"])):
        return ("The analyst relevance that pulls an event out has to be lower than the ones that push it to an "
                "alert or to the briefing. Nothing was saved.")
    return ""


def parse(setting: Setting, raw):
    """A value posted for a setting, as the config file stores it. One that
    was not posted keeps what is configured; one that cannot be read, or is
    out of range, takes the default."""
    if raw is None:
        return get(setting.key)
    default = setting.default
    if isinstance(default, bool):
        return raw == "true"
    if setting.choices:
        return raw if raw in setting.choices else default
    try:
        value = type(default)(raw)
    except (TypeError, ValueError):
        return default
    return value if setting.minimum <= value <= setting.maximum else default
