"""Per-feature AI configuration.

Stores provider, model, and prompt overrides for each LLM call site in
data/ai_features.json. Falls back to built-in defaults when the file is
absent or a feature is not listed.
"""

import json
import logging
from pathlib import Path

import config
from core.atomic_write import write_atomically

logger = logging.getLogger(__name__)

_AI_CONFIG_FILE = Path(config.DB_FILE).parent / "ai_features.json"

# Registry of all LLM call sites. Defines labels, descriptions shown in the
# UI, and the default prompt filename used when no override is saved.
FEATURES = {
    "judge_relevance": {
        "label": "Judge article relevance",
        "description": "Decides whether an article is worth a flash intel alert and a daily briefing story, against the focus points and the active PIRs and GIRs, and scores it. Run by the analyser once per event; the verdict is reused until the focus points, the requirements, this prompt or the model change.",
        "default_prompt": "analyser_relevance.md",
    },
    "generate_flash_intel": {
        "label": "Generate Flash Intel Alert (analyser)",
        "description": "Drafts a Flash Intel Alert from an article the relevance check found worth one. Run by the analyser pipeline.",
        "default_prompt": "flash_intel_generate.md",
    },
    "generate_fia_draft": {
        "label": "Build FIA draft",
        "description": "Builds a Flash Intel Alert draft in the web app from one or more manually selected source events (Build with AI button).",
        "default_prompt": "flash_intel_generate.md",
    },
    "draft_briefing_story": {
        "label": "Draft daily briefing story",
        "description": "Drafts a short 5-line briefing story from a collection event for use in the Daily Threat Briefing.",
        "default_prompt": "daily_briefing_story.md",
    },
    "draft_briefing_summary": {
        "label": "Draft daily briefing summary",
        "description": "Writes the narrative summary that opens a Daily Threat Briefing, from the stories the briefing holds. Run by the analyser pipeline and by the Draft with AI button on the summary field.",
        "default_prompt": "daily_briefing_summary.md",
    },
    "detect_story_overlaps": {
        "label": "Detect daily briefing overlap",
        "description": "Compares draft daily briefing stories and flags likely duplicate coverage of the same event.",
        "default_prompt": "daily_briefing_overlap.md",
    },
    "compare_stories": {
        "label": "Compare with earlier products",
        "description": "Compares an article the analyser would make an alert or a briefing story of with the alerts and briefing stories of the last month that resemble it, and says whether it is the same story and adds new facts. Run by the analyser before it drafts.",
        "default_prompt": "story_similarity.md",
    },
    "summarise_report": {
        "label": "Summarise MISP report",
        "description": "Generates a structured summary of a MISP event report. Used in data collection (AI summary button) and the manual summarise endpoint.",
        "default_prompt": "summarise_misp_report.md",
    },
    "draft_vea_sections": {
        "label": "Draft VEA sections",
        "description": "Drafts sections of a Vulnerability advisory from CVE information and optional article content.",
        "default_prompt": "vea_draft.md",
    },
    "draft_tap_sections": {
        "label": "Draft threat actor profile",
        "description": "Drafts the narrative fields of a Threat actor profile from the selected actors, the MISP galaxy context and any notes already on the form.",
        "default_prompt": "threat_actor_profile_draft.md",
    },
    "draft_landscape_trends": {
        "label": "Draft threat landscape trends",
        "description": "Drafts the Threat landscape report sections from the collection events queued for the reporting period.",
        "default_prompt": "threat_landscape_trends.md",
    },
    "review_product_draft": {
        "label": "QA review a product draft",
        "description": "Audits a product draft against its source material before publication and reports unsupported claims, invented identifiers and overstated confidence.",
        "default_prompt": "product_qa_review.md",
    },
}

PROVIDERS = ["openai", "local"]

# A feature that took over from another, whose provider, model and temperature
# it starts with when an administrator has not set its own: an article sent to
# a local model before must not go to OpenAI after an update. The prompt is the
# new feature's, as it asks for a different answer.
_TAKES_OVER_FROM = {"judge_relevance": "check_relevance"}


def _temperature(value):
    """Sampling temperature as a float, or None to leave it to the model."""
    try:
        return min(2.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return None


def _default_provider() -> str:
    return getattr(config, "LLM_DEFAULT_PROVIDER", "openai")


def load() -> dict:
    """Return per-feature config merged with defaults. Never raises."""
    overrides = {}
    try:
        if _AI_CONFIG_FILE.exists():
            overrides = json.loads(_AI_CONFIG_FILE.read_text())
    except Exception as exc:
        logger.warning("ai_config: load failed: %s", exc)
    result = {}
    for fid, meta in FEATURES.items():
        saved = overrides.get(fid)
        if saved is None:
            saved = dict(overrides.get(_TAKES_OVER_FROM.get(fid), {}))
            saved.pop("prompt", None)
        result[fid] = {
            "label": meta["label"],
            "description": meta["description"],
            "default_prompt": meta["default_prompt"],
            # A feature nobody chose a provider for goes to the default one:
            # one added by an update must not send articles to OpenAI on an
            # installation that has a local model as its default.
            "provider": saved.get("provider") or _default_provider(),
            "model": saved.get("model", ""),
            "temperature": _temperature(saved.get("temperature")),
            "prompt": saved.get("prompt", meta["default_prompt"]),
        }
    return result


def save(data: dict) -> None:
    """Persist per-feature overrides (provider, model, temperature, prompt) to the JSON file."""
    _AI_CONFIG_FILE.parent.mkdir(exist_ok=True)
    storable = {}
    for fid in FEATURES:
        if fid in data:
            entry = data[fid]
            provider = entry.get("provider", "openai")
            storable[fid] = {
                "provider": provider if provider in PROVIDERS else "openai",
                "model": entry.get("model", ""),
                "temperature": _temperature(entry.get("temperature")),
                "prompt": entry.get("prompt", FEATURES[fid]["default_prompt"]),
            }
    # Every LLM call reads this file, from the analyser process as well as from
    # here, so saving settings must not leave a moment where it reads as empty
    # and the call quietly falls back to the built-in provider and prompt.
    write_atomically(_AI_CONFIG_FILE, json.dumps(storable, indent=2))


def get_feature(feature_id: str) -> dict:
    """Return effective config for a single feature."""
    return load().get(feature_id, {
        "provider": _default_provider(),
        "model": "",
        "temperature": None,
        "prompt": FEATURES.get(feature_id, {}).get("default_prompt", ""),
    })
