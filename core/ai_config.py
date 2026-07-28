"""Per-feature AI configuration.

Stores provider, model, and prompt overrides for each LLM call site in
data/ai_features.json. Falls back to built-in defaults when the file is
absent or a feature is not listed.
"""

import json
import logging
from pathlib import Path

import config

logger = logging.getLogger(__name__)

_AI_CONFIG_FILE = Path(config.DB_FILE).parent / "ai_features.json"

# Registry of all LLM call sites. Defines labels, descriptions shown in the
# UI, and the default prompt filename used when no override is saved.
FEATURES = {
    "check_relevance": {
        "label": "Check article relevance",
        "description": "Evaluates whether a scraped article matches the configured focus points. Run by the analyser pipeline for every new event.",
        "default_prompt": "flash_intel_relevance.md",
    },
    "generate_flash_intel": {
        "label": "Generate Flash Intel Alert (analyser)",
        "description": "Auto-generates a Flash Intel Alert from a relevant scraped article. Run by the analyser pipeline when an event is deemed relevant.",
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
    "review_briefing_relevance": {
        "label": "Review daily briefing relevance",
        "description": "Evaluates whether a source event/report is useful for a Daily Threat Briefing and should be included.",
        "default_prompt": "daily_briefing_relevance.md",
    },
    "detect_story_overlaps": {
        "label": "Detect daily briefing overlap",
        "description": "Compares draft daily briefing stories and flags likely duplicate coverage of the same event.",
        "default_prompt": "daily_briefing_overlap.md",
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
}

PROVIDERS = ["openai", "local"]


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
        saved = overrides.get(fid, {})
        result[fid] = {
            "label": meta["label"],
            "description": meta["description"],
            "default_prompt": meta["default_prompt"],
            "provider": saved.get("provider", "openai"),
            "model": saved.get("model", ""),
            "prompt": saved.get("prompt", meta["default_prompt"]),
        }
    return result


def save(data: dict) -> None:
    """Persist per-feature overrides (provider, model, prompt) to the JSON file."""
    _AI_CONFIG_FILE.parent.mkdir(exist_ok=True)
    storable = {}
    for fid in FEATURES:
        if fid in data:
            entry = data[fid]
            provider = entry.get("provider", "openai")
            storable[fid] = {
                "provider": provider if provider in PROVIDERS else "openai",
                "model": entry.get("model", ""),
                "prompt": entry.get("prompt", FEATURES[fid]["default_prompt"]),
            }
    _AI_CONFIG_FILE.write_text(json.dumps(storable, indent=2))


def get_feature(feature_id: str) -> dict:
    """Return effective config for a single feature."""
    return load().get(feature_id, {
        "provider": "openai",
        "model": "",
        "prompt": FEATURES.get(feature_id, {}).get("default_prompt", ""),
    })
