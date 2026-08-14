import importlib
import json
import logging
import mimetypes
import os
import shutil
import subprocess
import sys
import ast
from pathlib import Path

import requests

import config as _config
from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, url_for
from markupsafe import escape
from core import flowintel_client
from core.atomic_write import write_atomically
from webapp import audit, misp_session, misp_store, newsletter_parsers
from webapp.rate_limit import rate_limited
from webapp.utils import (
    json_body as _json_object,
    normalize_notification_channels as _normalize_notification_channels,
    parse_bool as _parse_bool,
)

bp = Blueprint("config_page", __name__)
logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent.parent
_UPLOADS_DIR = _ROOT / "data" / "uploads"
_CONFIG_FILE = _ROOT / "config" / "__init__.py"
_BACKUP_FILE = _ROOT / "config" / "__init__.py.backup"
_PROMPTS_DIR = _ROOT / "zsazsaprompts"

# CTI products that can be linked to a Flowintel case template per instance.
FLOWINTEL_CASE_TEMPLATE_PRODUCTS = [
    {"key": "Flash intel alert", "label": "Flash intel report"},
    {"key": "Vulnerability advisory", "label": "Vulnerability advisory"},
]

# Maintenance migration scripts that can be run from the System tab. Each entry's
# "script" is resolved relative to the repository root and is the only path that
# may be executed; the client only ever sends the migration "id". Scripts that
# support a dry-run run without --apply first, then with --apply to commit.
MIGRATIONS = [
    {
        "id": "make_zsazsa_tags_local",
        "name": "Make zsazsa tags local",
        "script": "scripts/make_zsazsa_tags_local.py",
        "description": (
            "Convert existing zsazsa-namespace tag attachments (zsazsa:type, "
            "zsazsa:ctiproduct, zsazsa:source, ...) from global to local so they "
            "never sync to connected MISP instances."
        ),
        "supports_apply": True,
    },
    {
        "id": "rename_vea_subscription_product",
        "name": "Rename VEA product in subscriptions",
        "script": "scripts/rename_vea_subscription_product.py",
        "description": (
            "Rewrite the old \"Vulnerability exploitation advisory\" product name to "
            "\"Vulnerability advisory\" in existing stakeholder subscriptions stored "
            "in MISP, so they keep matching the renamed product."
        ),
        "supports_apply": True,
    },
    {
        "id": "backfill_product_source_log",
        "name": "Backfill product source log",
        "script": "scripts/backfill_product_source_log.py",
        "description": (
            "Record the source events of existing products (briefings, flash intel, "
            "VEAs) in the analyser log, so products created before source logging was "
            "added show up under the pipeline's By collection source. Already-logged "
            "entries are skipped, so it is safe to run more than once."
        ),
        "supports_apply": True,
    },
    {
        "id": "convert_url_attributes_to_link",
        "name": "Convert URL references to link",
        "script": "scripts/convert_url_attributes_to_link.py",
        "description": (
            "Retype the external references on manual collection entries from MISP's "
            "\"url\" type to \"link\". Entries created before this was fixed stored them "
            "as \"url\", where nothing that builds a product's reference list picks them "
            "up. Only External analysis attributes are touched, so genuine URL "
            "indicators are left alone."
        ),
        "supports_apply": True,
    },
]

_MIGRATIONS_BY_ID = {m["id"]: m for m in MIGRATIONS}


def _llm_usage_stats(provider: str) -> dict:
    """Return token usage totals for one provider from the analyser DB. Never raises."""
    empty = {"total_calls": 0, "total_tokens": 0,
             "today_calls": 0, "today_tokens": 0,
             "week_calls": 0, "week_tokens": 0, "by_feature": []}
    import sqlite3 as _sq
    from contextlib import closing
    db_path = getattr(_config, "DB_FILE", "data/analyser.db")
    if not os.path.exists(db_path):
        return empty
    try:
        with closing(_sq.connect(db_path)) as conn:
            conn.row_factory = _sq.Row
            r = conn.execute(
                "SELECT COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS tokens"
                " FROM llm_usage WHERE provider = ?",
                (provider,),
            ).fetchone()
            r_today = conn.execute(
                "SELECT COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS tokens"
                " FROM llm_usage WHERE provider = ? AND date(called_at) = date('now')",
                (provider,),
            ).fetchone()
            r_week = conn.execute(
                "SELECT COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS tokens"
                " FROM llm_usage WHERE provider = ? AND called_at >= datetime('now', '-7 days')",
                (provider,),
            ).fetchone()
            features = conn.execute(
                "SELECT feature, COUNT(*) AS calls,"
                " COALESCE(SUM(input_tokens),0) AS input_tokens,"
                " COALESCE(SUM(output_tokens),0) AS output_tokens,"
                " COALESCE(SUM(total_tokens),0) AS total_tokens"
                " FROM llm_usage WHERE provider = ? GROUP BY feature ORDER BY total_tokens DESC",
                (provider,),
            ).fetchall()
        return {
            "total_calls": r["calls"], "total_tokens": r["tokens"],
            "today_calls": r_today["calls"], "today_tokens": r_today["tokens"],
            "week_calls": r_week["calls"], "week_tokens": r_week["tokens"],
            "by_feature": [dict(f) for f in features],
        }
    except Exception:
        logger.warning("could not read LLM usage stats from %s", db_path, exc_info=True)
        return empty


def _load_ai_features() -> dict:
    try:
        from core.ai_config import load as _ai_load
        return _ai_load()
    except Exception as exc:
        logger.warning("_load_ai_features failed: %s", exc)
        return {}


def _list_prompts() -> list[dict]:
    prompts = []
    for p in sorted(_PROMPTS_DIR.glob("*.md")):
        content = p.read_text(encoding="utf-8")
        first_line = next((ln.strip() for ln in content.splitlines() if ln.strip()), "")
        description = first_line[:100] if first_line else ""
        prompts.append({"filename": p.name, "description": description, "content": content})
    return prompts


def _read_notification_channels() -> list:
    """Return NOTIFICATION_CHANNELS, migrating from legacy single-webhook config if needed."""
    return _normalize_notification_channels(
        getattr(_config, "NOTIFICATION_CHANNELS", []),
        legacy_url=getattr(_config, "MATTERMOST_WEBHOOK_URL", ""),
        legacy_enabled=getattr(_config, "MATTERMOST_ENABLED", False),
    )


def _read() -> dict:
    importlib.reload(_config)
    raw_exclusions = getattr(_config, "DAILY_BRIEFING_TITLE_EXCLUSIONS", [])
    if isinstance(raw_exclusions, str):
        daily_briefing_title_exclusions = [p.strip() for p in raw_exclusions.splitlines() if p.strip()]
    else:
        daily_briefing_title_exclusions = [str(p).strip() for p in (raw_exclusions or []) if str(p).strip()]
    focus_points_geographies = [str(p).strip() for p in (getattr(_config, "FOCUS_POINTS_GEOGRAPHIES", []) or []) if str(p).strip()]
    focus_points_sectors = [str(p).strip() for p in (getattr(_config, "FOCUS_POINTS_SECTORS", []) or []) if str(p).strip()]
    focus_points_technologies = [str(p).strip() for p in (getattr(_config, "FOCUS_POINTS_TECHNOLOGIES", []) or []) if str(p).strip()]
    focus_points_threat_types = [str(p).strip() for p in (getattr(_config, "FOCUS_POINTS_THREAT_TYPES", []) or []) if str(p).strip()]
    focus_points_threat_actors = [str(p).strip() for p in (getattr(_config, "FOCUS_POINTS_THREAT_ACTORS", []) or []) if str(p).strip()]
    raw_tat = getattr(_config, "THREAT_ACTOR_TYPES", []) or []
    threat_actor_types = [
        {"name": str(t.get("name", "")).strip(), "description": str(t.get("description", "")).strip()}
        for t in raw_tat if isinstance(t, dict)
    ]
    tag_strip_prefixes = [str(p).strip() for p in (getattr(_config, "COLLECTION_TAG_STRIP_PREFIXES", []) or []) if str(p).strip()]
    tag_hide_prefixes = [str(p).strip() for p in (getattr(_config, "COLLECTION_TAG_HIDE_PREFIXES", []) or []) if str(p).strip()]
    openai_api_key = getattr(_config, "OPENAI_API_KEY", getattr(_config, "ANTHROPIC_API_KEY", ""))
    openai_model = getattr(_config, "OPENAI_MODEL", getattr(_config, "ANTHROPIC_MODEL", ""))
    return {
        "MISP_URL": _config.MISP_URL,
        "MISP_KEY": _config.MISP_KEY,
        "MISP_VERIFYCERT": _config.MISP_VERIFYCERT,
        "MISP_WEBAPP_URL": _config.MISP_WEBAPP_URL,
        "MISP_WEBAPP_KEY": _config.MISP_WEBAPP_KEY,
        "MISP_WEBAPP_VERIFYCERT": _config.MISP_WEBAPP_VERIFYCERT,
        "MISP_EVENT_DISTRIBUTION": getattr(_config, "MISP_EVENT_DISTRIBUTION", 0),
        "OPENAI_API_KEY": openai_api_key,
        "OPENAI_MODEL": openai_model,
        "OPENAI_ENABLED": bool(getattr(_config, "OPENAI_ENABLED", True)),
        "LOCAL_LLM_ENABLED": bool(getattr(_config, "LOCAL_LLM_ENABLED", False)),
        "LOCAL_LLM_URL": getattr(_config, "LOCAL_LLM_URL", ""),
        "LOCAL_LLM_API_KEY": getattr(_config, "LOCAL_LLM_API_KEY", ""),
        "LOCAL_LLM_MODEL": getattr(_config, "LOCAL_LLM_MODEL", ""),
        "LLM_DEFAULT_PROVIDER": getattr(_config, "LLM_DEFAULT_PROVIDER", "openai"),
        "NOTIFICATION_CHANNELS": _read_notification_channels(),
        "SMTP_HOST": getattr(_config, "SMTP_HOST", ""),
        "SMTP_PORT": getattr(_config, "SMTP_PORT", 587),
        "SMTP_USE_TLS": getattr(_config, "SMTP_USE_TLS", True),
        "SMTP_USERNAME": getattr(_config, "SMTP_USERNAME", ""),
        "SMTP_PASSWORD": getattr(_config, "SMTP_PASSWORD", ""),
        "SMTP_FROM": getattr(_config, "SMTP_FROM", ""),
        "FLOWINTEL_INSTANCES": getattr(_config, "FLOWINTEL_INSTANCES", []),
        "FLOWINTEL_CASE_TEMPLATE_PRODUCTS": FLOWINTEL_CASE_TEMPLATE_PRODUCTS,
        "MISP_SERVERS": getattr(_config, "MISP_SERVERS", []),
        "IMAP_SOURCES": getattr(_config, "IMAP_SOURCES", []),
        "PRODUCT_TYPES": _config.PRODUCT_TYPES,
        "DAILY_BRIEFING_TITLE_EXCLUSIONS": daily_briefing_title_exclusions,
        "FOCUS_POINTS_GEOGRAPHIES": focus_points_geographies,
        "FOCUS_POINTS_SECTORS": focus_points_sectors,
        "FOCUS_POINTS_TECHNOLOGIES": focus_points_technologies,
        "FOCUS_POINTS_THREAT_TYPES": focus_points_threat_types,
        "FOCUS_POINTS_THREAT_ACTORS": focus_points_threat_actors,
        "THREAT_ACTOR_TYPES": threat_actor_types,
        "COLLECTION_TAG_STRIP_PREFIXES": tag_strip_prefixes,
        "COLLECTION_TAG_HIDE_PREFIXES": tag_hide_prefixes,
        "TAG_STAKEHOLDER": _config.TAG_STAKEHOLDER,
        "TAG_PIR": _config.TAG_PIR,
        "TAG_GIR": _config.TAG_GIR,
        "TAG_RFI": _config.TAG_RFI,
        "TAG_FLASH_INTEL": _config.TAG_FLASH_INTEL,
        "TAG_VEA": _config.TAG_VEA,
        "TAG_BRIEFING": _config.TAG_BRIEFING,
        "TAG_TLR": getattr(_config, "TAG_TLR", 'zsazsa:ctiproduct="threat-landscape-report"'),
        "TAG_THREAT_ACTOR_PROFILE": getattr(_config, "TAG_THREAT_ACTOR_PROFILE",
                                            'zsazsa:ctiproduct="threat-actor-profile"'),
        "TAG_INDICATOR_FEED": getattr(_config, "TAG_INDICATOR_FEED",
                                      'zsazsa:ctiproduct="indicator-feed"'),
        "TAG_COLLECTION_FOLLOWUP": getattr(_config, "TAG_COLLECTION_FOLLOWUP", 'zsazsa:collection="follow-up"'),
        "TAG_COLLECTION_DISMISSED": getattr(_config, "TAG_COLLECTION_DISMISSED", 'zsazsa:event="dismiss"'),
        "RECOMMENDED_ACTIONS_IMMEDIATE": getattr(_config, "RECOMMENDED_ACTIONS_IMMEDIATE", []),
        "RECOMMENDED_ACTIONS_NEAR_TERM": getattr(_config, "RECOMMENDED_ACTIONS_NEAR_TERM", []),
        "POLL_WINDOW_HOURS": _config.POLL_WINDOW_HOURS,
        "SCRAPER_MARKER_TAG": _config.SCRAPER_MARKER_TAG,
        "MISP_SCRAPER_LIMIT": getattr(_config, "MISP_SCRAPER_LIMIT", 500),
        "MISP_SCRAPER_SINCE_DAYS": getattr(_config, "MISP_SCRAPER_SINCE_DAYS", 30),
        "SCRAPER_REDIS_HOST": getattr(_config, "SCRAPER_REDIS_HOST", "127.0.0.1"),
        "SCRAPER_REDIS_PORT": getattr(_config, "SCRAPER_REDIS_PORT", 6379),
        "SCRAPER_REDIS_PASSWORD": getattr(_config, "SCRAPER_REDIS_PASSWORD", ""),
        "SCRAPER_REDIS_CHANNEL": getattr(_config, "SCRAPER_REDIS_CHANNEL", "urls"),
        "EVENT_LOG_RETENTION_DAYS": getattr(_config, "EVENT_LOG_RETENTION_DAYS", 90),
        "PIPELINE_RUN_LOG_RETENTION_DAYS": getattr(_config, "PIPELINE_RUN_LOG_RETENTION_DAYS", 365),
        "LOG_LEVEL": _config.LOG_LEVEL,
        "HOSTNAME": getattr(_config, "HOSTNAME", "0.0.0.0"),
        "PORT": getattr(_config, "PORT", 5000),
        "SSL_ENABLED": getattr(_config, "SSL_ENABLED", False),
        "SSL_CERT": getattr(_config, "SSL_CERT", "certs/zsazsa.crt"),
        "SSL_KEY": getattr(_config, "SSL_KEY", "certs/zsazsa.key"),
        "MISP_SESSION_COOKIE_NAME": getattr(_config, "MISP_SESSION_COOKIE_NAME", ""),
        "MISP_SESSION_REDIS_HOST": getattr(_config, "MISP_SESSION_REDIS_HOST", "127.0.0.1"),
        "MISP_SESSION_REDIS_PORT": getattr(_config, "MISP_SESSION_REDIS_PORT", 6379),
        "MISP_SESSION_REDIS_DB": getattr(_config, "MISP_SESSION_REDIS_DB", 0),
        "MISP_SESSION_REDIS_USERNAME": getattr(_config, "MISP_SESSION_REDIS_USERNAME", ""),
        "MISP_SESSION_REDIS_PASSWORD": getattr(_config, "MISP_SESSION_REDIS_PASSWORD", ""),
        "MISP_SESSION_REDIRECT_TO_LOGIN": getattr(_config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
        "prompts": _list_prompts(),
        "llm_usage": _llm_usage_stats("openai"),
        "llm_usage_local": _llm_usage_stats("local"),
        "ai_features": _load_ai_features(),
        "BRAND_COMPANY": getattr(_config, "BRAND_COMPANY", ""),
        "BRAND_DEPARTMENT": getattr(_config, "BRAND_DEPARTMENT", ""),
        "BRAND_COLOR_1": getattr(_config, "BRAND_COLOR_1", "#0f2d52"),
        "BRAND_COLOR_2": getattr(_config, "BRAND_COLOR_2", "#0078f1"),
        "BRAND_COLOR_3": getattr(_config, "BRAND_COLOR_3", "#64748b"),
        "BRAND_LOGO": getattr(_config, "BRAND_LOGO", ""),
        "THEME": getattr(_config, "THEME", "overmind"),
    }


def _form_tag(name: str) -> str:
    """A tag field, falling back to what is configured rather than to nothing.

    Every one of these marks a product or an entity type in MISP, so an empty
    one detaches everything carrying it. A form posted without the field, an
    older page left open across an upgrade, looks exactly like one where it was
    cleared, and neither should wipe the tag.
    """
    return request.form.get(name, "").strip() or getattr(_config, name, "")


def _form_str(name: str) -> str:
    """A text field, keeping what is configured when the form did not send it.

    Clearing a field on purpose still clears it: an empty value that was posted
    is a decision, an absent one is not. That distinction is what stops a page
    submitted without a field, from an older version or a tab whose inputs
    never rendered, wiping a MISP key or an SMTP password.
    """
    raw = request.form.get(name)
    return raw.strip() if raw is not None else str(getattr(_config, name, "") or "")


def _form_bool(name: str) -> bool:
    """A checkbox, keeping what is configured when the form did not send it.

    The stakes are one-sided here: an absent field reading as False turns off
    TLS verification, SMTP encryption or the login redirect without anyone
    asking for it.
    """
    raw = request.form.get(name)
    return raw == "true" if raw is not None else bool(getattr(_config, name, False))


def _form_lines(name: str) -> list | None:
    """One value per line, or None when the form did not send the field.

    None rather than an empty list, so the caller can tell "the analyst emptied
    the box" from "the box was never there" and keep the configured list.
    """
    raw = request.form.get(name)
    if raw is None:
        return None
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _form_int(name: str, default: int) -> int:
    """A number from the form, falling back the same way _form_tag does.

    A field the form never sent keeps whatever is configured: resetting a port
    or a Redis database number to a built-in default is as damaging as blanking
    a tag. A field that was sent but holds nothing usable takes the default,
    and never raises, since these are built before the save is even attempted.
    """
    raw = request.form.get(name)
    if raw is None:
        configured = getattr(_config, name, default)
        return configured if isinstance(configured, int) else default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _write(values):
    shutil.copy2(str(_CONFIG_FILE), str(_BACKUP_FILE))
    products = values["PRODUCT_TYPES"]
    products_repr = "[\n" + "".join(f"    {p!r},\n" for p in products) + "]"
    briefing_title_exclusions = values.get("DAILY_BRIEFING_TITLE_EXCLUSIONS", [])
    briefing_title_exclusions_repr = "[\n" + "".join(f"    {p!r},\n" for p in briefing_title_exclusions) + "]"
    fp_geographies = values.get("FOCUS_POINTS_GEOGRAPHIES", [])
    fp_geographies_repr = "[\n" + "".join(f"    {p!r},\n" for p in fp_geographies) + "]"
    fp_sectors = values.get("FOCUS_POINTS_SECTORS", [])
    fp_sectors_repr = "[\n" + "".join(f"    {p!r},\n" for p in fp_sectors) + "]"
    fp_technologies = values.get("FOCUS_POINTS_TECHNOLOGIES", [])
    fp_technologies_repr = "[\n" + "".join(f"    {p!r},\n" for p in fp_technologies) + "]"
    fp_threat_types = values.get("FOCUS_POINTS_THREAT_TYPES", [])
    fp_threat_types_repr = "[\n" + "".join(f"    {p!r},\n" for p in fp_threat_types) + "]"
    fp_threat_actors = values.get("FOCUS_POINTS_THREAT_ACTORS", [])
    fp_threat_actors_repr = "[\n" + "".join(f"    {p!r},\n" for p in fp_threat_actors) + "]"
    tag_strip = values.get("COLLECTION_TAG_STRIP_PREFIXES", [])
    tag_strip_repr = "[\n" + "".join(f"    {p!r},\n" for p in tag_strip) + "]"
    tag_hide = values.get("COLLECTION_TAG_HIDE_PREFIXES", [])
    tag_hide_repr = "[\n" + "".join(f"    {p!r},\n" for p in tag_hide) + "]"
    tat = values.get("THREAT_ACTOR_TYPES", [])
    if tat:
        tat_lines = ["[\n"]
        for t in tat:
            tat_lines.append(
                f"    {{'name': {t.get('name', '')!r}, 'description': {t.get('description', '')!r}}},\n"
            )
        tat_lines.append("]")
        tat_repr = "".join(tat_lines)
    else:
        tat_repr = "[]"
    servers = values.get("MISP_SERVERS", [])
    if servers:
        lines = []
        for s in servers:
            lines.append("    {")
            for k in ("id", "label", "url", "api_key", "verify_tls", "enabled", "tags", "tags_and", "tags_not", "org_filter_type", "org_filter", "since_days", "limit"):
                lines.append(f"        {k!r}: {s.get(k)!r},")
            lines.append("    },")
        servers_repr = "[\n" + "\n".join(lines) + "\n]"
    else:
        servers_repr = "[]"
    imap_sources = values.get("IMAP_SOURCES", [])
    if imap_sources:
        lines = []
        for m in imap_sources:
            lines.append("    {")
            for k in ("id", "name", "enabled", "host", "port", "ssl",
                      "username", "password", "folder"):
                lines.append(f"        {k!r}: {m.get(k)!r},")
            lines.append("        'sources': [")
            for s in m.get("sources") or []:
                lines.append("            {")
                for k in ("id", "name", "enabled", "parser", "subjects",
                          "senders", "reliability", "mode"):
                    lines.append(f"                {k!r}: {s.get(k)!r},")
                lines.append("            },")
            lines.append("        ],")
            lines.append("    },")
        imap_sources_repr = "[\n" + "\n".join(lines) + "\n]"
    else:
        imap_sources_repr = "[]"
    channels = values.get("NOTIFICATION_CHANNELS", [])
    if channels:
        ch_lines = []
        for c in channels:
            if (c.get("type") or "").lower() == "email":
                keys = ("id", "name", "type", "recipient", "enabled")
            else:
                keys = ("id", "name", "type", "url", "enabled", "verify_tls")
            ch_lines.append("    {")
            for k in keys:
                ch_lines.append(f"        {k!r}: {c.get(k)!r},")
            ch_lines.append("    },")
        channels_repr = "[\n" + "\n".join(ch_lines) + "\n]"
    else:
        channels_repr = "[]"
    flowintel_instances = values.get("FLOWINTEL_INSTANCES", [])
    if flowintel_instances:
        fi_lines = []
        for fi in flowintel_instances:
            fi_lines.append("    {")
            for k in ("id", "name", "url", "api_key", "enabled", "verify_tls"):
                fi_lines.append(f"        {k!r}: {fi.get(k)!r},")
            case_templates_repr = repr(fi.get("case_templates") or {})
            fi_lines.append(f"        'case_templates': {case_templates_repr},")
            fi_lines.append("    },")
        flowintel_instances_repr = "[\n" + "\n".join(fi_lines) + "\n]"
    else:
        flowintel_instances_repr = "[]"
    content = f"""SECRET_KEY = {_config.SECRET_KEY!r}

# MISP - scraper / analyser pipeline
MISP_URL = {values['MISP_URL']!r}
MISP_KEY = {values['MISP_KEY']!r}
MISP_VERIFYCERT = {bool(values['MISP_VERIFYCERT'])}

# MISP - webapp (CTI program objects: stakeholders, PIRs, GIRs)
# Defaults to the same server; override to use a dedicated MISP instance.
MISP_WEBAPP_URL = {values['MISP_WEBAPP_URL']!r}
MISP_WEBAPP_KEY = {values['MISP_WEBAPP_KEY']!r}
MISP_WEBAPP_VERIFYCERT = {bool(values['MISP_WEBAPP_VERIFYCERT'])}

# Distribution level for MISP events the backend creates (stakeholders, PIRs,
# GIRs, RFIs and products). 0 = your organisation only (default and safest),
# 1 = this community, 2 = connected communities, 3 = all communities.
MISP_EVENT_DISTRIBUTION = {int(values.get('MISP_EVENT_DISTRIBUTION') or 0)}

# LLM providers. LLM_DEFAULT_PROVIDER is the provider used by features that do
# not pick one themselves: 'openai' or 'local'.
LLM_DEFAULT_PROVIDER = {values.get('LLM_DEFAULT_PROVIDER', 'openai')!r}

# OpenAI
OPENAI_ENABLED = {bool(values.get('OPENAI_ENABLED', True))}
OPENAI_API_KEY = {values['OPENAI_API_KEY']!r}
OPENAI_MODEL = {values['OPENAI_MODEL']!r}

# Local LLM, reachable over an OpenAI-compatible API endpoint.
LOCAL_LLM_ENABLED = {bool(values.get('LOCAL_LLM_ENABLED', False))}
LOCAL_LLM_URL = {values.get('LOCAL_LLM_URL', '')!r}
LOCAL_LLM_API_KEY = {values.get('LOCAL_LLM_API_KEY', '')!r}
LOCAL_LLM_MODEL = {values.get('LOCAL_LLM_MODEL', '')!r}

# Notification channels
NOTIFICATION_CHANNELS = {channels_repr}

# Legacy aliases: first active Mattermost channel (used by notifier for fallback)
MATTERMOST_ENABLED = any(c.get('type') == 'mattermost' and c.get('enabled') for c in NOTIFICATION_CHANNELS)
MATTERMOST_WEBHOOK_URL = next((c.get('url', '') for c in NOTIFICATION_CHANNELS if c.get('type') == 'mattermost' and c.get('enabled')), '')

# SMTP server settings, shared by all email notification channels.
SMTP_HOST = {values.get('SMTP_HOST', '')!r}
SMTP_PORT = {int(values.get('SMTP_PORT') or 587)}
SMTP_USE_TLS = {bool(values.get('SMTP_USE_TLS', True))}
SMTP_USERNAME = {values.get('SMTP_USERNAME', '')!r}
SMTP_PASSWORD = {values.get('SMTP_PASSWORD', '')!r}
SMTP_FROM = {values.get('SMTP_FROM', '')!r}

# Flowintel case management instances
FLOWINTEL_INSTANCES = {flowintel_instances_repr}

# Additional MISP servers queried by the data-collection page.
MISP_SERVERS = {servers_repr}

# IMAP mailboxes polled by run_imap_collector.py for newsletter e-mails.
IMAP_SOURCES = {imap_sources_repr}

# Collection sources offered when editing a PIR or GIR.
# Derived automatically from the MISP scraper and configured MISP servers.
# Do not set manually; edit the sources above instead.
def _build_collection_sources():
    items = ['misp-scraper']
    for s in MISP_SERVERS:
        label = (s.get('label') or '').strip()
        if label and label not in items:
            items.append(label)
    return items

COLLECTION_SOURCES = _build_collection_sources()

# Product types used for stakeholder subscriptions and PIR deliverables
PRODUCT_TYPES = {products_repr}

# Threat actor types (ENISA taxonomy) - reference list available to all CTI products
THREAT_ACTOR_TYPES = {tat_repr}

# Daily briefing analyser: skip source events/reports whose titles contain
# any of these substrings (case-insensitive).
DAILY_BRIEFING_TITLE_EXCLUSIONS = {briefing_title_exclusions_repr}

# Organisation-wide focus points used for AI-assisted briefing and relevance logic.
FOCUS_POINTS_GEOGRAPHIES = {fp_geographies_repr}
FOCUS_POINTS_SECTORS = {fp_sectors_repr}
FOCUS_POINTS_TECHNOLOGIES = {fp_technologies_repr}
FOCUS_POINTS_THREAT_TYPES = {fp_threat_types_repr}
FOCUS_POINTS_THREAT_ACTORS = {fp_threat_actors_repr}

# MISP context tags - entity type markers (stakeholders, requirements, RFIs)
TAG_STAKEHOLDER = {values['TAG_STAKEHOLDER']!r}
TAG_PIR         = {values['TAG_PIR']!r}
TAG_GIR         = {values['TAG_GIR']!r}
TAG_RFI         = {values['TAG_RFI']!r}

# MISP context tags - product classification (serve as both type and product marker)
TAG_FLASH_INTEL = {values['TAG_FLASH_INTEL']!r}
TAG_VEA         = {values['TAG_VEA']!r}
TAG_BRIEFING    = {values['TAG_BRIEFING']!r}
TAG_TLR         = {values['TAG_TLR']!r}
TAG_INDICATOR_FEED = {values['TAG_INDICATOR_FEED']!r}
TAG_THREAT_ACTOR_PROFILE = {values['TAG_THREAT_ACTOR_PROFILE']!r}
TAG_COLLECTION_FOLLOWUP = {values['TAG_COLLECTION_FOLLOWUP']!r}
TAG_COLLECTION_DISMISSED = {values['TAG_COLLECTION_DISMISSED']!r}

# Data collection tag display settings
COLLECTION_TAG_STRIP_PREFIXES = {tag_strip_repr}
COLLECTION_TAG_HIDE_PREFIXES = {tag_hide_repr}

# Recommended actions shown in flash intel and VEA wizards
RECOMMENDED_ACTIONS_IMMEDIATE = {values.get('RECOMMENDED_ACTIONS_IMMEDIATE', [])!r}
RECOMMENDED_ACTIONS_NEAR_TERM = {values.get('RECOMMENDED_ACTIONS_NEAR_TERM', [])!r}

# Analyser
POLL_WINDOW_HOURS = {int(values['POLL_WINDOW_HOURS'])}
SCRAPER_MARKER_TAG = {values['SCRAPER_MARKER_TAG']!r}
MISP_SCRAPER_LIMIT = {int(values.get('MISP_SCRAPER_LIMIT') or 500)}
MISP_SCRAPER_SINCE_DAYS = {int(values.get('MISP_SCRAPER_SINCE_DAYS') or 0)}
EVENT_LOG_RETENTION_DAYS = {int(values.get('EVENT_LOG_RETENTION_DAYS') or 90)}
PIPELINE_RUN_LOG_RETENTION_DAYS = {int(values.get('PIPELINE_RUN_LOG_RETENTION_DAYS') or 365)}

# Manual sources pushing to the misp-scraper queue (Redis pub/sub the scraper subscribes to)
SCRAPER_REDIS_HOST = {values.get('SCRAPER_REDIS_HOST', '127.0.0.1')!r}
SCRAPER_REDIS_PORT = {int(values.get('SCRAPER_REDIS_PORT') or 6379)}
SCRAPER_REDIS_PASSWORD = {values.get('SCRAPER_REDIS_PASSWORD', '')!r}
SCRAPER_REDIS_CHANNEL = {values.get('SCRAPER_REDIS_CHANNEL') or 'urls'!r}

# Paths
STATE_FILE = {_config.STATE_FILE!r}
DB_FILE = {_config.DB_FILE!r}

# Logging
LOG_FILE = {_config.LOG_FILE!r}
LOG_LEVEL = {values['LOG_LEVEL']!r}

# Web server
HOSTNAME = {values['HOSTNAME']!r}
PORT = {int(values['PORT'])}
SSL_ENABLED = {bool(values['SSL_ENABLED'])}
SSL_CERT = {values['SSL_CERT']!r}
SSL_KEY = {values['SSL_KEY']!r}

# MISP - shared session SSO. zsazsa runs as a subpath behind MISP and
# identifies the logged-in user from MISP's own PHP session cookie, read
# directly from the Redis instance MISP stores its sessions in.
# MISP names its session cookie 'MISP-<instance uuid>', which is unique per
# install. Leave MISP_SESSION_COOKIE_NAME empty to derive it automatically from
# the MISP server's instance UUID; set it explicitly only to override.
MISP_SESSION_COOKIE_NAME = {values['MISP_SESSION_COOKIE_NAME']!r}
MISP_SESSION_REDIS_HOST = {values['MISP_SESSION_REDIS_HOST']!r}
MISP_SESSION_REDIS_PORT = {int(values['MISP_SESSION_REDIS_PORT'])}
MISP_SESSION_REDIS_DB = {int(values['MISP_SESSION_REDIS_DB'])}
MISP_SESSION_REDIS_USERNAME = {values['MISP_SESSION_REDIS_USERNAME']!r}
MISP_SESSION_REDIS_PASSWORD = {values['MISP_SESSION_REDIS_PASSWORD']!r}
# If True, visitors without a valid MISP session are redirected to MISP's
# login page. If False, they fall back to the admin@admin.test identity.
MISP_SESSION_REDIRECT_TO_LOGIN = {bool(values['MISP_SESSION_REDIRECT_TO_LOGIN'])}

# Branding (used for PDF outputs and channel notifications)
BRAND_COMPANY    = {values.get('BRAND_COMPANY', '')!r}
BRAND_DEPARTMENT = {values.get('BRAND_DEPARTMENT', '')!r}
BRAND_COLOR_1    = {values.get('BRAND_COLOR_1', '#0f2d52')!r}
BRAND_COLOR_2    = {values.get('BRAND_COLOR_2', '#0078f1')!r}
BRAND_COLOR_3    = {values.get('BRAND_COLOR_3', '#64748b')!r}
BRAND_LOGO       = {values.get('BRAND_LOGO', '')!r}

# UI theme: 'overmind' (MISP Overmind teal, default), 'uibeta' (MISP UiBeta-style
# light) or 'default' (zsazsa legacy navy)
THEME = {values.get('THEME', 'overmind')!r}
"""
    # A half-written config module is an application that will not start.
    write_atomically(_CONFIG_FILE, content)


_CONFIG_TABS = (
    "tab-connections", "tab-products", "tab-system", "tab-prompts",
    "tab-ai", "tab-context", "tab-notifications", "tab-styling",
)


@bp.route("/config", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Each of these keeps its configured value when the form did not carry
        # the field at all; see _form_lines.
        def lines(name):
            posted = _form_lines(name)
            return posted if posted is not None else list(getattr(_config, name, []) or [])

        products = lines("PRODUCT_TYPES")
        exclusions = lines("DAILY_BRIEFING_TITLE_EXCLUSIONS")
        fp_geographies = lines("FOCUS_POINTS_GEOGRAPHIES")
        fp_sectors = lines("FOCUS_POINTS_SECTORS")
        fp_technologies = lines("FOCUS_POINTS_TECHNOLOGIES")
        fp_threat_types = lines("FOCUS_POINTS_THREAT_TYPES")
        fp_threat_actors = lines("FOCUS_POINTS_THREAT_ACTORS")
        tat_posted = request.form.get("THREAT_ACTOR_TYPES")
        if tat_posted is None:
            threat_actor_types = list(getattr(_config, "THREAT_ACTOR_TYPES", []) or [])
        else:
            try:
                tat_raw = json.loads(tat_posted or "[]")
                threat_actor_types = [
                    {"name": str(t.get("name", "")).strip(), "description": str(t.get("description", "")).strip()}
                    for t in tat_raw if isinstance(t, dict)
                    if str(t.get("name", "")).strip() or str(t.get("description", "")).strip()
                ]
            except (json.JSONDecodeError, ValueError):
                threat_actor_types = []
        tag_strip_prefixes = lines("COLLECTION_TAG_STRIP_PREFIXES")
        tag_hide_prefixes = lines("COLLECTION_TAG_HIDE_PREFIXES")
        # When single sign-on is enabled, derive the MISP session cookie name from
        # the connected MISP server (it is 'MISP-<instance uuid>', unique per install)
        # and store it. Keep the existing value if derivation fails.
        sso_enabled = _form_bool("MISP_SESSION_REDIRECT_TO_LOGIN")
        session_cookie_name = getattr(_config, "MISP_SESSION_COOKIE_NAME", "")
        cookie_autodetected = False
        if sso_enabled:
            derived = misp_session.derive_cookie_name()
            if derived and derived != session_cookie_name:
                session_cookie_name = derived
                cookie_autodetected = True
        values = {
            "MISP_URL": getattr(_config, "MISP_URL", ""),
            "MISP_KEY": getattr(_config, "MISP_KEY", ""),
            "MISP_VERIFYCERT": getattr(_config, "MISP_VERIFYCERT", True),
            "MISP_SCRAPER_LIMIT": getattr(_config, "MISP_SCRAPER_LIMIT", 500),
            "MISP_SCRAPER_SINCE_DAYS": getattr(_config, "MISP_SCRAPER_SINCE_DAYS", 30),
            "MISP_SERVERS": getattr(_config, "MISP_SERVERS", []) or [],
            "IMAP_SOURCES": getattr(_config, "IMAP_SOURCES", []) or [],
            "MISP_WEBAPP_URL": _form_str("MISP_WEBAPP_URL"),
            "MISP_WEBAPP_KEY": _form_str("MISP_WEBAPP_KEY"),
            "MISP_WEBAPP_VERIFYCERT": _form_bool("MISP_WEBAPP_VERIFYCERT"),
            "MISP_EVENT_DISTRIBUTION": _form_int("MISP_EVENT_DISTRIBUTION", 0),
            # LLM provider settings live on the AI tab and are saved over AJAX.
            "OPENAI_API_KEY": getattr(_config, "OPENAI_API_KEY", getattr(_config, "ANTHROPIC_API_KEY", "")),
            "OPENAI_MODEL": getattr(_config, "OPENAI_MODEL", getattr(_config, "ANTHROPIC_MODEL", "")),
            "OPENAI_ENABLED": bool(getattr(_config, "OPENAI_ENABLED", True)),
            "LOCAL_LLM_ENABLED": bool(getattr(_config, "LOCAL_LLM_ENABLED", False)),
            "LOCAL_LLM_URL": getattr(_config, "LOCAL_LLM_URL", ""),
            "LOCAL_LLM_API_KEY": getattr(_config, "LOCAL_LLM_API_KEY", ""),
            "LOCAL_LLM_MODEL": getattr(_config, "LOCAL_LLM_MODEL", ""),
            "LLM_DEFAULT_PROVIDER": getattr(_config, "LLM_DEFAULT_PROVIDER", "openai"),
            "NOTIFICATION_CHANNELS": _read_notification_channels(),
            "SMTP_HOST": _form_str("SMTP_HOST"),
            "SMTP_PORT": _form_int("SMTP_PORT", 587),
            "SMTP_USE_TLS": _form_bool("SMTP_USE_TLS"),
            "SMTP_USERNAME": _form_str("SMTP_USERNAME"),
            "SMTP_PASSWORD": _form_str("SMTP_PASSWORD"),
            "SMTP_FROM": _form_str("SMTP_FROM"),
            "FLOWINTEL_INSTANCES": getattr(_config, "FLOWINTEL_INSTANCES", []),
            "PRODUCT_TYPES": products,
            "DAILY_BRIEFING_TITLE_EXCLUSIONS": exclusions,
            "FOCUS_POINTS_GEOGRAPHIES": fp_geographies,
            "FOCUS_POINTS_SECTORS": fp_sectors,
            "FOCUS_POINTS_TECHNOLOGIES": fp_technologies,
            "FOCUS_POINTS_THREAT_TYPES": fp_threat_types,
            "FOCUS_POINTS_THREAT_ACTORS": fp_threat_actors,
            "THREAT_ACTOR_TYPES": threat_actor_types,
            "COLLECTION_TAG_STRIP_PREFIXES": tag_strip_prefixes,
            "COLLECTION_TAG_HIDE_PREFIXES": tag_hide_prefixes,
            "TAG_STAKEHOLDER": _form_tag("TAG_STAKEHOLDER"),
            "TAG_PIR": _form_tag("TAG_PIR"),
            "TAG_GIR": _form_tag("TAG_GIR"),
            "TAG_RFI": _form_tag("TAG_RFI"),
            "TAG_FLASH_INTEL": _form_tag("TAG_FLASH_INTEL"),
            "TAG_VEA": _form_tag("TAG_VEA"),
            "TAG_BRIEFING": _form_tag("TAG_BRIEFING"),
            "TAG_TLR": _form_tag("TAG_TLR"),
            "TAG_THREAT_ACTOR_PROFILE": _form_tag("TAG_THREAT_ACTOR_PROFILE"),
            "TAG_INDICATOR_FEED": _form_tag("TAG_INDICATOR_FEED"),
            "TAG_COLLECTION_FOLLOWUP": _form_tag("TAG_COLLECTION_FOLLOWUP"),
            "TAG_COLLECTION_DISMISSED": _form_tag("TAG_COLLECTION_DISMISSED"),
            "RECOMMENDED_ACTIONS_IMMEDIATE": lines("RECOMMENDED_ACTIONS_IMMEDIATE"),
            "RECOMMENDED_ACTIONS_NEAR_TERM": lines("RECOMMENDED_ACTIONS_NEAR_TERM"),
            "POLL_WINDOW_HOURS": _form_int("POLL_WINDOW_HOURS", 24),
            "SCRAPER_MARKER_TAG": _form_tag("SCRAPER_MARKER_TAG"),
            "EVENT_LOG_RETENTION_DAYS": max(1, _form_int("EVENT_LOG_RETENTION_DAYS", 90)),
            "PIPELINE_RUN_LOG_RETENTION_DAYS": max(1, _form_int("PIPELINE_RUN_LOG_RETENTION_DAYS", 365)),
            "LOG_LEVEL": _form_str("LOG_LEVEL") or "INFO",
            "HOSTNAME": _form_str("HOSTNAME") or "0.0.0.0",
            "PORT": _form_int("PORT", 5000),
            "SSL_ENABLED": _form_bool("SSL_ENABLED"),
            "SSL_CERT": _form_str("SSL_CERT") or "certs/zsazsa.crt",
            "SSL_KEY": _form_str("SSL_KEY") or "certs/zsazsa.key",
            "MISP_SESSION_COOKIE_NAME": session_cookie_name,
            "MISP_SESSION_REDIS_HOST": _form_str("MISP_SESSION_REDIS_HOST") or "127.0.0.1",
            "MISP_SESSION_REDIS_PORT": _form_int("MISP_SESSION_REDIS_PORT", 6379),
            "MISP_SESSION_REDIS_DB": _form_int("MISP_SESSION_REDIS_DB", 0),
            "MISP_SESSION_REDIS_USERNAME": _form_str("MISP_SESSION_REDIS_USERNAME"),
            "MISP_SESSION_REDIS_PASSWORD": _form_str("MISP_SESSION_REDIS_PASSWORD"),
            "MISP_SESSION_REDIRECT_TO_LOGIN": _form_bool("MISP_SESSION_REDIRECT_TO_LOGIN"),
            "BRAND_COMPANY": _form_str("BRAND_COMPANY"),
            "BRAND_DEPARTMENT": _form_str("BRAND_DEPARTMENT"),
            "BRAND_COLOR_1": _form_str("BRAND_COLOR_1") or "#0f2d52",
            "BRAND_COLOR_2": _form_str("BRAND_COLOR_2") or "#0078f1",
            "BRAND_COLOR_3": _form_str("BRAND_COLOR_3") or "#64748b",
            "BRAND_LOGO": getattr(_config, "BRAND_LOGO", ""),
            "THEME": _form_str("THEME") or "overmind",
        }
        if values["THEME"] not in ("default", "uibeta", "overmind"):
            values["THEME"] = "overmind"
        active_tab = request.form.get("active_tab", "tab-connections")
        if active_tab not in _CONFIG_TABS:
            active_tab = "tab-connections"
        try:
            _write(values)
            importlib.reload(_config)
            audit.record("update", "config", details="full configuration saved")
            flash("Configuration saved. A backup was written to config/__init__.py.backup.", "success")
            if cookie_autodetected:
                flash(f"Single sign-on enabled: detected MISP session cookie '{session_cookie_name}' and stored it.", "info")
            elif sso_enabled and not session_cookie_name:
                flash("Single sign-on is enabled but the MISP session cookie name could not be detected. Check the MISP connection on the Connections tab.", "warning")
        except Exception as exc:
            logger.exception("config save failed")
            audit.record("update", "config", details="save failed")
            flash("Could not save configuration.", "warning")
        return redirect(url_for("config_page.index", tab=active_tab))

    cfg = _read()
    active_tab = request.args.get("tab", "tab-connections")
    if active_tab not in _CONFIG_TABS:
        active_tab = "tab-connections"
    return render_template("config_page.html", cfg=cfg, active_tab=active_tab, migrations=MIGRATIONS)


@bp.route("/config/run-migration", methods=["POST"])
@rate_limited("config_run_migration", limit=10, window_s=60)
def run_migration():
    """Run a registered maintenance migration script and return its output."""
    data, err = _json_object()
    if err:
        return err
    migration = _MIGRATIONS_BY_ID.get((data.get("id") or "").strip())
    if not migration:
        return jsonify({"ok": False, "error": "Unknown migration"}), 404
    apply = bool(data.get("apply")) and migration.get("supports_apply", False)

    cmd = [sys.executable, str(_ROOT / migration["script"])]
    if apply:
        cmd.append("--apply")

    mode = "apply" if apply else "dry-run"
    try:
        proc = subprocess.run(
            cmd, cwd=str(_ROOT), capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        audit.record("run", "migration", entity_label=migration["id"], details=f"{mode}: timed out")
        return jsonify({"ok": False, "error": "Migration timed out after 600s"}), 504
    except Exception:
        logger.exception("run_migration failed: %s", migration["id"])
        return jsonify({"ok": False, "error": "Could not run migration."}), 500

    output = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0
    audit.record(
        "run", "migration", entity_label=migration["id"],
        details=f"{mode}: {'ok' if ok else f'exit {proc.returncode}'}",
    )
    return jsonify({"ok": ok, "mode": mode, "output": output, "returncode": proc.returncode})


@bp.route("/config/sources/save-scraper", methods=["POST"])
def save_scraper_config():
    """Save only the MISP scraper connection settings."""
    current = _read()
    current["MISP_URL"] = request.form.get("MISP_URL", "").strip()
    current["MISP_KEY"] = request.form.get("MISP_KEY", "").strip()
    current["MISP_VERIFYCERT"] = request.form.get("MISP_VERIFYCERT") == "true"
    current["MISP_SCRAPER_LIMIT"] = max(1, _form_int("MISP_SCRAPER_LIMIT", 500))
    current["MISP_SCRAPER_SINCE_DAYS"] = max(0, _form_int("MISP_SCRAPER_SINCE_DAYS", 0))
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("update", "config", entity_label="misp-scraper")
        flash("MISP scraper settings saved.", "success")
    except Exception as exc:
        logger.exception("save_scraper_config failed")
        flash("Could not save configuration.", "warning")
    return redirect(url_for("collection_sources.index"))


@bp.route("/config/sources/save-scraper-redis", methods=["POST"])
def save_scraper_redis_config():
    """Save the misp-scraper Redis queue settings used by newsletter imports."""
    current = _read()
    current["SCRAPER_REDIS_HOST"] = request.form.get("SCRAPER_REDIS_HOST", "").strip()
    try:
        current["SCRAPER_REDIS_PORT"] = _form_int("SCRAPER_REDIS_PORT", 6379)
    except (ValueError, TypeError):
        current["SCRAPER_REDIS_PORT"] = 6379
    current["SCRAPER_REDIS_PASSWORD"] = request.form.get("SCRAPER_REDIS_PASSWORD", "")
    current["SCRAPER_REDIS_CHANNEL"] = request.form.get("SCRAPER_REDIS_CHANNEL", "").strip() or "urls"
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("update", "config", entity_label="scraper-redis")
        flash("Scraper queue settings saved.", "success")
    except Exception:
        logger.exception("save_scraper_redis_config failed")
        flash("Could not save configuration.", "warning")
    return redirect(url_for("collection_sources.index"))


@bp.route("/config/sources/save-server", methods=["POST"])
@rate_limited("config_save_server", limit=60, window_s=60)
def save_server_config():
    """Add or update a single MISP server entry (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    original_id = (data.get("original_id") or "").strip()
    label = (data.get("label") or "").strip()
    url = (data.get("url") or "").strip()
    if not label and not url:
        return jsonify({"ok": False, "error": "Label or URL required"}), 400
    sid = (data.get("id") or "").strip()
    if not sid:
        sid = "".join(c.lower() if c.isalnum() else "-" for c in label).strip("-") or "server"
    try:
        since = max(1, min(3650, int(data.get("since_days") or 7)))
    except (ValueError, TypeError):
        since = 7
    try:
        limit = max(1, int(data.get("limit") or 500))
    except (ValueError, TypeError):
        limit = 500
    try:
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
        enabled = _parse_bool(data.get("enabled", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    entry = {
        "id": sid,
        "label": label,
        "url": url,
        "api_key": (data.get("api_key") or "").strip(),
        "verify_tls": verify_tls,
        "enabled": enabled,
        "tags": (data.get("tags") or "").strip(),
        "tags_and": (data.get("tags_and") or "").strip(),
        "tags_not": (data.get("tags_not") or "").strip(),
        "org_filter_type": (data.get("org_filter_type") or "").strip(),
        "org_filter": (data.get("org_filter") or "").strip(),
        "since_days": since,
        "limit": limit,
    }
    current = _read()
    servers = list(current.get("MISP_SERVERS") or [])
    action = "create"
    if original_id:
        for i, s in enumerate(servers):
            if s.get("id") == original_id:
                servers[i] = entry
                action = "update"
                break
        if action == "create":
            servers.append(entry)
    else:
        servers.append(entry)
    current["MISP_SERVERS"] = servers
    try:
        _write(current)
        importlib.reload(_config)
        audit.record(action, "misp_server", entity_label=label)
        return jsonify({"ok": True, "new_id": sid})
    except Exception as exc:
        logger.exception("save_server_config failed")
        audit.record(action, "misp_server", entity_label=label, details="failed")
        return jsonify({"ok": False, "error": "Could not save server settings."}), 500


@bp.route("/config/sources/delete-server", methods=["POST"])
@rate_limited("config_delete_server", limit=60, window_s=60)
def delete_server_config():
    """Remove a single MISP server entry by ID (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    server_id = (data.get("server_id") or "").strip()
    if not server_id:
        return jsonify({"ok": False, "error": "server_id required"}), 400
    current = _read()
    servers = current.get("MISP_SERVERS") or []
    label = next((s.get("label", server_id) for s in servers if s.get("id") == server_id), server_id)
    current["MISP_SERVERS"] = [s for s in servers if s.get("id") != server_id]
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("delete", "misp_server", entity_label=label)
        return jsonify({"ok": True})
    except Exception as exc:
        logger.exception("delete_server_config failed")
        audit.record("delete", "misp_server", entity_label=label, details="failed")
        return jsonify({"ok": False, "error": "Could not delete server."}), 500


def _str_list(value) -> list[str]:
    """Accept a list or a newline/comma string and return a clean list of strings."""
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = value.replace(",", "\n").splitlines()
    else:
        items = []
    return [str(i).strip() for i in items if str(i).strip()]


def _slug_id(name: str, fallback: str, taken: set | None = None) -> str:
    """Kebab-case identifier from a display name, with repeated dashes collapsed.

    Pass `taken` to number off a name that is already spoken for, so two entries
    named alike do not end up sharing an id.
    """
    raw = "".join(c.lower() if c.isalnum() else "-" for c in name)
    slug = "-".join(p for p in raw.split("-") if p) or fallback
    candidate, n = slug, 2
    while taken and candidate in taken:
        candidate, n = f"{slug}-{n}", n + 1
    return candidate


def _build_imap_source(raw: dict, position: int, taken_ids: set) -> dict:
    """Validate one collection source from the save payload. Raises ValueError."""
    name = (raw.get("name") or "").strip()
    if not name:
        raise ValueError("Each collection source needs a name")
    parser = (raw.get("parser") or "").strip()
    if parser not in newsletter_parsers.available_sources():
        # Escape the echoed value: it is reflected back in the JSON error response.
        raise ValueError(f"Unknown newsletter parser '{escape(parser)}'")
    mode = (raw.get("mode") or "auto").strip().lower()
    if mode not in ("auto", "manual"):
        mode = "auto"
    sid = _slug_id(name, f"source-{position}", taken_ids)
    taken_ids.add(sid)
    return {
        "id": sid,
        "name": name,
        "enabled": _parse_bool(raw.get("enabled", True), default=True),
        "parser": parser,
        "subjects": _str_list(raw.get("subjects")),
        "senders": _str_list(raw.get("senders")),
        "reliability": (raw.get("reliability") or "").strip().upper(),
        "mode": mode,
    }


@bp.route("/config/sources/save-imap", methods=["POST"])
@rate_limited("config_save_imap", limit=60, window_s=60)
def save_imap_mailbox():
    """Add or update one IMAP mailbox and its collection sources (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    name = (data.get("name") or "").strip()
    host = (data.get("host") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Mailbox name required"}), 400
    if not host:
        return jsonify({"ok": False, "error": "IMAP host required"}), 400
    try:
        ssl_on = _parse_bool(data.get("ssl", True), default=True)
        enabled = _parse_bool(data.get("enabled", True), default=True)
        port = int(data.get("port") or (993 if ssl_on else 143))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Port must be a number"}), 400

    try:
        taken_ids = set()
        sources = [_build_imap_source(s, i + 1, taken_ids)
                   for i, s in enumerate(data.get("sources") or [])]
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    sid = (data.get("id") or "").strip() or _slug_id(name, "mailbox")
    entry = {
        "id": sid,
        "name": name,
        "enabled": enabled,
        "host": host,
        "port": port,
        "ssl": ssl_on,
        "username": (data.get("username") or "").strip(),
        "password": data.get("password") or "",
        "folder": (data.get("folder") or "INBOX").strip() or "INBOX",
        "sources": sources,
    }
    original_id = (data.get("original_id") or "").strip()
    current = _read()
    mailboxes = list(current.get("IMAP_SOURCES") or [])
    action = "create"
    if original_id:
        for i, m in enumerate(mailboxes):
            if m.get("id") == original_id:
                mailboxes[i] = entry
                action = "update"
                break
        else:
            mailboxes.append(entry)
    else:
        mailboxes.append(entry)
    current["IMAP_SOURCES"] = mailboxes
    try:
        _write(current)
        importlib.reload(_config)
        audit.record(action, "imap_mailbox", entity_label=name)
        return jsonify({"ok": True, "new_id": sid})
    except Exception:
        logger.exception("save_imap_mailbox failed")
        return jsonify({"ok": False, "error": "Could not save mailbox."}), 500


@bp.route("/config/sources/delete-imap", methods=["POST"])
@rate_limited("config_delete_imap", limit=60, window_s=60)
def delete_imap_mailbox():
    """Remove a single IMAP mailbox source by ID (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    mailbox_id = (data.get("mailbox_id") or "").strip()
    if not mailbox_id:
        return jsonify({"ok": False, "error": "mailbox_id required"}), 400
    current = _read()
    sources = current.get("IMAP_SOURCES") or []
    label = next((s.get("name", mailbox_id) for s in sources if s.get("id") == mailbox_id), mailbox_id)
    current["IMAP_SOURCES"] = [s for s in sources if s.get("id") != mailbox_id]
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("delete", "imap_mailbox", entity_label=label)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("delete_imap_mailbox failed")
        return jsonify({"ok": False, "error": "Could not delete mailbox."}), 500


@bp.route("/config/sources/test-imap", methods=["POST"])
@rate_limited("config_test_imap", limit=20, window_s=60)
def test_imap_mailbox():
    """Check that an IMAP mailbox can be opened with the supplied settings (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    from core import imap_collector

    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "IMAP host is required"}), 400
    try:
        ssl_on = _parse_bool(data.get("ssl", True), default=True)
        port = int(data.get("port") or (993 if ssl_on else 143))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "error": "Port must be a number"}), 400
    result = imap_collector.test_connection(
        host, port, ssl_on,
        (data.get("username") or "").strip(),
        data.get("password") or "",
        (data.get("folder") or "INBOX").strip() or "INBOX",
    )
    return jsonify(result)


@bp.route("/config/test_misp_connection", methods=["POST"])
@rate_limited("config_test_misp_connection", limit=20, window_s=60)
def test_misp_connection():
    data, err = _json_object()
    if err:
        return err
    url = (data.get("url") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    try:
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not url or not api_key:
        return jsonify({"ok": False, "error": "URL and API key are required"}), 400
    result = misp_store._test_connection(url, api_key, verify_tls)
    audit.record("test", "misp_connection", entity_label=url, details="ok" if result.get("ok") else result.get("error"))
    return jsonify(result)


@bp.route("/config/server_usage")
def server_usage():
    """Return PIR/GIR counts that reference a given collection source label."""
    label = request.args.get("label", "").strip()
    if not label:
        return jsonify({"ok": False, "error": "label required"}), 400
    try:
        pirs = misp_store.list_pirs()
        girs = misp_store.list_girs()
        pir_count = sum(1 for p in pirs if label in (p.collection_sources or []))
        gir_count = sum(1 for g in girs if label in (g.collection_sources or []))
        return jsonify({"ok": True, "pir_count": pir_count, "gir_count": gir_count,
                        "in_use": (pir_count + gir_count) > 0})
    except Exception as exc:
        logger.exception("server_usage failed")
        return jsonify({"ok": False, "error": "Could not compute server usage."}), 500


@bp.route("/config/test-sso")
@rate_limited("config_test_sso", limit=20, window_s=60)
def test_sso():
    """Report why single sign-on did or did not identify this request (AJAX)."""
    try:
        return jsonify({"ok": True, **misp_session.diagnose(request.cookies)})
    except Exception:
        logger.exception("test_sso failed")
        return jsonify({"ok": False, "error": "Could not run the single sign-on check."}), 500


@bp.route("/config/save-notification-channel", methods=["POST"])
@rate_limited("config_save_notification_channel", limit=30, window_s=60)
def save_notification_channel():
    """Add or update a single notification channel entry (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    original_id = (data.get("original_id") or "").strip()
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    try:
        enabled = _parse_bool(data.get("enabled", True), default=True)
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    channel_type = (data.get("type") or "mattermost").strip().lower()
    recipient = (data.get("recipient") or "").strip()
    if channel_type == "email" and not recipient:
        return jsonify({"ok": False, "error": "Recipient email address required"}), 400

    current = _read()
    channels = list(current.get("NOTIFICATION_CHANNELS") or [])
    index = next((i for i, ch in enumerate(channels) if ch.get("id") == original_id), None) if original_id else None
    if index is None:
        # Stakeholders subscribe by id, so two channels named alike must not share
        # one: a collision would deliver to both.
        cid = (data.get("id") or "").strip() or _slug_id(name, "channel", {ch.get("id") for ch in channels})
    else:
        # A rename keeps the id it was subscribed under; re-deriving it would leave
        # every subscription pointing at a channel that no longer exists.
        cid = original_id

    entry = {
        "id": cid,
        "name": name,
        "type": channel_type,
        "url": url,
        "enabled": enabled,
        "verify_tls": verify_tls,
    }
    if channel_type == "email":
        entry["recipient"] = recipient
    if index is None:
        action = "create"
        channels.append(entry)
    else:
        action = "update"
        channels[index] = entry
    current["NOTIFICATION_CHANNELS"] = channels
    try:
        _write(current)
        importlib.reload(_config)
        audit.record(action, "notification_channel", entity_label=name)
        return jsonify({"ok": True, "new_id": cid})
    except Exception:
        logger.exception("save_notification_channel failed")
        return jsonify({"ok": False, "error": "Could not save notification channel."}), 500


@bp.route("/config/delete-notification-channel", methods=["POST"])
@rate_limited("config_delete_notification_channel", limit=30, window_s=60)
def delete_notification_channel():
    """Remove a notification channel by ID (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    channel_id = (data.get("channel_id") or "").strip()
    if not channel_id:
        return jsonify({"ok": False, "error": "channel_id required"}), 400
    current = _read()
    channels = current.get("NOTIFICATION_CHANNELS") or []
    label = next((c.get("name", channel_id) for c in channels if c.get("id") == channel_id), channel_id)
    current["NOTIFICATION_CHANNELS"] = [c for c in channels if c.get("id") != channel_id]
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("delete", "notification_channel", entity_label=label)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("delete_notification_channel failed")
        return jsonify({"ok": False, "error": "Could not delete notification channel."}), 500


@bp.route("/config/ping-notification-channel", methods=["POST"])
@rate_limited("config_ping_notification_channel", limit=10, window_s=60)
def ping_notification_channel():
    data, err = _json_object()
    if err:
        return err
    channel_id = (data.get("channel_id") or "").strip()
    if not channel_id:
        return jsonify({"ok": False, "error": "channel_id required"}), 400
    channels = _read_notification_channels()
    ch = next((c for c in channels if c.get("id") == channel_id), None)
    if not ch:
        return jsonify({"ok": False, "error": "Channel not found"}), 404
    if (ch.get("type") or "").strip().lower() == "email":
        from notifier import email

        recipient = (ch.get("recipient") or "").strip()
        if not recipient:
            return jsonify({"ok": False, "error": "Channel has no recipient address configured"}), 400
        ok = email.send_email(
            [recipient],
            "zsazsa test notification",
            "This is a **zsazsa** test notification. The email channel is configured correctly.",
            f"test {channel_id}",
        )
        if ok:
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Send failed. Check SMTP settings and logs."})
    url = (ch.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "Channel has no webhook URL configured"}), 400
    verify_tls = bool(ch.get("verify_tls", True))
    try:
        r = requests.post(url, json={"text": "zsazsa test notification: channel is reachable."}, timeout=10, verify=verify_tls)
        r.raise_for_status()
        return jsonify({"ok": True})
    except requests.RequestException as exc:
        return jsonify({"ok": False, "error": str(exc)})


@bp.route("/config/save-flowintel-instance", methods=["POST"])
@rate_limited("config_save_flowintel_instance", limit=30, window_s=60)
def save_flowintel_instance():
    """Add or update a single Flowintel instance entry (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    original_id = (data.get("original_id") or "").strip()
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    if not url:
        return jsonify({"ok": False, "error": "URL required"}), 400
    cid = (data.get("id") or "").strip()
    if not cid:
        cid = "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-") or "flowintel"
    try:
        enabled = _parse_bool(data.get("enabled", True), default=True)
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    case_templates_raw = data.get("case_templates") or {}
    case_templates = {}
    if isinstance(case_templates_raw, dict):
        for product in FLOWINTEL_CASE_TEMPLATE_PRODUCTS:
            ct = case_templates_raw.get(product["key"])
            if isinstance(ct, dict):
                case_templates[product["key"]] = {
                    "enabled": bool(ct.get("enabled")),
                    "template_id": str(ct.get("template_id") or "").strip(),
                    "initial_task": str(ct.get("initial_task") or "").strip(),
                }

    entry = {
        "id": cid,
        "name": name,
        "url": url,
        "api_key": api_key,
        "enabled": enabled,
        "verify_tls": verify_tls,
        "case_templates": case_templates,
    }
    current = _read()
    instances = list(current.get("FLOWINTEL_INSTANCES") or [])
    action = "create"
    if original_id:
        for i, inst in enumerate(instances):
            if inst.get("id") == original_id:
                instances[i] = entry
                action = "update"
                break
        if action == "create":
            instances.append(entry)
    else:
        instances.append(entry)
    current["FLOWINTEL_INSTANCES"] = instances
    try:
        _write(current)
        importlib.reload(_config)
        audit.record(action, "flowintel_instance", entity_label=name)
        return jsonify({"ok": True, "new_id": cid})
    except Exception:
        logger.exception("save_flowintel_instance failed")
        return jsonify({"ok": False, "error": "Could not save Flowintel instance."}), 500


@bp.route("/config/delete-flowintel-instance", methods=["POST"])
@rate_limited("config_delete_flowintel_instance", limit=30, window_s=60)
def delete_flowintel_instance():
    """Remove a Flowintel instance by ID (AJAX)."""
    data, err = _json_object()
    if err:
        return err
    instance_id = (data.get("instance_id") or "").strip()
    if not instance_id:
        return jsonify({"ok": False, "error": "instance_id required"}), 400
    current = _read()
    instances = current.get("FLOWINTEL_INSTANCES") or []
    label = next((i.get("name", instance_id) for i in instances if i.get("id") == instance_id), instance_id)
    current["FLOWINTEL_INSTANCES"] = [i for i in instances if i.get("id") != instance_id]
    try:
        _write(current)
        importlib.reload(_config)
        audit.record("delete", "flowintel_instance", entity_label=label)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("delete_flowintel_instance failed")
        return jsonify({"ok": False, "error": "Could not delete Flowintel instance."}), 500


@bp.route("/config/test-flowintel-connection", methods=["POST"])
@rate_limited("config_test_flowintel_connection", limit=20, window_s=60)
def test_flowintel_connection():
    """Check connectivity to a Flowintel instance without sending any data."""
    data, err = _json_object()
    if err:
        return err
    url = (data.get("url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    try:
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not url or not api_key:
        return jsonify({"ok": False, "error": "URL and API key are required"}), 400
    return jsonify(flowintel_client.test_connection(url, api_key, verify_tls))


@bp.route("/config/test-smtp-connection", methods=["POST"])
@rate_limited("config_test_smtp_connection", limit=20, window_s=60)
def test_smtp_connection():
    """Check SMTP connectivity using the supplied settings, without sending mail."""
    data, err = _json_object()
    if err:
        return err
    from notifier import email

    host = (data.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "SMTP host is required"}), 400
    try:
        port = int(data.get("port") or 587)
        use_tls = _parse_bool(data.get("use_tls", True), default=True)
    except ValueError:
        return jsonify({"ok": False, "error": "Port must be a number"}), 400
    result = email.test_connection(
        host, port, use_tls,
        (data.get("username") or "").strip(),
        data.get("password") or "",
    )
    return jsonify(result)


@bp.route("/config/flowintel-case-templates", methods=["POST"])
@rate_limited("config_flowintel_case_templates", limit=20, window_s=60)
def flowintel_case_templates():
    """Return the case templates available on a Flowintel instance, given connection details."""
    data, err = _json_object()
    if err:
        return err
    url = (data.get("url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    try:
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not url or not api_key:
        return jsonify({"ok": False, "error": "URL and API key are required"}), 400
    return jsonify(flowintel_client.get_case_templates(url, api_key, verify_tls))


@bp.route("/config/flowintel-case-template-tasks", methods=["POST"])
@rate_limited("config_flowintel_case_template_tasks", limit=20, window_s=60)
def flowintel_case_template_tasks():
    """Return the tasks defined by a Flowintel case template, in order."""
    data, err = _json_object()
    if err:
        return err
    url = (data.get("url") or "").strip().rstrip("/")
    api_key = (data.get("api_key") or "").strip()
    template_id = (data.get("template_id") or "").strip()
    try:
        verify_tls = _parse_bool(data.get("verify_tls", True), default=True)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not url or not api_key or not template_id:
        return jsonify({"ok": False, "error": "URL, API key and template_id are required"}), 400
    return jsonify(flowintel_client.get_case_template_tasks(url, api_key, template_id, verify_tls))


@bp.route("/config/upload-logo", methods=["POST"])
@rate_limited("config_upload_logo", limit=10, window_s=60)
def upload_logo():
    f = request.files.get("logo")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "No file provided"}), 400
    ext = Path(f.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg"):
        return jsonify({"ok": False, "error": "Only PNG and JPG files are accepted"}), 400
    _UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    for old in _UPLOADS_DIR.glob("logo.*"):
        old.unlink(missing_ok=True)
    dest = _UPLOADS_DIR / f"logo{ext}"
    f.save(str(dest))
    current = _read()
    current["BRAND_LOGO"] = dest.name
    _write(current)
    importlib.reload(_config)
    return jsonify({"ok": True, "filename": dest.name})


@bp.route("/config/logo")
def serve_logo():
    logo = getattr(_config, "BRAND_LOGO", "")
    if not logo:
        return "", 404
    path = _UPLOADS_DIR / logo
    if not path.exists():
        return "", 404
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    return send_file(str(path), mimetype=mime)


@bp.route("/config/prompts", methods=["POST"])
@rate_limited("config_save_prompts", limit=30, window_s=60)
def save_prompts():
    data, err = _json_object()
    if err:
        return err
    prompts = data.get("prompts", [])
    if not isinstance(prompts, list):
        return jsonify({"ok": False, "error": "Invalid payload"}), 400
    _PROMPTS_DIR.mkdir(exist_ok=True)
    prompts_dir = _PROMPTS_DIR.resolve()
    try:
        for entry in prompts:
            filename = (entry.get("filename") or "").strip()
            content = entry.get("content") or ""
            if not filename or not filename.endswith(".md"):
                return jsonify({"ok": False, "error": f"Invalid filename: {filename!r}"}), 400
            target = (prompts_dir / filename).resolve()
            if target.parent != prompts_dir:
                return jsonify({"ok": False, "error": f"Unsafe filename: {filename!r}"}), 400
            target.write_text(content, encoding="utf-8")
    except Exception:
        logger.exception("save_prompts failed")
        audit.record("update", "prompt_templates", details="failed")
        return jsonify({"ok": False, "error": "Could not save prompt templates."}), 500
    filenames = ", ".join(e.get("filename", "") for e in prompts if e.get("filename"))
    audit.record("update", "prompt_templates", details=filenames or f"{len(prompts)} file(s)")
    return jsonify({"ok": True})


@bp.route("/config/save-ai-features", methods=["POST"])
@rate_limited("config_save_ai_features", limit=20, window_s=60)
def save_ai_features():
    data, err = _json_object()
    if err:
        return err
    features = data.get("features")
    if not isinstance(features, dict):
        return jsonify({"ok": False, "error": "Invalid payload"}), 400
    try:
        from core.ai_config import save as _ai_save, FEATURES, PROVIDERS
        # Validate: only accept known feature IDs and safe field values.
        # ai_config.save() falls back to OpenAI for an unknown provider.
        clean = {}
        for fid, vals in features.items():
            if fid not in FEATURES or not isinstance(vals, dict):
                continue
            model = (vals.get("model") or "").strip()
            prompt = (vals.get("prompt") or "").strip()
            if prompt and ("/" in prompt or "\\" in prompt):
                return jsonify({"ok": False, "error": f"Invalid prompt filename: {prompt!r}"}), 400
            clean[fid] = {
                "provider": (vals.get("provider") or "").strip(),
                "model": model,
                # ai_config.save() drops anything that is not a usable number.
                "temperature": vals.get("temperature"),
                "prompt": prompt,
            }
        _ai_save(clean)

        # Persist provider settings and the default model to config/__init__.py.
        providers = data.get("providers")
        default_model = (data.get("default_model") or "").strip()
        if default_model or isinstance(providers, dict):
            current = _read()
            if default_model:
                current["OPENAI_MODEL"] = default_model
            if isinstance(providers, dict):
                openai_p = providers.get("openai") or {}
                local_p = providers.get("local") or {}
                current["OPENAI_ENABLED"] = bool(openai_p.get("enabled"))
                current["OPENAI_API_KEY"] = (openai_p.get("api_key") or "").strip()
                current["LOCAL_LLM_ENABLED"] = bool(local_p.get("enabled"))
                current["LOCAL_LLM_URL"] = (local_p.get("url") or "").strip()
                current["LOCAL_LLM_API_KEY"] = (local_p.get("api_key") or "").strip()
                current["LOCAL_LLM_MODEL"] = (local_p.get("model") or "").strip()
                default_provider = (providers.get("default") or "").strip()
                if default_provider in PROVIDERS:
                    current["LLM_DEFAULT_PROVIDER"] = default_provider
            _write(current)
            importlib.reload(_config)

        audit.record("update", "ai_features", details=f"{len(clean)} feature(s) saved")
        return jsonify({"ok": True})
    except Exception as exc:
        logger.exception("save_ai_features failed")
        return jsonify({"ok": False, "error": "Could not save AI feature settings."}), 500
