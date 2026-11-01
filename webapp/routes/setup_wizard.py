"""The setup wizard: what a new zsazsa needs, one step at a time.

The steps save through the endpoints of the Settings pages: a step's form posts
to /config, which keeps every setting the form does not send, and the lists go
to the AJAX endpoints of the collection sources, the notification channels and
the AI providers. Anything else is on the Settings pages, as before.
"""

import logging

from flask import Blueprint, abort, redirect, render_template, url_for

import config
from webapp import misp_session, misp_store, newsletter_parsers
from webapp.routes.collection_sources import ADMIRALTY_OPTIONS
from webapp.utils import normalize_notification_channels, scraper_enabled

logger = logging.getLogger(__name__)
bp = Blueprint("setup_wizard", __name__, url_prefix="/config/setup")

# (name, title, icon), in the order they are walked through.
STEPS = [
    ("organisation", "Your organisation", "fa-building"),
    ("sources", "Data collection sources", "fa-database"),
    ("ai", "AI", "fa-robot"),
    ("focus", "Focus points", "fa-bullseye"),
    ("notifications", "Notifications", "fa-bell"),
    ("done", "Done", "fa-flag-checkered"),
]
STEP_NAMES = [name for name, _, _ in STEPS]

# (setting, label, example, icon)
FOCUS_LISTS = [
    ("FOCUS_POINTS_GEOGRAPHIES", "Geographies", "Belgium", "fa-earth-europe"),
    ("FOCUS_POINTS_SECTORS", "Sectors", "Energy", "fa-industry"),
    ("FOCUS_POINTS_VENDORS", "Vendors", "Fortinet", "fa-building"),
    ("FOCUS_POINTS_TECHNOLOGIES", "Technologies", "Microsoft 365", "fa-microchip"),
    ("FOCUS_POINTS_THREAT_TYPES", "Threat types", "Ransomware", "fa-virus"),
    ("FOCUS_POINTS_THREAT_ACTORS", "Threat actors", "APT29", "fa-user-secret"),
]


@bp.before_request
def _site_admins_only():
    return misp_session.refuse_unless_site_admin()


@bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


# What the example config has where an install has its own values.
def _openai_key_stored() -> bool:
    key = getattr(config, "OPENAI_API_KEY", "") or ""
    return bool(key) and "your-openai-key" not in key


def _scraper_set_up() -> bool:
    return scraper_enabled() and "your-misp-instance" not in (getattr(config, "MISP_URL", "") or "")


def _channels() -> list:
    """The channels that have somewhere to send to, the legacy webhook included."""
    channels = normalize_notification_channels(
        getattr(config, "NOTIFICATION_CHANNELS", []),
        legacy_url=getattr(config, "MATTERMOST_WEBHOOK_URL", ""),
        legacy_enabled=getattr(config, "MATTERMOST_ENABLED", False),
    )
    return [c for c in channels if c.get("url") or c.get("recipient")]


def status() -> dict:
    """Per step, whether what it asks for is in place."""
    return {
        "organisation": bool(getattr(config, "BRAND_COMPANY", "")),
        "sources": bool(_scraper_set_up() or getattr(config, "MISP_SERVERS", None)
                        or getattr(config, "IMAP_SOURCES", None)),
        # OpenAI is on unless switched off, as in the analyser.
        "ai": bool((getattr(config, "OPENAI_ENABLED", True) and _openai_key_stored())
                   or (getattr(config, "LOCAL_LLM_ENABLED", False) and getattr(config, "LOCAL_LLM_URL", ""))),
        "focus": any(getattr(config, key, None) for key, *_ in FOCUS_LISTS),
        "notifications": any(c.get("enabled") for c in _channels()),
    }


def next_step(name) -> str:
    """The step after ``name``; the last step is its own."""
    position = STEP_NAMES.index(name)
    return STEP_NAMES[min(position + 1, len(STEP_NAMES) - 1)]


def needs_setup() -> bool:
    """Without sources or focus points the analyser has nothing to work from."""
    done = status()
    return not (done["sources"] and done["focus"])


@bp.route("/")
def start():
    done = status()
    first = next((name for name in STEP_NAMES[:-1] if not done[name]), STEP_NAMES[0])
    return redirect(url_for("setup_wizard.step", name=first))


def _view(name) -> dict:
    """What a step shows. Keys, passwords and webhook URLs never reach the page:
    only whether one is stored, as on the Settings pages."""
    if name == "organisation":
        return {"company": getattr(config, "BRAND_COMPANY", ""), "department": getattr(config, "BRAND_DEPARTMENT", ""),
                "logo": bool(getattr(config, "BRAND_LOGO", ""))}
    if name == "sources":
        try:
            manual = misp_store.list_collection_sources()
        except Exception:
            logger.warning("setup wizard: could not list the manual sources", exc_info=True)
            manual = None
        return {
            "scraper": _scraper_set_up(),
            "scraper_url": getattr(config, "MISP_URL", ""),
            "servers": [{"label": s.get("label") or s.get("url"), "url": s.get("url"), "enabled": s.get("enabled", True)}
                        for s in getattr(config, "MISP_SERVERS", None) or []],
            "mailboxes": [{"name": m.get("name"), "host": m.get("host"),
                           "newsletters": [n.get("name") for n in m.get("sources") or []]}
                          for m in getattr(config, "IMAP_SOURCES", None) or []],
            "manual": manual,
            "newsletters": newsletter_parsers.available_sources(),
            "admiralty_options": ADMIRALTY_OPTIONS,
        }
    if name == "ai":
        return {
            "openai_enabled": bool(getattr(config, "OPENAI_ENABLED", True)),
            "openai_key_stored": _openai_key_stored(),
            "openai_model": getattr(config, "OPENAI_MODEL", ""),
            "local_enabled": bool(getattr(config, "LOCAL_LLM_ENABLED", False)),
            "local_url": getattr(config, "LOCAL_LLM_URL", ""),
            "local_key_stored": bool(getattr(config, "LOCAL_LLM_API_KEY", "")),
            "local_model": getattr(config, "LOCAL_LLM_MODEL", ""),
            "default": getattr(config, "LLM_DEFAULT_PROVIDER", "openai"),
        }
    if name == "focus":
        return {"lists": [(key, label, example, icon, getattr(config, key, None) or [])
                          for key, label, example, icon in FOCUS_LISTS]}
    if name == "notifications":
        return {
            "channels": [{"name": c.get("name"), "type": c.get("type"), "enabled": c.get("enabled"),
                          "recipient": c.get("recipient", "")} for c in _channels()],
            "smtp_host": getattr(config, "SMTP_HOST", ""),
            "smtp_port": getattr(config, "SMTP_PORT", 587),
            "smtp_tls": bool(getattr(config, "SMTP_USE_TLS", True)),
            "smtp_username": getattr(config, "SMTP_USERNAME", ""),
            "smtp_password_stored": bool(getattr(config, "SMTP_PASSWORD", "")),
            "smtp_from": getattr(config, "SMTP_FROM", ""),
            "smtp_sender_name": getattr(config, "SMTP_SENDER_NAME", ""),
        }
    return {}


@bp.route("/<name>")
def step(name):
    if name not in STEP_NAMES:
        abort(404)
    position = STEP_NAMES.index(name)
    _, title, icon = STEPS[position]
    return render_template(
        "setup_wizard.html",
        steps=STEPS,
        current=name,
        title=title,
        icon=icon,
        previous=STEP_NAMES[position - 1] if position else None,
        following=next_step(name),
        done=status(),
        view=_view(name),
    )
