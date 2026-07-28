import json
import logging
import re
from pathlib import Path

import openai
import config

logger = logging.getLogger(__name__)


def _default_model(provider: str) -> str:
    if provider == "local":
        model = getattr(config, "LOCAL_LLM_MODEL", "")
        if not model:
            raise RuntimeError("No local LLM model configured. Set LOCAL_LLM_MODEL.")
        return model
    model = getattr(config, "OPENAI_MODEL", getattr(config, "ANTHROPIC_MODEL", ""))
    if not model:
        raise RuntimeError("No LLM model configured. Set OPENAI_MODEL or ANTHROPIC_MODEL.")
    return model


def _local_base_url() -> str:
    """Base URL of the local server, with the OpenAI-compatible /v1 path added if missing."""
    url = (getattr(config, "LOCAL_LLM_URL", "") or "").strip().rstrip("/")
    if not url:
        raise RuntimeError("No local LLM endpoint configured. Set LOCAL_LLM_URL.")
    return url if url.endswith("/v1") else f"{url}/v1"


def _resolve_provider(provider: str) -> str:
    """Return the provider to call: the feature's own choice, or the configured default."""
    if provider not in ("openai", "local"):
        provider = getattr(config, "LLM_DEFAULT_PROVIDER", "openai")
    if provider == "local" and not getattr(config, "LOCAL_LLM_ENABLED", False):
        raise RuntimeError("The local LLM provider is not enabled.")
    if provider == "openai" and not getattr(config, "OPENAI_ENABLED", True):
        raise RuntimeError("The OpenAI provider is not enabled.")
    return provider


def _get_client(provider: str) -> openai.OpenAI:
    if provider == "local":
        # Local servers usually ignore the key, but the client insists on one.
        return openai.OpenAI(api_key=getattr(config, "LOCAL_LLM_API_KEY", "") or "no-key",
                             base_url=_local_base_url())
    return openai.OpenAI(api_key=getattr(config, "OPENAI_API_KEY", getattr(config, "ANTHROPIC_API_KEY", "")))


def _build_system_prompt(prompt_file: str, extra: str = "") -> str:
    base = Path(prompt_file).read_text()
    return f"{base}\n\n{extra}".strip() if extra else base


def _resolve_prompt(filename: str) -> str:
    """Convert a bare filename to its zsazsaprompts/ path."""
    if "/" in filename or "\\" in filename:
        return filename
    return str(Path("zsazsaprompts") / filename)


def _strip_think_blocks(text: str) -> str:
    """Drop <think> blocks that some local servers leave in the answer."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _is_reasoning_model(model: str) -> bool:
    """OpenAI reasoning models (o1, o3, o4-mini, ...) use a different token parameter."""
    return bool(re.match(r"^o\d", model.strip()))


def _call(system: str, user: str, max_tokens: int, feature: str = "unknown", model: str = None,
          provider: str = None) -> str:
    effective_provider = _resolve_provider((provider or "").strip())
    effective_model = (model or "").strip() or _default_model(effective_provider)
    kwargs = {
        "model": effective_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    # OpenAI reasoning models reject max_tokens and require max_completion_tokens.
    if effective_provider == "openai" and _is_reasoning_model(effective_model):
        kwargs["max_completion_tokens"] = max_tokens
    else:
        kwargs["max_tokens"] = max_tokens
    # Thinking models otherwise spend the whole token budget on reasoning and
    # return an empty answer. Ollama understands 'think'; a server that does not
    # know the field rejects the request, so try again without it.
    if effective_provider == "local":
        kwargs["extra_body"] = {"think": False}
    client = _get_client(effective_provider)
    try:
        response = client.chat.completions.create(**kwargs)
    except openai.BadRequestError:
        if "extra_body" not in kwargs:
            raise
        logger.info("local endpoint rejected the 'think' option, calling it again without")
        del kwargs["extra_body"]
        response = client.chat.completions.create(**kwargs)
    usage = response.usage
    if usage:
        try:
            from core.db import log_llm_usage
            log_llm_usage(feature, effective_model,
                          usage.prompt_tokens, usage.completion_tokens, usage.total_tokens,
                          provider=effective_provider)
        except Exception as exc:
            logger.warning("Could not record LLM usage: %s", exc)
    choice = response.choices[0]
    text = _strip_think_blocks(choice.message.content or "")
    if not text:
        # A model that runs out of tokens mid-answer returns an empty message
        # rather than an error, so say why the caller got nothing.
        logger.error("%s returned no content for %s (model %s, finish_reason %s, token budget %s)",
                     effective_provider, feature, effective_model, choice.finish_reason, max_tokens)
    return text


def _feature_cfg(feature_id: str) -> dict:
    try:
        from core.ai_config import get_feature
        return get_feature(feature_id)
    except Exception as exc:
        logger.warning("ai_config unavailable for %s: %s", feature_id, exc)
        return {}


def check_relevance(article_content: str, focus_points: dict, source_reliability: str) -> dict:
    fc = _feature_cfg("check_relevance")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_relevance.md"),
        f"Focus points:\n{json.dumps(focus_points, indent=2)}\n\nSource reliability (Admiralty Scale): {source_reliability}",
    )
    text = _call(system, article_content[:10000], 512, feature="check_relevance", model=fc.get("model"), provider=fc.get("provider"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error("Relevance check returned invalid JSON: %s", text[:200])
        return {"relevant": False, "reason": "LLM response parse error"}


def generate_flash_intel(
    article_content: str,
    focus_points: dict,
    matched_points: list,
    source_reliability: str,
    event_date: str,
) -> str:
    fc = _feature_cfg("generate_flash_intel")
    extra_parts = [f"Focus points configured:\n{json.dumps(focus_points, indent=2)}"]
    threat_actor_types = [
        t.get("name", "") for t in (getattr(config, "THREAT_ACTOR_TYPES", []) or []) if t.get("name")
    ]
    if threat_actor_types:
        extra_parts.append(
            "Available threat actor types (use exact names when completing 'Threat actor types'):\n"
            + "\n".join(f"- {n}" for n in threat_actor_types)
        )
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_generate.md"),
        "\n\n".join(extra_parts),
    )
    user_message = (
        f"Matched focus points: {json.dumps(matched_points)}\n"
        f"Source reliability (Admiralty Scale): {source_reliability}\n"
        f"Event date: {event_date}\n\n"
        f"Article content:\n{article_content[:12000]}"
    )
    return _call(system, user_message, 2048, feature="generate_flash_intel", model=fc.get("model"), provider=fc.get("provider"))


def generate_fia_draft(
    content: str,
    event_info: str = "",
    event_date: str = "",
    source_reliability: str = "",
    focus_points: dict | None = None,
) -> str:
    """Generate a Flash Intel Alert draft from article content."""
    if focus_points is None:
        focus_points = {
            "geographies": list(getattr(config, "FOCUS_POINTS_GEOGRAPHIES", []) or []),
            "sectors": list(getattr(config, "FOCUS_POINTS_SECTORS", []) or []),
            "technologies": list(getattr(config, "FOCUS_POINTS_TECHNOLOGIES", []) or []),
            "threat_types": list(getattr(config, "FOCUS_POINTS_THREAT_TYPES", []) or []),
            "threat_actors": list(getattr(config, "FOCUS_POINTS_THREAT_ACTORS", []) or []),
        }
    fc = _feature_cfg("generate_fia_draft")
    extra_parts = []
    if focus_points:
        extra_parts.append(f"Focus points configured:\n{json.dumps(focus_points, indent=2)}")
    threat_actor_types = [
        t.get("name", "") for t in (getattr(config, "THREAT_ACTOR_TYPES", []) or []) if t.get("name")
    ]
    if threat_actor_types:
        extra_parts.append(
            "Available threat actor types (use exact names when completing 'Threat actor types'):\n"
            + "\n".join(f"- {n}" for n in threat_actor_types)
        )
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "flash_intel_generate.md"),
        "\n\n".join(extra_parts),
    )
    user_message = (
        f"Event title: {event_info}\n"
        f"Event date: {event_date or 'unknown'}\n"
        f"Source reliability (Admiralty Scale): {source_reliability or 'unknown'}\n\n"
        f"Article content:\n{content[:12000]}"
    )
    return _call(system, user_message, 2048, feature="generate_fia_draft", model=fc.get("model"), provider=fc.get("provider"))


_ACTOR_TYPE_LINE_RE = re.compile(r'^\s*Threat actor type\s*:\s*(.+?)\s*$', re.IGNORECASE | re.MULTILINE)


def draft_briefing_story(article_content: str, focus_points: dict = None, threat_actor_types: list = None) -> tuple[str, str]:
    """Draft a five-line briefing story and a suggested threat actor type.

    Returns (story_text, suggested_actor_type). The actor type is one of the
    `name` values in `threat_actor_types`, or "" if the model could not
    attribute one.
    """
    fc = _feature_cfg("draft_briefing_story")
    extra_parts = []
    if focus_points:
        extra_parts.append(f"Organisation focus points:\n{json.dumps(focus_points, indent=2)}")
    if threat_actor_types:
        extra_parts.append(f"Threat actor types to choose from:\n{json.dumps(threat_actor_types, indent=2)}")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_story.md"),
        "\n\n".join(extra_parts),
    )
    raw = _call(system, article_content[:10000], 512, feature="draft_briefing_story", model=fc.get("model"), provider=fc.get("provider"))

    suggested_actor_type = ""
    match = _ACTOR_TYPE_LINE_RE.search(raw)
    if match:
        candidate = match.group(1).strip()
        valid_names = {t.get("name", "") for t in (threat_actor_types or [])}
        if candidate in valid_names:
            suggested_actor_type = candidate
        raw = _ACTOR_TYPE_LINE_RE.sub("", raw).strip()

    return raw, suggested_actor_type


def review_briefing_relevance(event_title: str, report_title: str, content: str) -> dict:
    """Decide if a source story should be included in the daily briefing."""
    fc = _feature_cfg("review_briefing_relevance")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_relevance.md")
    )
    payload = {
        "event_title": (event_title or "").strip(),
        "report_title": (report_title or "").strip(),
        "content": (content or "")[:12000],
    }
    text = _call(system, json.dumps(payload, ensure_ascii=True), 256, feature="review_briefing_relevance", model=fc.get("model"), provider=fc.get("provider"))
    try:
        parsed = json.loads(text)
        return {
            "include": bool(parsed.get("include", True)),
            "reason": (parsed.get("reason") or "").strip(),
        }
    except json.JSONDecodeError:
        logger.warning("review_briefing_relevance returned invalid JSON")
        return {"include": True, "reason": "fallback include on parse error"}


def detect_story_overlaps(stories: list[dict]) -> dict:
    """Detect potentially duplicate daily briefing stories.

    Returns a dict with keys:
    - overlaps: list of {a, b, score, reason}
    - summary: short operator-facing guidance
    """
    fc = _feature_cfg("detect_story_overlaps")
    system = _build_system_prompt(
        _resolve_prompt(fc.get("prompt") or "daily_briefing_overlap.md")
    )
    payload = {
        "stories": [
            {
                "index": idx + 1,
                "title": (s.get("title") or "").strip(),
                "content": (s.get("content") or "").strip(),
                "source_url": (s.get("source_url") or "").strip(),
            }
            for idx, s in enumerate(stories or [])
        ]
    }
    text = _call(system, json.dumps(payload, ensure_ascii=True), 1024, feature="detect_story_overlaps", model=fc.get("model"), provider=fc.get("provider"))
    try:
        parsed = json.loads(text)
        overlaps = parsed.get("overlaps") if isinstance(parsed, dict) else []
        if not isinstance(overlaps, list):
            overlaps = []
        cleaned = []
        for item in overlaps:
            if not isinstance(item, dict):
                continue
            try:
                a = int(item.get("a", 0))
                b = int(item.get("b", 0))
                score = float(item.get("score", 0))
            except (TypeError, ValueError):
                continue
            if a <= 0 or b <= 0 or a == b:
                continue
            cleaned.append({
                "a": a,
                "b": b,
                "score": max(0.0, min(1.0, score)),
                "reason": (item.get("reason") or "").strip(),
            })
        return {
            "overlaps": cleaned,
            "summary": (parsed.get("summary") or "").strip() if isinstance(parsed, dict) else "",
        }
    except json.JSONDecodeError:
        # Deterministic fallback: crude title token overlap only.
        def _tokens(v: str) -> set[str]:
            return {t for t in (v or "").lower().replace("/", " ").replace("-", " ").split() if len(t) > 3}

        items = [((s.get("title") or "").strip(), (s.get("content") or "").strip()) for s in (stories or [])]
        overlaps = []
        for i in range(len(items)):
            ti, ci = items[i]
            set_i = _tokens(ti) | _tokens(ci[:220])
            if not set_i:
                continue
            for j in range(i + 1, len(items)):
                tj, cj = items[j]
                set_j = _tokens(tj) | _tokens(cj[:220])
                if not set_j:
                    continue
                inter = len(set_i & set_j)
                union = len(set_i | set_j)
                if union <= 0:
                    continue
                score = inter / union
                if score >= 0.35:
                    overlaps.append({
                        "a": i + 1,
                        "b": j + 1,
                        "score": round(score, 2),
                        "reason": "High lexical overlap in title/opening text.",
                    })
        return {
            "overlaps": overlaps,
            "summary": "Fallback overlap check used.",
        }


def summarise_report(report_content: str, event_info: str = "", tags: list = None) -> str:
    """Summarise a MISP event report. Returns structured text or 'QUALITY: ...' if content is unusable."""
    fc = _feature_cfg("summarise_report")
    system = _build_system_prompt(_resolve_prompt(fc.get("prompt") or "summarise_misp_report.md"))
    ctx_lines = []
    if event_info:
        ctx_lines.append(f"Event title: {event_info}")
    if tags:
        ctx_lines.append(f"Event tags: {', '.join(tags)}")
    prefix = "\n".join(ctx_lines)
    user_message = f"{prefix}\n\nReport content:\n{report_content[:12000]}" if prefix else f"Report content:\n{report_content[:12000]}"
    return _call(system, user_message, 1024, feature="summarise_report", model=fc.get("model"), provider=fc.get("provider"))


def draft_vea_sections(cve_id: str, product_info: str = "", article_content: str = "") -> dict:
    """Draft VEA structured sections from CVE and article information."""
    fc = _feature_cfg("draft_vea_sections")
    system = _build_system_prompt(_resolve_prompt(fc.get("prompt") or "vea_draft.md"))
    user_message = "\n\n".join(filter(None, [
        f"CVE: {cve_id}" if cve_id else "",
        f"Product/context: {product_info}" if product_info else "",
        f"Article/advisory content:\n{article_content[:10000]}" if article_content else "",
    ]))
    text = _call(system, user_message, 1024, feature="draft_vea_sections", model=fc.get("model"), provider=fc.get("provider"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error("VEA draft returned invalid JSON: %s", text[:200])
        return {}
