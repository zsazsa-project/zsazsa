"""Shared newsletter ingest: publish selected article URLs to the scraper queue.

Used by the manual paste flow (data_collection routes), the automated IMAP
collector, and the pending-review approval, so all three build the same
misp-scraper messages and report the same delivery counts. Archiving the
newsletter itself stays in misp_store.create_newsletter_event.
"""

import logging

from core.net_safety import is_safe_public_url
from webapp import misp_store, scraper_queue
from webapp.redis_client import RedisError

logger = logging.getLogger(__name__)


def _message(source: str, article: dict) -> dict:
    """Build one misp-scraper publish payload from a parsed article."""
    feed_tags = []
    section = (article.get("section") or "").strip()
    if section:
        feed_tags.append(f'zsazsa:newsletter-section="{misp_store.source_slug(section)}"')
    priority = (article.get("priority") or "").strip()
    if priority:
        feed_tags.append(f'zsazsa:newsletter-priority="{priority}"')
    return {
        "link": (article.get("url") or "").strip(),
        "title": (article.get("title") or "").strip(),
        "feed_title": source,
        "feed": source,
        "feed_tags": feed_tags,
    }


def public_urls(articles: list[dict]) -> list[str]:
    """The article links the scraper will be sent, as recorded on the archived
    newsletter: a link publish_articles refuses must not read as pushed."""
    return [a["url"] for a in articles if is_safe_public_url(a["url"])]


def publish_articles(source: str, articles: list[dict]) -> dict:
    """Publish each article's URL to the scraper channel.

    `articles` is a list of dicts with keys url, title, section, priority.
    Returns {"published", "failed", "no_subscriber", "refused"} counts. Articles
    without a URL are skipped. A newsletter can arrive from anyone who can mail
    the mailbox, and the scraper fetches whatever it is sent, so a link that is
    not a public web address is refused rather than handed to it.
    """
    published = failed = no_subscriber = refused = 0
    for article in articles:
        url = (article.get("url") or "").strip()
        if not url:
            continue
        if not is_safe_public_url(url):
            refused += 1
            logger.warning("%s: not sending a non-public link to the scraper", source)
            continue
        try:
            receivers = scraper_queue.publish(_message(source, article))
        except (OSError, RedisError) as exc:
            failed += 1
            logger.warning("scraper publish failed for %s: %s", article.get("url"), exc)
        else:
            published += 1
            if receivers == 0:
                no_subscriber += 1
    return {"published": published, "failed": failed, "no_subscriber": no_subscriber, "refused": refused}


def articles_from_parsed(parsed: dict) -> list[dict]:
    """Map parser output (newsletter_parsers.parse) to publish-ready article dicts."""
    out = []
    for a in parsed.get("articles", []):
        url = (a.get("primary_url") or "").strip()
        if not url:
            continue
        out.append({
            "url": url,
            "title": a.get("title", ""),
            "section": a.get("section", ""),
            "priority": a.get("priority_key", ""),
        })
    return out
