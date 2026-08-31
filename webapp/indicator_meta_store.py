"""Local cache of MISP organisations, tags and attribute types.

The indicator-feed query builder needs pick-lists of every organisation, tag
and attribute type known to MISP. Those lists can be large and slow to fetch,
so they are cached locally and refreshed on demand by the analyst (the same
pattern org_store uses for registered organisations).
"""

import json
import logging

from core.db import row_connection as _conn

logger = logging.getLogger(__name__)


def init_db():
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS indicator_meta (
                kind        TEXT PRIMARY KEY,
                data_json   TEXT NOT NULL,
                refreshed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def get(kind):
    """Return (items, refreshed_at) for a kind; ([], None) when never refreshed."""
    with _conn() as db:
        row = db.execute(
            "SELECT data_json, refreshed_at FROM indicator_meta WHERE kind = ?", (kind,)
        ).fetchone()
    if not row:
        return [], None
    try:
        items = json.loads(row["data_json"])
    except Exception:
        items = []
    return items, row["refreshed_at"]


def last_refreshed():
    """Most recent refresh timestamp across all kinds, or None. Avoids parsing
    the (potentially large) cached lists just to show a timestamp."""
    with _conn() as db:
        row = db.execute("SELECT MAX(refreshed_at) AS ts FROM indicator_meta").fetchone()
    return row["ts"] if row else None


def suggest(kind, query, limit=25):
    """Return up to `limit` cached values for `kind` matching `query` (substring,
    case-insensitive). Prefix matches are ranked first."""
    items, _ = get(kind)
    q = (query or "").strip().lower()
    if not q:
        return items[:limit]
    starts, contains = [], []
    for v in items:
        lv = v.lower()
        if lv.startswith(q):
            starts.append(v)
        elif q in lv:
            contains.append(v)
        if len(starts) >= limit:
            break
    return (starts + contains)[:limit]


def _put(db, kind, items):
    db.execute(
        "INSERT INTO indicator_meta (kind, data_json, refreshed_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(kind) DO UPDATE SET data_json = excluded.data_json, refreshed_at = CURRENT_TIMESTAMP",
        (kind, json.dumps(items)),
    )


def refresh_all():
    """Pull the organisation and tag lists from MISP into the cache.

    Attribute types are not among them: they are a fixed list that
    misp_store.local_attribute_types reads without asking a server. Returns
    {kind: count} for the kinds successfully refreshed.
    """
    from webapp import misp_store
    pulls = {
        "orgs": misp_store.fetch_misp_organisations,
        "tags": misp_store.fetch_misp_tags,
    }
    counts = {}
    for kind, fetch in pulls.items():
        try:
            items = fetch()
        except Exception:
            logger.exception("Failed to refresh indicator metadata: %s", kind)
            continue
        with _conn() as db:
            _put(db, kind, items)
        counts[kind] = len(items)
    return counts
