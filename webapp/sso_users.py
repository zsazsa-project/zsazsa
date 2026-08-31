"""Track MISP users seen via SSO sessions.

Populated from webapp.__init__'s before_request hook whenever a request
carries a valid MISP session, so the community/users page can show who has
used zsazsa via SSO.
"""

import logging
from datetime import datetime, timezone
from types import SimpleNamespace

from core.db import row_connection as _conn
from webapp import org_store

logger = logging.getLogger(__name__)


def init_db():
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS sso_users (
                email             TEXT PRIMARY KEY,
                misp_user_id      TEXT,
                organisation      TEXT,
                organisation_uuid TEXT,
                role              TEXT,
                first_seen        TEXT NOT NULL,
                last_seen         TEXT NOT NULL
            )
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(sso_users)")}
        if "organisation_uuid" not in columns:
            db.execute("ALTER TABLE sso_users ADD COLUMN organisation_uuid TEXT")


def record_sighting(user):
    """Record (or refresh) a sighting of a MISP user from an SSO session."""
    email = user.get("email")
    if not email:
        return
    # Text column, compared against rows already written, so keep the format.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    misp_user_id = user.get("id", "")
    org = user.get("Organisation") or {}
    organisation = org.get("name", "")
    organisation_uuid = org.get("uuid", "")
    role = user.get("Role", {}).get("name", "")

    if organisation_uuid and not org_store.get_organisation(organisation_uuid):
        try:
            org_store.add_organisation(organisation_uuid)
        except ValueError as exc:
            logger.warning("could not register organisation %s: %s", organisation_uuid, exc)

    with _conn() as db:
        db.execute("""
            INSERT INTO sso_users
                (email, misp_user_id, organisation, organisation_uuid, role, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                misp_user_id = excluded.misp_user_id,
                organisation = excluded.organisation,
                organisation_uuid = excluded.organisation_uuid,
                role = excluded.role,
                last_seen = excluded.last_seen
        """, (email, misp_user_id, organisation, organisation_uuid, role, now, now))


def list_sso_users():
    """List recorded SSO users, grouped by MISP user id.

    Grouping by id (rather than just last_seen) puts entries side by side
    when the same MISP user has logged in under different email addresses
    (e.g. after their MISP login was changed), so the template can flag them
    as possibly the same user.
    """
    with _conn() as db:
        rows = db.execute(
            "SELECT email, misp_user_id, organisation, organisation_uuid, role, first_seen, last_seen "
            "FROM sso_users ORDER BY misp_user_id, last_seen DESC"
        ).fetchall()
    users = [SimpleNamespace(**dict(r)) for r in rows]
    for i, u in enumerate(users):
        prev_id = users[i - 1].misp_user_id if i > 0 else None
        next_id = users[i + 1].misp_user_id if i + 1 < len(users) else None
        u.possible_duplicate = bool(u.misp_user_id) and u.misp_user_id in (prev_id, next_id)
    return users


def organisation_uuids_in_use():
    """Return the set of organisation UUIDs referenced by recorded SSO users."""
    with _conn() as db:
        rows = db.execute(
            "SELECT DISTINCT organisation_uuid FROM sso_users "
            "WHERE organisation_uuid IS NOT NULL AND organisation_uuid != ''"
        ).fetchall()
    return {r["organisation_uuid"] for r in rows}
