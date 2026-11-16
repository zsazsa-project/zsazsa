"""Track MISP users seen via SSO sessions.

Populated from webapp.__init__'s before_request hook whenever a request
has a valid MISP session, so the community/users page can show who has
used zsazsa via SSO.
"""

import logging
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import config
from core.db import row_connection as _conn
from webapp import org_store

logger = logging.getLogger(__name__)

# The databases known to hold a recognised user. Rows are never deleted, so
# once any_recorded() is true it stays true, and need not be asked every request.
_recognised_in = set()

# Organisations of recognised users this process has already registered or
# tried to. A sighting is recorded on every request, and one MISP cannot look
# up would otherwise cost each of them a call to MISP and a warning.
_organisations_tried = set()


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
    role = (user.get("Role") or {}).get("name", "")

    if organisation_uuid and organisation_uuid not in _organisations_tried:
        _organisations_tried.add(organisation_uuid)
        if not org_store.get_organisation(organisation_uuid):
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
    _recognised_in.add(config.DB_FILE)


def any_recorded():
    """Whether any MISP user has been recognised through a session.

    It decides whether a request without a session is trusted, and every page
    asks, so a database that cannot be read answers yes: that request is then
    refused what needs trust, rather than every page failing.
    """
    if config.DB_FILE in _recognised_in:
        return True
    try:
        with _conn() as db:
            found = db.execute("SELECT 1 FROM sso_users LIMIT 1").fetchone() is not None
    except sqlite3.Error as exc:
        # The table is created when the app first starts, and before that
        # nobody has been recognised.
        if "no such table" in str(exc):
            return False
        logger.warning("could not read the recognised users, so a request without a MISP session "
                       "is not trusted: %s", exc)
        return True
    if found:
        _recognised_in.add(config.DB_FILE)
    return found


def list_sso_users():
    """List recorded SSO users, grouped by MISP user id.

    The same MISP user can have signed in under more than one email address,
    after their MISP login was changed. ``same_user_as`` lists the other
    addresses recorded with the user's MISP id, so the page can say which
    entries are possibly the same user.
    """
    with _conn() as db:
        rows = db.execute(
            "SELECT email, misp_user_id, organisation, organisation_uuid, role, first_seen, last_seen "
            "FROM sso_users ORDER BY misp_user_id, last_seen DESC"
        ).fetchall()
    users = [SimpleNamespace(**dict(r)) for r in rows]
    emails_by_id = {}
    for u in users:
        if u.misp_user_id:
            emails_by_id.setdefault(u.misp_user_id, []).append(u.email)
    for u in users:
        u.same_user_as = [e for e in emails_by_id.get(u.misp_user_id, []) if e != u.email]
    return users


def organisation_uuids_in_use():
    """Return the set of organisation UUIDs referenced by recorded SSO users."""
    with _conn() as db:
        rows = db.execute(
            "SELECT DISTINCT organisation_uuid FROM sso_users "
            "WHERE organisation_uuid IS NOT NULL AND organisation_uuid != ''"
        ).fetchall()
    return {r["organisation_uuid"] for r in rows}
