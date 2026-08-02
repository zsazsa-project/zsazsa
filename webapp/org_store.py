"""Local organisation registry.

Organisations are verified against the MISP webapp store by UUID before
being stored. They serve as a controlled vocabulary for the stakeholder
organisation field and cannot be deleted while linked to a stakeholder.
"""

import logging
from types import SimpleNamespace

from core.db import row_connection as _conn

logger = logging.getLogger(__name__)


def init_db():
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS organisations (
                uuid     TEXT PRIMARY KEY,
                name     TEXT NOT NULL,
                sector   TEXT,
                country  TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def _misp_lookup(uuid):
    """Fetch organisation from the MISP webapp store. Returns a dict or None."""
    from webapp import misp_store
    try:
        misp = misp_store._misp()
        org = misp.get_organisation(uuid, pythonify=True)
        if not org or isinstance(org, dict):
            return None
        return {
            "uuid": getattr(org, "uuid", uuid) or uuid,
            "name": getattr(org, "name", "") or "",
            "sector": getattr(org, "sector", "") or "",
            "country": getattr(org, "nationality", "") or "",
        }
    except Exception as exc:
        logger.warning("MISP organisation lookup failed for %s: %s", uuid, exc)
        return None


def add_organisation(uuid):
    """Look up UUID in the MISP webapp store and register it locally if found.

    Raises ValueError when the UUID is missing, already registered, or not
    found in MISP. Returns the created SimpleNamespace on success.
    """
    uuid = (uuid or "").strip()
    if not uuid:
        raise ValueError("UUID is required")

    with _conn() as db:
        if db.execute("SELECT 1 FROM organisations WHERE uuid = ?", (uuid,)).fetchone():
            raise ValueError("Organisation is already registered")

    info = _misp_lookup(uuid)
    if info is None:
        raise ValueError(f"No organisation with UUID {uuid!r} found in MISP")

    with _conn() as db:
        db.execute(
            "INSERT INTO organisations (uuid, name, sector, country) VALUES (?, ?, ?, ?)",
            (info["uuid"], info["name"], info["sector"], info["country"]),
        )
    return _to_ns(info)


def list_organisations():
    with _conn() as db:
        rows = db.execute(
            "SELECT uuid, name, sector, country, added_at FROM organisations ORDER BY name"
        ).fetchall()
    return [_to_ns(r) for r in rows]


def org_map():
    """Return {uuid: name} for template lookups."""
    return {o.uuid: o.name for o in list_organisations()}


def get_organisation(uuid):
    with _conn() as db:
        row = db.execute(
            "SELECT uuid, name, sector, country, added_at FROM organisations WHERE uuid = ?",
            (uuid,),
        ).fetchone()
    return _to_ns(row) if row else None


def sync_organisation(uuid):
    """Refresh local organisation fields from MISP for an existing UUID.

    Raises ValueError when the organisation is not registered locally or cannot
    be found in MISP. Returns the updated SimpleNamespace on success.
    """
    uuid = (uuid or "").strip()
    if not uuid:
        raise ValueError("UUID is required")

    existing = get_organisation(uuid)
    if not existing:
        raise ValueError("Organisation is not registered")

    info = _misp_lookup(uuid)
    if info is None:
        raise ValueError(f"No organisation with UUID {uuid!r} found in MISP")

    with _conn() as db:
        db.execute(
            "UPDATE organisations SET name = ?, sector = ?, country = ? WHERE uuid = ?",
            (info["name"], info["sector"], info["country"], uuid),
        )
    return get_organisation(uuid)


def sync_all_organisations():
    """Refresh all registered organisations from MISP.

    Returns a tuple: (updated_count, failed_count).
    """
    updated_count = 0
    failed_count = 0
    for org in list_organisations():
        info = _misp_lookup(org.uuid)
        if info is None:
            failed_count += 1
            continue
        with _conn() as db:
            db.execute(
                "UPDATE organisations SET name = ?, sector = ?, country = ? WHERE uuid = ?",
                (info["name"], info["sector"], info["country"], org.uuid),
            )
        updated_count += 1
    return updated_count, failed_count


def delete_organisation(uuid):
    """Delete organisation. Raises ValueError if a stakeholder or zsazsa user references it."""
    from webapp import misp_store, sso_users
    for s in misp_store.list_stakeholders():
        if s.organization == uuid:
            raise ValueError(f"Organisation is linked to stakeholder \"{s.name}\"")
    if uuid in sso_users.organisation_uuids_in_use():
        raise ValueError("Organisation is linked to a zsazsa user")
    with _conn() as db:
        db.execute("DELETE FROM organisations WHERE uuid = ?", (uuid,))


def _to_ns(row):
    d = dict(row) if not isinstance(row, dict) else row
    return SimpleNamespace(
        uuid=d["uuid"],
        name=d["name"],
        sector=d.get("sector") or "",
        country=d.get("country") or "",
        added_at=d.get("added_at") or "",
    )
