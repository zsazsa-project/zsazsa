#!/usr/bin/env python3
"""Give back the id of an RFI that lost it when its feedback was saved.

Before 1.0.0, saving feedback on an RFI sent an update carrying no rfi-id. MISP
soft-deletes an object attribute that an update leaves out, so the id vanished
from the RFI and from the event title, and the next RFI could be handed the same
number. The id itself is still on the event as a soft-deleted attribute, which is
what this reads to put it back.

By default it runs as a dry-run and only reports what would change.
Use --apply to write.

Examples:
    .venv/bin/python scripts/restore_rfi_ids.py
    .venv/bin/python scripts/restore_rfi_ids.py --apply
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webapp import misp_store
from webapp.routes.rfi import _rfi_data_from_store


def _deleted_id(misp, uuid):
    """The rfi-id MISP still holds for this event, from the attribute it soft-deleted."""
    event = misp.get_event(uuid, deleted=True, pythonify=True)
    if isinstance(event, dict) or event is None:
        return ""
    for obj in (event.objects or []):
        if obj.name != "zsazsa-rfi":
            continue
        for attr in (obj.attributes or []):
            if attr.object_relation == "rfi-id" and (attr.value or "").strip():
                return attr.value.strip()
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the changes")
    args = parser.parse_args()

    misp = misp_store._misp()
    print("Mode: " + ("APPLY" if args.apply else "DRY-RUN"))

    restored = unrecoverable = 0
    for rfi in misp_store.list_rfis():
        if (rfi.rfi_id or "").strip():
            continue
        recovered = _deleted_id(misp, rfi.uuid)
        question = (rfi.question or "")[:60]
        if not recovered:
            print(f"- {rfi.uuid}: no id left on the event - '{question}'")
            unrecoverable += 1
            continue
        print(f"- {rfi.uuid}: restore {recovered} - '{question}'")
        if args.apply:
            data = _rfi_data_from_store(rfi)
            data["rfi_id"] = recovered
            misp_store.update_rfi(rfi.uuid, data)
        restored += 1

    print(f"\nIds to restore: {restored}, beyond recovery: {unrecoverable}")
    if not args.apply and restored:
        print("Dry-run only. Re-run with --apply to write these.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
