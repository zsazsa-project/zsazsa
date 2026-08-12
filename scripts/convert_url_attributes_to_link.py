#!/usr/bin/env python3
"""Convert reference attributes on zsazsa events from type "url" to type "link".

References that zsazsa records on an event (the article, advisory or vendor
bulletin an entry was written from) belong to MISP's "link" type: they are
context, not indicators to match on. Manual collection entries created before
this was fixed stored their external references as "url" instead, which means
they never reach a product's reference list, since everything that reads a
source event's references looks for "link" attributes only.

This script finds those attributes on the webapp MISP (MISP_WEBAPP_URL), where
manual collection entries live, and retypes them. Only attributes in the
"External analysis" category are touched, so indicators that are genuinely of
type "url" are left alone.

By default this script runs in dry-run mode and only reports what would change.
Use --apply to actually convert the attributes.

Examples:
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/convert_url_attributes_to_link.py
    /home/koenv/Documents/zsazsa/.venv/bin/python scripts/convert_url_attributes_to_link.py --apply
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# Ensure repository root is importable when running this script directly.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from pymisp import PyMISP

# Manual collection entries are the only events zsazsa ever wrote a "url"
# reference on, and they all carry a source-type tag.
SEARCH_TAGS = ['zsazsa:source-type="%"']

REFERENCE_CATEGORY = "External analysis"


def _misp() -> PyMISP:
    return PyMISP(
        config.MISP_WEBAPP_URL,
        config.MISP_WEBAPP_KEY,
        config.MISP_WEBAPP_VERIFYCERT,
        False,
    )


def _url_references(event):
    """Yield the reference attributes of an event still typed as "url"."""
    for attr in (getattr(event, "attributes", []) or []):
        if getattr(attr, "deleted", False):
            continue
        if attr.type == "url" and (getattr(attr, "category", "") or "") == REFERENCE_CATEGORY:
            yield attr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, run as dry-run.",
    )
    args = parser.parse_args()

    misp = _misp()
    events = misp.search(tags=SEARCH_TAGS, limit=10000, pythonify=True)
    if not events or isinstance(events, dict):
        print("No zsazsa events found or search failed.")
        return 0

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Mode: {mode}")

    found = 0
    changed = 0

    for event in events:
        event_uuid = getattr(event, "uuid", "?")
        for attr in _url_references(event):
            found += 1
            print(f"- event={event_uuid} attribute={attr.uuid} {attr.value!r} url -> link")
            if args.apply:
                attr.type = "link"
                r = misp.update_attribute(attr)
                if isinstance(r, dict) and "errors" in r:
                    print(f"  ERROR retyping: {r['errors']}")
                    continue
                changed += 1

    print(f"URL reference attributes found: {found}, converted: {changed}")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to convert these attributes to link.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
