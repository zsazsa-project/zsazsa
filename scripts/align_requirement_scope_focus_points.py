#!/usr/bin/env python3
"""Make a requirement's scope lists and its scope items agree.

A PIR or GIR holds its scope twice: as lists on the zsazsa-pir/zsazsa-gir object,
which is what the edit form writes and what events are matched against, and as
scope items (focus point attributes), which is what the detail page shows. Only
geography, sector, threat actor and threat type were ever kept in step. A
technology, vendor, incident or campaign typed into the edit form never became a
scope item, so it did not show on the detail page; one added from the detail page
never reached the scope list, so it matched nothing.

Both are now kept in step, and this fills the gap on records written before that.
It works in both directions: a scope value with no item gets one, and an item
whose value is missing from the scope list is added to it. Run it once after
upgrading. Nothing is deleted, and running it twice changes nothing.

By default it runs as a dry-run and only reports what would change.
Use --apply to write.

Examples:
    .venv/bin/python scripts/align_requirement_scope_focus_points.py
    .venv/bin/python scripts/align_requirement_scope_focus_points.py --apply
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config
from webapp import misp_store


def _requirements(misp):
    """Every PIR and GIR event, with the object name to read its scope from."""
    for tag, object_name, namespace in (
        (config.TAG_PIR, "zsazsa-pir", misp_store._pir_ns),
        (config.TAG_GIR, "zsazsa-gir", misp_store._gir_ns),
    ):
        events = misp.search(tags=[tag], pythonify=True)
        if isinstance(events, dict) or not events:
            continue
        for event in events:
            if misp_store._get_obj(event, object_name):
                yield event, namespace(event)


def _scope_values(requirement, category):
    relation = misp_store._FP_CATEGORY_TO_RELATION[category]
    return list(getattr(requirement, relation.replace("-", "_"), []) or [])


def _plan(event, requirement):
    """What each side is missing, as {category: (items_to_add, values_to_add)}."""
    items = {}
    for attr in misp_store._get_fp_attrs(event):
        fp = misp_store._fp_ns(attr)
        items.setdefault(fp.category, []).append(fp.value)

    plan = {}
    for category in misp_store._FP_CATEGORY_TO_RELATION:
        scope = _scope_values(requirement, category)
        existing = items.get(category, [])
        have_items = {v.lower() for v in existing}
        have_scope = {v.lower() for v in scope}
        missing_items = [v for v in scope if v.lower() not in have_items]
        missing_scope = [v for v in existing if v.lower() not in have_scope]
        if missing_items or missing_scope:
            plan[category] = (missing_items, missing_scope)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the changes")
    args = parser.parse_args()

    misp = misp_store._misp()
    print("Mode: " + ("APPLY" if args.apply else "DRY-RUN"))

    requirements = items_added = scope_added = 0
    for event, requirement in _requirements(misp):
        plan = _plan(event, requirement)
        if not plan:
            continue
        requirements += 1
        label = getattr(requirement, "pir_id", None) or getattr(requirement, "gir_id", "") or event.uuid
        for category, (missing_items, missing_scope) in plan.items():
            for value in missing_items:
                print(f"- {label}: add scope item {category} '{value}'")
                if args.apply:
                    misp_store.add_focus_point(event.uuid, category, value)
                items_added += 1
            if missing_scope:
                relation = misp_store._FP_CATEGORY_TO_RELATION[category]
                print(f"- {label}: add to {relation} " + ", ".join(repr(v) for v in missing_scope))
                if args.apply:
                    values = _scope_values(requirement, category) + missing_scope
                    misp_store._rewrite_parent_scope(misp, event, relation, values)
                scope_added += len(missing_scope)

    print(f"\nRequirements needing work: {requirements}, "
          f"scope items to add: {items_added}, scope values to add: {scope_added}")
    if not args.apply and (items_added or scope_added):
        print("Dry-run only. Re-run with --apply to write these.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
