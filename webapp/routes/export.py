from datetime import datetime, timezone
from urllib.parse import quote

from flask import Blueprint, Response

from webapp import audit, misp_store

bp = Blueprint("export", __name__)


def _fmt_date(d):
    return d.strftime("%Y-%m-%d") if d else "-"


def _distribution_labels(values, stakeholders):
    by_uuid = {s.uuid: s.name for s in stakeholders if getattr(s, "uuid", None)}
    by_name = {s.name: s.name for s in stakeholders if getattr(s, "name", None)}
    labels = []
    seen = set()
    for raw_value in values or []:
        value = (raw_value or "").strip()
        if not value:
            continue
        label = by_uuid.get(value) or by_name.get(value) or value
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


def _pirs_markdown():
    pirs = misp_store.list_pirs()
    stakeholders = misp_store.list_stakeholders()
    lines = [
        "# Priority Intelligence Requirements",
        f"Exported: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for pir in pirs:
        lines += [f"## {pir.pir_id}", "", f"**Question:** {pir.question}", ""]
        if pir.context:
            lines += [f"**Context:** {pir.context}", ""]
        lines += [
            f"**Priority:** {pir.priority}",
            f"**Status:** {pir.status}",
            f"**Time sensitivity:** {pir.time_sensitivity or '-'}",
            f"**Owner:** {pir.owner_display or '-'}",
            f"**Next review:** {_fmt_date(pir.next_review)}",
        ]
        if any([pir.geographic_scope, pir.time_frame, pir.threat_types, pir.threat_actors, pir.sectors, pir.out_of_scope]):
            lines += ["", "**Scope:**"]
            if pir.geographic_scope:
                lines.append(f"- Geography: {', '.join(pir.geographic_scope)}")
            if pir.sectors:
                lines.append(f"- Sectors: {', '.join(pir.sectors)}")
            if pir.threat_actors:
                lines.append(f"- Threat actors: {', '.join(pir.threat_actors)}")
            if pir.threat_types:
                lines.append(f"- Threat types: {', '.join(pir.threat_types)}")
            if pir.time_frame:
                lines.append(f"- Time frame: {pir.time_frame}")
            if pir.out_of_scope:
                lines.append(f"- Out of scope: {', '.join(pir.out_of_scope)}")
        if any([pir.decision_supported, pir.decision_maker, pir.consequence]):
            lines += ["", "**Decision support:**"]
            if pir.decision_supported:
                lines.append(f"- Decision: {pir.decision_supported}")
            if pir.decision_maker:
                lines.append(f"- Decision maker: {pir.decision_maker}")
            if pir.consequence:
                lines.append(f"- Consequence if unanswered: {pir.consequence}")
        if pir.collection_sources:
            lines += ["", f"**Collection sources:** {', '.join(pir.collection_sources)}"]
        if pir.focus_points:
            lines += ["", "**Focus points:**"]
            for fp in pir.focus_points:
                note = f" ({fp.notes})" if fp.notes else ""
                lines.append(f"- [{fp.category}] {fp.value}{note}")
        if any([pir.output_format, pir.distribution]):
            lines += ["", "**Deliverable:**"]
            if pir.output_format:
                fmts = pir.output_format if isinstance(pir.output_format, list) else [pir.output_format]
                lines.append(f"- Format: {', '.join(fmts)}")
            if pir.distribution:
                dist = _distribution_labels(
                    pir.distribution if isinstance(pir.distribution, list) else [pir.distribution],
                    stakeholders,
                )
                lines.append(f"- Distribution: {', '.join(dist)}")
        if pir.resolution_note:
            lines += ["", f"**Resolution:** {pir.resolution_note}"]
        lines += ["", "---", ""]
    return "\n".join(lines)


def _girs_markdown():
    girs = misp_store.list_girs()
    stakeholders = misp_store.list_stakeholders()
    lines = [
        "# General Intelligence Requirements",
        f"Exported: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for gir in girs:
        lines += [f"## {gir.gir_id}: {gir.topic}", ""]
        if gir.description:
            lines += [gir.description, ""]
        lines += [
            f"**Status:** {gir.status}",
            f"**Review cycle:** {gir.review_cycle or '-'}",
            f"**Owner:** {gir.owner_display or '-'}",
            f"**Next review:** {_fmt_date(gir.next_review)}",
        ]
        if any([gir.geographic_scope, gir.sectors, gir.threat_actors, gir.threat_types, gir.out_of_scope]):
            lines += ["", "**Scope:**"]
            if gir.geographic_scope:
                lines.append(f"- Geography: {', '.join(gir.geographic_scope)}")
            if gir.sectors:
                lines.append(f"- Sectors: {', '.join(gir.sectors)}")
            if gir.threat_actors:
                lines.append(f"- Threat actors: {', '.join(gir.threat_actors)}")
            if gir.threat_types:
                lines.append(f"- Threat types: {', '.join(gir.threat_types)}")
            if gir.out_of_scope:
                lines.append(f"- Out of scope: {', '.join(gir.out_of_scope)}")
        if gir.collection_sources:
            lines += ["", f"**Collection sources:** {', '.join(gir.collection_sources)}"]
        if gir.distribution:
            lines += ["", f"**Distribution:** {', '.join(_distribution_labels(gir.distribution, stakeholders))}"]
        if gir.focus_points:
            lines += ["", "**Focus points:**"]
            for fp in gir.focus_points:
                note = f" ({fp.notes})" if fp.notes else ""
                lines.append(f"- [{fp.category}] {fp.value}{note}")
        lines += ["", "---", ""]
    return "\n".join(lines)


def _rfis_markdown():
    rfis = misp_store.list_rfis()
    lines = [
        "# Requests for Information",
        f"Exported: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for rfi in rfis:
        lines += [f"## {rfi.rfi_id}", "", f"**Question:** {rfi.question}", ""]
        if rfi.context:
            lines += [f"**Context:** {rfi.context}", ""]
        lines += [
            f"**Priority:** {rfi.priority}",
            f"**Status:** {rfi.status}",
            f"**Requester:** {rfi.requester_name or '-'}" + (f" ({rfi.requester_team})" if rfi.requester_team else ""),
            f"**Stakeholder:** {rfi.owner_name or '-'}",
            f"**Assigned analyst:** {rfi.assigned_analyst or '-'}",
            f"**Due date:** {_fmt_date(rfi.due_date)}",
        ]
        if rfi.output_format_list:
            fmts = ", ".join(f"{item['format']} (TLP:{item['tlp'].upper()})" for item in rfi.output_format_list)
            lines.append(f"**Output formats:** {fmts}")
        if rfi.response:
            lines += ["", "**Response:**", "", rfi.response]
        if any([rfi.feedback_requirement_met, rfi.feedback_on_time, rfi.feedback_usefulness, rfi.feedback_suggestions]):
            lines += ["", "**Feedback:**"]
            if rfi.feedback_requirement_met:
                lines.append(f"- Met the requirement: {rfi.feedback_requirement_met}")
            if rfi.feedback_on_time:
                lines.append(f"- Delivered on time: {rfi.feedback_on_time}")
            if rfi.feedback_usefulness:
                lines.append(f"- Usefulness: {rfi.feedback_usefulness}")
            if rfi.feedback_suggestions:
                lines.append(f"- Suggestions: {rfi.feedback_suggestions}")
        lines += ["", "---", ""]
    return "\n".join(lines)


def _stakeholders_markdown():
    stakeholders = misp_store.list_stakeholders()
    lines = [
        "# Stakeholders",
        f"Exported: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for s in stakeholders:
        lines += [
            f"## {s.name}",
            "",
            f"**Role:** {s.role or '-'}",
            f"**Organisation:** {s.organization or '-'}",
        ]
        if s.email:
            lines.append(f"**Email:** {s.email}")
        contacts = list(getattr(s, "contacts", []) or [])
        if contacts:
            rendered_contacts = []
            for contact in contacts:
                value = (contact.get("value") or "").strip()
                if not value:
                    continue
                prefix = f"{contact.get('type')}: " if contact.get("type") else ""
                suffix = " (preferred)" if contact.get("preferred") else ""
                rendered_contacts.append(f"{prefix}{value}{suffix}")
            if rendered_contacts:
                lines.append(f"**Contacts:** {', '.join(rendered_contacts)}")
        lines.append(f"**TLP clearance:** TLP:{s.tlp_clearance.upper()}")
        if s.products:
            lines += ["", f"**Products subscribed:** {', '.join(s.products)}"]
        owned_pirs = misp_store.pirs_for_stakeholder(s.uuid)
        owned_girs = misp_store.girs_for_stakeholder(s.uuid)
        if owned_pirs:
            lines += ["", "**Owned PIRs:**"]
            for pir in owned_pirs:
                lines.append(f"- {pir.pir_id}: {pir.question[:100]}")
        if owned_girs:
            lines += ["", "**Owned GIRs:**"]
            for gir in owned_girs:
                lines.append(f"- {gir.gir_id}: {gir.topic}")
        if s.notes:
            lines += ["", f"**Notes:** {s.notes}"]
        lines += ["", "---", ""]
    return "\n".join(lines)


def _dl(content, filename):
    return Response(
        content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


@bp.route("/pirs")
def pirs():
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit.record("export", "pirs", details=f"pirs-{ts}.md")
    return _dl(_pirs_markdown(), f"pirs-{ts}.md")


@bp.route("/girs")
def girs():
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit.record("export", "girs", details=f"girs-{ts}.md")
    return _dl(_girs_markdown(), f"girs-{ts}.md")


@bp.route("/rfis")
def rfis():
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit.record("export", "rfis", details=f"rfis-{ts}.md")
    return _dl(_rfis_markdown(), f"rfis-{ts}.md")


@bp.route("/stakeholders")
def stakeholders():
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    audit.record("export", "stakeholders", details=f"stakeholders-{ts}.md")
    return _dl(_stakeholders_markdown(), f"stakeholders-{ts}.md")
