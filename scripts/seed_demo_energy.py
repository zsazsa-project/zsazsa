#!/usr/bin/env python3
"""Seed and remove demo PIR/GIR/RFI data for an energy-sector scenario.

Modes:
- preview (default): show what would be created
- apply: create records and write a registry file with UUIDs
- delete: delete records listed in the registry file
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webapp import misp_store

DEFAULT_BATCH_ID = "demo-energy-be-20260529"
DEFAULT_REGISTRY = Path("data") / "demo_seed_registry_energy.json"


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _stakeholder_index():
    stakeholders = misp_store.list_stakeholders()
    by_name = {_norm(s.name): s for s in stakeholders}
    return stakeholders, by_name


def _resolve_stakeholder(by_name, name: str):
    item = by_name.get(_norm(name))
    if not item:
        raise ValueError(f"Stakeholder not found: {name}")
    return item


def _iso(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _payloads(batch_id: str, by_name: dict):
    external_csirt = _resolve_stakeholder(by_name, "External CSIRT")
    internal_csirt = _resolve_stakeholder(by_name, "Internal CSIRT")
    internal_soc = _resolve_stakeholder(by_name, "Internal SOC")
    security_office = _resolve_stakeholder(by_name, "Security Office")
    vuln_mgmt = _resolve_stakeholder(by_name, "Vulnerability management")

    distribution_core = [
        internal_soc.uuid,
        internal_csirt.uuid,
        security_office.uuid,
    ]

    pir_items = [
        {
            "question": "Detect and prioritize ransomware intrusion attempts targeting Belgian energy operations and supporting IT systems.",
            "context": "Focus on pre-encryption signals and lateral movement in power generation and distribution environments.",
            "owner": internal_soc,
            "priority": "Must have",
            "status": "Pending",
            "intake_status": "submitted",
            "time_sensitivity": "Immediate (<48h)",
            "threat_types": ["Ransomware", "Intrusion"],
            "threat_actors": ["Turla", "APT28"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium"],
            "technology": ["Fortinet", "Palo Alto", "Cisco", "Moxa", "Siemens"],
            "collection_sources": ["misp-scraper", "MISP-Intern"],
            "distribution": distribution_core,
            "notes": "Demo batch: " + batch_id,
        },
        {
            "question": "Identify supply chain compromise indicators affecting ICS vendors used by Belgian energy providers.",
            "context": "Prioritize Siemens and Moxa ecosystem abuse, including malicious updates and trusted channel hijacking.",
            "owner": security_office,
            "priority": "Should have",
            "status": "Pending",
            "intake_status": "acknowledged",
            "time_sensitivity": "Short-term (<2 weeks)",
            "threat_types": ["Supply chain compromise"],
            "threat_actors": ["APT33", "Turla"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium", "Europe"],
            "technology": ["Siemens", "Moxa"],
            "collection_sources": ["misp-scraper", "MISP-Intern"],
            "distribution": [internal_soc.uuid, vuln_mgmt.uuid],
            "notes": "Demo batch: " + batch_id,
        },
        {
            "question": "Track GRU-related targeting of remote access gateways in European utilities.",
            "context": "Assess abuse against firewall and VPN edge stacks with possible spillover to Belgian entities.",
            "owner": internal_csirt,
            "priority": "Could have",
            "status": "Retired",
            "intake_status": "approved",
            "time_sensitivity": "Ongoing",
            "threat_types": ["Espionage", "Credential abuse"],
            "threat_actors": ["APT28", "Sandworm"],
            "sectors": ["Energy"],
            "geographic_scope": ["Europe", "Belgium"],
            "technology": ["Fortinet", "Palo Alto", "Cisco"],
            "collection_sources": ["misp-scraper"],
            "distribution": [internal_soc.uuid, security_office.uuid],
            "notes": "Demo batch: " + batch_id,
        },
        {
            "question": "Monitor Iran-linked espionage activity against industrial control telemetry and historian systems.",
            "context": "Focus on operational disruption precursors and intelligence collection inside ICS enclaves.",
            "owner": external_csirt,
            "priority": "Should have",
            "status": "Pending",
            "intake_status": "rejected",
            "rejection_reason": "Scope overlaps with existing managed threat feed package.",
            "time_sensitivity": "Standard (<1 month)",
            "threat_types": ["Espionage"],
            "threat_actors": ["APT33", "APT34"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium"],
            "technology": ["Siemens", "Moxa"],
            "collection_sources": ["misp-scraper"],
            "distribution": [internal_csirt.uuid, security_office.uuid],
            "notes": "Demo batch: " + batch_id,
        },
        {
            "question": "Detect ransomware affiliate access brokering involving Belgian energy subcontractors.",
            "context": "Identify third-party compromise patterns that can lead to IT and ICS service interruption.",
            "owner": vuln_mgmt,
            "priority": "Must have",
            "status": "Retired",
            "intake_status": "merged",
            "time_sensitivity": "Short-term (<2 weeks)",
            "threat_types": ["Ransomware", "Supply chain compromise"],
            "threat_actors": ["Turla", "FIN7"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium", "Europe"],
            "technology": ["Cisco", "Fortinet"],
            "collection_sources": ["misp-scraper", "MISP-Intern"],
            "distribution": [internal_soc.uuid, internal_csirt.uuid, security_office.uuid],
            "notes": "Demo batch: " + batch_id,
        },
    ]

    gir_items = [
        {
            "topic": "Continuous monitoring of high-profile Russian and Iranian espionage campaigns targeting EU energy infrastructure.",
            "description": "Maintain a standing view of actor intent, capabilities, infrastructure, and likely collection targets in Belgium.",
            "owner": security_office,
            "status": "Active",
            "review_cycle": "Monthly",
            "collection_sources": ["misp-scraper", "MISP-Intern"],
            "threat_actors": ["Turla", "APT28", "APT33", "APT34"],
            "threat_types": ["Espionage"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium", "Europe"],
            "technology": ["Fortinet", "Palo Alto", "Cisco", "Siemens", "Moxa"],
            "distribution": distribution_core,
            "notes": "Demo batch: " + batch_id,
        },
        {
            "topic": "Baseline and trend tracking for ransomware pressure on Belgian utility IT/OT environments.",
            "description": "Track affiliates, access brokers, and tooling patterns that can result in service disruption.",
            "owner": internal_soc,
            "status": "Active",
            "review_cycle": "Weekly",
            "collection_sources": ["misp-scraper"],
            "threat_actors": ["Turla"],
            "threat_types": ["Ransomware"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium"],
            "technology": ["Fortinet", "Palo Alto", "Cisco"],
            "distribution": [internal_csirt.uuid, vuln_mgmt.uuid],
            "notes": "Demo batch: " + batch_id,
        },
        {
            "topic": "Supply chain exposure watch for ICS vendors and integrators in energy operations.",
            "description": "Track vulnerabilities, compromises, and exploit campaigns across Siemens and Moxa dependencies.",
            "owner": vuln_mgmt,
            "status": "Retired",
            "review_cycle": "Quarterly",
            "collection_sources": ["misp-scraper", "MISP-Intern"],
            "threat_actors": ["APT33"],
            "threat_types": ["Supply chain compromise"],
            "sectors": ["Energy"],
            "geographic_scope": ["Belgium", "Europe"],
            "technology": ["Siemens", "Moxa"],
            "distribution": [security_office.uuid, internal_csirt.uuid],
            "notes": "Demo batch: " + batch_id,
        },
    ]

    rfi_items = [
        {
            "question": "Provide current GRU-related indicators relevant to perimeter devices in our Belgian production network.",
            "context": "Need fast triage input for SOC hunt planning and emergency blocklist updates.",
            "owner": internal_soc,
            "priority": "High",
            "status": "Acknowledged",
            "due_days": 2,
            "requester_name": "SOC Duty Lead",
            "requester_team": "Internal SOC",
            "output_format_list": [{"format": "Flash intel alert", "tlp": "amber"}],
        },
        {
            "question": "Assess likelihood of ransomware-driven ICS disruption through third-party maintenance channels.",
            "context": "Executive steering asks for short risk statement and near-term controls.",
            "owner": security_office,
            "priority": "Medium",
            "status": "Acknowledged",
            "due_days": 5,
            "requester_name": "Head of Security Office",
            "requester_team": "Security Office",
            "output_format_list": [{"format": "Threat landscape report", "tlp": "amber"}],
        },
        {
            "question": "Map exposed Siemens and Moxa assets to known active exploitation campaigns in Europe.",
            "context": "Support patch sequencing and temporary segmentation decisions.",
            "owner": vuln_mgmt,
            "priority": "Medium",
            "status": "In Progress",
            "due_days": 7,
            "requester_name": "OT Vulnerability Lead",
            "requester_team": "Vulnerability management",
            "output_format_list": [{"format": "Vulnerability advisory", "tlp": "amber"}],
        },
        {
            "question": "Summarize Iran-linked collection objectives against EU energy sector entities in the last 30 days.",
            "context": "External coordination package needed for partner-facing briefing.",
            "owner": external_csirt,
            "priority": "Low",
            "status": "New",
            "due_days": 10,
            "requester_name": "External CSIRT Coordinator",
            "requester_team": "External CSIRT",
            "output_format_list": [{"format": "Daily threat briefing", "tlp": "green"}],
        },
    ]

    return pir_items, gir_items, rfi_items


def _pir_data(item, pir_id):
    owner = item["owner"]
    return {
        "pir_id": pir_id,
        "question": item["question"],
        "context": item["context"],
        "intel_level": ["Operational"],
        "owner_uuid": owner.uuid,
        "owner_name": owner.name,
        "owner_role": owner.role,
        "priority": item.get("priority", "Should have"),
        "status": item.get("status", "Pending"),
        "time_sensitivity": item.get("time_sensitivity", "Standard (<1 month)"),
        "geographic_scope": item.get("geographic_scope", ["Belgium", "Europe"]),
        "time_frame": "Current quarter",
        "threat_types": item.get("threat_types", []),
        "threat_actors": item.get("threat_actors", []),
        "sectors": item.get("sectors", ["Energy"]),
        "out_of_scope": ["Consumer fraud unrelated to utility operations"],
        "technology": item.get("technology", []),
        "vendor": ["Fortinet", "Palo Alto", "Cisco", "Moxa", "Siemens"],
        "incident": [],
        "campaign": [],
        "collection_sources": item.get("collection_sources", ["misp-scraper"]),
        "output_format": ["Flash intel alert", "Daily threat briefing"],
        "distribution": item.get("distribution", []),
        "resolution_note": item.get("notes", ""),
        "decision_supported": "Energy sector cyber risk and response prioritization",
        "decision_maker": ["CISO", "SOC Lead", "CSIRT Lead"],
        "consequence": ["Operational disruption", "Service outage", "Safety and resilience impact"],
        "deadline": _iso(14),
        "priority_justification": "Aligned to ransomware and IT/ICS disruption concerns.",
        "sub_questions": [
            "What indicators are most actionable this week?",
            "What actor behaviors map to our current exposure?",
        ],
        "next_review": _iso(30),
        "intake_status": item.get("intake_status", "submitted"),
        "acknowledged_at": _iso(-2) if item.get("intake_status") in {"acknowledged", "triaged", "approved", "rejected", "deferred", "merged"} else "",
        "triaged_at": _iso(-1) if item.get("intake_status") in {"triaged", "approved", "rejected", "deferred", "merged"} else "",
        "decision_at": _iso(0) if item.get("intake_status") in {"approved", "rejected", "deferred", "merged"} else "",
        "rejection_reason": item.get("rejection_reason", ""),
        "deferral_reason": "",
        "linked_pir_uuid": "",
        "mitre_attack_techniques": ["Exploit Public-Facing Application - T1190", "Data Encrypted for Impact - T1486",
                                   "Impair Defenses - T1562", "Exfiltration Over C2 Channel - T1041"],
        "focus_points": [
            {"category": "Sector", "value": "Energy", "notes": "Demo"},
            {"category": "Geography", "value": "Belgium", "notes": "Demo"},
            {"category": "Threat Actor", "value": "Turla", "notes": "Demo"},
            {"category": "Threat Type", "value": "Ransomware", "notes": "Demo"},
        ],
    }


def _gir_data(item, gir_id):
    owner = item["owner"]
    return {
        "gir_id": gir_id,
        "topic": item["topic"],
        "description": item["description"],
        "owner_uuid": owner.uuid,
        "owner_name": owner.name,
        "owner_role": owner.role,
        "status": item.get("status", "Active"),
        "review_cycle": item.get("review_cycle", "Monthly"),
        "collection_sources": item.get("collection_sources", ["misp-scraper"]),
        "geographic_scope": item.get("geographic_scope", ["Belgium", "Europe"]),
        "sectors": item.get("sectors", ["Energy"]),
        "threat_types": item.get("threat_types", []),
        "threat_actors": item.get("threat_actors", []),
        "out_of_scope": ["Non-energy sectors"],
        "technology": item.get("technology", []),
        "vendor": ["Fortinet", "Palo Alto", "Cisco", "Moxa", "Siemens"],
        "incident": [],
        "campaign": [],
        "output_format": ["Daily threat briefing", "Threat landscape report"],
        "distribution": item.get("distribution", []),
        "deadline": _iso(30),
        "priority_justification": item.get("notes", ""),
        "sub_questions": [
            "What changed since the previous review cycle?",
            "What action should IT/OT teams take now?",
        ],
        "next_review": _iso(30),
        "intel_level": ["Strategic", "Operational"],
        "mitre_attack_techniques": ["Exploit Public-Facing Application - T1190", "Commonly Used Port - T0885",
                                   "Standard Application Layer Protocol - T0869"],
    }


def _rfi_data(item, rfi_id, batch_id: str):
    owner = item["owner"]
    return {
        "rfi_id": rfi_id,
        "question": item["question"],
        "context": item["context"] + f"\nDemo batch: {batch_id}",
        "requester_name": item.get("requester_name", "Demo Requester"),
        "requester_team": item.get("requester_team", "Security Office"),
        "owner_uuid": owner.uuid,
        "owner_name": owner.name,
        "priority": item.get("priority", "Medium"),
        "status": item.get("status", "New"),
        "assigned_analyst": "CTI Demo Analyst",
        "due_date": _iso(item.get("due_days", 5)),
        "linked_pir_uuid": "",
        "linked_gir_uuid": "",
        "output_format_list": item.get("output_format_list", [{"format": "Daily threat briefing", "tlp": "amber"}]),
        "response": "",
        "feedback_requirement_met": "",
        "feedback_on_time": "",
        "feedback_usefulness": "",
        "feedback_suggestions": "",
    }


def preview(batch_id: str):
    _, by_name = _stakeholder_index()
    pir_items, gir_items, rfi_items = _payloads(batch_id, by_name)
    print(f"Batch: {batch_id}")
    print(f"PIR to create: {len(pir_items)}")
    for item in pir_items:
        print(f"  - {item['status']} / intake={item['intake_status']}: {item['question'][:88]}")
    print(f"GIR to create: {len(gir_items)}")
    for item in gir_items:
        print(f"  - {item['status']}: {item['topic'][:88]}")
    print(f"RFI to create: {len(rfi_items)}")
    for item in rfi_items:
        print(f"  - {item['status']} ({item['priority']}): {item['question'][:88]}")


def apply(batch_id: str, registry_file: Path):
    _, by_name = _stakeholder_index()
    pir_items, gir_items, rfi_items = _payloads(batch_id, by_name)

    registry = {
        "batch_id": batch_id,
        "created": {
            "pir": [],
            "gir": [],
            "rfi": [],
        },
    }

    for item in pir_items:
        pir_id = misp_store.next_pir_id()
        payload = _pir_data(item, pir_id)
        uuid = misp_store.create_pir(payload)
        registry["created"]["pir"].append({"id": pir_id, "uuid": uuid})

    for item in gir_items:
        gir_id = misp_store.next_gir_id()
        payload = _gir_data(item, gir_id)
        uuid = misp_store.create_gir(payload)
        registry["created"]["gir"].append({"id": gir_id, "uuid": uuid})

    for item in rfi_items:
        rfi_id = misp_store.next_rfi_id()
        payload = _rfi_data(item, rfi_id, batch_id)
        uuid = misp_store.create_rfi(payload)
        registry["created"]["rfi"].append({"id": rfi_id, "uuid": uuid})

    registry_file.parent.mkdir(parents=True, exist_ok=True)
    registry_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")

    print(f"Created PIR: {len(registry['created']['pir'])}")
    print(f"Created GIR: {len(registry['created']['gir'])}")
    print(f"Created RFI: {len(registry['created']['rfi'])}")
    print(f"Registry written to: {registry_file}")
    print("Created IDs:")
    for kind in ("pir", "gir", "rfi"):
        for item in registry["created"][kind]:
            print(f"  - {kind.upper()} {item['id']} ({item['uuid']})")


def delete(registry_file: Path):
    if not registry_file.exists():
        raise FileNotFoundError(f"Registry file not found: {registry_file}")

    data = json.loads(registry_file.read_text(encoding="utf-8"))
    created = data.get("created", {})

    deleted = {"pir": 0, "gir": 0, "rfi": 0}
    failed = []

    for item in created.get("rfi", []):
        try:
            misp_store.delete_rfi(item["uuid"])
            deleted["rfi"] += 1
        except Exception as exc:
            failed.append(("rfi", item, str(exc)))

    for item in created.get("gir", []):
        try:
            misp_store.delete_gir(item["uuid"])
            deleted["gir"] += 1
        except Exception as exc:
            failed.append(("gir", item, str(exc)))

    for item in created.get("pir", []):
        try:
            misp_store.delete_pir(item["uuid"])
            deleted["pir"] += 1
        except Exception as exc:
            failed.append(("pir", item, str(exc)))

    print(f"Deleted PIR: {deleted['pir']}")
    print(f"Deleted GIR: {deleted['gir']}")
    print(f"Deleted RFI: {deleted['rfi']}")

    if failed:
        print("Failures:")
        for kind, item, err in failed:
            print(f"  - {kind.upper()} {item.get('id', '')} {item.get('uuid', '')}: {err}")
    else:
        print("All seeded demo records were deleted.")


def main():
    parser = argparse.ArgumentParser(description="Seed or delete demo PIR/GIR/RFI data")
    parser.add_argument("--mode", choices=["preview", "apply", "delete"], default="preview")
    parser.add_argument("--batch-id", default=DEFAULT_BATCH_ID)
    parser.add_argument("--registry-file", default=str(DEFAULT_REGISTRY))
    args = parser.parse_args()

    registry_file = Path(args.registry_file)

    if args.mode == "preview":
        preview(args.batch_id)
        return
    if args.mode == "apply":
        apply(args.batch_id, registry_file)
        return
    delete(registry_file)


if __name__ == "__main__":
    main()
