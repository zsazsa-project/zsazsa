"""
Constants shared across routes and templates.

The data models (Stakeholder, PIR, GIR) are stored in MISP; see
webapp/misp_store.py. Collection sources are configured in config.py.
"""

import config

STAKEHOLDER_ROLES = [
    "SOC",
    "Incident Response",
    "Cyber Threat Intelligence",
    "Threat Hunting",
    "Detection Engineering",
    "Vulnerability Management",
    "Third Party Risk Management",
    "IT Security",
    "CISO / Leadership",
    "Other",
]

def cti_products():
    """Current CTI product types, read live from config.

    Read at call time (not captured at import) so edits to PRODUCT_TYPES on the
    config page take effect immediately, without restarting the application.
    Also used for output formats, which are the same list.
    """
    return list(config.PRODUCT_TYPES)


def subscribed_products(stakeholder) -> list:
    """The product types a stakeholder is subscribed to that are still offered.

    One removed under Settings > Products stays stored on the stakeholder until
    it is saved again, and the edit form, which offers only these, drops it
    then. Shown anywhere else, it would be a subscription to nothing.
    """
    offered = set(cti_products())
    return [p for p in stakeholder.products if p in offered]

TLP_LEVELS = ["clear", "green", "amber", "amber+strict", "red"]

MOSCOW_PRIORITIES = ["Must have", "Should have", "Could have", "Won't have"]

PIR_STATUSES = [
    "Pending",
    "Active",
    "In Development",
    "Under Evaluation",
    "Implemented",
    "Retired",
]

PIR_INTAKE_STATUSES = [
    "submitted",
    "acknowledged",
    "triaged",
    "approved",
    "rejected",
    "deferred",
    "merged",
]

GIR_STATUSES = ["Active", "Pending", "Retired"]

TIME_SENSITIVITIES = [
    "Immediate (<48h)",
    "Short-term (<2 weeks)",
    "Standard (<1 month)",
    "Ongoing",
]

REVIEW_CYCLES = ["Weekly", "Monthly", "Quarterly", "Continuous"]

FOCUS_CATEGORIES = ["Sector", "Technology", "Geography", "Threat Type", "Threat Actor", "Vendor", "Incident", "Campaign"]

# The organisation-wide focus point setting a requirement's scope category
# corresponds to. Incidents and campaigns have none.
FOCUS_POINT_SETTINGS = {
    "Geography": "FOCUS_POINTS_GEOGRAPHIES",
    "Sector": "FOCUS_POINTS_SECTORS",
    "Threat Actor": "FOCUS_POINTS_THREAT_ACTORS",
    "Threat Type": "FOCUS_POINTS_THREAT_TYPES",
    "Technology": "FOCUS_POINTS_TECHNOLOGIES",
    "Vendor": "FOCUS_POINTS_VENDORS",
}

INTEL_LEVELS = ["Strategic", "Operational", "Tactical"]
