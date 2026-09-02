import logging
import re

import requests

import config

logger = logging.getLogger(__name__)

# MISP object templates used when adding objects to a Flowintel case.
_VULNERABILITY_OBJECT_TEMPLATE = {"uuid": "81650945-f186-437b-8945-9f31715d32da", "name": "vulnerability"}
_WEAKNESS_OBJECT_TEMPLATE = {"uuid": "b8713fc0-d7a2-4b27-a182-38ed47966802", "name": "weakness"}

# Matches a CVSS score (e.g. "9.8" out of "9.8 (CRITICAL)").
_CVSS_SCORE_RE = re.compile(r"\d+(?:\.\d+)?")
# Matches CWE-style weakness ids (e.g. "CWE-77" out of "CWE-77, CWE-89").
_CWE_ID_RE = re.compile(r"cwe-\d+", re.IGNORECASE)


CHANNEL_PREFIX = "flowintel:"


def get_instances() -> list[dict]:
    """Return the configured Flowintel instances."""
    return getattr(config, "FLOWINTEL_INSTANCES", []) or []


def notification_channels() -> list[dict]:
    """Represent configured Flowintel instances as notification channels."""
    return [
        {
            "id": f"{CHANNEL_PREFIX}{instance.get('id')}",
            "name": instance.get("name") or instance.get("id"),
            "type": "flowintel",
            "enabled": bool(instance.get("enabled")),
        }
        for instance in get_instances()
        if instance.get("id")
    ]


def send_to_eligible_instances(stakeholders, product_key: str, send_fn):
    """Call `send_fn(instance)` for each Flowintel instance that a stakeholder in
    `stakeholders` is subscribed to and that has `product_key` enabled.

    Returns a list of (instance, result) tuples, where result is whatever
    send_fn returns (typically the dict from create_case_from_product).
    """
    subscribed_ids = {
        cid[len(CHANNEL_PREFIX):]
        for s in stakeholders
        for cid in (getattr(s, "notification_channels", None) or [])
        if cid.startswith(CHANNEL_PREFIX)
    }
    results = []
    for instance in get_instances():
        if instance.get("id") not in subscribed_ids or not instance.get("enabled"):
            continue
        product = (instance.get("case_templates") or {}).get(product_key) or {}
        if not product.get("enabled"):
            continue
        results.append((instance, send_fn(instance)))
    return results


def test_connection(url: str, api_key: str, verify_tls: bool = True) -> dict:
    """Check connectivity to a Flowintel instance without creating or sending anything."""
    url = url.rstrip("/")
    try:
        r = requests.get(f"{url}/api/case/all", headers={"X-API-KEY": api_key}, timeout=10, verify=verify_tls)
        if r.status_code == 403:
            return {"ok": False, "error": "Connected, but the API key was rejected (403 Forbidden)."}
        r.raise_for_status()
        return {"ok": True}
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}


def get_case_templates(url: str, api_key: str, verify_tls: bool = True) -> dict:
    """Return the case templates available on a Flowintel instance.

    Returns {"ok": True, "templates": [{"id": ..., "title": ...}, ...]} on success,
    or {"ok": False, "error": ...} on failure.
    """
    url = url.rstrip("/")
    try:
        r = requests.get(f"{url}/api/templating/cases", headers={"X-API-KEY": api_key}, timeout=10, verify=verify_tls)
        r.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    templates = [{"id": t["id"], "title": t["title"]} for t in r.json().get("templates", [])]
    return {"ok": True, "templates": templates}


def create_case_from_template(url: str, api_key: str, template_id: str, title: str, verify_tls: bool = True) -> dict:
    """Create a new case from a Flowintel case template.

    Returns {"ok": True, "message": ..., "case_id": ...} on success (case_id is
    omitted if it could not be parsed from the response), or {"ok": False, "error": ...}
    on failure (network error, missing template, or a title that already exists).
    """
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/templating/create_case_from_template/{template_id}",
            headers={"X-API-KEY": api_key},
            json={"title": title},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 201:
        message = data.get("message", "Case created.")
        result = {"ok": True, "message": message}
        match = re.search(r"id:\s*(\d+)", message)
        if match:
            result["case_id"] = match.group(1)
        return result
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def _create_misp_object(url: str, api_key: str, case_id: str, template: dict, attributes: list[dict], verify_tls: bool = True) -> dict:
    """Create a MISP object on a case from an object template and a list of attributes."""
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/case/{case_id}/create_misp_object",
            headers={"X-API-KEY": api_key},
            json={"object-template": template, "attributes": attributes},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 200:
        return {"ok": True, "message": data.get("message", "Object created.")}
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def add_vulnerability_object(url: str, api_key: str, case_id: str, cve_ids: list[str] = None,
                              cvss_score: str = None, description: str = None, summary: str = None,
                              verify_tls: bool = True) -> dict:
    """Add a MISP vulnerability object to a case.

    Any of cve_ids, cvss_score, description or summary may be omitted; only the
    attributes with a value are added to the object. Each id in cve_ids is added
    as its own "id" attribute (the relation accepts multiple CVEs).
    """
    attributes = []
    for cve_id in cve_ids or []:
        attributes.append({"value": cve_id, "type": "vulnerability", "object_relation": "id"})
    if cvss_score:
        attributes.append({"value": cvss_score, "type": "float", "object_relation": "cvss-score"})
    if description:
        attributes.append({"value": description, "type": "text", "object_relation": "description"})
    if summary:
        attributes.append({"value": summary, "type": "text", "object_relation": "summary"})
    return _create_misp_object(url, api_key, case_id, _VULNERABILITY_OBJECT_TEMPLATE, attributes, verify_tls)


def add_weakness_object(url: str, api_key: str, case_id: str, cwe_id: str = None,
                         name: str = None, verify_tls: bool = True) -> dict:
    """Add a MISP weakness object to a case.

    Either cwe_id or name (or both) may be given; only the attributes with a
    value are added to the object.
    """
    attributes = []
    if cwe_id:
        attributes.append({"value": cwe_id, "type": "weakness", "object_relation": "id"})
    if name:
        attributes.append({"value": name, "type": "text", "object_relation": "name"})
    return _create_misp_object(url, api_key, case_id, _WEAKNESS_OBJECT_TEMPLATE, attributes, verify_tls)


def append_case_note(url: str, api_key: str, case_id: str, note: str, verify_tls: bool = True) -> dict:
    """Append a note to a case."""
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/case/{case_id}/append_case_note",
            headers={"X-API-KEY": api_key},
            json={"note": f"\n{note}"},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 200:
        return {"ok": True, "message": data.get("message", "Note added."), "note": note}
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def find_task_by_title(url: str, api_key: str, case_id: str, title: str, verify_tls: bool = True) -> dict:
    """Return the id of the first open task in a case matching the given title."""
    url = url.rstrip("/")
    try:
        r = requests.get(f"{url}/api/case/{case_id}/tasks", headers={"X-API-KEY": api_key}, timeout=10, verify=verify_tls)
        r.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    for task in r.json():
        if task.get("title") == title:
            return {"ok": True, "task_id": task["id"]}
    return {"ok": False, "error": f"No task named '{title}' found in case {case_id}"}


def _post_external_reference(url: str, api_key: str, task_id: str, ref_url: str, verify_tls: bool = True) -> dict:
    """Add a single external reference URL to a task."""
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/task/{task_id}/create_external_reference",
            headers={"X-API-KEY": api_key},
            json={"url": ref_url},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 201:
        return {"ok": True, "url": ref_url, "task_id": task_id}
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def add_external_references_to_task(url: str, api_key: str, case_id: str, task_title: str,
                                     urls: list[str], verify_tls: bool = True) -> dict:
    """Find a task by title in a case and add each URL in `urls` to it as an external reference."""
    found = find_task_by_title(url, api_key, case_id, task_title, verify_tls)
    if not found["ok"]:
        return found
    results = [_post_external_reference(url, api_key, found["task_id"], ref_url, verify_tls) for ref_url in urls]
    return {"ok": all(r["ok"] for r in results), "task_id": found["task_id"], "results": results}


def get_case_template_tasks(url: str, api_key: str, template_id: str, verify_tls: bool = True) -> dict:
    """Return the tasks defined by a Flowintel case template, in template order.

    Returns {"ok": True, "tasks": [{"id": ..., "title": ...}, ...]} on success,
    or {"ok": False, "error": ...} on failure.
    """
    url = url.rstrip("/")
    try:
        r = requests.get(f"{url}/api/templating/case/{template_id}", headers={"X-API-KEY": api_key}, timeout=10, verify=verify_tls)
        r.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    tasks = [{"id": t["id"], "title": t["title"]} for t in r.json().get("tasks", [])]
    return {"ok": True, "tasks": tasks}


def add_case_tags(url: str, api_key: str, case_id: str, tags: list[str], verify_tls: bool = True) -> dict:
    """Set the taxonomy tags on a case, replacing any existing tags."""
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/case/{case_id}/edit",
            headers={"X-API-KEY": api_key},
            json={"tags": tags},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 200:
        return {"ok": True, "message": data.get("message", "Tags updated."), "tags": tags}
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def add_task_note(url: str, api_key: str, task_id: str, note: str, verify_tls: bool = True) -> dict:
    """Append a note to a task."""
    url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/task/{task_id}/create_note",
            headers={"X-API-KEY": api_key},
            json={"note": note},
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        data = r.json()
    except ValueError:
        data = {}

    if r.status_code == 200:
        return {"ok": True, "message": data.get("message", "Note added."), "note": note}
    return {"ok": False, "error": data.get("message") or f"HTTP {r.status_code}"}


def add_note_to_task(url: str, api_key: str, case_id: str, task_title: str, note: str, verify_tls: bool = True) -> dict:
    """Find a task by title in a case and append a note to it."""
    found = find_task_by_title(url, api_key, case_id, task_title, verify_tls)
    if not found["ok"]:
        return found
    return add_task_note(url, api_key, found["task_id"], note, verify_tls)


def create_case_from_product(instance: dict, product_key: str, title: str, note: str = None,
                              tags: list[str] = None,
                              vulnerability: dict = None, weaknesses: list[dict] = None,
                              external_references: list[str] = None,
                              initial_task_note: str = None) -> dict:
    """Create a Flowintel case from the template configured for a CTI product, then
    populate it with an optional note, tags, MISP objects and initial-task content.

    `instance` is a Flowintel instance config dict (see config.FLOWINTEL_INSTANCES).
    `product_key` selects the case template via instance["case_templates"][product_key];
    the product must be enabled and have a template_id configured.
    `tags`, if given, is a list of taxonomy tags (e.g. "tlp:amber") set on the case.
    `vulnerability`, if given, is a dict with optional cve_ids/cvss_score/description/summary
    keys added as a MISP vulnerability object.
    `weaknesses`, if given, is a list of dicts with optional cwe_id/name keys, each
    added as its own MISP weakness object.
    `external_references` and `initial_task_note`, if given, are added to the case's
    configured "initial task" (instance["case_templates"][product_key]["initial_task"]).
    Both are skipped if no initial task is configured for the product.

    Returns {"ok": bool, "case_id": ..., "message": ..., "steps": {...}} once the
    case has been created (ok is False if a later step failed), or
    {"ok": False, "error": ...} if the case itself could not be created.
    """
    instance_label = instance.get("name") or instance.get("id") or "Flowintel"
    case_templates = instance.get("case_templates") or {}
    product = case_templates.get(product_key) or {}
    if not product.get("enabled"):
        return {"ok": False, "error": f"'{product_key}' is not enabled for {instance_label}"}
    template_id = product.get("template_id")
    if not template_id:
        return {"ok": False, "error": f"No case template configured for '{product_key}' on {instance_label}"}
    initial_task = (product.get("initial_task") or "").strip()

    url = instance.get("url", "")
    api_key = instance.get("api_key", "")
    verify_tls = instance.get("verify_tls", True)

    created = create_case_from_template(url, api_key, template_id, title, verify_tls)
    if not created["ok"]:
        return created
    case_id = created.get("case_id")
    if not case_id:
        return {"ok": False, "error": f"Case created but no case ID found in response: {created.get('message')}"}

    steps = {}
    ok = True

    if tags:
        step = add_case_tags(url, api_key, case_id, tags, verify_tls=verify_tls)
        steps["tags"] = step
        ok = ok and step["ok"]

    if vulnerability:
        step = add_vulnerability_object(
            url, api_key, case_id,
            cve_ids=vulnerability.get("cve_ids"),
            cvss_score=vulnerability.get("cvss_score"),
            description=vulnerability.get("description"),
            summary=vulnerability.get("summary"),
            verify_tls=verify_tls,
        )
        steps["vulnerability_object"] = step
        ok = ok and step["ok"]

    for weakness in weaknesses or []:
        step = add_weakness_object(
            url, api_key, case_id,
            cwe_id=weakness.get("cwe_id"), name=weakness.get("name"),
            verify_tls=verify_tls,
        )
        steps.setdefault("weakness_objects", []).append(step)
        ok = ok and step["ok"]

    if note:
        step = append_case_note(url, api_key, case_id, note, verify_tls=verify_tls)
        steps["note"] = step
        ok = ok and step["ok"]

    if initial_task:
        if external_references:
            step = add_external_references_to_task(
                url, api_key, case_id, initial_task, external_references, verify_tls=verify_tls,
            )
            steps["external_references"] = step
            ok = ok and step["ok"]

        if initial_task_note:
            step = add_note_to_task(url, api_key, case_id, initial_task, initial_task_note, verify_tls=verify_tls)
            steps["initial_task_note"] = step
            ok = ok and step["ok"]

    return {"ok": ok, "case_id": case_id, "message": created.get("message"), "steps": steps}


def send_vea_to_flowintel(instance: dict, vea, markdown: str, preview_url: str = "") -> dict:
    """Create a Flowintel case for a published vulnerability exploitation advisory.

    Populates the case with the advisory's TLP tag, a vulnerability object (CVSS
    score, summary and description), one weakness object per CWE referenced by
    the advisory, a note containing the full advisory markdown, and external
    references on the configured initial task for the advisory preview URL and
    any links listed under the advisory's References section.
    """
    subject = vea.title or vea.cve_id or "Vulnerability advisory"
    # Prefix with the advisory ID so multiple advisories about the same
    # vulnerability (and thus the same subject) each get their own case.
    case_title = f"{vea.vea_id}: {subject}" if vea.vea_id else subject

    cvss_match = _CVSS_SCORE_RE.search(vea.cvss or "")
    cve_ids = [c.strip() for c in re.split(r"[,\n]", vea.cve_id or "") if c.strip()]
    vulnerability = {
        "cve_ids": cve_ids,
        "cvss_score": cvss_match.group(0) if cvss_match else None,
        "description": vea.summary,
        "summary": subject,
    }

    weaknesses = [{"cwe_id": m.group(0).upper(), "name": subject} for m in _CWE_ID_RE.finditer(vea.cwe or "")]

    external_references = [u for u in [preview_url, *(vea.references or [])] if u]

    return create_case_from_product(
        instance,
        "Vulnerability advisory",
        case_title,
        note=markdown,
        tags=[f"tlp:{vea.tlp or 'amber'}"],
        vulnerability=vulnerability,
        weaknesses=weaknesses,
        external_references=external_references,
    )


def send_flash_intel_to_flowintel(instance: dict, fia, markdown: str, preview_url: str = "") -> dict:
    """Create a Flowintel case for a published flash intel alert.

    Populates the case with the alert's TLP tag, a note containing the full
    alert markdown, the "Recommended actions" content as a note on the
    configured initial task, and external references on that same task for
    the alert preview URL and any links listed under the alert's References
    section.
    """
    case_title = f"{fia.fia_id}: {fia.title}" if fia.fia_id else (fia.title or "Flash intel alert")

    recommended_actions = "\n".join(
        f"- {line}" for line in [*(fia.actions_immediate or []), *(fia.actions_near_term or [])]
    )
    initial_task_note = f"**Recommended actions**\n\n{recommended_actions}" if recommended_actions else None

    external_references = [u for u in [preview_url, *(fia.external_references or [])] if u]

    return create_case_from_product(
        instance,
        "Flash intel alert",
        case_title,
        note=markdown,
        tags=[f"tlp:{fia.tlp or 'amber'}"],
        external_references=external_references,
        initial_task_note=initial_task_note,
    )
