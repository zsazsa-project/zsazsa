# The zsazsa API

The API lets other tools work with zsazsa. 

zsazsa describes the API in OpenAPI at `/api/v1/openapi.json`, and `/api/v1/docs` shows that description in Swagger UI.

## Switching it on

The API is off until a site admin switches it on, under Settings > Connections > API (`API_ENABLED`).

## Signing in

A tool sends the MISP API key of its own user in the `Authorization` header. zsazsa asks MISP who the key belongs to on every call, and makes each MISP call for it with that key: MISP decides what the tool may see and change, and the audit log names its user. That user has to be in the organisation of the key zsazsa stores its records with (`MISP_WEBAPP_KEY`).

Give the tool a MISP user of its own. To create and update, its role needs **Add**, **Modify Org** and **Tagger**, and the key must not be read-only. Modify Org is there because the records made on zsazsa's pages were saved by the user of `MISP_WEBAPP_KEY`, and Tagger because zsazsa finds its records by their tags. The tool needs neither site admin nor publish rights. A role without those three permissions can still list and read.

## Errors

An error comes back as JSON, with a code and a message that names the field when there is one:

```json
{"error": {"code": "unprocessable-entity", "message": "The priority has to be one of: Low, Medium, High, Critical, or none."}}
```

| Status | When |
|---|---|
| `400` | The body is not a JSON object |
| `401` | No key, or one MISP refuses |
| `403` | The key's user is in another organisation, its role lacks a permission above, or the key is read-only |
| `404` | The record is not there, or the key cannot see it |
| `409` | The record cannot be changed any more |
| `422` | A field that cannot be set, or a value that is not valid, in the body or in a filter |
| `500` | Something went wrong in zsazsa; its log has the details |
| `502` | MISP did not take the change, or not all of it, with its reason |
| `503` | MISP cannot be reached |

## Detection engineering requests

| Call | Does |
|---|---|
| `POST /detection-engineering/requests` | Creates a request, `201` with its `Location`. If MISP cannot read it back straight away, the reply has only `uuid` and `der_id` |
| `GET /detection-engineering/requests` | Lists them, newest first. Filters: `review_state`, `status`, `priority`, `tlp` and `audience`, as on zsazsa's list. Pages: `page` and `limit`, 100 at most |
| `GET /detection-engineering/requests/<uuid>` | Returns one. Anything but a UUID is a `404`, MISP's numeric event id included |
| `PATCH /detection-engineering/requests/<uuid>` | Changes the fields given and keeps the others, so `{}` changes nothing. A published request is a `409` |

A tool sets `title` (required), `technique`, `cve_ids`, `hypothesis`, `log_sources`, `expected_output`, `existing_coverage`, `test_cases`, `priority`, `tlp`, `audience`, `author` and `review_state`. A new request is TLP:AMBER and a draft unless the tool says otherwise. `review_state` can be `draft` or `pending-review`, as approving is done in zsazsa; setting it on a rejected request sends it back and clears the rejection reason. `format` and `draft_rule` can only be set when a request is created. After that they change on zsazsa's detail page, which checks the rule with Rulezet.

`title` cannot be empty, while `priority` and `format` can be, as on zsazsa's form. A field is cleared with an empty string or list, not with `null`. An entry of a list is one line, as the form stores them.

A technique is given as its ATT&CK ID, `T1190`, or as the galaxy value, `Exploit Public-Facing Application - T1190`, and is stored as the galaxy value, as zsazsa's form stores it. A tactic in the galaxy, such as `Collection - TA0009`, is given by its value. `technique_ids` returns the IDs. `audience` is a list of stakeholder roles.

A request also returns `uuid`, `der_id`, `status`, `rejection_reason`, `creator`, `approved_by`, `published`, `published_at`, `created_at`, `misp_url`, `source_event_uuids` and `linked_pir_uuid`, which a tool cannot set. Approving, publishing and delivering a request, its engineering status, its source events and its linked PIR stay with zsazsa's pages.

## Alerts, advisories and briefings

These can be listed, for now. Each list is newest first, filters as its page in zsazsa does, and pages with `page` and `limit`, 100 at most. A key that cannot write can list.

| Call | Filters | Each has |
|---|---|---|
| `GET /flash-intel-alerts` | `review_state`, `tlp`, `audience` | `fia_id`, `summary`, `audience` |
| `GET /vulnerability-advisories` | `review_state`, `exploitation`, `tlp`, `audience` | `vea_id`, `cve_id`, `cvss`, `exploitation`, `summary`, `audience` |
| `GET /daily-briefings` | `review_state`, `tlp` | `date`, `story_count`, `summary` |

Each also has `uuid`, `title`, `review_state`, `tlp`, `creator`, `approved_by`, `published`, `published_at`, `created_at` and `misp_url`.

## Trying it out

The quickest way is `/api/v1/docs`: select **Authorize**, paste the key, and use **Try it out** on a call. The examples below do the same from a shell. Set the address zsazsa answers on and the key first:

```sh
ZSAZSA=https://misp.example.org/zsazsa
KEY='<MISP API key>'
```

The first and the last example create a real request, which then shows on zsazsa's list of detection engineering requests. Delete it there when you are done.

Create a request, as a draft:

```sh
curl -s -X POST "$ZSAZSA/api/v1/detection-engineering/requests" \
     -H "Authorization: $KEY" -H "Content-Type: application/json" \
     -d '{"title": "Detect PAN-OS GlobalProtect exploitation",
          "technique": ["T1190"],
          "cve_ids": ["CVE-2024-3400"],
          "hypothesis": "A GlobalProtect session is followed by a shell spawned by the gateway.",
          "priority": "High"}'
```

List the requests waiting for a review, showing their ID and title (with `jq`):

```sh
curl -s -H "Authorization: $KEY" \
     "$ZSAZSA/api/v1/detection-engineering/requests?review_state=pending-review" \
  | jq -r '.requests[] | "\(.der_id)  \(.title)"'
```

Create a request in Python, then send it for review:

```python
import requests

ZSAZSA = "https://misp.example.org/zsazsa/api/v1"
session = requests.Session()
session.headers["Authorization"] = "<MISP API key>"


def call(method, path, body):
    reply = session.request(method, f"{ZSAZSA}{path}", json=body, timeout=60)
    if not reply.ok:
        raise SystemExit(f"{reply.status_code}: {reply.text}")
    return reply.json()


created = call("POST", "/detection-engineering/requests", {
    "title": "Detect PAN-OS GlobalProtect exploitation",
    "technique": ["T1190"],
    "cve_ids": ["CVE-2024-3400"],
})
print("Created", created["der_id"], created["misp_url"])

submitted = call("PATCH", f"/detection-engineering/requests/{created['uuid']}",
                 {"review_state": "pending-review"})
print(submitted["der_id"], "is", submitted["review_state"])
```
