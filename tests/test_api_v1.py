"""The API under /api/v1, which so far has detection engineering requests.

A caller signs in with the MISP key of its own user, and every MISP call made
for it uses that key. So this pins who is let in, and as whom: no key or a
refused one is a 401, a user of another organisation a 403, and a request
never runs as MISP_WEBAPP_KEY or as the fallback identity of an install without
single sign-on. It also pins what a write needs and may change, how the fields
are read and returned, and that the OpenAPI description says what the code does.

MISP's /users/view/me is a stub and PyMISP an autospec. The store reads its
requests from a dict and its writes are recorded rather than made, except in
ThroughTheStore, which runs a change through the store against the autospec.
The database and the log are temporary, so the audit log is read back as
written.

    python -m unittest tests.test_api_v1
"""

import json
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests
from pymisp import MISPEvent, PyMISP

import config
from webapp import audit, collection_cache, create_app, job_store, misp_store
from webapp.routes import api_v1

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
NEW_UUID = "9d2b6c1e-4f3a-4b8e-a7d5-0c1e2f3a4b5c"
REQUESTS = "/api/v1/detection-engineering/requests"
WRITER = {"perm_add": True, "perm_modify_org": True, "perm_tagger": True, "perm_sync": True}
USERS = {
    "caller-key": {"User": {"id": "7", "email": "rulezet@example.org", "org_id": "1"}, "Role": WRITER},
    "service-key": {"User": {"id": "1", "email": "zsazsa@example.org", "org_id": "1"}, "Role": WRITER},
    "other-org-key": {"User": {"id": "8", "email": "someone@elsewhere.example", "org_id": "2"}, "Role": WRITER},
    "reader-key": {"User": {"id": "9", "email": "reader@example.org", "org_id": "1"},
                   "Role": {**WRITER, "perm_tagger": False}},
}
# What the Api tests stand in for, which ThroughTheStore puts back.
STORE = {name: getattr(misp_store, name) for name in ("_zsazsa_event", "_der_ns", "_write_der")}
# The galaxy has tactics as well, with a TA id.
TECHNIQUES = ["Windows Management Instrumentation - T1047", "Exploit Public-Facing Application - T1190",
              "Collection - TA0009", "Command and Control - TA0011"]


def _view_me(url, headers, **_):
    user = USERS.get(headers["Authorization"])
    return SimpleNamespace(status_code=200 if user else 403,
                           json=lambda: user or {"name": "Authentication failed."})


def _der(**changes):
    der = SimpleNamespace(
        uuid=UUID, der_id="DER-00042", title="Detect WMI lateral movement", technique=[TECHNIQUES[0]],
        cve_ids=[], hypothesis="Actors pivot with wmic.", log_sources=["Sysmon"],
        expected_output="One alert per host.", existing_coverage=[], test_cases=["Run wmic /node"],
        format="sigma", draft_rule="title: x", priority="High", status=misp_store.DER_STATUS_PENDING,
        tlp="amber", author="koen", audience="SOC", review_state=misp_store.DER_REVIEW_DRAFT,
        rejection_reason="", source_event_uuids=[], source_event_hints={}, linked_pir_uuid="",
        creator="analyst@example.org", approved_by="", published=False, published_at=None,
        created_at=datetime(2026, 11, 12), misp_url=f"https://misp.example/events/view/{UUID}",
    )
    der.__dict__.update(changes)
    return der


def _product(builder, reader, n, **fields):
    """A product as the store reads it back from a MISP event."""
    event = MISPEvent()
    event.uuid = f"00000000-0000-4000-8000-{n:012d}"
    event.id = n
    event.date = "2026-11-0" + str(n)
    event.add_object(builder(fields))
    return reader(event)


def _fia(n, **fields):
    return _product(misp_store._fia_obj, misp_store._fia_ns, n, fia_id=f"FIA-0000{n}", title=f"Alert {n}", **fields)


def _vea(n, **fields):
    return _product(misp_store._vea_obj, misp_store._vea_ns, n, vea_id=f"VEA-0000{n}", title=f"Advisory {n}",
                    cve_id=f"CVE-2026-000{n}", **fields)


def _briefing(n, **fields):
    return _product(misp_store._briefing_obj, misp_store._briefing_ns, n, date=f"2026-11-0{n}",
                    title=f"Briefing {n}", **fields)


# Each list: the key it returns its products under, its filters, the schema of
# a product in the description, and a product to hold the schema to.
LISTS = {
    "/detection-engineering/requests": ("requests", api_v1._DER_FILTERS, "Request", lambda: api_v1._der_json(_der())),
    "/flash-intel-alerts": ("alerts", api_v1._FIA_FILTERS, "AlertSummary", lambda: api_v1._fia_json(_fia(1))),
    "/vulnerability-advisories": ("advisories", api_v1._VEA_FILTERS, "AdvisorySummary",
                                  lambda: api_v1._vea_json(_vea(1))),
    "/daily-briefings": ("briefings", api_v1._BRIEFING_FILTERS, "BriefingSummary",
                         lambda: api_v1._briefing_json(_briefing(1))),
}


class Api(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.stored = {UUID: _der()}
        self.clients = []
        self.version = {"version": "2.5.30", "perm_sync": True}
        patches = [
            mock.patch.multiple(config, create=True, DB_FILE=str(Path(tmp.name) / "test.db"),
                                LOG_FILE=str(Path(tmp.name) / "test.log"),
                                MISP_WEBAPP_URL="https://misp.example", MISP_WEBAPP_KEY="service-key",
                                MISP_WEBAPP_VERIFYCERT=True, API_ENABLED=True,
                                MISP_SESSION_REDIRECT_TO_LOGIN=False, MISP_SESSION_COOKIE_NAME=""),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.dict(api_v1._records_org, clear=True),
            mock.patch.object(api_v1.requests, "get", side_effect=_view_me),
            mock.patch.object(api_v1, "PyMISP", side_effect=self.client_for),
            mock.patch.object(misp_store, "_zsazsa_event", side_effect=lambda uuid, *_: self.stored.get(uuid)),
            mock.patch.object(misp_store, "_der_ns", side_effect=lambda der: der),
            mock.patch.object(misp_store, "list_ders", side_effect=lambda strict: list(self.stored.values())),
            mock.patch.object(misp_store, "create_der", side_effect=self.create),
            mock.patch.object(misp_store, "_write_der", side_effect=self.write),
            mock.patch.object(misp_store, "galaxy_mitre_attack_patterns", return_value=TECHNIQUES),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def client_for(self, url, key, ssl, timeout):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.misp_instance_version = self.version
        self.clients.append((key, misp))
        return misp

    def create(self, data):
        self.created_with = misp_store._misp()
        self.stored[NEW_UUID] = _der(uuid=NEW_UUID, der_id="DER-00043", **data)
        return NEW_UUID, "DER-00043"

    def write(self, der, data):
        self.stored[der.uuid] = _der(uuid=der.uuid, **data)
        return self.stored[der.uuid]

    def written(self):
        """What the last change wrote over the request."""
        der, data = misp_store._write_der.call_args.args
        self.assertEqual(der.uuid, UUID)
        return data

    def call(self, method, path="", key="caller-key", json=None, query=None):
        headers = {"Authorization": key} if key else {}
        return self.client.open(REQUESTS + path, method=method, headers=headers, json=json, query_string=query)

    def assertError(self, reply, status, text=""):
        self.assertEqual(reply.status_code, status, reply.get_data(as_text=True))
        self.assertIn(text, reply.get_json()["error"]["message"])


class WhoIsLetIn(Api):
    def test_nothing_answers_while_the_api_is_off(self):
        with mock.patch.object(config, "API_ENABLED", False):
            self.assertError(self.call("GET"), 404)

    def test_no_key_is_refused_even_without_single_sign_on(self):
        """Such an install serves its pages as the fallback admin; the API does not."""
        self.assertError(self.call("GET", key=""), 401, "Authorization header")
        misp_store.list_ders.assert_not_called()

    def test_a_key_misp_refuses_is_refused(self):
        self.assertError(self.call("GET", key="wrong-key"), 401)
        self.assertEqual(self.clients, [])

    def test_its_description_and_documentation_need_no_key(self):
        for path in ("/api/v1/openapi.json", "/api/v1/docs"):
            with self.subTest(path):
                self.assertEqual(self.client.get(path).status_code, 200)
                with mock.patch.object(config, "API_ENABLED", False):
                    self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.clients, [])

    def test_the_description_names_the_path_zsazsa_is_served_under(self):
        spec = self.client.get("/api/v1/openapi.json", environ_overrides={"SCRIPT_NAME": "/zsazsa"}).get_json()
        self.assertEqual(spec["servers"], [{"url": "/zsazsa/api/v1"}])

    def test_the_description_is_the_one_of_the_code_that_runs(self):
        """Read from disk on each call, it offered calls an update had added
        while zsazsa, not restarted yet, still ran the code without them."""
        with tempfile.TemporaryDirectory() as tmp:
            newer = Path(tmp) / "openapi_v1.json"
            newer.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/added-since": {}}}))
            with mock.patch.object(api_v1, "_OPENAPI_FILE", newer):
                spec = self.client.get("/api/v1/openapi.json").get_json()
        self.assertNotIn("/added-since", spec["paths"])
        self.assertIn("/daily-briefings", spec["paths"])

    def test_a_path_or_method_it_does_not_have_is_answered_as_the_api_answers(self):
        """Not with the MISP login, nor the 403 of a missing CSRF token: no
        route matched, so Flask cannot tell it is the API's."""
        with mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", True):
            self.assertError(self.call("GET", "-typo"), 404)
            self.assertError(self.call("DELETE", f"/{UUID}"), 405)

    def test_a_disabled_user_or_an_answer_that_is_not_json_is_refused(self):
        disabled = {"User": {**USERS["caller-key"]["User"], "disabled": True}, "Role": WRITER}
        for reply in (SimpleNamespace(status_code=200, json=lambda: disabled),
                      SimpleNamespace(status_code=200, json=mock.Mock(side_effect=ValueError))):
            with self.subTest(reply), mock.patch.object(api_v1.requests, "get", return_value=reply):
                self.assertError(self.call("GET"), 401)
        self.assertEqual(self.clients, [])

    def test_misp_failing_to_answer_who_a_key_is_is_a_503(self):
        with mock.patch.object(api_v1.requests, "get", return_value=SimpleNamespace(status_code=502)):
            self.assertError(self.call("GET"), 503, "502")

    def test_a_user_of_another_organisation_is_refused(self):
        self.assertError(self.call("GET", key="other-org-key"), 403, "organisation")
        misp_store.list_ders.assert_not_called()

    def test_misp_out_of_reach_is_a_503(self):
        with mock.patch.object(api_v1.requests, "get", side_effect=requests.ConnectionError("refused")), \
             self.assertLogs("webapp.routes.api_v1", "WARNING"):
            self.assertError(self.call("GET"), 503)

    def test_every_misp_call_is_made_with_the_callers_key(self):
        reply = self.call("POST", json={"title": "Detect PAN-OS exploitation"})
        self.assertEqual(reply.status_code, 201)
        self.assertEqual([key for key, _ in self.clients], ["caller-key"])
        self.assertIs(self.created_with, self.clients[0][1])

    def test_a_write_needs_no_csrf_token_and_the_audit_log_names_the_caller(self):
        self.call("POST", json={"title": "Detect PAN-OS exploitation"})
        entry = audit.get_logs(limit=1)[0]
        self.assertEqual((entry["user"], entry["action"], entry["details"]), ("rulezet@example.org", "create", "api"))


class WhatAWriteNeeds(Api):
    def test_a_role_without_perm_tagger_cannot_write(self):
        self.assertError(self.call("POST", key="reader-key", json={"title": "x"}), 403, "perm_tagger")
        misp_store.create_der.assert_not_called()

    def test_it_can_still_read(self):
        self.assertEqual(self.call("GET", f"/{UUID}", key="reader-key").status_code, 200)

    def test_a_read_only_key_cannot_write(self):
        self.version["perm_sync"] = False
        self.assertError(self.call("PATCH", f"/{UUID}", json={"priority": "Low"}), 403, "read-only")
        misp_store._write_der.assert_not_called()

    def test_a_write_misp_refuses_is_a_502_with_its_reason(self):
        """Not a 403: the role was checked above, so the reason is MISP's own."""
        misp_store.create_der.side_effect = RuntimeError("add DER object: (403, 'not allowed')")
        self.assertError(self.call("POST", json={"title": "x"}), 502, "not allowed")

    def test_anything_else_that_goes_wrong_is_still_answered_in_json(self):
        misp_store._write_der.side_effect = KeyError("tlp")
        with self.assertLogs("webapp.routes.api_v1", "ERROR"):
            self.assertError(self.call("PATCH", f"/{UUID}", json={"priority": "Low"}), 500)


class Creating(Api):
    def test_a_request_is_created_with_its_fields_read_as_the_form_stores_them(self):
        reply = self.call("POST", json={"title": " Detect PAN-OS exploitation ", "technique": ["t1190"],
                                        "cve_ids": ["cve-2024-3400"], "audience": ["SOC", "Threat Hunting"],
                                        "format": "sigma", "review_state": "pending-review"})
        self.assertEqual(reply.status_code, 201)
        self.assertTrue(reply.headers["Location"].endswith(f"{REQUESTS}/{NEW_UUID}"))
        data = misp_store.create_der.call_args.args[0]
        self.assertEqual(data["title"], "Detect PAN-OS exploitation")
        self.assertEqual(data["technique"], ["Exploit Public-Facing Application - T1190"])
        self.assertEqual(data["cve_ids"], ["CVE-2024-3400"])
        self.assertEqual(data["audience"], "SOC, Threat Hunting")
        self.assertEqual(data["review_state"], "pending-review")
        body = reply.get_json()
        self.assertEqual(body["technique_ids"], ["T1190"])
        self.assertEqual(body["audience"], ["SOC", "Threat Hunting"])

    def test_a_request_misp_cannot_read_back_is_still_created(self):
        """Saying it failed would have the caller create it a second time."""
        misp_store.create_der.side_effect = lambda data: (NEW_UUID, "DER-00043")
        reply = self.call("POST", json={"title": "x"})
        self.assertEqual(reply.status_code, 201)
        self.assertEqual(reply.get_json(), {"uuid": NEW_UUID, "der_id": "DER-00043"})
        self.assertTrue(reply.headers["Location"].endswith(f"{REQUESTS}/{NEW_UUID}"))

    def test_it_needs_a_title(self):
        for body in ({"hypothesis": "x"}, {"title": ""}, {"title": "   "}):
            with self.subTest(body):
                self.assertError(self.call("POST", json=body), 422, "title")
        misp_store.create_der.assert_not_called()

    def test_priority_and_format_can_be_left_empty_as_on_the_form(self):
        reply = self.call("POST", json={"title": "x", "priority": "", "format": ""})
        self.assertEqual(reply.status_code, 201, reply.get_data(as_text=True))
        data = misp_store.create_der.call_args.args[0]
        self.assertEqual((data["priority"], data["format"]), ("", ""))

    def test_it_cannot_be_approved_on_creation(self):
        self.assertError(self.call("POST", json={"title": "x", "review_state": "approved"}), 422, "review_state")

    def test_a_field_it_cannot_set_is_named(self):
        for field in ("colour", "status", "source_event_uuids", "linked_pir_uuid", "der_id"):
            with self.subTest(field):
                self.assertError(self.call("POST", json={"title": "x", field: "y"}), 422, field)
        misp_store.create_der.assert_not_called()

    def test_a_technique_that_is_not_in_attack_is_refused(self):
        self.assertError(self.call("POST", json={"title": "x", "technique": ["T9999"]}), 422, "T9999")

    def test_every_value_of_the_galaxy_is_taken_as_on_the_form(self):
        """The tactics have no T id, and only the last of them used to be found."""
        reply = self.call("POST", json={"title": "x", "technique": TECHNIQUES})
        self.assertEqual(reply.status_code, 201, reply.get_data(as_text=True))
        self.assertEqual(misp_store.create_der.call_args.args[0]["technique"], TECHNIQUES)

    def test_an_entry_of_a_list_cannot_hold_a_line_break(self):
        """The lists are stored a line each, so it would come back as two."""
        for text in ("Sysmon\nEDR", "Sysmon\r\nEDR", "Sysmon\rEDR", "Sysmon\u2028EDR"):
            with self.subTest(text):
                self.assertError(self.call("POST", json={"title": "x", "log_sources": [text]}), 422, "log_sources")
        self.assertEqual(self.call("POST", json={"title": "x", "log_sources": ["Sysmon\n"]}).status_code, 201)

    def test_a_value_of_the_wrong_kind_is_refused(self):
        for body in ({"title": 3}, {"title": "x", "log_sources": "Sysmon"}, {"title": "x", "cve_ids": ["Log4Shell"]},
                     {"title": "x", "audience": ["Marketing"]}, {"title": "x", "priority": "Urgent"},
                     {"title": "x", "test_cases": ["Run wmic", 3]}, {"title": "x", "technique": "T1047"},
                     {"title": "x", "hypothesis": None}, {"title": "x", "tlp": "white"}, {"title": "x", "tlp": ""},
                     {"title": "x", "review_state": ""}, {"title": "x", "format": "snort"}):
            with self.subTest(body):
                self.assertEqual(self.call("POST", json=body).status_code, 422)
        misp_store.create_der.assert_not_called()

    def test_a_body_that_is_not_an_object_is_refused(self):
        self.assertError(self.call("POST", json=["title"]), 400)


class Updating(Api):
    def test_the_fields_it_leaves_out_keep_what_is_stored(self):
        reply = self.call("PATCH", f"/{UUID}", json={"priority": "Low"})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json()["priority"], "Low")
        data = self.written()
        self.assertEqual(data["priority"], "Low")
        self.assertEqual((data["title"], data["draft_rule"], data["format"], data["status"]),
                         ("Detect WMI lateral movement", "title: x", "sigma", misp_store.DER_STATUS_PENDING))

    def test_the_rule_its_format_and_the_status_stay_with_the_web_pages(self):
        for field in ("draft_rule", "format", "status"):
            with self.subTest(field):
                self.assertError(self.call("PATCH", f"/{UUID}", json={field: "x"}), 422, field)
        misp_store._write_der.assert_not_called()

    def test_sending_a_rejected_request_back_clears_its_reason(self):
        """As saving it on the edit page does: the detail page shows any reason it has."""
        self.stored[UUID].__dict__.update(review_state=misp_store.DER_REVIEW_REJECTED, rejection_reason="Too broad.")
        self.call("PATCH", f"/{UUID}", json={"review_state": misp_store.DER_REVIEW_PENDING})
        data = self.written()
        self.assertEqual((data["review_state"], data["rejection_reason"]), (misp_store.DER_REVIEW_PENDING, ""))

    def test_a_published_request_cannot_be_changed(self):
        self.stored[UUID].review_state = misp_store.DER_REVIEW_APPROVED
        for body in ({"priority": "Low"}, {}):
            with self.subTest(body):
                self.assertError(self.call("PATCH", f"/{UUID}", json=body), 409, "published")
        misp_store._write_der.assert_not_called()

    def test_an_active_request_cannot_lose_its_rule(self):
        """Active needs a rule that passed Rulezet, which only the detail page
        checks, so the API cannot set the rule, its format or the status."""
        der = self.stored[UUID]
        der.review_state, der.status = misp_store.DER_REVIEW_APPROVED, misp_store.DER_STATUS_ACTIVE
        for body in ({"draft_rule": ""}, {"format": ""}, {"status": misp_store.DER_STATUS_PENDING}):
            with self.subTest(body):
                self.assertError(self.call("PATCH", f"/{UUID}", json=body), 422, next(iter(body)))
        misp_store._write_der.assert_not_called()

    def test_a_request_cannot_be_made_active(self):
        self.assertError(self.call("POST", json={"title": "x", "format": "sigma", "draft_rule": "title: x",
                                                 "status": misp_store.DER_STATUS_ACTIVE}), 422, "status")
        self.assertError(self.call("PATCH", f"/{UUID}", json={"status": misp_store.DER_STATUS_ACTIVE}),
                         422, "status")

    def test_an_unknown_request_is_a_404(self):
        for body in ({"priority": "Low"}, {}):
            with self.subTest(body):
                self.assertError(self.call("PATCH", f"/{NEW_UUID}", json=body), 404, "No such")
        misp_store._write_der.assert_not_called()

    def test_only_a_uuid_names_a_request(self):
        """MISP would also take a numeric event id, but the API is described with the UUID."""
        for path in ("/nothing", "/10275", f"/{UUID[:-1]}"):
            with self.subTest(path):
                self.assertError(self.call("PATCH", path, json={"priority": "Low"}), 404)
                self.assertError(self.call("GET", path), 404)
        misp_store._zsazsa_event.assert_not_called()

    def test_a_uuid_in_capitals_is_the_same_request(self):
        self.assertEqual(self.call("GET", f"/{UUID.upper()}").get_json()["uuid"], UUID)
        self.assertEqual(self.call("PATCH", f"/{UUID.upper()}", json={}).get_json()["uuid"], UUID)

    def test_an_empty_change_writes_nothing(self):
        reply = self.call("PATCH", f"/{UUID}", json={})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.get_json()["priority"], "High")
        misp_store._write_der.assert_not_called()
        self.assertEqual(audit.get_logs(), [])

    def test_a_title_cannot_be_emptied(self):
        self.assertError(self.call("PATCH", f"/{UUID}", json={"title": "  "}), 422, "title")
        misp_store._write_der.assert_not_called()

    def test_priority_can_be_cleared_and_other_fields_emptied(self):
        reply = self.call("PATCH", f"/{UUID}", json={"priority": "", "hypothesis": "", "test_cases": []})
        self.assertEqual(reply.status_code, 200, reply.get_data(as_text=True))
        data = self.written()
        self.assertEqual((data["priority"], data["hypothesis"], data["test_cases"]), ("", "", []))

    def test_a_value_of_the_wrong_kind_is_refused(self):
        for body in ({"tlp": "white"}, {"review_state": misp_store.DER_REVIEW_APPROVED}, {"priority": None},
                     {"cve_ids": "CVE-2024-3400"}, {"audience": "SOC"}):
            with self.subTest(body):
                self.assertEqual(self.call("PATCH", f"/{UUID}", json=body).status_code, 422)
        misp_store._write_der.assert_not_called()

    def test_a_body_that_is_not_an_object_is_refused(self):
        for body in (None, "priority", ["priority"]):
            with self.subTest(body):
                self.assertError(self.call("PATCH", f"/{UUID}", json=body), 400)


class ThroughTheStore(Api):
    """A change made through the store itself, with only MISP standing in.

    The route used to read the request and the store to read it again before
    writing. A request deleted in between was a 502, and one reviewed in
    between had the review undone, so the store now reads it once, right before
    the write.
    """

    def setUp(self):
        super().setUp()
        patcher = mock.patch.multiple(misp_store, **STORE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.event = self.stored_event(misp_store.DER_REVIEW_DRAFT)

    def stored_event(self, review_state):
        event = MISPEvent()
        event.from_dict(uuid=UUID, id="42", info="[zsazsa:der] x", date="2026-11-12")
        stored = misp_store._der_obj({"der_id": "DER-00042", "title": "x", "priority": "High",
                                      "review_state": review_state})
        stored.id = 7
        event.Object.append(stored)
        return event

    def client_for(self, url, key, ssl, timeout):
        misp = super().client_for(url, key, ssl, timeout)
        if isinstance(self.event, list):
            misp.get_event.side_effect = self.event  # one read after the other
        else:
            misp.get_event.return_value = self.event
        return misp

    def callers_misp(self):
        return next(misp for key, misp in self.clients if key == "caller-key")

    def test_a_change_reads_the_request_once_before_writing_it(self):
        reply = self.call("PATCH", f"/{UUID}", json={"priority": "Low"})
        self.assertEqual(reply.status_code, 200, reply.get_data(as_text=True))
        misp = self.callers_misp()
        written = misp.update_object.call_args.args[0]
        self.assertEqual(misp_store._obj_attr(written, "priority"), "Low")
        self.assertEqual(misp_store._obj_attr(written, "title"), "x")
        # Once to change it, and once after, to write its report from what MISP stored.
        self.assertEqual(misp.get_event.call_count, 2)

    def test_a_request_that_is_gone_is_a_404(self):
        self.event = {"errors": (404, {"message": "Invalid event"})}
        self.assertError(self.call("PATCH", f"/{UUID}", json={"priority": "Low"}), 404)
        self.callers_misp().update_object.assert_not_called()

    def test_a_change_misp_cannot_read_back_is_a_502_that_says_so(self):
        """The report is written from that read, so it is out of date. A 500
        said nothing of what went wrong."""
        self.event = [self.event, {"errors": (404, {"message": "Invalid event"})}]
        self.assertError(self.call("PATCH", f"/{UUID}", json={"priority": "Low"}), 502, "read the changed DER back")

    def test_a_published_request_is_refused_and_left_as_it_is(self):
        self.event = self.stored_event(misp_store.DER_REVIEW_APPROVED)
        self.assertError(self.call("PATCH", f"/{UUID}", json={"priority": "Low"}), 409, "DER-00042 is published")
        misp = self.callers_misp()
        for write in (misp.add_object, misp.update_object, misp.update_event, misp.tag):
            write.assert_not_called()


class OneChangeAtATime(unittest.TestCase):
    """A request is read, changed and written back in several MISP calls. Ten
    changes at once on the live MISP left it with half its fields deleted and
    three reports, so a change waits for the one before it, from the API or
    from a page."""

    def test_a_change_waits_for_the_write_before_it(self):
        writing, release = threading.Event(), threading.Event()
        reads = []

        def write(event, data):
            writing.set()
            release.wait(5)
            return _der()

        with mock.patch.object(misp_store, "_zsazsa_event", side_effect=lambda uuid, *_: reads.append(uuid) or _der()), \
             mock.patch.object(misp_store, "_der_ns", side_effect=lambda der: der), \
             mock.patch.object(misp_store, "_write_der", side_effect=write):
            first = threading.Thread(target=misp_store.update_der, args=(UUID, {"title": "x"}))
            second = threading.Thread(target=misp_store.change_der, args=(UUID, {"priority": "Low"}))
            first.start()
            self.assertTrue(writing.wait(5))
            second.start()
            second.join(0.3)
            self.assertEqual(len(reads), 1, "the second change read the request while the first wrote it")
            release.set()
            first.join(5)
            second.join(5)
        self.assertEqual(len(reads), 2)


class Listing(Api):
    def setUp(self):
        super().setUp()
        for n in range(3, 6):
            self.stored[str(n) * 36] = _der(uuid=str(n) * 36, der_id=f"DER-0004{n}",
                                            review_state=misp_store.DER_REVIEW_PENDING, priority="Low",
                                            tlp="green", audience="SOC, Threat Hunting")

    def test_it_filters(self):
        listed = self.call("GET", query={"review_state": "pending-review", "priority": "Low"}).get_json()
        self.assertEqual(listed["total"], 3)
        self.assertEqual(self.call("GET", query={"priority": "Critical"}).get_json()["total"], 0)

    def test_it_filters_as_the_list_page_does(self):
        """On TLP and on one role of the audience as well, through the same filters."""
        self.assertEqual(self.call("GET", query={"tlp": "green"}).get_json()["total"], 3)
        self.assertEqual(self.call("GET", query={"audience": "Threat Hunting"}).get_json()["total"], 3)
        self.assertEqual(self.call("GET", query={"audience": "SOC", "tlp": "amber"}).get_json()["total"], 1)

    def test_it_pages(self):
        listed = self.call("GET", query={"page": 2, "limit": 3}).get_json()
        self.assertEqual((listed["page"], listed["limit"], listed["total"]), (2, 3, 4))
        self.assertEqual(len(listed["requests"]), 1)

    def test_it_returns_no_more_than_100_at_a_time(self):
        self.assertEqual(self.call("GET", query={"limit": 1000}).get_json()["limit"], 100)

    def test_a_page_or_limit_that_is_not_a_whole_number_of_1_or_more_is_refused(self):
        for query in ({"page": 0}, {"page": -1}, {"page": "two"}, {"limit": 0}, {"limit": "1.5"}):
            with self.subTest(query):
                self.assertError(self.call("GET", query=query), 422, next(iter(query)))

    def test_a_filter_it_cannot_match_is_refused_rather_than_answered_with_nothing(self):
        for query in ({"review_state": "pending"}, {"status": "active"}, {"priority": "Urgent"},
                      {"tlp": "white"}, {"audience": "Marketing"}):
            with self.subTest(query):
                self.assertError(self.call("GET", query=query), 422, next(iter(query)))

    def test_a_search_misp_failed_is_a_503_not_an_empty_list(self):
        misp_store.list_ders.side_effect = RuntimeError("MISP search page 1 failed")
        with self.assertLogs("webapp.routes.api_v1", "WARNING"):
            self.assertError(self.call("GET"), 503)


class ProductLists(Api):
    """The lists of alerts, advisories and briefings, read with any key."""

    def setUp(self):
        super().setUp()
        self.fias = [_fia(1, review_state="draft", tlp="amber", audience="SOC"),
                     _fia(2, review_state="approved", tlp="green", audience="SOC, CISO / Leadership"),
                     _fia(3, review_state="rejected", tlp="amber")]
        self.veas = [_vea(1, review_state="approved", observed_exploitation="Yes, in the wild", cvss="9.8"),
                     _vea(2, review_state="approved", cisa_kev="Yes"),
                     _vea(3, review_state="draft", exploit_availability="PoC public", audience="IT Security"),
                     _vea(4, review_state="draft")]
        self.briefings = [_briefing(1, tlp="amber", review_state="published", summary="Quiet day."),
                          _briefing(2, tlp="clear", review_state="published"),
                          _briefing(3, tlp="amber", review_state="draft")]
        for name, records in (("list_fias", self.fias), ("list_veas", self.veas), ("list_briefings", self.briefings)):
            patcher = mock.patch.object(misp_store, name, side_effect=lambda strict, records=records: list(records))
            patcher.start()
            self.addCleanup(patcher.stop)

    def listed(self, path, key="caller-key", **query):
        reply = self.client.get("/api/v1" + path, headers={"Authorization": key}, query_string=query)
        self.assertEqual(reply.status_code, 200, reply.get_data(as_text=True))
        return reply.get_json()

    def test_each_list_has_every_product_with_its_summary(self):
        alerts = self.listed("/flash-intel-alerts")
        self.assertEqual(alerts["total"], 3)
        self.assertEqual(alerts["alerts"][1]["audience"], ["SOC", "CISO / Leadership"])
        self.assertEqual(alerts["alerts"][1]["fia_id"], "FIA-00002")
        advisory = self.listed("/vulnerability-advisories")["advisories"][0]
        self.assertEqual((advisory["vea_id"], advisory["cve_id"], advisory["cvss"], advisory["exploitation"]),
                         ("VEA-00001", "CVE-2026-0001", "9.8", "Active"))
        briefing = self.listed("/daily-briefings")["briefings"][0]
        self.assertEqual((briefing["date"], briefing["summary"], briefing["created_at"][:10]),
                         ("2026-11-01", "Quiet day.", "2026-11-01"))

    def test_they_filter_as_their_pages(self):
        for path, query, expected in (
                ("/flash-intel-alerts", {"review_state": "approved"}, ["FIA-00002"]),
                ("/flash-intel-alerts", {"tlp": "amber", "audience": "SOC"}, ["FIA-00001"]),
                ("/vulnerability-advisories", {"exploitation": "KEV listed"}, ["VEA-00002"]),
                ("/vulnerability-advisories", {"exploitation": "Unknown", "review_state": "draft"}, ["VEA-00004"]),
                ("/vulnerability-advisories", {"audience": "IT Security"}, ["VEA-00003"]),
                ("/daily-briefings", {"tlp": "amber", "review_state": "published"}, ["2026-11-01"])):
            with self.subTest(path=path, query=query):
                body = self.listed(path, **query)
                key = next(k for k in body if k not in ("page", "limit", "total"))
                ids = [p.get("fia_id") or p.get("vea_id") or p["date"] for p in body[key]]
                self.assertEqual(ids, expected)

    def test_a_filter_it_does_not_have_or_cannot_match_is_refused(self):
        for path, query in (("/flash-intel-alerts", {"review_state": "pending"}),
                            ("/vulnerability-advisories", {"exploitation": "kev"}),
                            ("/daily-briefings", {"review_state": "pending-review"}),
                            ("/daily-briefings", {"tlp": "AMBER"})):
            with self.subTest(path=path, query=query):
                reply = self.client.get("/api/v1" + path, headers={"Authorization": "caller-key"}, query_string=query)
                self.assertError(reply, 422, next(iter(query)))

    def test_they_page(self):
        body = self.listed("/vulnerability-advisories", page=2, limit=3)
        self.assertEqual((body["total"], [a["vea_id"] for a in body["advisories"]]), (4, ["VEA-00004"]))

    def test_a_key_that_cannot_write_can_still_list(self):
        for path in ("/flash-intel-alerts", "/vulnerability-advisories", "/daily-briefings"):
            with self.subTest(path):
                self.assertGreater(self.listed(path, key="reader-key")["total"], 0)
        self.assertEqual(self.client.get("/api/v1/daily-briefings").status_code, 401)

    def test_a_search_misp_failed_is_a_503_not_an_empty_list(self):
        misp_store.list_fias.side_effect = RuntimeError("MISP search page 1 failed")
        with self.assertLogs("webapp.routes.api_v1", "WARNING"):
            reply = self.client.get("/api/v1/flash-intel-alerts", headers={"Authorization": "caller-key"})
        self.assertError(reply, 503, "alerts")


class ThePagesAndTheApiFilterAlike(Api):
    """A page and its list in the API filter through misp_store.product_filters(),
    so a filter added to a page and not to the API would work in one only."""

    def test_every_filter_of_a_page_is_in_its_api_list(self):
        pages = {"/products/detection-eng/": api_v1._DER_FILTERS, "/products/flash-intel/": api_v1._FIA_FILTERS,
                 "/products/vea/": api_v1._VEA_FILTERS, "/briefing/": api_v1._BRIEFING_FILTERS}
        with mock.patch.object(misp_store, "list_ders", return_value=[]), \
             mock.patch.object(misp_store, "list_fias", return_value=[]), \
             mock.patch.object(misp_store, "list_veas", return_value=[]), \
             mock.patch.object(misp_store, "list_briefings", return_value=[]), \
             mock.patch.object(job_store, "by_entity", return_value={}):
            for path, filters in pages.items():
                with self.subTest(path), \
                     mock.patch.object(misp_store, "product_filters", wraps=misp_store.product_filters) as used:
                    self.assertEqual(self.client.get(path).status_code, 200)
                    self.assertLessEqual(set(used.call_args.kwargs), set(filters))


class TheFooter(Api):
    """Links to the API's documentation while the API is on, and only then."""

    def test_it_links_to_the_api_only_while_it_is_on(self):
        docs = 'href="/api/v1/docs"'
        with mock.patch.object(misp_store, "list_ders", return_value=[]):
            self.assertIn(docs, self.client.get("/products/detection-eng/").get_data(as_text=True))
            with mock.patch.object(config, "API_ENABLED", False):
                self.assertNotIn(docs, self.client.get("/products/detection-eng/").get_data(as_text=True))

class TheDescription(unittest.TestCase):
    """openapi_v1.json is written by hand, so it is held to the code here."""

    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(api_v1._OPENAPI_FILE.read_text())
        cls.schemas = cls.spec["components"]["schemas"]

    def test_it_has_every_endpoint_and_no_other(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(config, create=True, DB_FILE=f"{tmp}/test.db", LOG_FILE=f"{tmp}/test.log"), \
             mock.patch.object(collection_cache, "start_worker"):
            app = create_app()
        served = {(str(rule).removeprefix("/api/v1").replace("<uuid:uuid>", "{uuid}"), method.lower())
                  for rule in app.url_map.iter_rules() if rule.endpoint.startswith("api_v1.")
                  and rule.endpoint not in ("api_v1.openapi", "api_v1.docs")
                  for method in rule.methods - {"HEAD", "OPTIONS"}}
        described = {(path, method) for path, item in self.spec["paths"].items()
                     for method in item if method != "parameters"}
        self.assertEqual(described, served)

    def test_it_has_the_fields_a_caller_sets(self):
        changes = self.schemas["RequestChanges"]["properties"]
        self.assertEqual(set(changes), set(api_v1._FIELDS))
        created = self.schemas["NewRequest"]["allOf"][1]["properties"]
        self.assertEqual(set(created), set(api_v1._CREATE_ONLY_FIELDS))

    def test_it_has_the_fields_a_request_is_returned_with(self):
        self.assertEqual(set(self.schemas["Request"]["properties"]), set(api_v1._der_json(_der())))

    def test_it_has_the_filters_of_each_list(self):
        for path, (_, filters, _, _) in LISTS.items():
            with self.subTest(path):
                parameters = self.spec["paths"][path]["get"]["parameters"]
                described = {p["name"]: p["schema"]["enum"] for p in parameters if p["name"] not in ("page", "limit")}
                self.assertEqual(described, {name: list(choices) for name, choices in filters.items()})

    def test_it_has_the_fields_a_list_returns(self):
        for path, (key, _, schema, record) in LISTS.items():
            with self.subTest(path):
                returned = self.spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
                listed = self.schemas[returned["schema"]["$ref"].rsplit("/", 1)[-1]]["properties"]
                self.assertEqual(set(listed), {key, "page", "limit", "total"})
                self.assertEqual(set(self.schemas[schema]["properties"]), set(record()))

    def test_its_choices_are_those_of_the_code(self):
        changes = self.schemas["RequestChanges"]["properties"]
        created = self.schemas["NewRequest"]["allOf"][1]["properties"]
        returned = self.schemas["Request"]["properties"]
        for described, choices in ((changes["priority"]["enum"], ["", *misp_store.DER_PRIORITIES]),
                                   (changes["tlp"]["enum"], misp_store.FIA_TLP_LEVELS),
                                   (changes["audience"]["items"]["enum"], misp_store.STAKEHOLDER_ROLES),
                                   (changes["review_state"]["enum"],
                                    [misp_store.DER_REVIEW_DRAFT, misp_store.DER_REVIEW_PENDING]),
                                   (created["format"]["enum"], ["", *misp_store.DER_FORMATS]),
                                   (returned["status"]["enum"], misp_store.DER_STATUSES),
                                   (returned["review_state"]["enum"], misp_store.DER_REVIEW_STATES)):
            with self.subTest(described):
                self.assertEqual(described, list(choices))


if __name__ == "__main__":
    unittest.main()
