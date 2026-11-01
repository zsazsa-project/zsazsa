"""Saving the configuration must only change what was actually submitted.

The page rewrites the whole config module from the posted form, so a field the
form did not carry, a page left open across an upgrade, a tab whose inputs never
rendered, would otherwise be written back as an empty string, an empty list or
False. That silently drops MISP keys, SMTP passwords and TLS switches.

An additional MISP server's organisation filter is also checked on save, because
the collection sources page shows it back, and a server entry is written back
with the keys it has, so one saved before a release added a key stays as it was.

    python -m unittest tests.test_config_form
"""

import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

import config as _config
from webapp.routes import config_page

_DERIVE_COOKIE_NAME = config_page.misp_session.derive_cookie_name


def _keyvals(path):
    namespace = {}
    exec(compile(Path(path).read_text(), str(path), "exec"), namespace)
    return {k: v for k, v in namespace.items() if k.isupper()}


class ConfigSave(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        self.client = app.test_client()

        patches = [
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
            mock.patch.object(config_page.misp_session, "derive_cookie_name", return_value=""),
            mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self):
        return _keyvals(self.target)

    def full_form(self):
        """Everything the rendered page posts, unchanged."""
        return {k: ("true" if v else "false") if isinstance(v, bool) else str(v)
                for k, v in config_page._read().items() if isinstance(v, (str, int, bool))}

    def test_an_empty_post_changes_nothing(self):
        before = self.saved()
        self.client.post("/config", data={})
        self.assertEqual(self.saved(), before)

    def test_a_post_missing_the_credentials_keeps_them(self):
        before = self.saved()
        form = self.full_form()
        for gone in ("MISP_WEBAPP_KEY", "SMTP_PASSWORD", "SMTP_USE_TLS", "SCRAPER_MARKER_TAG"):
            form.pop(gone, None)
        self.client.post("/config", data=form)

        after = self.saved()
        for kept in ("MISP_WEBAPP_KEY", "SMTP_PASSWORD", "SMTP_USE_TLS", "SCRAPER_MARKER_TAG"):
            self.assertEqual(after[kept], before[kept], kept)

    def test_the_scraper_queue_settings_survive_a_save(self):
        """They are edited under Collection sources, so this form has no inputs
        for them, and the file is rewritten whole on every save. Left out of the
        payload they fell back to the built-in defaults, quietly pointing the
        newsletter imports at a Redis nobody listens on.

        The values below are all deliberately unlike the defaults, so the check
        cannot pass just because the developer's own config matches them."""
        configured = {
            "SCRAPER_REDIS_HOST": "10.0.0.9",
            "SCRAPER_REDIS_PORT": 6380,
            "SCRAPER_REDIS_PASSWORD": "s3cret",
            "SCRAPER_REDIS_CHANNEL": "scraper-urls",
        }
        with mock.patch.multiple(_config, **configured):
            form = self.full_form()
            for key in configured:
                form.pop(key, None)
            self.client.post("/config", data=form)

        after = self.saved()
        for key, value in configured.items():
            self.assertEqual(after[key], value, key)

    def test_the_job_redis_settings_survive_a_save(self):
        configured = {
            "JOB_REDIS_HOST": "10.0.0.19",
            "JOB_REDIS_PORT": 6381,
            "JOB_REDIS_DB": 5,
            "JOB_REDIS_USERNAME": "jobs",
            "JOB_REDIS_PASSWORD": "s3cret-jobs",
            "JOB_REDIS_KEY": "zsazsa:jobs:test",
        }
        with mock.patch.multiple(_config, **configured):
            form = self.full_form()
            for key in configured:
                form.pop(key, None)
            self.client.post("/config", data=form)

        after = self.saved()
        for key, value in configured.items():
            self.assertEqual(after[key], value, key)

    def test_the_lists_survive_a_post_that_omits_them(self):
        before = self.saved()
        form = self.full_form()   # the list fields are textareas, never in full_form
        self.client.post("/config", data=form)

        after = self.saved()
        for kept in ("PRODUCT_TYPES", "FOCUS_POINTS_SECTORS", "THREAT_ACTOR_TYPES",
                     "RECOMMENDED_ACTIONS_IMMEDIATE"):
            self.assertEqual(after[kept], before[kept], kept)

    def test_an_unticked_switch_turns_its_setting_off(self):
        """A browser leaves an unticked box out of the form and sends only the
        hidden "false" behind it; ticked, it sends "true" first."""
        switches = ("SSL_ENABLED", "MISP_SESSION_REDIRECT_TO_LOGIN", "SMTP_USE_TLS")
        for value in (True, False):
            with self.subTest(ticked=value):
                form = self.full_form()
                for name in switches:
                    form[name] = ["true", "false"] if value else "false"
                self.client.post("/config", data=form)
                after = self.saved()
                for name in switches:
                    self.assertIs(after[name], value, name)

    def test_every_switch_on_the_page_is_followed_by_its_false(self):
        """Without it, a switch of the settings page can be turned on but never off.
        The setup wizard posts its switches to the same form handler."""
        for template, least in (("config_page.html", 3), ("setup_wizard.html", 1)):
            page = Path("webapp/templates", template).read_text()
            # A switch a macro writes has its name as {{ name }}: checked there, it
            # holds for every switch the macro writes.
            switches = re.findall(r'type="checkbox" name="([A-Z_]+|\{\{ \w+ \}\})"[^>]*\s+value="true"', page)
            self.assertGreaterEqual(len(switches), least, template)
            for name in switches:
                name = re.escape(name)
                self.assertRegex(page, rf'name="{name}"[^>]*value="true"[^>]*>\s*<input type="hidden" name="{name}" value="false">',
                                 f"{template}: {name}")

    def test_edits_and_deliberate_clearing_both_land(self):
        form = self.full_form()
        form["BRAND_COMPANY"] = "New Name"
        form["SMTP_USERNAME"] = ""
        form["SMTP_USE_TLS"] = "false"
        form["PRODUCT_TYPES"] = "Flash intel alert\nDaily threat briefing"
        self.client.post("/config", data=form)

        after = self.saved()
        self.assertEqual(after["BRAND_COMPANY"], "New Name")
        self.assertEqual(after["SMTP_USERNAME"], "")
        self.assertFalse(after["SMTP_USE_TLS"])
        self.assertEqual(after["PRODUCT_TYPES"], ["Flash intel alert", "Daily threat briefing"])

    def test_the_rulezet_url_is_saved_and_can_be_cleared(self):
        """Empty is meaningful here: it switches the Rulezet integration off."""
        form = self.full_form()
        form["RULEZET_URL"] = "https://rulezet.example"
        self.client.post("/config", data=form)
        self.assertEqual(self.saved()["RULEZET_URL"], "https://rulezet.example")

        form["RULEZET_URL"] = ""
        self.client.post("/config", data=form)
        self.assertEqual(self.saved()["RULEZET_URL"], "")

    def test_the_misp_url_is_saved_without_a_trailing_slash(self):
        """Links append "/events/view/..." to it and would show "//"."""
        form = self.full_form()
        form["MISP_WEBAPP_URL"] = "https://misp.example/"
        self.client.post("/config", data=form)
        self.assertEqual(self.saved()["MISP_WEBAPP_URL"], "https://misp.example")

    def test_a_key_without_sync_permission_keeps_the_session_cookie_name(self):
        """MISP tells such a key "-" for its instance UUID. A save with single
        sign-on on stored "MISP--", which no browser sends, so every request
        went to the MISP login and the settings could not be reached to undo it."""
        stored = "MISP-d3d487f0-82ae-4a17-9165-c144c871c665"
        form = self.full_form()
        form["MISP_SESSION_REDIRECT_TO_LOGIN"] = "true"
        with mock.patch.object(_config, "MISP_SESSION_COOKIE_NAME", stored, create=True), \
             mock.patch.object(config_page.misp_session, "derive_cookie_name", _DERIVE_COOKIE_NAME), \
             mock.patch("pymisp.PyMISP") as PyMISP, \
             self.assertLogs("webapp.misp_session", level="WARNING"):
            PyMISP.return_value.misp_instance_version = {"version": "2.5.50", "uuid": "-"}
            self.client.post("/config", data=form)
        self.assertEqual(self.saved()["MISP_SESSION_COOKIE_NAME"], stored)

    def test_every_key_survives_a_save(self):
        before = self.saved()
        self.client.post("/config", data=self.full_form())
        self.assertEqual(set(self.saved()), set(before))

    def save_server(self, org_filter):
        return self.client.post("/config/sources/save-server", json={
            "label": "Partner", "url": "https://misp.partner.example",
            "org_filter_type": "include", "org_filter": org_filter,
        })

    def test_a_server_org_filter_takes_organisation_uuids_only(self):
        """The page shows the filter back, so markup in it ran as script
        (GHSA-2hmh-2qrq-872r)."""
        before = self.saved()
        for org_filter in ("<img/src=x/onerror=alert(1)>",
                           "55f6ea5e-2c60-40e5-964f-47a8950d210f, not-a-uuid"):
            resp = self.save_server(org_filter)
            self.assertEqual(resp.status_code, 400, org_filter)
        self.assertEqual(self.saved(), before)

    def test_a_server_org_filter_keeps_its_uuids(self):
        org_filter = "55f6ea5e-2c60-40e5-964f-47a8950d210f, 55F6EA5E-2C60-40E5-964F-47A8950D2110"
        self.assertTrue(self.save_server(org_filter).get_json()["ok"])
        self.assertEqual(self.saved()["MISP_SERVERS"][-1]["org_filter"], org_filter)
        self.assertTrue(self.save_server("").get_json()["ok"])

    def test_an_audit_retention_of_0_is_kept(self):
        """0 keeps the audit log for good, which "or the default" would undo."""
        form = self.full_form()
        form["AUDIT_LOG_RETENTION_DAYS"] = "0"
        self.client.post("/config", data=form)
        self.assertEqual(self.saved()["AUDIT_LOG_RETENTION_DAYS"], 0)

    def test_a_server_may_allow_adding_reports(self):
        for sent, stored in ((True, True), (None, False)):
            with self.subTest(sent=sent):
                body = {"label": "Partner", "url": "https://misp.partner.example"}
                if sent is not None:
                    body["allow_reports"] = sent
                self.assertTrue(self.client.post("/config/sources/save-server", json=body).get_json()["ok"])
                self.assertIs(self.saved()["MISP_SERVERS"][-1]["allow_reports"], stored)

    def test_a_server_s_events_are_analysed_unless_switched_off(self):
        for sent, stored in ((False, False), (True, True), (None, True)):
            with self.subTest(sent=sent):
                body = {"label": "Partner", "url": "https://misp.partner.example"}
                if sent is not None:
                    body["analyse"] = sent
                self.assertTrue(self.client.post("/config/sources/save-server", json=body).get_json()["ok"])
                self.assertIs(self.saved()["MISP_SERVERS"][-1]["analyse"], stored)

    def test_a_server_saved_by_an_older_release_is_written_back_as_it_was(self):
        """It has no allow_reports, which was written back as None."""
        server = {"id": "partner", "label": "Partner", "url": "https://misp.partner.example",
                  "api_key": "k", "verify_tls": True, "enabled": True}
        with mock.patch.object(_config, "MISP_SERVERS", [server]):
            self.client.post("/config", data={})
        self.assertEqual(self.saved()["MISP_SERVERS"], [server])

    def save_smtp(self, **posted):
        stored = {"SMTP_HOST": "smtp.example.org", "SMTP_PASSWORD": "stored-password", "SMTP_FROM": "cti@example.org"}
        body = {"host": "smtp.example.org", "port": "587", "use_tls": True, "username": "cti",
                "password": "", "from": "cti@example.org", "sender_name": "CTI team", **posted}
        with mock.patch.multiple(_config, create=True, **stored):
            return self.client.post("/config/save-smtp", json=body)

    def test_the_smtp_server_is_saved_from_its_own_card(self):
        """The card had no button of its own, and a From typed into it was lost
        when the page was left without Save configuration."""
        before = self.saved()
        self.assertTrue(self.save_smtp(**{"from": "alerts@example.org"}).get_json()["ok"])
        after = self.saved()
        self.assertEqual((after["SMTP_FROM"], after["SMTP_SENDER_NAME"], after["SMTP_PASSWORD"]),
                         ("alerts@example.org", "CTI team", "stored-password"))
        self.assertEqual(after["MISP_WEBAPP_KEY"], before["MISP_WEBAPP_KEY"])

    def test_an_smtp_host_without_a_from_address_is_refused(self):
        before = self.saved()
        answer = self.save_smtp(**{"from": ""})
        self.assertEqual(answer.status_code, 400)
        self.assertIn("From address", answer.get_json()["error"])
        self.assertEqual(self.saved(), before)

    def test_the_smtp_password_follows_the_host(self):
        self.assertEqual(self.save_smtp(host="smtp.elsewhere.example").status_code, 400)
        self.save_smtp(remove_password=True)
        self.assertEqual(self.saved()["SMTP_PASSWORD"], "")


if __name__ == "__main__":
    unittest.main()
