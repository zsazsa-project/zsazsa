"""The Configuration page warns when MISP_WEBAPP_KEY may not do what zsazsa needs.

zsazsa stores and tags its records and publishes products with that key, so a
role without those permissions breaks them, and a read-only key breaks every
write. Site admin is not needed: the settings pages ask MISP for the role of
whoever is logged in. The warning names each missing permission, and stays
away when MISP cannot be asked.

    python -m unittest tests.test_webapp_key_permissions
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pymisp import PyMISP, PyMISPError

import config as _config
from webapp import collection_cache, create_app, misp_store
from webapp.routes import config_page

FULL_ROLE = {"name": "Publisher", "perm_add": True, "perm_modify": True, "perm_modify_org": True, "perm_tagger": True,
             "perm_tag_editor": True, "perm_publish": True, "perm_sync": True, "perm_sighting": True,
             "perm_galaxy_editor": True, "perm_analyst_data": True, "perm_site_admin": False}
# What getVersion reports for a request made with the key.
FULL_VERSION = {"version": "2.5.50", "perm_sync": True, "perm_sighting": True,
                "perm_galaxy_editor": True, "perm_analyst_data": True,
                "uuid": "d3d487f0-82ae-4a17-9165-c144c871c665"}


def _shortcomings(role=FULL_ROLE, version=FULL_VERSION, me=None):
    misp = mock.create_autospec(PyMISP, instance=True)
    misp.get_user.return_value = me if me is not None else {"User": {"id": "5"}, "Role": role}
    misp.misp_instance_version = version
    with mock.patch.object(misp_store, "PyMISP", return_value=misp):
        return misp_store.webapp_key_shortcomings()


class Shortcomings(unittest.TestCase):
    def test_a_role_with_what_zsazsa_uses_needs_no_site_admin(self):
        self.assertEqual(_shortcomings(), [])

    def test_each_missing_permission_is_named(self):
        role = {**FULL_ROLE, "perm_publish": False, "perm_sync": False}
        lines = _shortcomings(role, {**FULL_VERSION, "perm_sync": False, "uuid": "-"})
        self.assertEqual(lines, ["Without perm_publish, zsazsa cannot publish products in MISP.",
                                 "Without perm_sync, zsazsa cannot read the instance UUID that the "
                                 "session cookie name is made from."])

    def test_a_read_only_key_is_named_as_such(self):
        """Its user's role is stored with every permission; the key has none of them."""
        version = {**FULL_VERSION, "perm_sync": False, "perm_sighting": False,
                   "perm_galaxy_editor": False, "perm_analyst_data": False, "uuid": "-"}
        self.assertEqual(_shortcomings(version=version),
                         ["The key is read-only, so zsazsa cannot store or change anything in MISP."])

    def test_a_permission_an_older_misp_does_not_report_is_not_read_as_read_only(self):
        version = {k: v for k, v in FULL_VERSION.items() if k != "perm_analyst_data"}
        self.assertEqual(_shortcomings(version=version), [])

    def test_a_role_that_may_only_add_cannot_change_what_it_stored(self):
        role = {**FULL_ROLE, "perm_modify": False, "perm_modify_org": False}
        self.assertEqual([line.split(",")[0] for line in _shortcomings(role)],
                         ["Without perm_modify", "Without perm_modify_org"])

    def test_a_permission_stored_as_misp_writes_it_counts(self):
        """MISP can return a permission as 1 or "1" as well as true."""
        role = {perm: "1" if isinstance(value, bool) and value else value for perm, value in FULL_ROLE.items()}
        self.assertEqual(_shortcomings(role), [])

    def test_nothing_is_said_when_misp_cannot_be_asked(self):
        self.assertIsNone(_shortcomings(me={"errors": (403, "Authentication failed.")}))
        # PyMISP already reaches MISP when it is created, and fails there.
        with mock.patch.object(misp_store, "PyMISP", side_effect=PyMISPError("Unable to connect to MISP")), \
             self.assertLogs("webapp.misp_store", level="WARNING"):
            self.assertIsNone(misp_store.webapp_key_shortcomings())

    def test_misp_is_asked_with_a_short_timeout(self):
        """The settings page is where a wrong MISP address is put right; it should
        not wait the 30 seconds the rest of zsazsa gives MISP before it opens."""
        with mock.patch.object(misp_store, "PyMISP", side_effect=PyMISPError("timed out")) as client, \
             self.assertLogs("webapp.misp_store", level="WARNING"):
            misp_store.webapp_key_shortcomings()
        self.assertLessEqual(client.call_args.kwargs["timeout"], 5)


class Banner(unittest.TestCase):
    def page(self, shortcomings, url="https://misp.example.org"):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.multiple(_config, create=True, DB_FILE=str(Path(tmp) / "test.db"),
                                 LOG_FILE=str(Path(tmp) / "test.log"),
                                 MISP_SESSION_REDIRECT_TO_LOGIN=False, MISP_WEBAPP_URL=url,
                                 MISP_WEBAPP_KEY="webapp-key"), \
             mock.patch.object(config_page, "importlib"), \
             mock.patch.object(config_page, "_focus_point_choices", return_value=({}, {})), \
             mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
             mock.patch.object(misp_store, "webapp_key_shortcomings", return_value=shortcomings) as check, \
             mock.patch.object(collection_cache, "start_worker"):
            html = create_app().test_client().get("/config").get_data(as_text=True)
        return html, check

    def test_each_shortcoming_is_listed(self):
        html, _ = self.page(["Without perm_publish, zsazsa cannot publish products in MISP."])
        self.assertIn('id="key-shortcomings"', html)
        self.assertIn("<li>Without perm_publish, zsazsa cannot publish products in MISP.</li>", html)

    def test_no_banner_for_a_key_that_may_do_everything_or_when_misp_cannot_be_asked(self):
        for shortcomings in ([], None):
            with self.subTest(shortcomings=shortcomings):
                self.assertNotIn('id="key-shortcomings"', self.page(shortcomings)[0])

    def test_misp_is_not_asked_before_it_is_configured(self):
        _, check = self.page(["anything"], url="")
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
