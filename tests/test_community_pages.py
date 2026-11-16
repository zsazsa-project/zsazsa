"""The organisations and users pages.

The organisations page says, for each organisation, how many stakeholders and
zsazsa users belong to it, links to those stakeholders, and only offers Remove
for one nobody belongs to. Its banner counts the stakeholders without an
organisation. The users page groups the users by when they were last seen,
marks a user recorded under more than one address with the other ones, and
links to MISP only for a user with a MISP id.

MISP is patched; the database and log are temporary.

    python -m unittest tests.test_community_pages
"""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup

import config
from core.db import row_connection
from webapp import collection_cache, create_app, misp_store, org_store, sso_users
from webapp.routes import community

ORG = "5c1eb4f8-bae5-45f5-a772-06d4a3f64c3e"
MSSP = "bc081572-a389-49c7-bd2a-5e405834b181"
SPARE = "0d6b1f3e-2c4a-4e8b-9f7d-1a2b3c4d5e6f"


class Pages(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
        ):
            self.enterContext(patch)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, "html.parser")

    def seen(self, email, misp_id, last_seen, org_uuid=ORG, org="DEMO-CSIRT", role="User"):
        stamp = last_seen.strftime("%Y-%m-%dT%H:%M:%S")
        with row_connection() as db:
            db.execute("INSERT INTO sso_users (email, misp_user_id, organisation, organisation_uuid, role, first_seen, last_seen)"
                       " VALUES (?, ?, ?, ?, ?, ?, ?)", (email, misp_id, org, org_uuid, role, stamp, stamp))


class Organisations(Pages):
    ORGS = [SimpleNamespace(uuid=ORG, name="DEMO-CSIRT", sector="", country="Belgium", added_at=""),
            SimpleNamespace(uuid=MSSP, name="MSSP demo", sector="IT", country="Belgium", added_at=""),
            SimpleNamespace(uuid=SPARE, name="Spare org", sector="Energy", country="", added_at="")]
    STAKEHOLDERS = [SimpleNamespace(organization=ORG)] * 3 + [SimpleNamespace(organization=MSSP),
                                                              SimpleNamespace(organization="")]

    def organisations(self):
        self.seen("analyst@example.org", "199", datetime.now(timezone.utc))
        with mock.patch.object(org_store, "list_organisations", return_value=self.ORGS), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=self.STAKEHOLDERS):
            return self.page("/community/organisations")

    def row(self, page, uuid):
        return page.select_one(f"tr#org-{uuid}")

    def test_each_says_what_it_is_used_by(self):
        page = self.organisations()
        chips = [a.get_text(" ", strip=True) for a in self.row(page, ORG).select(".use-chip")]
        self.assertEqual(chips, ["3 stakeholders", "1 user"])
        self.assertEqual(self.row(page, ORG).select_one(".use-chip")["href"], f"/stakeholders/?organization={ORG}")
        self.assertEqual([a.get_text(" ", strip=True) for a in self.row(page, MSSP).select(".use-chip")], ["1 stakeholder"])
        self.assertIn("Not in use", self.row(page, SPARE).get_text())

    def test_only_one_nobody_belongs_to_can_be_removed(self):
        page = self.organisations()
        for uuid in (ORG, MSSP):
            self.assertIsNotNone(self.row(page, uuid).select_one("button.btn-outline-danger[disabled]"), uuid)
        form = self.row(page, SPARE).select_one("form[data-submit-confirm^='Remove organisation']")
        self.assertIsNotNone(form)
        self.assertEqual(form["action"], f"/community/organisations/{SPARE}/delete")

    def test_the_banner_counts_the_stakeholders_without_one(self):
        hero = self.organisations().select_one("section.record-hero")
        figures = [k.get_text(" ", strip=True) for k in hero.select(".record-kpi")]
        self.assertEqual(figures, ["3 organisations", "4 stakeholders in them", "1 zsazsa user in them", "1 country",
                                   "1 stakeholder without one"])
        self.assertIn("warn", hero.select(".record-kpi")[-1]["class"])
        self.assertIn("none 1", hero.select_one(".list-stats").get_text(" ", strip=True))
        sector = hero.select(".list-stats > div")[1].select_one(".chart-legend").get_text(" ", strip=True)
        self.assertEqual(sector, "Energy 1 IT 1 not set 1")

    def test_sync_all_still_asks_first(self):
        form = self.organisations().select_one("section.record-hero form")
        self.assertEqual(form["action"], "/community/organisations/sync-all")
        self.assertEqual(form["data-submit-confirm"], "Sync all local organisation details from MISP?")


class Users(Pages):
    NOW = datetime(2026, 11, 15, 23, 0, tzinfo=timezone.utc)

    def users(self):
        self.seen("admin@admin.test", "1", self.NOW - timedelta(minutes=20), role="admin")
        self.seen("analyst@example.org", "199", self.NOW - timedelta(days=3))
        self.seen("cti-lead@example.org", "1", self.NOW - timedelta(days=157), role="admin")
        self.seen("review@test", "", self.NOW - timedelta(days=103), org_uuid="", org="", role="")

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return Users.NOW

        with mock.patch.object(community, "datetime", Clock):
            return self.page("/community/users")

    def rows(self, page):
        return {tr.select_one(".name").get_text(strip=True): tr for tr in page.select("tbody tr:not(.lane-head)")}

    def test_users_are_grouped_by_when_they_were_last_seen(self):
        page = self.users()
        lanes = []
        for tr in page.select("tbody tr"):
            if "lane-head" in tr.get("class", []):
                lanes.append((tr.select_one(".lane-name").get_text(), []))
            else:
                lanes[-1][1].append(tr.select_one(".name").get_text(strip=True))
        self.assertEqual(lanes, [("Seen in the last 7 days", ["admin@admin.test", "analyst@example.org"]),
                                 ("Earlier", ["review@test", "cti-lead@example.org"])])

    def test_when_is_a_date_and_how_long_ago(self):
        last = self.rows(self.users())["analyst@example.org"].select(".seen")[1]
        self.assertEqual(last.get_text(" ", strip=True), "12-11-2026 23:00 3 days ago")

    def test_one_misp_user_under_two_addresses_is_marked(self):
        page = self.users()
        rows = self.rows(page)
        self.assertIn("Same MISP user as cti-lead@example.org", rows["admin@admin.test"].select_one(".dup-note").get_text())
        self.assertIn("Same MISP user as admin@admin.test", rows["cti-lead@example.org"].select_one(".dup-note").get_text())
        self.assertIsNone(rows["analyst@example.org"].select_one(".dup-note"))
        warn = page.select_one("section.record-hero .record-kpi.warn")
        self.assertEqual(warn.get_text(" ", strip=True), "1 possibly the same user twice")

    def test_misp_links_only_for_a_user_with_a_misp_id(self):
        rows = self.rows(self.users())
        self.assertEqual(rows["review@test"].select("a.btn"), [])
        self.assertIn("no MISP ID", rows["review@test"].get_text())
        self.assertTrue(rows["analyst@example.org"].select_one("a[title='View in MISP']")["href"].endswith("/admin/users/view/199"))

    def test_the_breakdowns_put_the_users_without_one_last(self):
        legends = [d.select_one(".chart-legend").get_text(" ", strip=True)
                   for d in self.users().select("section.record-hero .list-stats > div")]
        self.assertEqual(legends, ["admin 2 User 1 unknown 1", "DEMO-CSIRT 3 none 1"])

    def test_how_long_ago(self):
        now = self.NOW
        for days, said in ((0, "today"), (1, "yesterday"), (13, "13 days ago"), (14, "2 weeks ago"),
                           (59, "8 weeks ago"), (60, "2 months ago"), (400, "13 months ago")):
            with self.subTest(days=days):
                self.assertEqual(community._ago(now - timedelta(days=days), now), said)


class SameUserAs(Pages):
    def test_the_other_addresses_of_the_same_misp_id(self):
        now = datetime.now(timezone.utc)
        self.seen("a@example.org", "7", now)
        self.seen("b@example.org", "7", now)
        self.seen("c@example.org", "7", now)
        self.seen("d@example.org", "8", now)
        self.seen("e@example.org", "", now)
        self.seen("f@example.org", "", now)
        users = {u.email: u.same_user_as for u in sso_users.list_sso_users()}
        self.assertEqual(sorted(users["a@example.org"]), ["b@example.org", "c@example.org"])
        self.assertEqual(users["d@example.org"], [])
        # Without a MISP id, two addresses are not taken for the same user.
        self.assertEqual(users["e@example.org"], [])


if __name__ == "__main__":
    unittest.main()
