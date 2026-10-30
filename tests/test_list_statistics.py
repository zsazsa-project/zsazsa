"""The filter cards of the PIR, GIR, RFI, briefing and product lists, and what they leave out.

Each list counts what it shows beside its filters, and each field it filters on
by what the other filters let through, so that a bar still offers every choice;
a click on one filters the list and sets its dropdown. The RFI list leaves the
closed ones out until asked for them, or for their status, the PIR list the
rejected ones and the GIR list the retired ones, and the status board says how
many there are. An alert or advisory the analyser drafted says why under its
title.

Records come from the store's own builders, so they have every field the
templates read; the database and log are temporary.

    python -m unittest tests.test_list_statistics
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent

import config
from webapp import collection_cache, create_app, job_store, misp_store
from webapp.utils import ordered_counts


def _record(builder, reader, n, **fields):
    event = MISPEvent()
    event.uuid = f"00000000-0000-4000-8000-{n:012d}"
    event.id = n
    event.date = "2026-10-01"
    event.add_object(builder(fields))
    return reader(event)


def _pir(n, **fields):
    return _record(misp_store._pir_obj, misp_store._pir_ns, n, pir_id=f"PIR-00{n}", question=f"Question {n}", **fields)


def _gir(n, **fields):
    return _record(misp_store._gir_obj, misp_store._gir_ns, n, gir_id=f"GIR-00{n}", topic=f"Topic {n}", **fields)


def _rfi(n, status, **fields):
    fields.setdefault("priority", "Medium")
    return _record(misp_store._rfi_obj, misp_store._rfi_ns, n, rfi_id=f"RFI-00{n}", question=f"Question {n}",
                   status=status, **fields)


class OrderedCounts(unittest.TestCase):
    def test_the_order_first_then_the_rest_most_frequent_first(self):
        self.assertEqual(ordered_counts(["Low", "x", "High", "x", "y"], ["High", "Medium", "Low"]),
                         [("High", 1), ("Low", 1), ("x", 2), ("y", 1)])


class _Page(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
                        mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
                        mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
                        mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
                        mock.patch.object(collection_cache, "start_worker"),
                        mock.patch.object(misp_store, "list_stakeholders", return_value=[]),
                        # The PIR and GIR lists each read the other for their links.
                        mock.patch.object(misp_store, "list_pirs", return_value=[]),
                        mock.patch.object(misp_store, "list_girs", return_value=[])):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")

    def stats(self, page):
        return page.select_one(".list-stats").get_text(" ", strip=True)


class Lists(_Page):

    def test_pirs_by_status_priority_and_level(self):
        pirs = [_pir(1, status="Active", priority="Must have", intel_level=["Strategic", "Operational"]),
                _pir(2, status="Pending", intake_status="rejected", priority="Should have"),
                _pir(3, status="Pending", priority="Should have", intel_level=["Operational"])]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs):
            page = self.page("/pirs?rejected=1")
            strategic = self.page("/pirs?intel_level=Strategic")
        self.assertIn("Status Pending 1 Active 1 Rejected 1", self.stats(page))
        self.assertIn("Priority Must have 1 Should have 2", self.stats(page))
        self.assertIn("Intelligence level Strategic 1 Operational 2 Unspecified 1", self.stats(page))
        self.assertIn("3 PIRs", page.select_one(".list-filters").get_text(" ", strip=True))
        self.assertIn("Status Active 1", self.stats(strategic))

    def test_a_click_on_a_pir_bar_filters_by_priority_or_level(self):
        pirs = [_pir(1, status="Active", priority="Must have", intel_level=["Strategic"]),
                _pir(2, status="Active", priority="Should have", intel_level=["Operational"])]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs):
            page = self.page("/pirs?intel_level=Strategic")
            must = self.page("/pirs?priority=Must+have")
        self.assertEqual([a["href"] for a in page.select(".list-stats a.chart-filter")],
                         ["/pirs?intel_level=Strategic&priority=Must+have", "/pirs", "/pirs?intel_level=Operational"])
        self.assertIn("Intelligence level Strategic 1 Operational 1", self.stats(page))
        self.assertEqual([a.get_text() for a in must.select("tbody .req-id-badge")], ["PIR-001"])
        self.assertEqual(must.select_one('select[name="priority"] option[selected]')["value"], "Must have")

    def test_girs_by_status_level_and_review_cycle(self):
        girs = [_gir(1, status="Active", review_cycle="Weekly", intel_level=["Tactical"]),
                _gir(2, status="Retired", review_cycle="Quarterly")]
        with mock.patch.object(misp_store, "list_girs", return_value=girs):
            text = self.stats(self.page("/girs?retired=1"))
        self.assertIn("Status Active 1 Retired 1", text)
        self.assertIn("Intelligence level Tactical 1 Unspecified 1", text)
        self.assertIn("Review cycle Weekly 1 Quarterly 1", text)

    def test_a_click_on_a_gir_bar_filters_by_review_cycle(self):
        girs = [_gir(1, status="Active", review_cycle="Weekly"), _gir(2, status="Active", review_cycle="Quarterly")]
        with mock.patch.object(misp_store, "list_girs", return_value=girs):
            page = self.page("/girs")
            weekly = self.page("/girs?review_cycle=Weekly")
        self.assertIn("/girs?review_cycle=Weekly", [a["href"] for a in page.select(".list-stats a.chart-filter")])
        self.assertEqual([a.get_text() for a in weekly.select("tbody .req-id-badge")], ["GIR-001"])
        self.assertEqual(weekly.select_one('select[name="review_cycle"] option[selected]')["value"], "Weekly")
        self.assertIn("Review cycle Weekly 1 Quarterly 1", self.stats(weekly))

    def test_the_id_opens_the_requirement_like_its_title(self):
        with mock.patch.object(misp_store, "list_pirs", return_value=[_pir(1, status="Active")]), \
             mock.patch.object(misp_store, "list_girs", return_value=[_gir(1, status="Active")]):
            pages = {"PIR": self.page("/pirs"), "GIR": self.page("/girs")}
        for name, page in pages.items():
            with self.subTest(name):
                badge, title = page.select("tbody tr.req-row td")[:2]
                self.assertEqual(badge.a["href"], title.a["href"])

    def pirs(self, path):
        pirs = [_pir(1, status="Active"), _pir(2, status="Pending", intake_status="rejected"),
                _pir(3, status="Pending", intake_status="rejected")]
        with mock.patch.object(misp_store, "list_pirs", return_value=pirs):
            return self.page(path)

    def test_the_rejected_pirs_are_left_out_and_counted(self):
        page = self.pirs("/pirs")
        self.assertEqual([a.get_text() for a in page.select("tbody .req-id-badge")], ["PIR-001"])
        show = page.select_one(".list-filters a.btn")
        self.assertEqual((show.get_text(" ", strip=True), show["href"]), ("Show rejected PIRs (2)", "/pirs?rejected=1"))
        rejected = page.select(".kanban-col")[-1]
        self.assertEqual(rejected.select_one(".badge").get_text(strip=True), "2")
        self.assertEqual(rejected.select_one("a.kanban-closed")["href"], "/pirs?rejected=1")
        self.assertEqual(rejected.select(".kanban-card"), [])

    def test_the_rejected_pirs_are_shown_when_asked_for(self):
        page = self.pirs("/pirs?rejected=1")
        self.assertEqual(len(page.select("tbody .req-id-badge")), 3)
        self.assertEqual(len(page.select(".kanban-col")[-1].select(".kanban-card")), 2)
        self.assertEqual(page.select_one('.list-filters input[name="rejected"]')["value"], "1")
        self.assertIn("Hide rejected PIRs", page.select_one(".list-filters a.btn").get_text(" ", strip=True))

    def girs(self, path):
        girs = [_gir(1, status="Active"), _gir(2, status="Retired")]
        with mock.patch.object(misp_store, "list_girs", return_value=girs):
            return self.page(path)

    def test_the_retired_girs_are_left_out_and_counted(self):
        page = self.girs("/girs")
        self.assertEqual([a.get_text() for a in page.select("tbody .req-id-badge")], ["GIR-001"])
        show = page.select_one(".list-filters a.btn")
        self.assertEqual((show.get_text(" ", strip=True), show["href"]), ("Show retired GIRs (1)", "/girs?retired=1"))
        retired = page.select_one('.kanban-col[data-status="Retired"]')
        self.assertEqual(retired.select_one(".badge").get_text(strip=True), "1")
        self.assertEqual(retired.select_one("a.kanban-closed")["href"], "/girs?retired=1")
        self.assertEqual(retired.select(".kanban-card"), [])

    def test_the_retired_girs_are_shown_when_asked_for(self):
        page = self.girs("/girs?retired=1")
        self.assertEqual(len(page.select("tbody .req-id-badge")), 2)
        retired = page.select_one('.kanban-col[data-status="Retired"]')
        self.assertEqual(len(retired.select(".kanban-card")), 1)
        self.assertIsNone(retired.select_one("a.kanban-closed"))
        self.assertIn("Hide retired GIRs", page.select_one(".list-filters a.btn").get_text(" ", strip=True))

    def rfis(self, path):
        rfis = [_rfi(1, "Acknowledged"), _rfi(2, "Closed"), _rfi(3, "Closed")]
        with mock.patch.object(misp_store, "list_rfis", return_value=rfis):
            return self.page(path)

    def test_the_closed_rfis_are_left_out_and_counted(self):
        page = self.rfis("/rfis/")
        self.assertEqual([a.get_text() for a in page.select("tbody .req-id-badge")], ["RFI-001"])
        self.assertIn("1 RFI open", page.select_one(".list-filters").get_text(" ", strip=True))
        show = page.select_one(".list-filters a.btn")
        self.assertEqual((show.get_text(" ", strip=True), show["href"]), ("Show closed RFIs (2)", "/rfis/?closed=1"))
        closed = page.select_one('.kanban-col[data-status="Closed"]')
        self.assertEqual(closed.select_one(".badge").get_text(strip=True), "2")
        self.assertEqual(closed.select_one("a.kanban-closed")["href"], "/rfis/?closed=1")
        self.assertEqual(closed.select(".kanban-card"), [])
        self.assertIn("SLA No due date 1", self.stats(page))

    def test_they_are_shown_when_asked_for_or_filtered_on(self):
        for path in ("/rfis/?closed=1", "/rfis/?status=Closed"):
            with self.subTest(path):
                page = self.rfis(path)
                closed = page.select_one('.kanban-col[data-status="Closed"]')
                self.assertEqual(len(closed.select(".kanban-card")), 2)
                self.assertIsNone(closed.select_one("a.kanban-closed"))
        page = self.rfis("/rfis/?closed=1")
        self.assertEqual(page.select_one('.list-filters input[name="closed"]')["value"], "1")
        self.assertIn("Hide closed RFIs", page.select_one(".list-filters a.btn").get_text(" ", strip=True))
        self.assertIn("Status Acknowledged 1 Closed 2", self.stats(page))

    def test_rfis_by_priority_and_sla(self):
        rfis = [_rfi(1, "Acknowledged", priority="High", due_date="2026-01-01"),
                _rfi(2, "In Progress", priority="High"),
                _rfi(3, "Acknowledged", priority="Low", due_date="2026-01-01"),
                _rfi(4, "Closed", priority="High")]
        with mock.patch.object(misp_store, "list_rfis", return_value=rfis):
            page = self.page("/rfis/?priority=High")
            overdue = self.page("/rfis/?sla=Overdue&priority=High")
        self.assertEqual([a.get_text() for a in page.select("tbody .req-id-badge")], ["RFI-001", "RFI-002"])
        self.assertEqual(page.select_one('select[name="priority"] option[selected]')["value"], "High")
        self.assertIn("Priority High 2 Low 1", self.stats(page))
        self.assertIn("/rfis/?priority=High&sla=Overdue", [a["href"] for a in page.select(".list-stats a.chart-filter")])
        self.assertEqual([a.get_text() for a in overdue.select("tbody .req-id-badge")], ["RFI-001"])
        self.assertEqual(overdue.select_one('select[name="sla"] option[selected]')["value"], "Overdue")
        self.assertIn("SLA Overdue 1 No due date 1", self.stats(overdue))
        # The closed RFI that matches the priority is there to show, and showing it keeps the filter.
        self.assertEqual(page.select_one(".list-filters a.btn").get_text(" ", strip=True), "Show closed RFIs (1)")
        self.assertEqual(page.select_one(".list-filters a.btn")["href"], "/rfis/?priority=High&closed=1")


def _fia(n, state, **fields):
    return _record(misp_store._fia_obj, misp_store._fia_ns, n, fia_id=f"FIA-0000{n}", title=f"Alert {n}",
                   review_state=state, **fields)


def _vea(n, state, **fields):
    return _record(misp_store._vea_obj, misp_store._vea_ns, n, vea_id=f"VEA-0000{n}", title=f"Advisory {n}",
                   review_state=state, **fields)


def _feed(n, cache_interval, **fields):
    return _record(misp_store._indicator_feed_obj, misp_store._indicator_feed_ns, n, feed_id=f"FEED-00{n}",
                   name=f"Feed {n}", cache_interval=cache_interval, **fields)


class ProductLists(_Page):
    def test_a_click_on_the_state_filters_an_alert_list(self):
        fias = [_fia(1, "draft", tlp="amber", audience="SOC"), _fia(2, "approved", tlp="clear")]
        with mock.patch.object(misp_store, "list_fias", return_value=fias):
            page = self.page("/products/flash-intel/?state=approved")
        self.assertEqual([a.get_text() for a in page.select("tbody tr[id^=fia-row] .req-id-badge")], ["FIA-00002"])
        self.assertEqual(page.select_one('select[name="state"] option[selected]')["value"], "approved")
        self.assertIn("Review state draft 1 approved 1", self.stats(page))
        self.assertIn("TLP CLEAR 1", self.stats(page))
        self.assertEqual([a["href"] for a in page.select(".list-stats a.chart-filter")],
                         ["/products/flash-intel/?state=draft", "/products/flash-intel/",
                          "/products/flash-intel/?state=approved&tlp=CLEAR"])

    def test_every_product_list_filters_on_tlp_and_audience(self):
        """An audience is matched as recipients are, so an old spelling of a
        role still counts under the role."""
        def record(builder, reader, n, **fields):
            return _record(builder, reader, n, title=f"Record {n}", **fields)

        lists = {
            "/products/flash-intel/": ("list_fias", misp_store._fia_obj, misp_store._fia_ns),
            "/products/vea/": ("list_veas", misp_store._vea_obj, misp_store._vea_ns),
            "/products/threat-actor-profile/": ("list_threat_actor_profiles", misp_store._tap_obj, misp_store._tap_ns),
            "/products/indicator-feed/": ("list_indicator_feeds", misp_store._indicator_feed_obj,
                                          misp_store._indicator_feed_ns),
            "/products/detection-eng/": ("list_ders", misp_store._der_obj, misp_store._der_ns),
        }
        for path, (lister, builder, reader) in lists.items():
            with self.subTest(path):
                records = [record(builder, reader, 1, tlp="amber", audience="SOC, CISO"),
                           record(builder, reader, 2, tlp="amber+strict", audience="soc"),
                           record(builder, reader, 3, tlp="clear", audience="CISO")]
                with mock.patch.object(misp_store, lister, return_value=records):
                    page = self.page(path + "?tlp=AMBER&audience=SOC")
                    both = self.page(path + "?audience=SOC")
                table = str(page.select_one("tbody"))
                self.assertIn("000000000001", table)
                self.assertNotIn("000000000002", table)
                self.assertNotIn("000000000003", table)
                self.assertEqual(page.select_one('select[name="tlp"] option[selected]')["value"], "AMBER")
                self.assertEqual(page.select_one('select[name="audience"] option[selected]')["value"], "SOC")
                self.assertIn("TLP AMBER 1 AMBER+STRICT 1", self.stats(page))
                self.assertIn("SOC 1", self.stats(page))
                self.assertIn("SOC 2", self.stats(both))
                self.assertIn(path + "?tlp=AMBER%2BSTRICT&audience=SOC",
                              [a["href"] for a in page.select(".list-stats a.chart-filter")])

    def test_a_draft_says_why_the_analyser_made_it(self):
        """Under the title. Part of it is the model's own words, so it is escaped."""
        fias = [_fia(1, "draft", analyser_reason="Focus points: Palo Alto. <b>Unit 42</b> wrote it."), _fia(2, "draft")]
        veas = [_vea(1, "draft", analyser_reason="The event names CVE-2026-0257.")]
        with mock.patch.object(misp_store, "list_fias", return_value=fias), \
             mock.patch.object(misp_store, "list_veas", return_value=veas):
            alerts, advisories = self.page("/products/flash-intel/"), self.page("/products/vea/")
        reasons = [div.get_text() for div in alerts.select("tbody tr[id^=fia-row] td:nth-of-type(3) .text-muted")]
        self.assertEqual(reasons, ["Focus points: Palo Alto. <b>Unit 42</b> wrote it."])
        self.assertIn("The event names CVE-2026-0257.",
                      advisories.select_one("tbody tr[id^=vea-row] td:nth-of-type(4) .text-muted").get_text())

    def test_the_bars_stay_when_the_filters_leave_nothing(self):
        """The bars went with the last record, and with them the way back."""
        fias = [_fia(1, "draft", tlp="red", audience="CISO"), _fia(2, "draft", tlp="clear", audience="SOC")]
        with mock.patch.object(misp_store, "list_fias", return_value=fias):
            page = self.page("/products/flash-intel/?tlp=RED&audience=SOC")
        self.assertEqual(page.select("tbody tr[id^=fia-row]"), [])
        self.assertIn("No flash intel alerts match these filters.", page.get_text())
        self.assertEqual([a["href"] for a in page.select(".list-stats a.chart-filter")],
                         ["/products/flash-intel/?tlp=CLEAR&audience=SOC", "/products/flash-intel/?tlp=RED&audience=CISO"])

    def test_detection_requests_by_priority(self):
        ders = [_record(misp_store._der_obj, misp_store._der_ns, n, der_id=f"DER-0000{n}", title=f"Request {n}",
                        priority=priority) for n, priority in ((1, "Critical"), (2, "Low"))]
        with mock.patch.object(misp_store, "list_ders", return_value=ders):
            page = self.page("/products/detection-eng/?priority=Low")
        self.assertNotIn("DER-00001", str(page.select_one("tbody")))
        self.assertIn("DER-00002", str(page.select_one("tbody")))
        self.assertEqual(page.select_one('select[name="priority"] option[selected]')["value"], "Low")
        self.assertIn("Priority Critical 1 Low 1", self.stats(page))

    def test_advisories_by_exploitation(self):
        veas = [_vea(1, "approved", observed_exploitation="Yes, in the wild"),
                _vea(2, "approved", cisa_kev="Yes"),
                _vea(3, "draft", exploit_availability="PoC public"),
                _vea(4, "draft")]
        with mock.patch.object(misp_store, "list_veas", return_value=veas):
            page = self.page("/products/vea/")
            kev = self.page("/products/vea/?exploitation=KEV+listed&sort=title&dir=asc")
        self.assertIn("Exploitation Active 1 KEV listed 1 PoC public 1 Unknown 1", self.stats(page))
        self.assertEqual([td.get_text(" ", strip=True) for td in page.select("tbody tr[id^=vea-row] td:nth-of-type(6)")],
                         ["Active", "KEV listed", "PoC public", "Unknown"])
        self.assertEqual([a.get_text() for a in kev.select("tbody tr[id^=vea-row] .req-id-badge")], ["VEA-00002"])
        self.assertEqual(kev.select_one('select[name="exploitation"] option[selected]')["value"], "KEV listed")
        self.assertIn("Review state approved 1", self.stats(kev))
        # Sorting keeps the filter.
        self.assertIn("exploitation=KEV+listed", kev.select_one("thead th a")["href"])

    def test_profiles_and_detection_requests_by_state(self):
        taps = [_record(misp_store._tap_obj, misp_store._tap_ns, n, tap_id=f"TAP-0000{n}", title=f"Profile {n}",
                        status=status) for n, status in ((1, "Draft"), (2, "Published"))]
        ders = [_record(misp_store._der_obj, misp_store._der_ns, n, der_id=f"DER-0000{n}", title=f"Request {n}",
                        review_state=state, status="In Dev", priority="High")
                for n, state in ((1, "draft"), (2, "approved"))]
        with mock.patch.object(misp_store, "list_threat_actor_profiles", return_value=taps), \
             mock.patch.object(misp_store, "list_ders", return_value=ders):
            profiles = self.page("/products/threat-actor-profile/?state=Published")
            requests = self.page("/products/detection-eng/?state=draft")
        self.assertIn("State Draft 1 Published 1", self.stats(profiles))
        self.assertEqual(profiles.select_one('select[name="state"] option[selected]')["value"], "Published")
        self.assertIn("1 profile", profiles.select_one(".list-filters").get_text(" ", strip=True))
        self.assertIn("Review state draft 1 approved 1 Status In Dev 1 Priority High 1", self.stats(requests))
        self.assertEqual(requests.select_one('select[name="state"] option[selected]')["value"], "draft")

    def test_briefings_by_state_and_tlp(self):
        briefings = [_record(misp_store._briefing_obj, misp_store._briefing_ns, n, date=f"2026-10-0{n}",
                             title=f"Briefing {n}", tlp=tlp, review_state=state)
                     for n, tlp, state in ((1, "amber", "published"), (2, "clear", "published"), (3, "amber", "draft"))]
        with mock.patch.object(misp_store, "list_briefings", return_value=briefings), \
             mock.patch.object(job_store, "by_entity", return_value={}):
            page = self.page("/briefing/?tlp=AMBER&sort=title&dir=asc")
        self.assertEqual([td.get_text(strip=True) for td in page.select("tbody tr[id^=briefing-row] td:nth-of-type(2)")],
                         ["Briefing 1", "Briefing 3"])
        self.assertEqual(page.select_one('select[name="tlp"] option[selected]')["value"], "AMBER")
        self.assertIn("Review state draft 1 published 1 TLP CLEAR 1 AMBER 2", self.stats(page))
        self.assertIn("/briefing/?tlp=AMBER&sort=title&dir=asc&state=draft",
                      [a["href"] for a in page.select(".list-stats a.chart-filter")])

    def test_a_feed_shows_its_audience_under_its_name(self):
        """As the alert and detection request lists do, rather than in a column."""
        with mock.patch.object(misp_store, "list_indicator_feeds",
                               return_value=[_feed(1, "", audience="SOC, CISO"), _feed(2, "")]):
            page = self.page("/products/indicator-feed/")
        self.assertNotIn("Audience", [th.get_text(strip=True) for th in page.select("thead th")])
        rows = page.select("tbody tr")
        self.assertEqual([b.get_text() for b in rows[0].select("td:nth-of-type(2) .chip-source")], ["SOC", "CISO"])
        self.assertEqual(rows[1].select(".chip-source"), [])

    def test_feeds_by_caching(self):
        feeds = [_feed(1, ""), _feed(2, "daily"), _feed(3, "hourly")]
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=feeds):
            page = self.page("/products/indicator-feed/?caching=Daily")
        self.assertEqual([a.get_text() for a in page.select("tbody .req-id-badge")], ["FEED-002"])
        self.assertEqual(page.select_one('select[name="caching"] option[selected]')["value"], "Daily")
        self.assertIn("Caching Not cached 1 Hourly 1 Daily 1", self.stats(page))
        self.assertIn("/products/indicator-feed/?caching=Hourly",
                      [a["href"] for a in page.select(".list-stats a.chart-filter")])


if __name__ == "__main__":
    unittest.main()
