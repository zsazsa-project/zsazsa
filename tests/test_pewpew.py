"""The pew-pew map on Reporting: what it shows and what it sends out.

The collection cache keeps the indicators of the events it reads, those in
objects too, and replaces them with their events. Only addresses from
TLP:CLEAR and TLP:GREEN events are sent to ip.circl.lu, never one that is not
public, and a lookup that fails stops the round rather than storing nothing as
an answer. The page shows TLP:CLEAR unless another level is chosen, never
AMBER+STRICT or RED, leaves hashes out when asked, catches an indicator whose
event a PIR or GIR matches or an open RFI is linked to one of, defangs every
value, and says why an address has no place on the map.

No MISP and no network: requests and the store are patched, the databases are
temporary.

    python -m unittest tests.test_pewpew
"""

import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent, MISPObject

import config
from core import db as core_db
from core import ip_geolocation
from webapp import collection_cache, create_app, job_store, matching, misp_store, pewpew

TODAY = date.today().isoformat()
CIRCL_ANSWER = [{"country": {"iso_code": "NL"}, "ip": "8.8.8.8",
                 "country_info": {"Country": "Netherlands", "Latitude (average)": "52.5", "Longitude (average)": "5.75"}}]


def _event(attributes=(), objects=()):
    event = MISPEvent()
    event.from_dict(info="An event", date=TODAY, uuid="11111111-1111-4111-8111-111111111111", id="1")
    for type_, value in attributes:
        event.add_attribute(type_, value, timestamp=1763600000)
    for obj in objects:
        event.add_object(obj)
    return event


class _Cache(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db"))
        patcher.start()
        self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def add(self, uuid, tags, indicators, source_id="scraper", info="An event", day=TODAY):
        collection_cache.insert_event({
            "source_id": source_id, "uuid": uuid, "event_id": uuid, "info": info, "date": day, "tags": tags,
            "galaxy_names": [],
            "indicators": [{"uuid": f"{uuid}-{n}", "type": t, "value": v, "timestamp": 1000.0 + n}
                           for n, (t, v) in enumerate(indicators)],
        })

    def locate(self, ip, country="NL", name="Netherlands", lat=52.5, lon=5.75):
        with collection_cache._db() as conn:
            conn.execute("INSERT INTO ip_geo (ip, country, name, lat, lon, looked_up_at) VALUES (?, ?, ?, ?, ?, 0)",
                         (ip, country, name, lat, lon))


class Extraction(unittest.TestCase):
    def test_the_attributes_the_map_shows_are_kept_those_in_objects_too(self):
        obj = MISPObject("file", standalone=False)
        obj.add_attribute("sha256", value="a" * 64, timestamp=1763600000)
        event = _event([("ip-dst", "8.8.8.8"), ("text", "a note"), ("domain", "bad.example")], [obj])
        found = collection_cache._extract_indicators(event)
        self.assertEqual(sorted((i["type"], i["value"]) for i in found),
                         [("domain", "bad.example"), ("ip-dst", "8.8.8.8"), ("sha256", "a" * 64)])
        self.assertEqual({i["timestamp"] for i in found}, {1763600000.0})

    def test_an_attribute_whose_value_is_not_text_is_passed_over(self):
        """PyMISP reads the value of a datetime attribute as a datetime, and
        stripping it failed the refresh of the whole source."""
        event = _event([("datetime", "2026-11-20T10:00:00+00:00"), ("ip-dst", "8.8.8.8")])
        self.assertEqual([i["value"] for i in collection_cache._extract_indicators(event)], ["8.8.8.8"])

    def test_a_value_twice_is_kept_once(self):
        event = _event([("ip-dst", "8.8.8.8"), ("ip-dst", "8.8.8.8")])
        self.assertEqual(len(collection_cache._extract_indicators(event)), 1)

    def test_the_address_of_a_combined_attribute(self):
        self.assertEqual(collection_cache.indicator_ip("domain|ip", "bad.example|8.8.8.8"), "8.8.8.8")
        self.assertEqual(collection_cache.indicator_ip("ip-dst|port", "8.8.8.8|443"), "8.8.8.8")


class Storage(_Cache):
    def stored(self):
        with collection_cache._db() as conn:
            return sorted(r[0] for r in conn.execute("SELECT value FROM indicators"))

    def test_a_refresh_replaces_the_indicators_of_a_source(self):
        self.add("e1", ["tlp:clear"], [("ip-dst", "8.8.8.8")])
        row = {"source_id": "scraper", "uuid": "e1", "indicators": [
            {"uuid": "new", "type": "ip-dst", "value": "9.9.9.9", "timestamp": None}]}
        with collection_cache._db() as conn:
            collection_cache._replace_indicators(conn, "scraper", [row], since=9e12, now=9e12)
        self.assertEqual(self.stored(), ["9.9.9.9"])

    def test_a_source_that_is_forgotten_takes_its_indicators_along(self):
        self.add("e1", ["tlp:clear"], [("ip-dst", "8.8.8.8")])
        collection_cache.forget_source("scraper")
        self.assertEqual(self.stored(), [])

    def test_a_pulled_event_replaces_its_own_indicators_only(self):
        self.add("e1", ["tlp:clear"], [("ip-dst", "8.8.8.8")])
        self.add("e2", ["tlp:clear"], [("ip-dst", "1.1.1.1")])
        self.add("e1", ["tlp:clear"], [("ip-dst", "9.9.9.9")])
        self.assertEqual(self.stored(), ["1.1.1.1", "9.9.9.9"])


class Lookups(_Cache):
    def test_only_addresses_from_clear_and_green_events_are_sent(self):
        self.add("clear", ["tlp:clear"], [("ip-dst", "1.1.1.1")])
        self.add("green", ["tlp:green"], [("domain|ip", "bad.example|2.2.2.2")])
        self.add("amber", ["tlp:amber"], [("ip-dst", "3.3.3.3")])
        self.add("red", ["tlp:red"], [("ip-src", "4.4.4.4")])
        self.add("none", [], [("ip-dst", "5.5.5.5")])
        self.add("mixed", ["tlp:clear", "tlp:amber"], [("ip-dst", "6.6.6.6")])
        self.assertEqual(sorted(collection_cache.ips_to_locate()), ["1.1.1.1", "2.2.2.2"])

    def test_an_address_looked_up_before_is_not_asked_again(self):
        self.add("clear", ["tlp:clear"], [("ip-dst", "1.1.1.1"), ("ip-dst", "2.2.2.2")])
        self.locate("1.1.1.1")
        self.assertEqual(collection_cache.ips_to_locate(), ["2.2.2.2"])

    def test_a_failed_lookup_stops_the_round_and_stores_nothing(self):
        self.add("clear", ["tlp:clear"], [("ip-dst", "1.1.1.1"), ("ip-dst", "2.2.2.2")])
        with mock.patch.object(ip_geolocation, "lookup", return_value=None) as lookup:
            self.assertEqual(collection_cache.locate_ips(), 0)
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(collection_cache.ip_locations(["1.1.1.1", "2.2.2.2"]), {})

    def test_an_answer_is_stored(self):
        self.add("clear", ["tlp:clear"], [("ip-dst", "8.8.8.8")])
        response = mock.Mock(status_code=200)
        response.json.return_value = CIRCL_ANSWER
        with mock.patch("requests.Session.get", return_value=response):
            self.assertEqual(collection_cache.locate_ips(), 1)
        self.assertEqual(collection_cache.ip_locations(["8.8.8.8"])["8.8.8.8"]["country"], "NL")


class SweepLookups(unittest.TestCase):
    """The lookups run after the sweep has answered the job waiting on it: a
    Refresh click on Data collection waited for up to 200 of them."""

    def setUp(self):
        for patcher in (mock.patch.object(job_store, "_command", return_value=None),
                        mock.patch.object(collection_cache, "refresh_indicator_stats"),
                        mock.patch.object(collection_cache, "_build_sources", return_value=[{"id": "a", "label": "A"}]),
                        mock.patch.object(collection_cache, "refresh_source",
                                          return_value={"events": 1, "new": 0, "error": ""})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(job_store._memory.clear)
        self.job = job_store.create_job("collection-refresh", label="Refresh collection cache")
        collection_cache._pending_jobs.append(self.job["id"])
        self.addCleanup(collection_cache._pending_jobs.clear)

    def test_the_job_has_its_answer_before_the_lookups(self):
        status = []
        with mock.patch.object(collection_cache, "locate_ips",
                               side_effect=lambda: status.append(job_store.get_job(self.job["id"])["status"])):
            collection_cache._sweep()
        self.assertEqual(status, ["completed"])

    def test_lookups_that_fail_do_not_fail_the_job(self):
        with mock.patch.object(collection_cache, "locate_ips", side_effect=RuntimeError("boom")), \
             self.assertLogs("webapp.collection_cache", "ERROR"):
            collection_cache._sweep()
        self.assertEqual(job_store.get_job(self.job["id"])["status"], "completed")


class CirclClient(unittest.TestCase):
    def test_an_address_that_is_not_public_is_never_sent(self):
        with mock.patch("requests.get") as get:
            for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "192.0.2.10", "not an ip"):
                self.assertEqual(ip_geolocation.lookup(ip), {})
        get.assert_not_called()

    def test_the_answer_is_read_and_the_request_has_a_timeout(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = CIRCL_ANSWER
        with mock.patch("requests.get", return_value=response) as get:
            self.assertEqual(ip_geolocation.lookup("8.8.8.8"),
                             {"country": "NL", "name": "Netherlands", "lat": 52.5, "lon": 5.75})
        self.assertEqual(get.call_args.args[0], "https://ip.circl.lu/geolookup/8.8.8.8")
        self.assertTrue(get.call_args.kwargs["timeout"])

    def test_an_unknown_country_is_an_empty_answer_and_an_error_is_none(self):
        unknown = mock.Mock(status_code=200)
        unknown.json.return_value = [{"country": {"iso_code": "None"}, "country_info": {}}]
        failing = mock.Mock(status_code=503)
        with mock.patch("requests.get", side_effect=[unknown, failing]), \
             self.assertLogs("core.ip_geolocation", "WARNING"):
            self.assertEqual(ip_geolocation.lookup("8.8.8.8"), {})
            self.assertIsNone(ip_geolocation.lookup("8.8.8.8"))


class MapData(_Cache):
    def setUp(self):
        super().setUp()
        self.pir = SimpleNamespace(uuid="pir-uuid", pir_id="PIR-00001", question="q", threat_actors=["Sandworm"])
        self.rfis = []
        for patcher in (
            mock.patch.object(matching, "get_requirements", return_value=([self.pir], [])),
            mock.patch.object(misp_store, "list_rfis", side_effect=lambda: self.rfis),
            mock.patch.object(config, "MISP_SERVERS", [{"id": "partner", "label": "Partner MISP", "url": "u", "api_key": "k"}]),
            mock.patch.object(collection_cache, "scraper_enabled", return_value=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def values(self, **kwargs):
        return sorted(i["value"] for i in pewpew.map_data(**kwargs)["indicators"])

    def test_clear_is_shown_unless_another_level_is_chosen(self):
        self.add("clear", ["tlp:clear"], [("md5", "clear")])
        self.add("green", ["tlp:green"], [("md5", "green")])
        self.assertEqual(self.values(), ["clear"])

    def test_hashes_can_be_left_out(self):
        self.add("e", ["tlp:clear"], [("md5", "m"), ("sha1", "s1"), ("sha256", "s2"), ("domain", "bad.example")])
        data = pewpew.map_data(exclude_hashes=True)
        self.assertEqual([i["value"] for i in data["indicators"]], ["bad[.]example"])
        self.assertEqual(data["totals"]["litter"], 1)

    def test_the_tlp_chosen_decides_and_amber_strict_and_red_never_show(self):
        for level in ("clear", "green", "amber", "amber+strict", "red"):
            self.add(level, [f"tlp:{level}"], [("md5", level)])
        self.assertEqual(self.values(tlp="green"), ["clear", "green"])
        self.assertEqual(self.values(tlp="amber"), ["amber", "clear", "green"])
        # A level the map does not offer falls back to the default.
        self.assertEqual(self.values(tlp="red"), ["clear"])

    def test_only_the_window_is_shown(self):
        self.add("new", ["tlp:clear"], [("md5", "new")])
        self.add("old", ["tlp:clear"], [("md5", "old")], day=(date.today() - timedelta(days=3)).isoformat())
        self.assertEqual(self.values(days=1), ["new"])
        self.assertEqual(self.values(days=7), ["new", "old"])

    def test_an_indicator_is_caught_by_a_matching_pir_and_an_open_rfi_linked_to_it(self):
        self.rfis = [SimpleNamespace(rfi_id="RFI-00002", status="In Progress", linked_pir_uuid="pir-uuid", linked_gir_uuid=""),
                     SimpleNamespace(rfi_id="RFI-00003", status="Closed", linked_pir_uuid="pir-uuid", linked_gir_uuid="")]
        self.add("hit", ["tlp:clear"], [("md5", "hit")], info="Sandworm infrastructure")
        self.add("miss", ["tlp:clear"], [("md5", "miss")], info="Something else")
        caught = {i["value"]: i["caught"] for i in pewpew.map_data()["indicators"]}
        self.assertEqual(caught, {"hit": ["PIR-00001", "RFI-00002"], "miss": []})

    def test_the_collection_means_of_each_source(self):
        self.add("a", ["tlp:clear"], [("md5", "scraped")])
        self.add("b", ["tlp:clear"], [("md5", "synced")], source_id="partner")
        self.add("c", ["tlp:clear", pewpew.NEWSLETTER_TAG], [("md5", "mailed")], source_id="manual-newsletter")
        self.add("d", ["tlp:clear"], [("md5", "typed")], source_id="manual-desk")
        data = pewpew.map_data()
        self.assertEqual({i["value"]: (i["means"], i["source"]) for i in data["indicators"]},
                         {"scraped": ("scraper", "MISP scraper"), "synced": ("misp", "Partner MISP"),
                          "mailed": ("newsletter", "newsletter"), "typed": ("manual", "desk")})
        self.assertEqual({m["id"]: m["count"] for m in data["means"]},
                         {"scraper": 1, "misp": 1, "newsletter": 1, "manual": 1})

    def test_the_counts_cover_more_than_the_replay(self):
        self.add("e", ["tlp:clear"], [("md5", f"h{n}") for n in range(5)])
        with mock.patch.object(pewpew, "_MAX_INDICATORS", 2):
            data = pewpew.map_data()
        self.assertEqual([i["value"] for i in data["indicators"]], ["h3", "h4"])
        self.assertEqual(data["totals"]["indicators"], 5)
        self.assertEqual({m["id"]: m["count"] for m in data["means"]}["scraper"], 5)

    def test_values_are_defanged(self):
        self.add("e", ["tlp:clear"], [("url", "https://bad.example/x"), ("ip-dst", "8.8.8.8")])
        self.assertEqual(self.values(), ["8[.]8[.]8[.]8", "hxxps://bad[.]example/x"])

    def test_a_located_address_flies_and_the_others_say_why_not(self):
        self.locate("8.8.8.8")
        self.locate("9.9.9.9", country="", name=None, lat=None, lon=None)
        self.add("clear", ["tlp:clear"], [("ip-dst", "8.8.8.8"), ("ip-dst", "9.9.9.9"), ("ip-dst", "1.1.1.1")])
        self.add("amber", ["tlp:amber"], [("ip-dst", "3.3.3.3")])
        data = pewpew.map_data(tlp="amber")
        by_value = {i["value"]: i for i in data["indicators"]}
        located = by_value["8[.]8[.]8[.]8"]
        self.assertEqual(located["country"], "NL")
        self.assertLess(abs(located["lat"] - 52.5), 2)
        self.assertEqual(by_value["9[.]9[.]9[.]9"]["why_not"], "no country known")
        self.assertEqual(by_value["1[.]1[.]1[.]1"]["why_not"], "not located yet")
        self.assertEqual(by_value["3[.]3[.]3[.]3"]["why_not"], "not sent to CIRCL at TLP:AMBER")
        self.assertEqual(data["totals"], {"indicators": 4, "caught": 0, "located": 1, "countries": 1, "litter": 3})


class Page(_Cache):
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(collection_cache, "scraper_enabled", return_value=True),
            mock.patch.object(matching, "get_requirements", return_value=([], [])),
            mock.patch.object(misp_store, "list_rfis", return_value=[]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        core_db.init_db()
        self.client = create_app().test_client()

    def test_the_page_and_its_data(self):
        self.add("e", ["tlp:clear"], [("md5", "abc")], info="<b>An event</b>")
        page = self.client.get("/stats/pewpew?days=30&tlp=amber")
        self.assertEqual(page.status_code, 200)
        soup = BeautifulSoup(page.data, "html.parser")
        self.assertIsNone(soup.find("b", string="An event"))
        self.assertIn("/stats/pewpew.json?days=30&tlp=amber", soup.find("canvas")["data-json-url"])
        self.assertEqual(soup.find("select", id="pew-tlp").find("option", selected=True)["value"], "amber")
        self.assertTrue(soup.find("a", href="/stats/pewpew"))
        reply = self.client.get("/stats/pewpew.json?days=30")
        self.assertEqual([i["value"] for i in reply.get_json()["indicators"]], ["abc"])

    def test_a_window_or_level_the_page_does_not_offer_falls_back_to_the_default(self):
        data = self.client.get("/stats/pewpew.json?days=999&tlp=red").get_json()
        self.assertEqual((data["days"], data["tlp"]), (pewpew.DEFAULT_WINDOW, "clear"))
        data = self.client.get("/stats/pewpew.json?days=abc").get_json()
        self.assertEqual(data["days"], pewpew.DEFAULT_WINDOW)

    def test_an_empty_window_says_so(self):
        text = BeautifulSoup(self.client.get("/stats/pewpew").data, "html.parser").get_text(" ", strip=True)
        self.assertIn("No indicators in this window up to TLP:CLEAR", text)

    def test_excluding_hashes_is_kept_when_the_page_reads_its_data_again(self):
        soup = BeautifulSoup(self.client.get("/stats/pewpew?exclude_hashes=1").data, "html.parser")
        self.assertTrue(soup.find("input", id="pew-hashes").has_attr("checked"))
        self.assertIn("exclude_hashes=1", soup.find("canvas")["data-json-url"])
        self.assertTrue(soup.find("button", id="pew-max"))


if __name__ == "__main__":
    unittest.main()
