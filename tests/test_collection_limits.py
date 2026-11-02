"""Searches capped by a limit, and what the pipeline page says about a source.

Asked for no order, MISP answers oldest first, so a refresh or a page cut off
by its limit dropped the newest events. Every limited search asks for
the newest first. A refresh records whether it filled its limit, from what MISP
sent rather than what the org filter kept; a server's own limit is the one
used, and each manual source is searched on its own tag. The source health
check asks a server only whether it answers, and takes the rest from the
cache: it runs on every load of the pipeline and statistics pages, and a
partner can hold tens of thousands of events.

MISP is an autospec of PyMISP; the databases are temporary.

    python -m unittest tests.test_collection_limits
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from pymisp import MISPEvent, MISPOrganisation, PyMISP

import config
from core import db as core_db
from webapp import collection_cache, create_app, misp_store
from webapp.routes import config_page, pipeline, products

PARTNER = {"id": "partner", "kind": "misp", "label": "Partner", "url": "https://partner.example.org",
           "api_key": "k", "verify_tls": True, "tags": [], "tags_and": [], "tags_not": [],
           "org_filter_type": "exclude", "org_filter": ["org-b"], "since_days": 7, "limit": 3}
MANUAL = {"id": "manual-newsletter", "kind": "manual", "label": "Newsletter", "url": "https://misp.example.org",
          "api_key": "k", "verify_tls": True, "source_tag": 'zsazsa:source="newsletter"'}


def _event(n, org="org-a"):
    event = MISPEvent()
    event.uuid = f"00000000-0000-4000-8000-{n:012d}"
    event.id = n
    event.info = f"Event {n}"
    event.date = f"2026-10-{n:02d}"
    event.Orgc = MISPOrganisation()
    event.Orgc.uuid = event.Orgc.name = org
    return event


class _TempCache(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(collection_cache, "_DB_FILE", str(Path(tmp.name) / "cache.db"))
        patcher.start()
        self.addCleanup(patcher.stop)
        collection_cache.init_db()

    def refresh(self, src, events):
        """Refresh ``src`` from a MISP that answers ``events``; returns that MISP."""
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.return_value = events
        with mock.patch.object(collection_cache, "PyMISP", return_value=misp):
            collection_cache.refresh_source(src)
        return misp

    def status(self, source_id):
        return collection_cache.get_source_status()[source_id]


class Refresh(_TempCache):
    def test_every_kind_of_source_is_read_newest_first(self):
        scraper = {"id": "scraper", "kind": "scraper"}
        with mock.patch.object(config, "MISP_SCRAPER_LIMIT", 3, create=True):
            for src in (scraper, PARTNER, MANUAL):
                misp = self.refresh(src, [])
                self.assertEqual(misp.search.call_args.kwargs["order"], misp_store.NEWEST_FIRST, src["id"])

    def test_a_full_answer_is_marked_even_when_the_org_filter_keeps_less(self):
        """Read from the cached rows, a full answer the org filter thinned out
        would look like a source with room to spare."""
        self.refresh(PARTNER, [_event(3), _event(2, org="org-b"), _event(1)])
        self.assertEqual(self.status("partner")["last_event_count"], 2)
        self.assertEqual(self.status("partner")["last_limit_reached"], 1)

    def test_an_answer_under_the_limit_is_not(self):
        self.refresh(PARTNER, [_event(2), _event(1)])
        self.assertEqual(self.status("partner")["last_limit_reached"], 0)

    def test_a_failed_refresh_says_nothing_about_the_limit(self):
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.search.side_effect = ConnectionError("timed out")
        with mock.patch.object(collection_cache, "PyMISP", return_value=misp), \
             self.assertLogs(collection_cache.logger, "WARNING"):
            collection_cache.refresh_source(PARTNER)
        self.assertIsNone(self.status("partner")["last_limit_reached"])

    def test_a_manual_source_is_searched_on_its_own_tag(self):
        """One search for every manual entry shared the limit between all manual
        sources, so a busy one pushed a quiet one out of the cache."""
        misp = self.refresh(MANUAL, [_event(1)])
        misp.build_complex_query.assert_called_once_with(
            and_parameters=[misp_store.TAG_MANUAL_ENTRY, MANUAL["source_tag"]])
        self.assertEqual(misp.search.call_args.kwargs["tags"], misp.build_complex_query.return_value)
        self.assertEqual(self.status("manual-newsletter")["last_event_count"], 1)

    def test_a_servers_own_limit_is_used(self):
        """The Max events of a server was saved but never reached the refresh,
        which read 500 whatever it said."""
        server = {"id": "partner", "url": "https://partner.example.org", "api_key": "k", "limit": 2000}
        with mock.patch.object(config, "MISP_SERVERS", [server]), \
             mock.patch.object(collection_cache, "scraper_enabled", return_value=False):
            src = collection_cache._build_sources(with_manual=False)[0]
        misp = self.refresh(src, [])
        self.assertEqual(misp.search.call_args.kwargs["limit"], 2000)

    def test_the_newest_event_is_the_latest_date_cached(self):
        self.refresh(PARTNER, [_event(9), _event(4)])
        self.assertEqual(self.status("partner")["newest_event"], "2026-10-09")


class SourceHealth(_TempCache):
    def health(self):
        server = mock.create_autospec(PyMISP, instance=True)
        with mock.patch("webapp.routes.data_collection._sources", return_value=[PARTNER]), \
             mock.patch.object(misp_store, "_test_connection", return_value={"ok": True, "version": "2.5"}), \
             mock.patch("pymisp.PyMISP", return_value=server):
            rows = pipeline._source_health()
        return rows[0], server

    def test_the_page_does_not_search_the_server(self):
        """Every load of the page searched every source twice, and the count it
        asked for was refused by PyMISP before it was sent."""
        _row, server = self.health()
        server.search.assert_not_called()

    def test_it_shows_what_the_last_refresh_read(self):
        self.refresh(PARTNER, [_event(12), _event(11), _event(10)])
        row, _server = self.health()
        self.assertTrue(row["ok"])
        self.assertEqual(row["newest_event"], "2026-10-12")
        self.assertTrue(row["limit_reached"])
        self.assertEqual(row["cached_events"], 3)

    def test_the_page_says_so(self):
        self.refresh(PARTNER, [_event(12), _event(11), _event(10)])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True), \
             mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True), \
             mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False), \
             mock.patch.object(config, "IMAP_SOURCES", [], create=True), \
             mock.patch.object(collection_cache, "start_worker"), \
             mock.patch("webapp.routes.data_collection._sources", return_value=[PARTNER]), \
             mock.patch.object(misp_store, "_test_connection", return_value={"ok": True}), \
             mock.patch.object(misp_store, "test_scraper_misp", return_value={"ok": True}), \
             mock.patch.object(misp_store, "test_webapp_misp", return_value={"ok": True}), \
             mock.patch.object(misp_store, "data_collection_source_counts", return_value=[]):
            core_db.init_db()
            page = create_app().test_client().get("/pipeline")
        text = BeautifulSoup(page.data, "html.parser").get_text(" ", strip=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Limit reached", text)
        self.assertIn("Newest event 2026-10-12", text)
        self.assertIn("Partner filled its limit on the last refresh", text)
        self.assertNotIn("on server", text)


class OtherLimitedSearches(unittest.TestCase):
    """The other searches a limit cuts short ask for the newest first too."""

    def setUp(self):
        self.misp = mock.create_autospec(PyMISP, instance=True)
        self.misp.search.return_value = []

    def order(self):
        return self.misp.search.call_args.kwargs.get("order")

    def test_all_products(self):
        with mock.patch.object(misp_store, "_misp", return_value=self.misp):
            products._list_product_events(None, None)
        self.assertEqual(self.order(), misp_store.NEWEST_FIRST)

    def test_the_pull_estimate_asks_as_the_refresh_does(self):
        """Its count of what a refresh would store came from the oldest events."""
        app = Flask(__name__)
        app.register_blueprint(config_page.bp)
        with mock.patch.object(config_page.misp_session, "refuse_unless_site_admin", return_value=None), \
             mock.patch("pymisp.PyMISP", return_value=self.misp):
            answer = app.test_client().post("/config/sources/pull-estimate", json={
                "misp_url": "https://partner.example.org", "misp_key": "k", "tags_not": "tlp:red"})
        self.assertEqual(answer.get_json(), {"count": 0, "error": None})
        self.assertEqual(self.order(), misp_store.NEWEST_FIRST)
        self.misp.build_complex_query.assert_called_once_with(
            or_parameters=None, and_parameters=None, not_parameters=["tlp:red"])


if __name__ == "__main__":
    unittest.main()
