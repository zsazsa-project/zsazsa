"""The misp-scraper is an optional source.

An installation that collects only from other MISP servers leaves MISP_URL and
MISP_KEY empty. Pins two things: a scraper that is absent or unreachable must
not take the other sources down with it (issue #29, where events from a second
MISP server could not be added to a daily briefing), and the source lists, the
generated config and the product source markers must all leave it out.

    python -m unittest tests.test_optional_scraper
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask, get_flashed_messages
from pymisp.exceptions import PyMISPError

from webapp import collection_cache, create_app, misp_store
from webapp.routes import collection_sources, config_page, daily_briefing, data_collection


def _event(uuid, info="A collected event"):
    return SimpleNamespace(uuid=uuid, id=7, info=info, date=None,
                           tags=[], attributes=[], objects=[], event_reports=[])


def _server(sid="community", url="https://community.example.org"):
    return {"id": sid, "label": sid, "url": url, "api_key": "k", "enabled": True}


def pin_config(test, **values):
    """Pin config values for the duration of one test.

    MISP_SCRAPER_ENABLED is pinned whether or not the test names it: these tests
    must not depend on whether the scraper happens to be switched on in the
    developer's own config/__init__.py, nor on whether that file carries the key
    at all. A config written by a zsazsa that predates the switch has no such
    attribute, which is what create=True is for.
    """
    values.setdefault("MISP_SCRAPER_ENABLED", True)
    for name, value in values.items():
        patcher = mock.patch.object(misp_store.config, name, value, create=True)
        patcher.start()
        test.addCleanup(patcher.stop)


class SourceClients(unittest.TestCase):
    """_all_source_clients() is what every source-event lookup goes through."""

    def setUp(self):
        # A webapp store distinct from the scraper, so its own client is built.
        pin_config(self, MISP_URL="https://scraper.example.org", MISP_KEY="sk",
                   MISP_WEBAPP_URL="https://webapp.example.org", MISP_WEBAPP_KEY="wk",
                   MISP_SERVERS=[_server()])

    def ids(self):
        return [sid for sid, _client, _label in misp_store._all_source_clients()]

    def test_an_unreachable_scraper_does_not_hide_the_other_servers(self):
        """PyMISP contacts the instance while constructing the client, so an
        unreachable scraper raised out of the whole function and every other
        source went with it."""
        with mock.patch.object(misp_store, "_scraper_misp",
                               side_effect=PyMISPError("connection refused")), \
             mock.patch("pymisp.PyMISP", return_value=mock.Mock()), \
             mock.patch.object(misp_store, "_misp", return_value=mock.Mock()):
            self.assertEqual(self.ids(), ["community", "webapp"])

    def test_an_unconfigured_scraper_is_left_out_without_being_contacted(self):
        with mock.patch.object(misp_store.config, "MISP_URL", ""), \
             mock.patch.object(misp_store.config, "MISP_KEY", ""), \
             mock.patch.object(misp_store, "_scraper_misp") as scraper, \
             mock.patch("pymisp.PyMISP", return_value=mock.Mock()), \
             mock.patch.object(misp_store, "_misp", return_value=mock.Mock()):
            self.assertEqual(self.ids(), ["community", "webapp"])
            scraper.assert_not_called()

    def test_a_configured_scraper_is_still_tried_first(self):
        with mock.patch.object(misp_store, "_scraper_misp", return_value=mock.Mock()), \
             mock.patch("pymisp.PyMISP", return_value=mock.Mock()), \
             mock.patch.object(misp_store, "_misp", return_value=mock.Mock()):
            self.assertEqual(self.ids(), ["scraper", "community", "webapp"])

    def test_asking_for_the_scraper_client_without_one_raises_a_misp_error(self):
        """PyMISP's own NoURL, so an unguarded caller still lands on the
        application's PyMISPError handler and its "unreachable" page."""
        with mock.patch.object(misp_store.config, "MISP_URL", ""), \
             mock.patch.object(misp_store.config, "MISP_KEY", ""):
            with self.assertRaises(PyMISPError):
                misp_store._scraper_misp()


class BriefingSeeding(unittest.TestCase):
    """Issue #29: selecting events from a second MISP server and adding them to
    a daily briefing."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"
        pin_config(self, MISP_URL="", MISP_KEY="",
                   MISP_WEBAPP_URL="https://webapp.example.org", MISP_WEBAPP_KEY="wk",
                   MISP_SERVERS=[_server()])

    def test_a_story_seeds_from_another_server_with_no_scraper(self):
        uuid = "11111111-2222-3333-4444-555555555555"
        client = mock.Mock(root_url="https://community.example.org")
        client.get_event.return_value = _event(uuid)
        client.get_event_reports.return_value = []

        with mock.patch("pymisp.PyMISP", return_value=client), \
             mock.patch.object(misp_store, "_misp", return_value=mock.Mock()), \
             self.app.test_request_context():
            stories = daily_briefing._seed_stories([f"{uuid}|community"])

        self.assertEqual(len(stories), 1)
        self.assertEqual(stories[0]["source_event_uuid"], uuid)
        self.assertEqual(stories[0]["source_id"], "community")
        # No article link on a third-party event, so the story points at the
        # event page on the server it came from.
        self.assertEqual(stories[0]["source_url"],
                         f"https://community.example.org/events/view/{uuid}")

    def test_an_event_that_cannot_be_read_is_reported_not_silently_dropped(self):
        uuid = "11111111-2222-3333-4444-555555555555"
        with mock.patch.object(misp_store, "resolve_source_event",
                               return_value=(None, None, "")), \
             self.app.test_request_context():
            stories = daily_briefing._seed_stories([f"{uuid}|community"])
            messages = get_flashed_messages()

        self.assertEqual(stories, [])
        self.assertTrue(any("Could not read 1 of the selected" in m for m in messages),
                        messages)


class ProductSourceMarkers(unittest.TestCase):
    """Only scraper events carry the zsazsa:product markers."""

    def setUp(self):
        pin_config(self, MISP_URL="https://scraper.example.org", MISP_KEY="sk")
        # The marker is mirrored into the cache; that is not what these pin.
        patcher = mock.patch.object(collection_cache, "patch_event_tags")
        patcher.start()
        self.addCleanup(patcher.stop)

    def tag_with(self, **kwargs):
        """Run the tagger against a stub scraper and return the client it used."""
        client = mock.Mock()
        client.get_event.return_value = _event("u1")
        with mock.patch.object(misp_store, "_scraper_misp", return_value=client):
            misp_store._tag_scraper_event_as_product_source("u1", "daily-briefing", **kwargs)
        return client

    def product_tags(self, client):
        return [call.args[1] for call in client.tag.call_args_list]

    def test_an_event_from_another_server_is_left_to_that_server(self):
        client = self.tag_with(source_id="community")
        client.get_event.assert_not_called()

    def test_a_scraper_event_is_marked(self):
        client = self.tag_with(source_id="scraper")
        self.assertIn('zsazsa:product="daily-briefing"', self.product_tags(client))

    def test_an_unrecorded_source_is_treated_as_the_scraper(self):
        """Products stored before the hint was recorded have no source to go on."""
        client = self.tag_with()
        self.assertIn('zsazsa:product="daily-briefing"', self.product_tags(client))

    def test_nothing_is_marked_when_there_is_no_scraper(self):
        with mock.patch.object(misp_store.config, "MISP_URL", ""), \
             mock.patch.object(misp_store.config, "MISP_KEY", ""), \
             mock.patch.object(misp_store, "_scraper_misp") as scraper:
            misp_store._tag_scraper_event_as_product_source("u1", "daily-briefing")
            scraper.assert_not_called()

    def test_a_manual_entry_is_marked_on_the_webapp_store(self):
        """Manual entries are on the webapp MISP, which zsazsa writes to, so
        they carry the marker like scraper events do."""
        webapp = mock.Mock()
        webapp.get_event.return_value = _event("u1")
        with mock.patch.object(misp_store, "_misp", return_value=webapp), \
             mock.patch.object(misp_store, "_scraper_misp") as scraper:
            misp_store._tag_scraper_event_as_product_source(
                "u1", "daily-briefing", source_id="manual-vendor-blog")
            scraper.assert_not_called()
        self.assertIn('zsazsa:product="daily-briefing"', self.product_tags(webapp))

    def test_an_event_found_on_the_webapp_store_is_marked_there(self):
        """resolve_source_event() labels anything it finds through the generic
        webapp client "webapp"; that store is ours to write to."""
        webapp = mock.Mock()
        webapp.get_event.return_value = _event("u1")
        with mock.patch.object(misp_store, "_misp", return_value=webapp), \
             mock.patch.object(misp_store, "_scraper_misp") as scraper:
            misp_store._tag_scraper_event_as_product_source(
                "u1", "daily-briefing", source_id="webapp")
            scraper.assert_not_called()
        self.assertIn('zsazsa:product="daily-briefing"', self.product_tags(webapp))

    def test_a_caller_passing_its_own_client_still_tags_a_remote_event(self):
        """Queuing an event for a landscape report tags it on the server it is
        on, which is the one case that writes a marker outside the scraper."""
        client = mock.Mock()
        client.get_event.return_value = _event("u1")
        misp_store._tag_scraper_event_as_product_source(
            "u1", "threat-landscape-report", misp_client=client)
        self.assertIn('zsazsa:product="threat-landscape-report"', self.product_tags(client))


class SourceLists(unittest.TestCase):
    def setUp(self):
        pin_config(self, MISP_URL="", MISP_KEY="", MISP_SERVERS=[_server()])
        patcher = mock.patch.object(misp_store, "list_collection_sources", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_collection_page_does_not_offer_a_scraper_it_has_not_got(self):
        self.assertEqual([s["id"] for s in data_collection._sources()], ["community"])

    def test_the_cache_does_not_refresh_a_scraper_it_has_not_got(self):
        self.assertEqual([s["id"] for s in collection_cache._build_sources()], ["community"])

    def test_a_pull_from_the_scraper_is_refused_rather_than_attempted(self):
        self.assertIsNone(data_collection._resolve_pull_source("scraper"))

    def test_a_requirement_is_not_offered_a_scraper_it_has_not_got(self):
        """This list is what the PIR and GIR edit forms draw their checkboxes
        from; config.COLLECTION_SOURCES is written but never read."""
        with mock.patch.object(misp_store, "imap_source_labels", return_value=[]):
            self.assertEqual(misp_store.get_all_collection_source_labels(), ["community"])

    def test_a_requirement_is_offered_the_scraper_once_it_is_configured(self):
        with mock.patch.object(misp_store.config, "MISP_URL", "https://s.example.org"), \
             mock.patch.object(misp_store.config, "MISP_KEY", "sk"), \
             mock.patch.object(misp_store, "imap_source_labels", return_value=[]):
            self.assertEqual(misp_store.get_all_collection_source_labels(),
                             ["misp-scraper", "community"])


class ScraperCard(unittest.TestCase):
    """The Collection sources page renders the scraper's own settings."""

    def setUp(self):
        # This install may have single sign-on on, which would answer 302.
        patches = [
            mock.patch.object(misp_store.config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(misp_store, "list_collection_sources", return_value=[]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = create_app().test_client()

    def page(self, enabled=True, url="https://scraper.example.org", key="sk"):
        pin_config(self, MISP_SCRAPER_ENABLED=enabled, MISP_URL=url, MISP_KEY=key)
        return self.client.get("/config/sources/").get_data(as_text=True)

    def card(self, **kwargs):
        """The scraper card alone, so a badge further down cannot match."""
        body = self.page(**kwargs)
        return body[:body.index("Manual sources pushing to scraper")]

    def test_a_working_scraper_reads_as_enabled(self):
        """The badge needs scraper_enabled passed into the template. Without it
        the variable is undefined, and a perfectly good scraper reads as "Not
        configured" while its own connection test succeeds."""
        card = self.card()
        self.assertIn("Enabled</span>", card)
        self.assertNotIn("Not configured", card)

    def test_the_queue_card_says_nothing_while_the_scraper_works(self):
        self.assertNotIn("nothing on the other end of the channel", self.page())

    def test_the_queue_card_is_marked_disabled_without_a_scraper(self):
        self.assertIn("nothing on the other end of the channel", self.page(enabled=False))

    def test_the_enabled_switch_starts_on_when_the_scraper_is_on(self):
        """The switch reads cfg.MISP_SCRAPER_ENABLED. Left out of that dict it
        is never checked, and saving the card would switch the scraper off."""
        self.assertIn('id="scraper-enabled-switch" checked', self.card(enabled=True))

    def test_the_enabled_switch_starts_off_when_the_scraper_is_off(self):
        self.assertNotIn('id="scraper-enabled-switch" checked', self.card(enabled=False))

    def test_switched_off_reads_as_disabled_not_unconfigured(self):
        self.assertIn("Disabled", self.card(enabled=False))

    def test_blank_credentials_read_as_unconfigured(self):
        self.assertIn("Not configured", self.card(url="", key=""))


class CachedScraperEvents(unittest.TestCase):
    """Rows for a source that is gone are never refreshed again, so the sweep
    drops them rather than leaving them to reappear."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        patcher = mock.patch.object(collection_cache, "_DB_FILE", tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        collection_cache.init_db()

        with collection_cache._db() as conn:
            conn.execute(
                "INSERT INTO events (source_id, uuid, info, date, tags, galaxy_names)"
                " VALUES ('scraper', 'u1', 'old', '2026-01-01', '[]', '[]')")
            conn.execute(
                "INSERT INTO events (source_id, uuid, info, date, tags, galaxy_names)"
                " VALUES ('community', 'u2', 'kept', '2026-01-01', '[]', '[]')")
            conn.execute(
                "INSERT INTO source_status (source_id, error) VALUES ('scraper', 'boom')")

    def remaining(self):
        return sorted(r["source_id"] for r in collection_cache.get_events(
            ["scraper", "community"], [], 100))

    def test_forget_source_drops_the_events_and_the_status_row(self):
        collection_cache.forget_source("scraper")
        self.assertEqual(self.remaining(), ["community"])
        self.assertNotIn("scraper", collection_cache.get_source_status())

    def test_the_sweep_drops_them_once_the_scraper_is_unconfigured(self):
        with mock.patch.object(collection_cache, "_build_sources", return_value=[]), \
             mock.patch.object(collection_cache.config, "MISP_URL", ""), \
             mock.patch.object(collection_cache.config, "MISP_KEY", ""):
            collection_cache._sweep()
        self.assertEqual(self.remaining(), ["community"])

    def test_the_sweep_keeps_them_while_the_scraper_is_configured(self):
        pin_config(self, MISP_URL="https://s.example.org", MISP_KEY="sk")
        with mock.patch.object(collection_cache, "_build_sources", return_value=[]):
            collection_cache._sweep()
        self.assertEqual(self.remaining(), ["community", "scraper"])


class ScopePreviewSources(unittest.TestCase):
    """The PIR/GIR scope preview searches every configured collection source."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        for patcher in (mock.patch.object(collection_cache, "_DB_FILE", tmp.name),
                        mock.patch.object(misp_store, "list_collection_sources", return_value=[])):
            patcher.start()
            self.addCleanup(patcher.stop)
        pin_config(self, MISP_URL="https://scraper.example.org", MISP_KEY="sk",
                   MISP_SERVERS=[_server()])
        collection_cache.init_db()

    def cache(self, source_id, count=1, date="2026-09-01"):
        with collection_cache._db() as conn:
            for i in range(count):
                conn.execute(
                    "INSERT INTO events (source_id, uuid, info, date, tags, galaxy_names)"
                    " VALUES (?,?,?,?,'[]','[]')",
                    (source_id, f"{source_id}-{i}", f"{source_id} ransomware story", date))

    def matches(self, **kwargs):
        return sorted({r["info"] for r in
                       misp_store.preview_scope_matches(["ransomware"], **kwargs)})

    def test_events_from_another_server_are_matched_not_only_scraper_ones(self):
        """Without this the preview was empty for an installation that has no
        scraper, whatever its scope said."""
        self.cache("community")
        self.assertEqual(self.matches(), ["community ransomware story"])

    def test_every_configured_source_is_searched(self):
        self.cache("scraper")
        self.cache("community")
        self.assertEqual(self.matches(),
                         ["community ransomware story", "scraper ransomware story"])

    def test_a_busy_source_does_not_crowd_out_a_quiet_one(self):
        """get_events() caps with one SQL LIMIT, so a single combined query for
        all sources returns the busiest one's rows and nothing else. More
        scraper events than any combined cap, all of them newer."""
        self.cache("scraper", count=12, date="2026-09-10")
        self.cache("community", count=1, date="2026-01-01")
        self.assertEqual(self.matches(limit=5),
                         ["community ransomware story", "scraper ransomware story"])

    def test_a_source_removed_from_the_config_stops_being_searched(self):
        self.cache("scraper")
        self.cache("community")
        with mock.patch.object(misp_store.config, "MISP_SERVERS", []):
            self.assertEqual(self.matches(), ["scraper ransomware story"])

    def test_manual_sources_are_searched_without_naming_them_out_of_misp(self):
        """Listing manual sources pages through MISP, and this runs on every PIR
        detail page, so their ids come from the cache's own rows instead."""
        self.cache("manual-vendor-blog")
        with mock.patch.object(misp_store, "list_collection_sources") as listed:
            self.assertEqual(self.matches(), ["manual-vendor-blog ransomware story"])
            listed.assert_not_called()


class GeneratedConfig(unittest.TestCase):
    """COLLECTION_SOURCES is generated source code inside config/__init__.py.

    Nothing reads it back, the requirement forms use
    get_all_collection_source_labels(), but it is a documented setting and the
    file has to stay honest about what is configured."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.target = self.dir / "__init__.py"
        shutil.copy2("config/__init__.py", self.target)

        app = Flask(__name__)
        app.secret_key = "test"
        app.config["TESTING"] = True
        app.register_blueprint(config_page.bp)
        # The save redirects back to the sources page, so that endpoint has to exist.
        app.register_blueprint(collection_sources.bp)
        self.client = app.test_client()

        patches = [
            mock.patch.object(config_page, "_CONFIG_FILE", self.target),
            mock.patch.object(config_page, "_BACKUP_FILE", self.dir / "backup.py"),
            mock.patch.object(config_page, "importlib"),
            mock.patch.object(config_page.audit, "record"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def settings(self):
        namespace = {}
        exec(compile(self.target.read_text(), str(self.target), "exec"), namespace)
        return namespace

    def collection_sources(self):
        return self.settings()["COLLECTION_SOURCES"]

    def save_scraper(self, **fields):
        self.client.post("/config/sources/save-scraper",
                         data={"MISP_SCRAPER_ENABLED": "true", **fields})

    def test_clearing_the_scraper_drops_it_from_the_generated_config(self):
        self.save_scraper(MISP_URL="", MISP_KEY="")
        self.assertNotIn("misp-scraper", self.collection_sources())

    def test_switching_the_scraper_off_drops_it_but_keeps_the_credentials(self):
        self.save_scraper(MISP_SCRAPER_ENABLED="false",
                          MISP_URL="https://scraper.example.org", MISP_KEY="sk")
        saved = self.settings()
        self.assertNotIn("misp-scraper", saved["COLLECTION_SOURCES"])
        self.assertEqual(saved["MISP_URL"], "https://scraper.example.org")
        self.assertEqual(saved["MISP_KEY"], "sk")

    def test_a_configured_scraper_stays_in_the_generated_config(self):
        self.save_scraper(MISP_URL="https://scraper.example.org", MISP_KEY="sk")
        self.assertIn("misp-scraper", self.collection_sources())


if __name__ == "__main__":
    unittest.main()
