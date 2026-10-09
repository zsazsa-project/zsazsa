"""Caching a rendered indicator feed on disk.

A feed with an interval is run once and written in every format it is served
in, so a consumer polling its URL reads a file instead of sending zsazsa back
to MISP. What matters is when the query runs and when it does not.

    python -m unittest tests.test_feed_cache
"""

import os
import pathlib
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import feed_cache, misp_store
from webapp.routes import indicator_feed

_UUID = "u" * 36
def _row(value, **over):
    """A result row in the shape misp_store.search_indicators builds them, so a
    template rendered here meets the same fields it meets in the application."""
    row = {"server_id": "misp-one", "server_label": "One", "attribute_id": "7",
           "event_id": "42", "event_uuid": "e" * 36,
           "event_url": "https://misp.example/events/view/" + "e" * 36,
           "event_title": "Ransomware infrastructure", "creator_org": "CIRCL",
           "event_date": "2026-01-01", "attribute_timestamp": "2026-01-01 10:00",
           "_ts": 1767261600, "type": "ip-dst", "value": value,
           "to_ids": True, "tags": ["tlp:clear"]}
    row.update(over)
    return row


_ROWS = [_row("1.2.3.4")]


def _client():
    """A bare app with only this blueprint: create_app() would start the
    collection-cache worker and reach MISP."""
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(indicator_feed.bp)
    return app.test_client()


def _feed(interval="daily", saved="2026-09-04T14:16:00", **over):
    data = dict(uuid=_UUID, id=_UUID, feed_id="FEED-001", name="demo", description="",
                query={"types": ["ip-dst"], "limit": 100}, tlp="clear", audience="",
                author="", linked_pir_uuid="", creator="", token="t" * 22, public_url_enabled=True,
                cache_interval=interval, cache_anchor=saved)
    data.update(over)
    return SimpleNamespace(**data)


class CacheFiles(unittest.TestCase):
    """The store itself: what it hands back and when it refuses to."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "feed_cache"
        patcher = mock.patch.object(feed_cache, "_CACHE_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_nothing_is_served_before_anything_is_written(self):
        self.assertIsNone(feed_cache.read(_feed(), "txt"))
        self.assertIsNone(feed_cache.written_at(_feed()))

    def test_what_was_written_comes_back(self):
        feed_cache.write(_feed(), {"txt": "1.2.3.4", "json": "{}"})
        self.assertEqual(feed_cache.read(_feed(), "txt"), "1.2.3.4")
        self.assertEqual(feed_cache.read(_feed(), "json"), "{}")

    def test_a_feed_without_an_interval_is_never_written_or_served(self):
        feed_cache.write(_feed(interval=""), {"txt": "1.2.3.4"})
        self.assertFalse(self.dir.exists())
        self.assertIsNone(feed_cache.read(_feed(interval=""), "txt"))

    def test_an_unknown_interval_counts_as_off(self):
        self.assertEqual(feed_cache.interval(_feed(interval="fortnightly")), "")
        self.assertEqual(feed_cache.interval(_feed(interval="DAILY")), "daily")

    def _written_at(self, feed, when):
        feed_cache.write(feed, {"txt": "body"})
        os.utime(self.dir / f"{_UUID}.txt", (when.timestamp(), when.timestamp()))

    def test_an_entry_older_than_the_last_slot_is_not_served(self):
        feed = _feed("hourly")
        slot = feed_cache._slot_at_or_before(datetime.now(), feed)
        self._written_at(feed, slot - timedelta(seconds=1))
        self.assertIsNone(feed_cache.read(feed, "txt"))

    def test_an_entry_written_after_the_last_slot_is_served(self):
        feed = _feed("hourly")
        slot = feed_cache._slot_at_or_before(datetime.now(), feed)
        self._written_at(feed, slot + timedelta(seconds=1))
        self.assertEqual(feed_cache.read(feed, "txt"), "body")

    def test_clearing_drops_every_format(self):
        feed_cache.write(_feed(), {"txt": "a", "csv": "b", "json": "c"})
        feed_cache.clear(_UUID)
        self.assertEqual(list(self.dir.glob("*")), [])

    def test_a_cached_csv_keeps_its_line_endings(self):
        """csv.writer ends lines with CRLF; a cached pull has to be byte for byte
        what a live one returns."""
        body = misp_store.indicator_csv_text([{"type": "ip-dst", "value": "1.2.3.4"}])
        self.assertIn("\r\n", body)
        feed_cache.write(_feed(), {"csv": body})
        self.assertEqual(feed_cache.read(_feed(), "csv"), body)

    def test_the_age_is_the_moment_it_was_written(self):
        feed_cache.write(_feed(), {"txt": "a"})
        self.assertLess(time.time() - feed_cache.written_at(_feed()), 5)


class Schedule(unittest.TestCase):
    """A feed refreshes on the clock of the moment it was saved, so feeds saved
    at different times do not all come due together."""

    def test_hourly_runs_at_the_minute_it_was_saved(self):
        feed = _feed("hourly", saved="2026-09-04T14:16:00")
        self.assertEqual(feed_cache.schedule_text(feed), "every hour at :16")
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 4, 15, 3), feed),
                         datetime(2026, 9, 4, 14, 16))

    def test_hourly_before_the_minute_falls_back_an_hour(self):
        feed = _feed("hourly", saved="2026-09-04T14:16:00")
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 4, 15, 2), feed),
                         datetime(2026, 9, 4, 14, 16))
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 4, 14, 15), feed),
                         datetime(2026, 9, 4, 13, 16))

    def test_daily_runs_at_the_hour_and_minute_it_was_saved(self):
        feed = _feed("daily", saved="2026-09-04T14:16:00")
        self.assertEqual(feed_cache.schedule_text(feed), "every day at 14:16")
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 5, 9, 0), feed),
                         datetime(2026, 9, 4, 14, 16))
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 5, 20, 0), feed),
                         datetime(2026, 9, 5, 14, 16))

    def test_weekly_runs_on_the_weekday_it_was_saved(self):
        feed = _feed("weekly", saved="2026-09-03T09:05:00")   # a Thursday
        self.assertEqual(feed_cache.schedule_text(feed), "every Thursday at 09:05")
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 4, 15, 0), feed),
                         datetime(2026, 9, 3, 9, 5))
        # the moment before the slot belongs to the week before
        self.assertEqual(feed_cache._slot_at_or_before(datetime(2026, 9, 3, 9, 4), feed),
                         datetime(2026, 8, 27, 9, 5))

    def test_two_feeds_saved_minutes_apart_come_due_minutes_apart(self):
        early, late = _feed("hourly", saved="2026-09-04T14:05:00"), _feed("hourly", saved="2026-09-04T14:47:00")
        now = datetime(2026, 9, 4, 15, 30)
        self.assertEqual(feed_cache._slot_at_or_before(now, early), datetime(2026, 9, 4, 15, 5))
        self.assertEqual(feed_cache._slot_at_or_before(now, late), datetime(2026, 9, 4, 14, 47))

    def test_the_next_refresh_is_one_interval_after_the_last_slot(self):
        for every, gap in [("hourly", timedelta(hours=1)), ("daily", timedelta(days=1)),
                           ("weekly", timedelta(days=7))]:
            with self.subTest(every=every):
                feed = _feed(every)
                expected = feed_cache._slot_at_or_before(datetime.now(), feed) + gap
                self.assertEqual(feed_cache.next_refresh(feed), expected)
                self.assertGreater(feed_cache.next_refresh(feed), datetime.now())

    def test_a_feed_that_is_not_cached_has_no_schedule(self):
        feed = _feed(interval="")
        self.assertEqual(feed_cache.schedule_text(feed), "")
        self.assertIsNone(feed_cache.next_refresh(feed))

    def test_a_feed_saved_before_the_stamp_existed_still_schedules(self):
        """A feed from before the anchor field reads back empty, not missing:
        misp_store fills every field of the object. Those fall back to now."""
        feed = _feed(saved="")
        self.assertTrue(feed_cache.schedule_text(feed).startswith("every day at"))
        self.assertIsNotNone(feed_cache.next_refresh(feed))


class ServingAFeed(unittest.TestCase):
    """The routes: a cached feed reaches MISP once, an uncached one every time."""

    def setUp(self):
        self.client = _client()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name) / "feed_cache"),
            mock.patch.object(misp_store, "search_indicators", return_value=_ROWS),
            # The refresh files an audit entry; without this the suite writes
            # rows about made-up feeds into the log of whoever runs it.
            mock.patch.object(feed_cache.audit, "record"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.search = misp_store.search_indicators

    def _serve(self, feed, fmt="txt", query=""):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed):
            return self.client.get(f"/products/indicator-feed/{_UUID}/download.{fmt}{query}")

    def test_a_cached_feed_runs_the_query_once_for_every_format(self):
        feed = _feed()
        first = self._serve(feed, "txt")
        self.assertEqual(self.search.call_count, 1)
        self.assertEqual(first.data.decode(), "1.2.3.4")
        # the other formats were written at the same time, so none of them run it again
        for fmt in ("csv", "tsv", "json"):
            with self.subTest(fmt=fmt):
                self.assertEqual(self._serve(feed, fmt).status_code, 200)
        self.assertEqual(self.search.call_count, 1)

    def test_an_uncached_feed_runs_the_query_every_time(self):
        feed = _feed(interval="")
        for _ in range(3):
            self._serve(feed)
        self.assertEqual(self.search.call_count, 3)

    def test_truncate_off_always_runs_the_query_and_leaves_the_cache_alone(self):
        feed = _feed()
        self._serve(feed)                       # fills the cache
        self._serve(feed, query="?truncate=off")
        self.assertEqual(self.search.call_count, 2)
        self.assertEqual(self.search.call_args.kwargs["limit"], misp_store.MAX_SEARCH_LIMIT)
        self.assertEqual(feed_cache.read(feed, "txt"), "1.2.3.4")

    def test_a_failed_query_is_not_cached(self):
        """An outage would otherwise be served as an empty feed for a week."""
        feed = _feed("weekly")
        self.search.side_effect = RuntimeError("MISP down")
        self.assertEqual(self._serve(feed).data, b"")
        self.assertIsNone(feed_cache.read(feed, "txt"))

    def test_a_feed_that_matches_nothing_is_still_cached(self):
        """An empty result is an answer; only a failed query is not."""
        feed = _feed()
        self.search.return_value = []
        self.assertEqual(self._serve(feed).data, b"")
        self.assertEqual(feed_cache.read(feed, "txt"), "")
        self._serve(feed)
        self.assertEqual(self.search.call_count, 1)

    def test_the_public_url_is_served_from_the_same_cache(self):
        feed = _feed()
        self._serve(feed, "txt")
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=feed):
            r = self.client.get(f"/products/indicator-feed/public/{'t' * 22}")
        self.assertEqual(r.data.decode(), "1.2.3.4")
        self.assertEqual(self.search.call_count, 1)


class ScheduledRefresh(unittest.TestCase):
    """The analyser run re-runs feeds whose interval has passed, so the first
    consumer after that reads a file instead of paying for the query."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name) / "feed_cache"),
            mock.patch.object(misp_store, "search_indicators", return_value=_ROWS),
            # The refresh files an audit entry; without this the suite writes
            # rows about made-up feeds into the log of whoever runs it.
            mock.patch.object(feed_cache.audit, "record"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.search = misp_store.search_indicators

    def _refresh(self, feeds):
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=feeds):
            return feed_cache.refresh_due()

    def test_it_fills_a_cache_that_was_never_written(self):
        feed = _feed()
        self.assertEqual(self._refresh([feed]), 1)
        self.assertEqual(feed_cache.read(feed, "json")[:1], "{")

    def test_it_leaves_a_fresh_cache_alone(self):
        feed = _feed()
        self._refresh([feed])
        self.assertEqual(self._refresh([feed]), 0)
        self.assertEqual(self.search.call_count, 1)

    def test_it_re_runs_a_feed_whose_interval_has_passed(self):
        feed = _feed("hourly")
        self._refresh([feed])
        for path in feed_cache._files(_UUID):
            os.utime(path, (time.time() - 3601, time.time() - 3601))
        self.assertEqual(self._refresh([feed]), 1)
        self.assertEqual(self.search.call_count, 2)

    def test_it_ignores_feeds_that_are_not_cached(self):
        self.assertEqual(self._refresh([_feed(interval="")]), 0)
        self.search.assert_not_called()

    def test_a_feed_that_fails_keeps_the_copy_it_had(self):
        feed = _feed()
        self._refresh([feed])
        for path in feed_cache._files(_UUID):
            os.utime(path, (0, 0))
        self.search.side_effect = RuntimeError("MISP down")
        self.assertEqual(self._refresh([feed]), 0)
        # expired for reading, but still on disk rather than replaced by nothing
        self.assertTrue(list(feed_cache._files(_UUID)))

    def test_one_broken_feed_does_not_stop_the_others(self):
        good, bad = _feed(), _feed(uuid="v" * 36, feed_id="FEED-002")
        self.search.side_effect = [RuntimeError("MISP down"), _ROWS]
        self.assertEqual(self._refresh([bad, good]), 1)

    def test_a_feed_that_cannot_be_written_does_not_fail_the_analyser_run(self):
        """The refresh runs inside the analyser's try block, so anything it
        raises would mark the whole pipeline run as failed."""
        with mock.patch.object(feed_cache, "render_all", side_effect=RuntimeError("boom")):
            self.assertEqual(self._refresh([_feed()]), 0)

    def test_an_unreachable_misp_does_not_fail_the_analyser_run(self):
        with mock.patch.object(misp_store, "list_indicator_feeds", side_effect=RuntimeError("down")):
            self.assertEqual(feed_cache.refresh_due(), 0)


class SavingAFeed(unittest.TestCase):
    """The switch on the form has to reach the MISP object, and editing a feed
    has to drop what was cached for the previous query."""

    def setUp(self):
        self.client = _client()
        patches = [
            mock.patch.object(misp_store, "create_indicator_feed", return_value=_UUID),
            mock.patch.object(misp_store, "update_indicator_feed"),
            mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()),
            mock.patch.object(indicator_feed.audit, "record"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_saving_with_the_switch_on_stores_the_interval(self):
        self.client.post("/products/indicator-feed/save",
                         data={"name": "demo", "cache_enabled": "yes", "cache_interval": "weekly"})
        self.assertEqual(misp_store.create_indicator_feed.call_args[0][0]["cache_interval"], "weekly")

    def test_saving_with_the_switch_off_stores_nothing(self):
        self.client.post("/products/indicator-feed/save",
                         data={"name": "demo", "cache_interval": "weekly"})
        self.assertEqual(misp_store.create_indicator_feed.call_args[0][0]["cache_interval"], "")

    def test_editing_a_feed_drops_what_was_cached_for_the_old_query(self):
        with mock.patch.object(indicator_feed.feed_cache, "clear") as clear:
            self.client.post(f"/products/indicator-feed/{_UUID}/edit", data={"name": "demo"})
        clear.assert_called_once_with(_UUID)


class CacheForm(unittest.TestCase):
    def test_the_switch_decides_whether_an_interval_is_stored(self):
        self.assertEqual(indicator_feed._cache_fields({"cache_interval": "weekly"}),
                         {"cache_interval": "", "cache_anchor": ""})
        self.assertEqual(
            indicator_feed._cache_fields({"cache_enabled": "yes", "cache_interval": "weekly"})["cache_interval"],
            "weekly")

    def test_an_unknown_interval_falls_back_to_daily(self):
        for form in ({"cache_enabled": "yes", "cache_interval": "never"}, {"cache_enabled": "yes"}):
            self.assertEqual(indicator_feed._cache_fields(form)["cache_interval"], "daily")

    def test_saving_stamps_the_time_the_schedule_hangs_off(self):
        stamped = indicator_feed._cache_fields({"cache_enabled": "yes", "cache_interval": "hourly"})["cache_anchor"]
        saved = datetime.fromisoformat(stamped)
        self.assertLess(abs((datetime.now() - saved).total_seconds()), 120)
        self.assertEqual(saved.second, 0)


class RefreshFailures(unittest.TestCase):
    """A refresh that does not work has to leave a trace: the feed keeps serving
    what it has, and the list says that what it serves is older than promised."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name)),
                        mock.patch.object(feed_cache.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_nothing_is_noted_until_something_fails(self):
        self.assertIsNone(feed_cache.failure(_feed()))

    def test_a_failure_keeps_the_reason_and_the_moment(self):
        feed_cache.note_failure(_feed(), ConnectionError("MISP unreachable"))
        note = feed_cache.failure(_feed())
        self.assertIn("MISP unreachable", note["reason"])
        self.assertIsInstance(note["at"], datetime)

    def test_a_working_refresh_forgets_the_last_failure(self):
        feed = _feed()
        feed_cache.note_failure(feed, "down")
        feed_cache.clear_failure(feed)
        self.assertIsNone(feed_cache.failure(feed))

    def test_the_note_is_not_mistaken_for_a_cached_body(self):
        """written_at drives the age shown on the page; a failure note is not a
        refresh and must not make an empty cache look fresh."""
        feed = _feed()
        feed_cache.note_failure(feed, "down")
        self.assertIsNone(feed_cache.written_at(feed))
        self.assertIsNone(feed_cache.read(feed, "txt"))

    def test_the_scheduled_refresh_notes_a_failure_and_logs_it(self):
        feed = _feed()
        with mock.patch.object(feed_cache.misp_store, "list_indicator_feeds", return_value=[feed]), \
             mock.patch.object(feed_cache.misp_store, "search_indicators",
                               side_effect=ConnectionError("no server answered")), \
             mock.patch.object(feed_cache.audit, "record") as record:
            self.assertEqual(feed_cache.refresh_due(), 0)
        self.assertIn("no server answered", feed_cache.failure(feed)["reason"])
        self.assertEqual(record.call_args.args[0], "refresh-failed")
        self.assertEqual(record.call_args.kwargs["entity_label"], "FEED-001")

    def test_a_scheduled_refresh_that_works_is_logged_too(self):
        feed = _feed()
        feed_cache.note_failure(feed, "an older outage")
        with mock.patch.object(feed_cache.misp_store, "list_indicator_feeds", return_value=[feed]), \
             mock.patch.object(feed_cache.misp_store, "search_indicators",
                               return_value=[{"type": "ip-dst", "value": "1.2.3.4"}]), \
             mock.patch.object(feed_cache.audit, "record") as record:
            self.assertEqual(feed_cache.refresh_due(), 1)
        self.assertIsNone(feed_cache.failure(feed))
        self.assertEqual(record.call_args.args[0], "refresh")
        self.assertIn("1 indicators", record.call_args.kwargs["details"])
        self.assertEqual(record.call_args.kwargs["user"], "analyser")

    def test_a_log_that_cannot_be_written_does_not_stop_the_refresh(self):
        with mock.patch.object(feed_cache.misp_store, "list_indicator_feeds", return_value=[_feed()]), \
             mock.patch.object(feed_cache.misp_store, "search_indicators", return_value=[]), \
             mock.patch.object(feed_cache.audit, "record", side_effect=RuntimeError("no table")):
            self.assertEqual(feed_cache.refresh_due(), 1)


class Orphans(unittest.TestCase):
    """A feed deleted in zsazsa has its files cleared. One deleted straight in
    MISP does not, and its files would sit there for good."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name)),
                        mock.patch.object(feed_cache.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_analyser_drops_what_no_feed_owns(self):
        alive, gone = _feed(), _feed(uuid="g" * 36, feed_id="FEED-009")
        feed_cache.write(alive, {"txt": "1.2.3.4"})
        feed_cache.write(gone, {"txt": "5.6.7.8"})
        feed_cache.note_failure(gone, "an outage nobody will read about now")
        with mock.patch.object(feed_cache.misp_store, "list_indicator_feeds", return_value=[alive]), \
             mock.patch.object(feed_cache.misp_store, "search_indicators", return_value=[]):
            feed_cache.refresh_due()
        self.assertEqual(feed_cache.read(alive, "txt"), "1.2.3.4")
        self.assertEqual(feed_cache._files(gone.uuid), [])

    def test_it_leaves_everything_alone_when_the_feeds_cannot_be_listed(self):
        """An empty list because MISP is unreachable is not an empty list of
        feeds: wiping the cache on an outage is the opposite of the point."""
        feed = _feed()
        feed_cache.write(feed, {"txt": "1.2.3.4"})
        with mock.patch.object(feed_cache.misp_store, "list_indicator_feeds",
                               side_effect=RuntimeError("down")):
            feed_cache.refresh_due()
        self.assertEqual(feed_cache.read(feed, "txt"), "1.2.3.4")


class UnwritableCache(unittest.TestCase):
    """The disk is the one thing the cache depends on. When it refuses, the feed
    has to keep working and the analyst has to be able to see why it is live."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name)),
                        mock.patch.object(feed_cache.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_write_that_fails_takes_the_older_answer_with_it(self):
        """Half a set is worse than none: the formats would then answer for
        different queries and nothing downstream could tell."""
        feed = _feed()
        feed_cache.write(feed, {"txt": "an older answer"})
        with mock.patch.object(feed_cache, "write_atomically", side_effect=OSError("no space")):
            feed_cache.write(feed, {"txt": "1.2.3.4", "csv": "a,b"})
        self.assertIsNone(feed_cache.read(feed, "txt"))
        self.assertIsNone(feed_cache.written_at(feed))

    def test_the_note_survives_the_clearing_that_comes_with_it(self):
        """The formats cannot be written but the note can. It is written after
        the clearing, which would otherwise take it straight back out again."""
        feed = _feed()
        real = feed_cache.write_atomically

        def only_the_formats_fail(path, body):
            if path.suffix == ".error":
                return real(path, body)
            raise OSError("no space")

        with mock.patch.object(feed_cache, "write_atomically", side_effect=only_the_formats_fail):
            feed_cache.write(feed, {"txt": "1.2.3.4"})
        self.assertIn("no space", feed_cache.failure(feed)["reason"])
        self.assertIsNone(feed_cache.read(feed, "txt"))


class ServingDuringAnOutage(unittest.TestCase):
    """What a consumer polling a feed URL receives while MISP is unreachable.

    An empty feed and a feed that could not be read look identical to whatever
    is pulling it, and a tool acting on the first would drop every indicator it
    was given. A cached feed therefore keeps handing out its last copy.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for patcher in (mock.patch.object(feed_cache, "_CACHE_DIR", Path(tmp.name)),
                        mock.patch.object(feed_cache.audit, "record")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = _client()

    def _pull(self, feed, fmt="txt"):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed):
            return self.client.get(f"/products/indicator-feed/{feed.uuid}/download.{fmt}").data

    def test_the_last_copy_is_served_when_the_query_cannot_run(self):
        feed = _feed()
        with mock.patch.object(misp_store, "search_indicators", return_value=_ROWS):
            good = self._pull(feed)
        self.assertTrue(good)
        _age(feed)
        with mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")):
            self.assertEqual(self._pull(feed), good)
        self.assertIn("down", feed_cache.failure(feed)["reason"])

    def test_every_format_falls_back_to_its_own_copy(self):
        feed = _feed()
        with mock.patch.object(misp_store, "search_indicators", return_value=_ROWS):
            good = {fmt: self._pull(feed, fmt) for fmt in misp_store.INDICATOR_FORMATS}
        _age(feed)
        with mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")):
            for fmt in misp_store.INDICATOR_FORMATS:
                self.assertEqual(self._pull(feed, fmt), good[fmt], fmt)

    def test_a_feed_that_was_never_cached_has_nothing_to_fall_back_on(self):
        feed = _feed()
        with mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")):
            self.assertEqual(self._pull(feed), b"")

    def test_an_uncached_feed_is_not_given_someone_elses_copy(self):
        """last_copy only answers for a feed that asked to be cached."""
        feed = _feed(interval="")
        self.assertIsNone(feed_cache.last_copy(feed, "txt"))


def _age(feed, days=7):
    """Push the cached files back in time, as they are between two refreshes."""
    old = time.time() - days * 24 * 3600
    for path in feed_cache._files(feed.uuid):
        os.utime(path, (old, old))


class FeedIdsFromUrls(unittest.TestCase):
    """clear() is called with the id out of a delete request, so the id decides
    a filename. It has to stay a filename."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        cache = self.tmp / "feed_cache"
        cache.mkdir()
        (self.tmp / "keep.txt").write_text("not the cache's to delete")
        patcher = mock.patch.object(feed_cache, "_CACHE_DIR", cache)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_walked_id_writes_inside_the_cache(self):
        feed_cache.note_failure(_feed(uuid="../escaped"), "down")
        self.assertTrue((self.tmp / "feed_cache" / "escaped.error").exists())
        self.assertFalse((self.tmp / "escaped.error").exists())

    def test_a_walked_id_clears_nothing_outside_the_cache(self):
        feed_cache.clear("../keep")
        self.assertTrue((self.tmp / "keep.txt").exists())


if __name__ == "__main__":
    unittest.main()
