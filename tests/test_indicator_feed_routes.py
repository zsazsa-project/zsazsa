"""Download and public-feed routes.

The public capability URL and the download links are the two ways a feed leaves
zsazsa without an analyst looking at it, so what they return has to be pinned:
the same query the feed page runs, and only the formats that exist.

    python -m unittest tests.test_indicator_feed_routes
"""

import json
import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import misp_store
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


# The same value on two servers: the value list folds them, the CSV does not.
_ROWS = [_row("1.2.3.4", server_label="One"), _row("1.2.3.4", server_label="Two")]


def _client():
    """A bare app with only this blueprint: create_app() would start the
    collection-cache worker and reach MISP."""
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(indicator_feed.bp)
    return app.test_client()


def _feed(**over):
    """A feed with the fields misp_store._indicator_feed_ns fills in.

    It fills every one of them, so an uncached feed carries empty caching
    fields rather than none at all, and code may read them directly.
    """
    data = dict(uuid=_UUID, id=_UUID, feed_id="FEED-001", name="Ports & Terminals",
                description="", query={"types": ["ip-dst"]}, tlp="clear", audience="",
                author="", linked_pir_uuid="", creator="", token="t" * 22, public_url_enabled=True,
                cache_interval="", cache_anchor="", feedback_by=None, created_at=None)
    data.update(over)
    return SimpleNamespace(**data)


class Download(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        patches = [
            mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()),
            mock.patch.object(misp_store, "search_indicators", return_value=_ROWS),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_the_value_list_is_deduplicated_and_the_csv_is_not(self):
        txt = self.client.get(f"/products/indicator-feed/{_UUID}/download.txt")
        self.assertEqual(txt.data.decode(), "1.2.3.4")
        csv = self.client.get(f"/products/indicator-feed/{_UUID}/download.csv")
        self.assertEqual(csv.data.decode().count("1.2.3.4"), 2)

    def test_the_filename_comes_from_the_feed_name(self):
        r = self.client.get(f"/products/indicator-feed/{_UUID}/download.csv")
        self.assertIn('filename="ports-terminals.csv"', r.headers["Content-Disposition"])

    def test_only_the_real_formats_are_served(self):
        for fmt in ("txt", "csv", "tsv", "json"):
            with self.subTest(fmt=fmt):
                self.assertEqual(
                    self.client.get(f"/products/indicator-feed/{_UUID}/download.{fmt}").status_code, 200)
        for fmt in ("exe", "xml", "html"):
            with self.subTest(fmt=fmt):
                self.assertEqual(
                    self.client.get(f"/products/indicator-feed/{_UUID}/download.{fmt}").status_code, 404)


class Formats(unittest.TestCase):
    """A feed leaves zsazsa in four shapes. The value list is what the public URL
    has always returned, so it must not change."""

    def setUp(self):
        self.client = _client()
        rows = [
            {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True, "tags": ["tlp:amber"],
             "attribute_timestamp": "2026-09-02 02:40", "server_label": "One", "event_id": "7",
             "event_uuid": "e" * 36, "event_title": "Campaign", "creator_org": "CERT",
             "event_date": "2026-09-01", "event_url": "https://misp/events/view/e",
             "_ts": 1, "server_id": "s1", "attribute_id": "99"},
            # the same value on a second event: one line in the lists, two rows in CSV/JSON
            {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True, "tags": [],
             "attribute_timestamp": "2026-09-02 02:41", "server_label": "Two", "event_id": "8",
             "event_uuid": "f" * 36, "event_title": "Other", "creator_org": "CERT",
             "event_date": "2026-09-01", "event_url": "https://misp/events/view/f",
             "_ts": 2, "server_id": "s2", "attribute_id": "100"},
            {"type": "domain", "value": "evil.example", "to_ids": False, "tags": [],
             "attribute_timestamp": "2026-09-02 02:42", "server_label": "One", "event_id": "7",
             "event_uuid": "e" * 36, "event_title": "Campaign", "creator_org": "CERT",
             "event_date": "2026-09-01", "event_url": "https://misp/events/view/e",
             "_ts": 3, "server_id": "s1", "attribute_id": "101"},
        ]
        patches = [
            mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed(tlp="amber")),
            mock.patch.object(misp_store, "search_indicators", return_value=rows),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _get(self, fmt):
        return self.client.get(f"/products/indicator-feed/{_UUID}/download.{fmt}")

    def test_the_value_list_is_unchanged(self):
        self.assertEqual(self._get("txt").data.decode(), "1.2.3.4\nevil.example")

    def test_the_typed_list_carries_the_type_before_a_tab(self):
        self.assertEqual(self._get("tsv").data.decode(),
                         "ip-dst\t1.2.3.4\ndomain\tevil.example")

    def test_the_typed_list_splits_on_the_first_tab_even_with_commas_in_a_value(self):
        # E-mail subjects carry commas, which is why this is not comma-separated.
        rows = [{"type": "email-subject", "value": "Invoice, urgent: 42"}]
        with mock.patch.object(misp_store, "search_indicators", return_value=rows):
            line = self._get("tsv").data.decode()
        self.assertEqual(line.split("\t", 1), ["email-subject", "Invoice, urgent: 42"])

    def test_json_describes_the_feed_and_lists_every_row(self):
        doc = json.loads(self._get("json").data)
        self.assertEqual(doc["feed"], {"id": "FEED-001", "name": "Ports & Terminals",
                                       "description": "", "tlp": "amber"})
        self.assertEqual(doc["count"], 3)
        self.assertEqual(len(doc["indicators"]), 3)
        self.assertTrue(doc["generated_at"].endswith("Z"))

    def test_json_keeps_the_context_the_value_list_drops(self):
        first = json.loads(self._get("json").data)["indicators"][0]
        self.assertEqual(first["type"], "ip-dst")
        self.assertEqual(first["event_uuid"], "e" * 36)
        self.assertEqual(first["tags"], ["tlp:amber"])
        self.assertIs(first["to_ids"], True)

    def test_json_does_not_leak_the_internal_row_keys(self):
        first = json.loads(self._get("json").data)["indicators"][0]
        for internal in ("_ts", "server_id", "attribute_id"):
            self.assertNotIn(internal, first)

    def test_the_ad_hoc_download_has_no_feed_block(self):
        doc = json.loads(self.client.get("/products/indicator-feed/download.json?types=ip-dst").data)
        self.assertNotIn("feed", doc)
        self.assertEqual(doc["count"], 3)

    def test_every_format_is_served_with_its_own_content_type(self):
        expected = {"txt": "text/plain", "tsv": "text/tab-separated-values",
                    "csv": "text/csv", "json": "application/json"}
        for fmt, mimetype in expected.items():
            with self.subTest(fmt=fmt):
                r = self._get(fmt)
                self.assertEqual(r.status_code, 200)
                self.assertTrue(r.headers["Content-Type"].startswith(mimetype))
                self.assertIn(f'filename="ports-terminals.{fmt}"', r.headers["Content-Disposition"])


class EffectiveLimit(unittest.TestCase):
    """One helper answers "how many will this query fetch", so the search, the
    count, the summary and the PyMISP preview cannot disagree."""

    def test_it_defaults_caps_and_survives_nonsense(self):
        cases = [({}, misp_store.DEFAULT_INDICATOR_LIMIT),
                 ({"limit": 250}, 250),
                 ({"limit": 0}, misp_store.DEFAULT_INDICATOR_LIMIT),
                 ({"limit": 999999}, misp_store.MAX_SEARCH_LIMIT),
                 ({"limit": -5}, 1),
                 ({"limit": "abc"}, misp_store.DEFAULT_INDICATOR_LIMIT),
                 ({"limit": None}, misp_store.DEFAULT_INDICATOR_LIMIT)]
        for filters, expected in cases:
            with self.subTest(filters=filters):
                self.assertEqual(misp_store.indicator_limit(filters), expected)


class TruncateOff(unittest.TestCase):
    """The saved limit sizes the result table. `truncate=off` on an export URL
    asks for the whole set instead, capped by misp_store.MAX_SEARCH_LIMIT."""

    def setUp(self):
        self.client = _client()
        search = mock.patch.object(misp_store, "search_indicators", return_value=_ROWS)
        self.search = search.start()
        self.addCleanup(search.stop)
        feed = mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed())
        feed.start()
        self.addCleanup(feed.stop)

    def limit_used(self):
        return self.search.call_args.kwargs["limit"]

    def test_a_download_keeps_the_saved_limit_by_default(self):
        self.client.get(f"/products/indicator-feed/{_UUID}/download.txt")
        self.assertIsNone(self.limit_used())

    def test_a_download_with_truncate_off_asks_for_everything(self):
        self.client.get(f"/products/indicator-feed/{_UUID}/download.txt?truncate=off")
        self.assertEqual(self.limit_used(), misp_store.MAX_SEARCH_LIMIT)

    def test_the_ad_hoc_download_honours_it_too(self):
        self.client.get("/products/indicator-feed/download.csv?types=ip-dst&truncate=off")
        self.assertEqual(self.limit_used(), misp_store.MAX_SEARCH_LIMIT)

    def test_the_public_url_honours_it_too(self):
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=_feed()):
            self.client.get("/products/indicator-feed/public/" + "t" * 22 + "?truncate=off")
        self.assertEqual(self.limit_used(), misp_store.MAX_SEARCH_LIMIT)

    def test_only_off_switches_it_off(self):
        for value in ["on", "yes", "true", "1", "", "OFFF"]:
            with self.subTest(value=value):
                self.client.get(f"/products/indicator-feed/{_UUID}/download.txt?truncate={value}")
                self.assertIsNone(self.limit_used())

    def test_the_value_is_read_case_insensitively(self):
        for value in ["OFF", " Off "]:
            with self.subTest(value=value):
                self.client.get(f"/products/indicator-feed/{_UUID}/download.txt?truncate={value}")
                self.assertEqual(self.limit_used(), misp_store.MAX_SEARCH_LIMIT)


class Delete(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        patches = [
            mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()),
            mock.patch.object(misp_store, "delete_indicator_feed"),
            mock.patch.object(indicator_feed.audit, "record"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _delete(self):
        with self.client:
            self.client.post(f"/products/indicator-feed/{_UUID}/delete")
            from flask import get_flashed_messages
            return get_flashed_messages(with_categories=True)

    def test_deleting_a_feed_a_profile_links_names_that_profile(self):
        """The profile keeps the uuid and drops the feed from its product, so
        the analyst has to be told which product just got shorter."""
        linked = [SimpleNamespace(tap_id="TAP-007")]
        with mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=linked):
            messages = self._delete()
        self.assertEqual(messages[0][0], "warning")
        self.assertIn("TAP-007", messages[0][1])

    def test_deleting_an_unlinked_feed_is_a_plain_confirmation(self):
        with mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[]):
            messages = self._delete()
        self.assertEqual(messages[0][0], "info")
        self.assertEqual(messages[0][1], "FEED-001 deleted.")


class PublicFeed(unittest.TestCase):
    def setUp(self):
        self.client = _client()

    def test_an_unknown_token_is_not_found(self):
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=None):
            r = self.client.get("/products/indicator-feed/public/nope")
        self.assertEqual(r.status_code, 404)

    def test_it_runs_the_same_query_as_the_detail_page(self):
        """A feed stores only the filters that were set. The detail page fills
        the rest in from the defaults before searching, and so must this."""
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", return_value=_ROWS) as search:
            self.client.get("/products/indicator-feed/public/" + "t" * 22)
        used = search.call_args[0][0]
        self.assertEqual(used, indicator_feed._merge_filters({"types": ["ip-dst"]}))
        self.assertEqual(used["limit"], 100)
        self.assertEqual(used["to_ids"], "any")

    def test_text_is_deduplicated_and_csv_keeps_every_row(self):
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", return_value=_ROWS):
            txt = self.client.get("/products/indicator-feed/public/" + "t" * 22)
            csv = self.client.get("/products/indicator-feed/public/" + "t" * 22 + "?format=csv")
        self.assertEqual(txt.data.decode(), "1.2.3.4")
        self.assertEqual(csv.data.decode().count("1.2.3.4"), 2)

    def test_it_offers_the_same_formats_as_the_download(self):
        rows = [{"type": "ip-dst", "value": "1.2.3.4"}]
        expected = {"": "text/plain", "csv": "text/csv", "tsv": "text/tab-separated-values",
                    "json": "application/json", "nonsense": "text/plain"}
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", return_value=rows):
            for fmt, mimetype in expected.items():
                with self.subTest(format=fmt):
                    r = self.client.get(f"/products/indicator-feed/public/{'t' * 22}?format={fmt}")
                    self.assertTrue(r.headers["Content-Type"].startswith(mimetype))

    def test_a_search_failure_does_not_leak_the_error_to_the_consumer(self):
        with mock.patch.object(misp_store, "get_indicator_feed_by_token", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("MISP down")):
            r = self.client.get("/products/indicator-feed/public/" + "t" * 22)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, b"")


class ProductsListing(unittest.TestCase):
    """The products page counts the event reports of each product. An indicator
    feed keeps a query object and no report, so the column said 0 for every feed
    and cost a MISP fetch per row to work that out."""

    def test_a_feed_is_not_asked_for_its_report_count(self):
        from webapp.routes import products
        event = SimpleNamespace(uuid="e" * 36, id="1", info="[zsazsa:indicator-feed] FEED-001: demo",
                                date="2026-01-01", event_reports=[])
        misp = mock.MagicMock()
        misp.search.return_value = [event]
        app = Flask(__name__)
        app.register_blueprint(indicator_feed.bp)
        with app.test_request_context(), \
             mock.patch.object(products, "_event_tags",
                               return_value=['zsazsa:ctiproduct="indicator-feed"']), \
             mock.patch.object(products, "_non_feedback_report_count") as count, \
             mock.patch.object(products.misp_store, "_misp", return_value=misp):
            rows = products._list_product_events(None, None)
        self.assertEqual(rows[0]["report_count"], None)
        count.assert_not_called()


if __name__ == "__main__":
    unittest.main()
