"""The indicator feed pages: the product list, a feed's product page and the
query builder.

The builder and the product page share the query partial and post to the same
routes, so what matters here is that each page hands the template what it needs
and that the buttons on them reach the right endpoint.

    python -m unittest tests.test_indicator_feed_pages
"""

import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bs4 import BeautifulSoup
from flask import Flask
from werkzeug.datastructures import MultiDict

import config
from webapp import collection_cache, create_app, misp_store
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


def _feed(interval="daily", saved="2026-09-04T14:16:00", **over):
    data = dict(uuid=_UUID, id=_UUID, feed_id="FEED-001", name="demo", description="",
                query={"types": ["ip-dst"], "limit": 100}, tlp="clear", audience="",
                author="", linked_pir_uuid="", creator="", token="t" * 22, public_url_enabled=True,
                cache_interval=interval, cache_anchor=saved, feedback_by=None, created_at=None)
    data.update(over)
    return SimpleNamespace(**data)


class PageContext(unittest.TestCase):
    """What the views hand their template. Rendering is mocked out here, so a
    missing key shows up as a missing key and not as a page that looks fine."""

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(indicator_feed.bp)
        self.client = app.test_client()
        # Everything the product page reads from MISP, so the test never leaves
        # the machine: the page pulls stakeholders, PIRs, servers and metadata
        # besides the feed itself.
        patches = [
            mock.patch.object(misp_store, "list_indicator_feeds", return_value=[_feed()]),
            mock.patch.object(misp_store, "search_indicators", return_value=_ROWS),
            mock.patch.object(misp_store, "recipient_preview", return_value=[]),
            mock.patch.object(misp_store, "get_pir", return_value=None),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[]),
            mock.patch.object(misp_store, "indicator_feed_servers", return_value=[]),
            mock.patch.object(misp_store, "local_attribute_types", return_value=["ip-dst"]),
            mock.patch.object(indicator_feed.indicator_meta_store, "last_refreshed", return_value=""),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _context(self, url, feed=None):
        """What the view hands the template. Rendering needs base.html and the
        globals create_app registers, which is not what these tests are about.
        """
        with mock.patch.object(indicator_feed, "render_template", return_value="rendered") as render, \
             mock.patch.object(misp_store, "get_indicator_feed", return_value=feed):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return render.call_args.kwargs

    def test_the_list_shows_every_feed_with_its_schedule(self):
        with mock.patch.object(indicator_feed, "render_template", return_value="rendered") as render:
            self.assertEqual(self.client.get("/products/indicator-feed/").status_code, 200)
        feeds = render.call_args.kwargs["feeds"]
        self.assertEqual([f.feed_id for f in feeds], ["FEED-001"])
        self.assertIsNotNone(feeds[0].next_refresh)

    def test_a_link_kept_from_the_old_builder_still_runs_its_query(self):
        """This route was the builder until this release. A bookmark with
        filters on it would otherwise open the list and drop them."""
        response = self.client.get("/products/indicator-feed/?types=ip-dst&run=1")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"],
                         "/products/indicator-feed/new?types=ip-dst&run=1")

    def test_the_list_itself_is_not_a_redirect(self):
        with mock.patch.object(indicator_feed, "render_template", return_value="rendered"):
            self.assertEqual(self.client.get("/products/indicator-feed/").status_code, 200)

    def test_an_unknown_feed_is_not_found(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None):
            self.assertEqual(self.client.get("/products/indicator-feed/nope").status_code, 404)

    def test_the_product_page_carries_the_feed_its_rows_and_its_schedule(self):
        context = self._context(f"/products/indicator-feed/{_UUID}", _feed("hourly"))
        self.assertEqual(context["feed"].feed_id, "FEED-001")
        self.assertEqual(context["rows"], _ROWS)
        self.assertEqual(context["cache_schedule"], "every hour at :16")
        self.assertIsNotNone(context["cache_next"])
        # Nothing is written yet in a test, and the page says so rather than
        # pretending the feed was cached a moment ago.
        self.assertEqual(context["cache_age"], "")

    def test_the_product_page_carries_what_the_editable_fields_need(self):
        """Name, TLP, audience, the linked PIR and the query editor all render
        from this context, so a missing key is a broken page."""
        context = self._context(f"/products/indicator-feed/{_UUID}", _feed())
        for key in ("pirs", "audiences", "tlp_levels", "servers", "attribute_types",
                    "to_ids_choices", "published_choices", "attr_ranges", "event_ranges",
                    "cache_intervals", "filters", "summary",
                    "query_string", "pymisp_query"):
            with self.subTest(key=key):
                self.assertIn(key, context)

    def test_running_a_search_from_the_product_page_previews_without_saving(self):
        """The form posts back to the page, so an analyst can try a filter and
        see the result before deciding to save it."""
        feed = _feed()
        stored = self._context(f"/products/indicator-feed/{_UUID}", feed)
        self.assertEqual(stored["filters"]["types"], ["ip-dst"])

        tried = self._context(f"/products/indicator-feed/{_UUID}?types=domain&limit=10", feed)
        self.assertEqual(tried["filters"]["types"], ["domain"])
        self.assertEqual(tried["filters"]["limit"], 10)
        self.assertEqual(feed.query["types"], ["ip-dst"])   # nothing was written

    def test_the_recipients_fragment_says_who_receives_it(self):
        """The page holds a button, not the answer: the shared modal fetches
        this fragment when somebody asks, as on the other product pages."""
        preview = [{"name": "SOC", "role": "analyst", "uuid": "s1", "status": "green", "reason": "ok"}]
        with mock.patch.object(misp_store, "recipient_preview", return_value=preview) as lookup, \
             mock.patch.object(indicator_feed, "render_template", return_value="rendered") as render, \
             mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()):
            response = self.client.get(f"/products/indicator-feed/{_UUID}/recipients")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(render.call_args.args[0], "_recipients_preview.html")
        self.assertEqual(render.call_args.kwargs["recipients"], preview)
        self.assertEqual(lookup.call_args.args, (indicator_feed.PRODUCT_NAME, "clear", ""))

    def test_the_recipients_fragment_of_an_unknown_feed_is_not_found(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None):
            response = self.client.get(f"/products/indicator-feed/{_UUID}/recipients")
        self.assertEqual(response.status_code, 404)

    def test_a_corrupt_stored_limit_falls_back_instead_of_breaking_the_page(self):
        feed = _feed(query={"types": ["ip-dst"], "limit": "abc"})
        context = self._context(f"/products/indicator-feed/{_UUID}", feed)
        self.assertIn(f"limit {misp_store.DEFAULT_INDICATOR_LIMIT}", context["summary"])


class OrgFilters(unittest.TestCase):
    """A pasted organisation UUID is kept as the organisation it names, so the
    chips, the summary and the PyMISP card all say who rather than which id."""

    def _filters(self, **args):
        pairs = [(k, v) for k, vs in args.items() for v in vs]
        return indicator_feed._filters_from(MultiDict(pairs))

    def test_a_uuid_is_kept_as_the_organisation_it_names(self):
        with mock.patch.object(misp_store, "organisation_name", return_value="CUDESO-PRIV"):
            filters = self._filters(orgs_include=["5e1b7d20-bbbc-456e-b270-479b29b8f09f"])
        self.assertEqual(filters["orgs_include"], ["CUDESO-PRIV"])

    def test_a_name_is_left_alone_and_costs_no_lookup(self):
        with mock.patch.object(misp_store, "organisation_name", return_value="") as lookup:
            filters = self._filters(orgs_exclude=["CIRCL"])
        self.assertEqual(filters["orgs_exclude"], ["CIRCL"])
        lookup.assert_called_once_with("CIRCL")

    def test_a_uuid_no_server_knows_stays_as_it_was_typed(self):
        with mock.patch.object(misp_store, "organisation_name", return_value=""):
            filters = self._filters(orgs_include=["00000000-0000-0000-0000-000000000000"])
        self.assertEqual(filters["orgs_include"], ["00000000-0000-0000-0000-000000000000"])

    def test_the_page_can_ask_for_the_name_of_a_chip_it_just_added(self):
        """A chip is built in the browser and does not pass through the filters
        until the feed is saved, so the page looks the name up on its own."""
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(indicator_feed.bp)
        with mock.patch.object(misp_store, "organisation_name", return_value="CUDESO-PRIV"):
            response = app.test_client().get(
                "/products/indicator-feed/org-name",
                query_string={"value": "5e1b7d20-bbbc-456e-b270-479b29b8f09f"})
        self.assertEqual(response.get_json(), {"name": "CUDESO-PRIV"})


class TimeRanges(unittest.TestCase):
    """The two time filters sit side by side and offer the same windows."""

    def test_they_offer_the_same_windows_apart_from_the_hour(self):
        """An event carries a date and no time, so it cannot answer "last hour".
        Everything else has to read the same on both rows or an analyst has to
        work out which control means what."""
        attr = [label for _value, label in indicator_feed.ATTR_RANGES]
        event = [label for _value, label in indicator_feed.EVENT_RANGES]
        self.assertEqual(attr, ["Last hour"] + event)

    def test_today_is_not_the_same_window_as_the_last_day(self):
        """Since midnight, against the last 24 hours. MISP's relative shorthand
        only says the second, so the first goes as a date."""
        today = date.today().isoformat()
        self.assertEqual(
            misp_store._indicator_search_kwargs({"attr_last": "today"})["timestamp"], today)
        self.assertEqual(
            misp_store._indicator_search_kwargs({"attr_last": "1d"})["timestamp"], "1d")
        self.assertEqual(
            misp_store._indicator_search_kwargs({"event_last": "0"})["date_from"], today)


class QuerySummary(unittest.TestCase):
    def test_it_reads_as_a_sentence_of_filters(self):
        filters = dict(indicator_feed._default_filters(),
                       types=["ip-dst", "domain"], tags_include=["tlp:amber"],
                       attr_last="1d", to_ids="yes", limit=500)
        self.assertEqual(
            indicator_feed._query_summary(filters),
            ["ip-dst, domain", "1 tag", "attributes last day", "to_ids yes", "limit 500"])

    def test_every_list_the_query_card_offers_is_summarised(self):
        """An excluded organisation narrows a feed as much as an included one.
        While three of the six lists were missing here, two different queries
        could show the same summary."""
        filters = dict(indicator_feed._default_filters(),
                       tags_include=["t"], tags_exclude=["x"],
                       orgs_include=["A"], orgs_exclude=["B"],
                       events_include=["e"], events_exclude=["f"])
        self.assertEqual(indicator_feed._query_summary(filters),
                         ["1 tag", "1 excluded tag", "1 org", "1 excluded org",
                          "1 event", "1 excluded event", "limit 100"])

    def test_an_exclusion_on_its_own_is_still_a_query(self):
        filters = dict(indicator_feed._default_filters(), orgs_exclude=["CIRCL", "eCrimeLabs"])
        self.assertEqual(indicator_feed._query_summary(filters),
                         ["2 excluded orgs", "limit 100"])

    def test_a_long_type_list_is_counted_rather_than_listed(self):
        filters = dict(indicator_feed._default_filters(), types=["a", "b", "c", "d", "e"])
        self.assertEqual(indicator_feed._query_summary(filters)[0], "a, b, c +2")

    def test_a_date_range_is_named_when_no_relative_range_is_set(self):
        filters = dict(indicator_feed._default_filters(),
                       attr_after="2026-01-01", event_last="7")
        self.assertEqual(indicator_feed._query_summary(filters)[:2],
                         ["attributes 2026-01-01 to …", "events last 7 days"])

    def test_a_query_that_filters_nothing_has_no_summary(self):
        """The summary is what the query card collapses behind, so a new feed
        whose only "filter" is the default limit opens with the builder shown."""
        self.assertEqual(indicator_feed._query_summary(indicator_feed._default_filters()), [])

    def test_one_filter_is_enough_to_summarise_and_the_limit_comes_along(self):
        filters = dict(indicator_feed._default_filters(), types=["ip-dst"])
        self.assertEqual(indicator_feed._query_summary(filters), ["ip-dst", "limit 100"])




class RenderedPages(unittest.TestCase):
    """The markup a browser actually receives.

    These assert on the rendered page rather than on the context: the buttons an
    analyst presses, the fields the form posts back and the state each card is
    in. A template can drop any of those while every route test still passes.
    """

    def setUp(self):
        # These assert on the rendered markup, so they need the real app: the
        # pages extend base.html, which only create_app fills in. The database,
        # the log and the cache worker are pointed somewhere harmless, and the
        # login redirect is off, or a developer who runs single sign-on gets a
        # 302 here instead of a page.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patches = [
            mock.patch.object(config, "DB_FILE", str(Path(tmp.name) / "test.db"), create=True),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp.name) / "test.log"), create=True),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch.object(misp_store, "list_indicator_feeds", return_value=[]),
            mock.patch.object(misp_store, "search_indicators", return_value=_ROWS),
            mock.patch.object(misp_store, "list_pirs", return_value=[]),
            mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[]),
            mock.patch.object(misp_store, "indicator_feed_servers", return_value=[]),
            mock.patch.object(misp_store, "local_attribute_types", return_value=["ip-dst"]),
            mock.patch.object(indicator_feed.indicator_meta_store, "last_refreshed", return_value=""),
            mock.patch.object(indicator_feed.audit, "record"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = create_app().test_client()

    def _form(self):
        html = self.client.get("/products/indicator-feed/new").data
        return BeautifulSoup(html, "html.parser").find("form", id="indicator-form")

    def test_the_builder_offers_a_save_button_that_reaches_the_save_route(self):
        save = [b for b in self._form().select("button[formaction]")
                if "Save as feed" in b.get_text()]
        self.assertEqual(len(save), 1)
        self.assertEqual(save[0]["formaction"], "/products/indicator-feed/save")
        self.assertEqual(save[0]["formmethod"], "post")

    def test_the_fields_the_form_carries_create_a_feed(self):
        fields = {i["name"]: i.get("value", "") for i in self._form().select("input[name]")
                  if i.get("type") not in ("checkbox", "radio")}
        fields["name"] = "from the builder"
        with mock.patch.object(misp_store, "create_indicator_feed", return_value=_UUID) as create:
            response = self.client.post("/products/indicator-feed/save", data=fields)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(create.call_args[0][0]["name"], "from the builder")

    def test_a_feed_page_can_edit_every_filter_it_stores(self):
        """A field the page does not render is a field the form does not post,
        and edit() rebuilds the query from the form: whatever is missing is
        wiped. The servers went that way once."""
        query = {k: [f"v-{k}"] for k in indicator_feed._LIST_KEYS}
        query.update({k: "2026-01-01" for k in indicator_feed._SCALAR_KEYS})
        query.update(servers=["s1"], types=["ip-dst"], to_ids="yes", published="no",
                     enforce_warninglist="yes", attr_last="1d", event_last="7", limit=100)
        feed = _feed(query=query)
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed), \
             mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch.object(misp_store, "indicator_feed_servers",
                               return_value=[{"id": "s1", "label": "One", "url": "u", "enabled": True,
                                              "store": False, "usable": True}]):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        form = BeautifulSoup(html, "html.parser").find("form", id="indicator-form")
        posted = {i["name"] for i in form.select("input[name], select[name]")}
        for key in indicator_feed._LIST_KEYS + indicator_feed._SCALAR_KEYS + ["limit"]:
            self.assertIn(key, posted, f"{key} is stored but the page cannot post it")
        # And the values themselves come back, not just the field names.
        chips = {i["name"]: i["value"] for i in form.select("input[type=hidden][name]")}
        for key in indicator_feed._QUERY_LIST_KEYS:
            if key != "types":
                self.assertEqual(chips.get(key), f"v-{key}")

    def test_a_feed_page_offers_save_changes_instead(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "recipient_preview", return_value=[]), \
             mock.patch.object(misp_store, "get_pir", return_value=None):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        save = BeautifulSoup(html, "html.parser").select_one(".card-footer button[formaction]")
        self.assertEqual(save["formaction"], f"/products/indicator-feed/{_UUID}/edit")

    def test_a_new_feed_gets_the_page_a_saved_feed_gets(self):
        """One form, not two: the fields an analyst fills in have to sit in the
        same places whether the feed exists yet or not."""
        def fields(html):
            form = BeautifulSoup(html, "html.parser").find("form", id="indicator-form")
            return sorted({i["name"] for i in form.select("input[name], select[name], textarea[name]")
                           if i.get("type") != "hidden"})

        new = self.client.get("/products/indicator-feed/new").data
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "get_pir", return_value=None):
            saved = self.client.get(f"/products/indicator-feed/{_UUID}").data
        self.assertEqual(fields(new), fields(saved))

    def test_run_search_is_the_only_submit_without_a_formaction(self):
        """The script lets a submit through when it carries a formaction and
        swaps the results itself otherwise, so Run search must be the one
        button that does not name a target."""
        html = self.client.get("/products/indicator-feed/new").data
        form = BeautifulSoup(html, "html.parser").find("form", id="indicator-form")
        self.assertTrue(form["data-results-url"].endswith("/results"))
        plain = [b.get_text(" ", strip=True) for b in form.find_all("button", type="submit")
                 if not b.has_attr("formaction")]
        self.assertTrue(plain and all("Run search" in t for t in plain), plain)

    def test_a_new_feed_has_a_card_waiting_for_the_first_search(self):
        """Run search swaps this block, so it has to be there before the first
        one, saying it holds nothing yet rather than an empty table."""
        html = self.client.get("/products/indicator-feed/new").data
        card = BeautifulSoup(html, "html.parser").select_one("#results .card")
        self.assertIsNotNone(card)
        self.assertIn("no query run", card.get_text())
        # Nothing has been fetched, so there is nothing to count or download.
        self.assertIsNone(card.select_one("#count-total-btn"))
        self.assertEqual(card.select("a[href*='download.']"), [])

    def test_a_saved_feed_shows_its_indicators_straight_away(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "get_pir", return_value=None):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        card = BeautifulSoup(html, "html.parser").select_one("#results .card")
        self.assertNotIn("no query run", card.get_text())
        self.assertIsNotNone(card.select_one("#results-table"))

    def test_a_saved_feed_offers_its_pymisp_script_with_the_downloads(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "get_pir", return_value=None):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        card = BeautifulSoup(html, "html.parser").select_one("#results .card")
        link = card.select_one("a[href$='/pymisp.py']")
        self.assertEqual(link["href"], f"/products/indicator-feed/{_UUID}/pymisp.py")
        self.assertTrue(link.has_attr("download"))

    def test_the_query_fields_are_separated_from_the_feed_fields(self):
        """The script marks the results outdated when something inside a
        [data-query-part] region changes. A field on the wrong side of that line
        either never warns (a filter) or warns about nothing (the feed's name).
        The regions are the query card and the server picker beside the feed's
        own fields, which is why this asks for the marker and not for one id."""
        query = {k: [f"v-{k}"] for k in indicator_feed._LIST_KEYS}
        query.update({k: "2026-01-01" for k in indicator_feed._SCALAR_KEYS})
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed(query=query)), \
             mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch.object(misp_store, "indicator_feed_servers",
                               return_value=[{"id": "s1", "label": "One", "url": "u", "enabled": True,
                                              "store": False, "usable": True}]):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        soup = BeautifulSoup(html, "html.parser")
        boxes = soup.select("[data-query-part]")
        self.assertTrue(boxes)
        inside = {i["name"] for box in boxes for i in box.select("input[name], select[name]")}
        for key in indicator_feed._LIST_KEYS + indicator_feed._SCALAR_KEYS + ["limit"]:
            self.assertIn(key, inside, f"{key} filters the query but sits outside")
        for key in ("name", "tlp", "audience", "author", "cache_interval"):
            self.assertNotIn(key, inside, f"{key} is the feed itself, not its query")

    def test_the_stale_banner_only_warns(self):
        """Run search is in the results header right under it."""
        banner = BeautifulSoup(self.client.get("/products/indicator-feed/new").data,
                               "html.parser").find(id="results-stale")
        self.assertIsNotNone(banner)
        self.assertIsNone(banner.find("button"))
        self.assertIn("d-none", banner["class"])

    def test_a_plain_submit_still_runs_the_search(self):
        """The script swaps the results without leaving the page, but it must
        not be the only way: a browser that submits the form anyway has to come
        back with the indicators, not with the page it started on."""
        form = self._form()
        pairs = [(i["name"], i.get("value", "")) for i in form.select("input[name]")
                 if i.get("type") not in ("checkbox", "radio")]
        self.assertIn(("run", "1"), pairs)
        response = self.client.get(form["action"], query_string=dict(pairs))
        card = BeautifulSoup(response.data, "html.parser").select_one("#results .card")
        self.assertNotIn("no query run", card.get_text())

    def test_the_page_names_the_profiles_that_use_the_feed(self):
        """A feed embedded in a threat actor profile travels inside that product,
        so the analyst has to see which ones before changing or deleting it."""
        tap = SimpleNamespace(uuid="t" * 36, tap_id="TAP-002", title="Actor infrastructure")
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[tap]):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        link = BeautifulSoup(html, "html.parser").select_one(f"a[href$='{tap.uuid}']")
        self.assertIsNotNone(link)
        self.assertEqual(link.get_text(strip=True), "TAP-002")
        self.assertTrue(link["href"].startswith("/products/threat-actor-profile/"), link["href"])

    def test_a_feed_no_profile_uses_says_so(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch.object(misp_store, "profiles_using_indicator_feed", return_value=[]):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        self.assertIn("No threat actor profile", html.decode())

    def _feed_page(self, can_publish, **feed):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed(**feed)), \
             mock.patch.object(misp_store, "get_pir", return_value=None), \
             mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
            html = self.client.get(f"/products/indicator-feed/{_UUID}").data
        return BeautifulSoup(html, "html.parser")

    def test_only_a_publisher_gets_the_public_url_switch(self):
        switch = self._feed_page(True).select_one("input[type=checkbox][name=public_url]")
        self.assertIsNotNone(switch)
        self.assertTrue(switch.has_attr("checked"))
        page = self._feed_page(False)
        self.assertIsNone(page.select_one("[name=public_url]"))
        self.assertIn("Only users with MISP publish rights can switch it on or off", page.get_text())

    def test_a_switched_off_public_url_is_not_shown(self):
        page = self._feed_page(True, public_url_enabled=False)
        self.assertFalse(page.select_one("input[type=checkbox][name=public_url]").has_attr("checked"))
        self.assertIsNone(page.select_one("input.public-url"))
        self.assertIn("Off. The link answers", page.get_text())
        self.assertIsNotNone(self._feed_page(True).select_one("input.public-url"))

    def test_a_new_feed_by_anyone_but_a_publisher_says_its_url_starts_off(self):
        with mock.patch("webapp.misp_session.current_user_can_publish", return_value=False):
            html = self.client.get("/products/indicator-feed/new").data.decode()
        self.assertIn("Off when you save the feed.", html)

    def test_the_list_offers_delivery_only_to_a_publisher(self):
        notify = f"/products/indicator-feed/{_UUID}/notify"
        for can_publish in (True, False):
            with self.subTest(can_publish=can_publish), \
                 mock.patch.object(misp_store, "list_indicator_feeds", return_value=[_feed()]), \
                 mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
                html = self.client.get("/products/indicator-feed/").data
            row = BeautifulSoup(html, "html.parser").select_one("tbody tr")
            self.assertEqual(bool(row.select(f'form[action="{notify}"]')), can_publish)
            self.assertEqual(bool(row.select("button[disabled] .fa-paper-plane")), not can_publish)

    def test_the_list_says_when_a_feed_could_not_be_refreshed(self):
        note = {"at": datetime(2026, 9, 5, 10, 30), "reason": "MISP unreachable"}
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=[_feed()]), \
             mock.patch.object(indicator_feed.feed_cache, "failure", return_value=note):
            html = self.client.get("/products/indicator-feed/").data
        row = BeautifulSoup(html, "html.parser").select_one("tbody tr")
        caching = row.select("td")[4].get_text(" ", strip=True)
        self.assertIn("refresh failed", caching)
        self.assertIn("05-09 10:30", caching)

    def test_a_result_row_carries_the_context_the_analyst_acts_on(self):
        """Each row links to its event in MISP and offers the four buttons that
        put that event or that organisation into the query."""
        response = self.client.get("/products/indicator-feed/results",
                                   query_string={"types": "ip-dst"})
        row = BeautifulSoup(response.data, "html.parser").select_one("#results-table tbody tr")
        self.assertIn("events/view", row.select_one("a")["href"])
        self.assertEqual(sorted(b["data-field"] for b in row.select("button.add-filter")),
                         ["events_exclude", "events_include", "orgs_exclude", "orgs_include"])
        # The table sorts on the attribute timestamp without going back to MISP.
        self.assertEqual(row.select_one("td[data-v]")["data-v"], "1767261600")

    def test_a_search_that_could_not_run_says_so_instead_of_nothing_matched(self):
        """An unreachable MISP used to read as a query with no matches, which is
        the one answer an indicator feed must never give by accident."""
        with mock.patch.object(misp_store, "search_indicators",
                               side_effect=RuntimeError("no MISP server answered")):
            response = self.client.get("/products/indicator-feed/results",
                                       query_string={"types": "ip-dst"})
        card = BeautifulSoup(response.data, "html.parser").select_one(".card")
        self.assertIn("search failed", card.select_one(".card-header").get_text())
        self.assertIn("no MISP server answered", card.select_one(".card-body").get_text())
        self.assertNotIn("No indicators match", card.get_text())
        # Downloading now would hand over an empty file as if that were the feed.
        self.assertEqual(card.select("a[href*='download.']"), [])

    def test_a_failed_search_drops_the_live_badge(self):
        """The badge says the table came from MISP just now. Beside a failure it
        would be saying the opposite of what happened."""
        feed = _feed(interval="hourly")
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed), \
             mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")):
            failed = self.client.get(f"/products/indicator-feed/{_UUID}/results").data
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=feed):
            worked = self.client.get(f"/products/indicator-feed/{_UUID}/results").data
        self.assertNotIn("live", BeautifulSoup(failed, "html.parser").select_one(".card-header").get_text())
        self.assertIn("live", BeautifulSoup(worked, "html.parser").select_one(".card-header").get_text())

    def test_a_feed_is_not_delivered_when_it_could_not_be_read(self):
        """The delivery embeds the indicators; during an outage that would tell
        every stakeholder the feed is empty."""
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()), \
             mock.patch.object(misp_store, "search_indicators", side_effect=RuntimeError("down")), \
             mock.patch.object(indicator_feed.notify_jobs, "start") as start:
            token = self._form().select_one("input[name=csrf_token]")["value"]
            response = self.client.post(f"/products/indicator-feed/{_UUID}/notify",
                                        data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        start.assert_not_called()

    def test_the_results_fragment_is_only_the_results(self):
        """Run search replaces that block, so the fragment must not carry a
        second copy of the form or the page around it."""
        response = self.client.get("/products/indicator-feed/results",
                                   query_string={"types": "ip-dst", "limit": "5"})
        self.assertEqual(response.status_code, 200)
        frag = BeautifulSoup(response.data, "html.parser")
        self.assertIsNone(frag.find("form", id="indicator-form"))
        self.assertIsNone(frag.find("html"))
        self.assertIsNotNone(frag.select_one("#results-table"))

    def test_the_fragment_of_an_unknown_feed_is_not_found(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None):
            response = self.client.get(f"/products/indicator-feed/{_UUID}/results")
        self.assertEqual(response.status_code, 404)

    def test_the_pymisp_card_is_rendered_by_the_store(self):
        """The card updates as the filters change. It asks the server for it so
        the browser never holds a second version of that mapping."""
        response = self.client.get("/products/indicator-feed/pymisp-query",
                                   query_string={"types": "ip-dst", "limit": "7"})
        self.assertEqual(response.status_code, 200)
        query = response.get_json()["query"]
        self.assertEqual(query, misp_store.pymisp_query_string(
            indicator_feed._filters_from(MultiDict([("types", "ip-dst"), ("limit", "7")]))))
        self.assertIn("limit=7", query)

    def test_the_query_endpoint_also_returns_the_summary(self):
        """The one-line summary in the card header follows the filters as they
        are edited, and rides the round trip the PyMISP card already makes."""
        response = self.client.get("/products/indicator-feed/pymisp-query",
                                   query_string={"types": "ip-dst", "limit": "7"})
        body = response.get_json()
        self.assertEqual(body["summary"],
                         indicator_feed._query_summary(indicator_feed._filters_from(
                             MultiDict([("types", "ip-dst"), ("limit", "7")]))))
        self.assertIn("limit 7", body["summary"])

    def test_the_card_shows_the_limit_the_search_is_capped_to(self):
        """A limit above the cap is clamped before MISP sees it, so the card has
        to show the clamped number, not what was typed."""
        response = self.client.get("/products/indicator-feed/pymisp-query",
                                   query_string={"limit": "50000"})
        self.assertIn(f"limit={misp_store.MAX_SEARCH_LIMIT}", response.get_json()["query"])

    def test_a_failed_save_returns_to_the_builder_with_the_query(self):
        # Without this the analyst is dropped on the product list and the query
        # they just built is gone.
        token = self._form().select_one("input[name=csrf_token]")["value"]
        response = self.client.post(
            "/products/indicator-feed/save",
            data={"name": "", "types": "ip-dst", "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].startswith(
            "/products/indicator-feed/new?"), response.headers["Location"])
        self.assertIn("types=ip-dst", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
