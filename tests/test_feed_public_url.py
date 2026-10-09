"""A feed's public URL is a setting only a publisher changes.

The public URL hands a feed's indicators to anyone holding the link, without a
login. Each feed now carries a public-url setting on its MISP object, and only
a user with MISP publish rights switches it on or off. A feed a publisher
creates starts with it on, one anyone else creates starts with it off, and
feeds saved before the setting existed keep their URL on. While it is off, the
link answers like an unknown one.

    python -m unittest tests.test_feed_public_url
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent

from webapp import misp_store
from webapp.routes import indicator_feed

UUID = "u" * 36
TOKEN = "t" * 22


def _feed(public_url_enabled=True):
    return SimpleNamespace(uuid=UUID, id=UUID, feed_id="FEED-001", name="demo", description="",
                           query={"types": ["ip-dst"]}, tlp="clear", audience="", author="",
                           linked_pir_uuid="", creator="", token=TOKEN,
                           public_url_enabled=public_url_enabled,
                           cache_interval="", cache_anchor="", feedback_by=None, created_at=None)


def _event(public_url=None):
    """A feed event as MISP returns it, with or without the setting stored."""
    obj = misp_store._build_obj("zsazsa-indicator-feed")
    obj.add_attribute("feed-id", value="FEED-001", type="text")
    obj.add_attribute("token", value=TOKEN, type="text")
    if public_url:
        obj.add_attribute("public-url", value=public_url, type="text")
    event = MISPEvent()
    event.uuid = UUID
    event.id = "42"
    event.info = "[zsazsa:indicator-feed] FEED-001: demo"
    event.date = "2026-10-09"
    event.Object.append(obj)
    return event


class StoredSetting(unittest.TestCase):
    def test_a_feed_saved_before_the_setting_keeps_its_url(self):
        self.assertTrue(misp_store._indicator_feed_ns(_event()).public_url_enabled)

    def test_the_stored_setting_is_read_back(self):
        self.assertTrue(misp_store._indicator_feed_ns(_event("enabled")).public_url_enabled)
        self.assertFalse(misp_store._indicator_feed_ns(_event("disabled")).public_url_enabled)

    def test_the_setting_is_written_to_the_object(self):
        for enabled, stored in ((True, "enabled"), (False, "disabled")):
            with self.subTest(enabled=enabled):
                obj = misp_store._indicator_feed_obj({"public_url_enabled": enabled})
                self.assertEqual(misp_store._obj_attr(obj, "public-url"), stored)

    def test_an_update_that_does_not_name_it_keeps_it(self):
        """Any code saving a feed without the field must not switch the URL back on."""
        misp = mock.Mock()
        misp.get_event.return_value = _event("disabled")
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "_sync_object_attributes") as sync:
            misp_store.update_indicator_feed(UUID, {"feed_id": "FEED-001", "name": "demo"})
        new_obj = sync.call_args.args[3]
        self.assertEqual(misp_store._obj_attr(new_obj, "public-url"), "disabled")

    def test_a_switched_off_feed_is_not_found_by_its_token(self):
        feeds = [_feed(public_url_enabled=False)]
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=feeds):
            self.assertIsNone(misp_store.get_indicator_feed_by_token(TOKEN))
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=[_feed()]):
            self.assertIsNotNone(misp_store.get_indicator_feed_by_token(TOKEN))


class ChangingIt(unittest.TestCase):
    """Saving and editing a feed, with and without the publish right."""

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = "test"
        app.register_blueprint(indicator_feed.bp)
        self.client = app.test_client()
        patches = [
            mock.patch.object(misp_store, "create_indicator_feed", return_value=UUID),
            mock.patch.object(misp_store, "update_indicator_feed"),
            mock.patch.object(indicator_feed.feed_cache, "clear"),
            mock.patch.object(indicator_feed.audit, "record"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def saved(self, can_publish, **form):
        with mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
            self.client.post("/products/indicator-feed/save", data={"name": "demo", **form})
        return misp_store.create_indicator_feed.call_args.args[0]["public_url_enabled"]

    def edited(self, can_publish, current, **form):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed(current)), \
             mock.patch("webapp.misp_session.current_user_can_publish", return_value=can_publish):
            self.client.post(f"/products/indicator-feed/{UUID}/edit", data={"name": "demo", **form})
        return misp_store.update_indicator_feed.call_args.args[1]["public_url_enabled"]

    def test_a_feed_a_publisher_creates_starts_with_it_on(self):
        self.assertTrue(self.saved(can_publish=True))

    def test_a_feed_anyone_else_creates_starts_with_it_off(self):
        self.assertFalse(self.saved(can_publish=False))

    def test_a_publisher_can_create_a_feed_with_it_off(self):
        self.assertFalse(self.saved(can_publish=True, public_url="disabled"))

    def test_anyone_else_cannot_switch_it_on_when_creating_a_feed(self):
        self.assertFalse(self.saved(can_publish=False, public_url=["disabled", "enabled"]))

    def test_a_publisher_switches_it_on_and_off(self):
        # The page posts a hidden "disabled", then "enabled" when the switch is on.
        self.assertFalse(self.edited(can_publish=True, current=True, public_url="disabled"))
        self.assertTrue(self.edited(can_publish=True, current=False, public_url=["disabled", "enabled"]))

    def test_anyone_else_leaves_it_as_it_is(self):
        self.assertFalse(self.edited(can_publish=False, current=False, public_url="enabled"))
        self.assertTrue(self.edited(can_publish=False, current=True, public_url="disabled"))

    def test_a_form_without_the_field_leaves_it_as_it_is(self):
        self.assertFalse(self.edited(can_publish=True, current=False))


class PublicRoute(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.register_blueprint(indicator_feed.bp)
        self.client = app.test_client()

    def test_a_switched_off_link_answers_like_an_unknown_one(self):
        feeds = [_feed(public_url_enabled=False)]
        with mock.patch.object(misp_store, "list_indicator_feeds", return_value=feeds), \
             mock.patch.object(indicator_feed, "_feed_export") as export:
            resp = self.client.get(f"/products/indicator-feed/public/{TOKEN}")
            unknown = self.client.get(f"/products/indicator-feed/public/{'x' * 22}")
        self.assertEqual((resp.status_code, resp.data), (unknown.status_code, unknown.data))
        self.assertEqual(resp.status_code, 404)
        export.assert_not_called()


if __name__ == "__main__":
    unittest.main()
