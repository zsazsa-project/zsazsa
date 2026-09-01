"""Regression coverage for product type mapping on the products page.

    python -m unittest tests.test_products_route
"""

import unittest
from types import SimpleNamespace
from unittest import mock

import config
from flask import Flask

from webapp.routes import indicator_feed, products, threat_actor_profile
from webapp.utils import product_detail_url


class ProductTypeMapping(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"
        self.app.register_blueprint(products.bp)
        self.app.register_blueprint(indicator_feed.bp)
        self.app.register_blueprint(threat_actor_profile.bp)

    def test_filter_uses_the_configured_tag_value(self):
        fake_misp = mock.MagicMock()
        fake_misp.search.return_value = []
        with mock.patch.object(products.misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(config, "TAG_THREAT_ACTOR_PROFILE",
                               'zsazsa:ctiproduct="threat-actor-profile"', create=True):
            products._list_product_events("Threat actor profile", None)
        self.assertEqual(fake_misp.search.call_args.kwargs["tags"],
                         ['zsazsa:ctiproduct="threat-actor-profile"'])

    def test_rows_use_the_display_name_not_the_tag_slug(self):
        event = SimpleNamespace(
            uuid="u" * 36,
            id="7",
            info="[zsazsa:tap] Example",
            date="2026-09-01",
            tags=[SimpleNamespace(name='zsazsa:ctiproduct="indicator-feed"')],
            event_reports=[],
        )
        fake_misp = mock.MagicMock()
        fake_misp.search.return_value = [event]
        with self.app.test_request_context("/products"), \
             mock.patch.object(products.misp_store, "_misp", return_value=fake_misp), \
             mock.patch.object(config, "MISP_WEBAPP_URL", "https://misp.example.test", create=True), \
             mock.patch.object(config, "TAG_INDICATOR_FEED",
                               'zsazsa:ctiproduct="indicator-feed"', create=True):
            rows = products._list_product_events(None, None)
        self.assertEqual(rows[0]["product_type"], "Indicator feed")

    def test_product_detail_url_covers_indicator_feed_and_threat_actor_profile(self):
        with self.app.test_request_context("/"):
            self.assertEqual(
                product_detail_url("indicator-feed", "feed-1", fallback_url="/fallback"),
                "/products/indicator-feed/feed-1",
            )
            self.assertEqual(
                product_detail_url("Threat actor profile", "tap-1", fallback_url="/fallback"),
                "/products/threat-actor-profile/tap-1",
            )


if __name__ == "__main__":
    unittest.main()
