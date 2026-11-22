"""A CTI product with its own page is registered everywhere it has to be.

webapp.utils._PRODUCT_TYPES names, per product, the config setting holding its
MISP tag, the tag value zsazsa ships with, and the endpoints of its detail page
and its list. Those live in three files, and the product also has to be in the
list an analyst picks from and described in README.md. Nothing fails at startup
when one of them is missed: the product simply has no page, or has a tag no
search looks for.

    python -m unittest tests.test_product_registry
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config
from webapp import collection_cache, create_app
from webapp.utils import PRODUCT_TAG_PREFIX, _PRODUCT_TYPES, product_list_url

ROOT = Path(__file__).parent.parent


def _shipped_settings():
    """What config/__init__.py.example gives a fresh install, as Python values.

    Not the live config: that one is gitignored and the Settings page rewrites
    it, so an admin who renames a tag or drops a product from the list would
    otherwise fail this on their own checkout.
    """
    path = ROOT / "config" / "__init__.py.example"
    namespace = {}
    exec(compile(path.read_text(), str(path), "exec"), namespace)
    return {k: v for k, v in namespace.items() if k.isupper()}


class ProductRegistry(unittest.TestCase):
    def setUp(self):
        self.shipped = _shipped_settings()

    def test_detail_and_list_pages_exist(self):
        # The real app, so a product whose blueprint create_app never registers
        # fails here rather than 404ing in a browser. Database, log and cache
        # worker are pointed somewhere harmless.
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(collection_cache, "start_worker"):
            app = create_app()

        for label, (_, _, endpoint, list_endpoint) in _PRODUCT_TYPES.items():
            with self.subTest(product=label):
                self.assertIn(endpoint, app.view_functions)
                # The list is the page the product's blueprint opens on.
                blueprint = app.blueprints[endpoint.split(".")[0]]
                with app.test_request_context():
                    self.assertEqual(product_list_url(label), f"{blueprint.url_prefix}/")
        with app.test_request_context():
            self.assertEqual(product_list_url("Weekly digest"), "")

    def test_tag_setting_ships_with_the_builtin_value(self):
        for label, (setting, builtin, _, _) in _PRODUCT_TYPES.items():
            with self.subTest(product=label):
                self.assertEqual(self.shipped.get(setting),
                                 f'{PRODUCT_TAG_PREFIX}"{builtin}"')

    def test_offered_and_documented(self):
        readme = (ROOT / "README.md").read_text().lower()
        for label in _PRODUCT_TYPES:
            with self.subTest(product=label):
                self.assertIn(label, self.shipped["PRODUCT_TYPES"])
                self.assertIn(label.lower(), readme)


if __name__ == "__main__":
    unittest.main()
