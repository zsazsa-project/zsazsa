"""A config file from before a product existed still runs (product tag settings).

Each CTI product added after the first release brought a TAG_* setting, and a
config/__init__.py written before then has none: saving the Settings page is
what adds it. Pages read the setting directly, so on such an install the
product's list failed with "module 'config' has no attribute 'TAG_DETECTION_ENG'".
The webapp now gives a missing setting the tag zsazsa ships with.

    python -m unittest tests.test_older_config
"""

import unittest
from unittest import mock

import config
from webapp import misp_store, utils


class MissingProductTags(unittest.TestCase):
    def setUp(self):
        saved = {attr: getattr(config, attr) for attr, _b, _e in utils._PRODUCT_TYPES.values()
                 if hasattr(config, attr)}
        self.addCleanup(lambda: [setattr(config, k, v) for k, v in saved.items()])

    def test_a_missing_tag_gets_the_one_zsazsa_ships_with(self):
        del config.TAG_DETECTION_ENG
        utils.fill_product_tag_defaults()
        self.assertEqual(config.TAG_DETECTION_ENG, 'zsazsa:ctiproduct="detection-eng-request"')

    def test_the_product_list_works_without_the_setting(self):
        """The error from the production report."""
        del config.TAG_DETECTION_ENG
        utils.fill_product_tag_defaults()
        with mock.patch.object(misp_store, "_misp"), \
             mock.patch.object(misp_store, "_search_all", return_value=[]) as search:
            self.assertEqual(misp_store.list_ders(), [])
        self.assertEqual(search.call_args.kwargs["tags"], ['zsazsa:ctiproduct="detection-eng-request"'])

    def test_a_configured_tag_is_left_alone(self):
        config.TAG_DETECTION_ENG = 'zsazsa:ctiproduct="detection-request"'
        utils.fill_product_tag_defaults()
        self.assertEqual(config.TAG_DETECTION_ENG, 'zsazsa:ctiproduct="detection-request"')


if __name__ == "__main__":
    unittest.main()
