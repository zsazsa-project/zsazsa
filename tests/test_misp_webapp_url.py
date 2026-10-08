"""The misp_webapp_url template global has no trailing slash.

Templates append paths such as "/admin/users/view/1" to it, and a config file
edited by hand or saved by an older version can still end in a slash.

    python -m unittest tests.test_misp_webapp_url
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import render_template_string

import config
from webapp import collection_cache, create_app


class MispWebappUrlGlobal(unittest.TestCase):
    def test_a_trailing_slash_is_dropped(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db"), create=True), \
             mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log"), create=True), \
             mock.patch.object(config, "MISP_WEBAPP_URL", "https://misp.example/"), \
             mock.patch.object(collection_cache, "start_worker"):
            app = create_app()
            with app.test_request_context("/"):
                rendered = render_template_string("{{ misp_webapp_url }}/admin/users/view/1")
        self.assertEqual(rendered, "https://misp.example/admin/users/view/1")


if __name__ == "__main__":
    unittest.main()
