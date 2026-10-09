"""The PyMISP script export of an indicator feed.

The script is code written from what analysts typed, the feed name and every
query value, and it is meant to be run elsewhere. So it has to compile, run the
same search the feed runs, carry no credential, and keep a hostile value a
string rather than letting it end the literal it sits in.

    python -m unittest tests.test_indicator_feed_pymisp_script
"""

import contextlib
import io
import os
import unittest
from datetime import date, timedelta
from types import SimpleNamespace
from unittest import mock

from flask import Flask

from webapp import misp_store
from webapp.routes import indicator_feed

_UUID = "u" * 36
# Everything that could end a string, a comment or a docstring, or start a new line of code.
_HOSTILE = 'x\'"\n"""\'\'\'\\\nimport os; os.system("id") #}}{{\r\x00'


def _feed(**over):
    data = dict(uuid=_UUID, id=_UUID, feed_id="FEED-001", name="Ports & Terminals",
                description="", query={"types": ["ip-dst"]}, tlp="amber", audience="",
                author="", linked_pir_uuid="", creator="", token="secret-feed-token", public_url_enabled=True,
                cache_interval="", cache_anchor="", feedback_by=None, created_at=None)
    data.update(over)
    return SimpleNamespace(**data)


class _FakeMISP:
    """Stands in for PyMISP: records the search it is asked for."""

    def __init__(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs
        self.searched = None

    def search(self, **kwargs):
        self.searched = kwargs
        return {"Attribute": [
            {"type": "ip-dst", "value": "1.2.3.4", "timestamp": "10", "to_ids": True,
             "event_id": "7", "Event": {"info": "Campaign", "date": "2026-09-01"}},
            {"type": "ip-dst", "value": "1.2.3.4", "timestamp": "30", "event_id": "8"},
            {"type": "domain", "value": "evil.example", "timestamp": "20", "event_id": "7"},
        ]}


def _load(src):
    """The script as a module, without running its main()."""
    ns = {"__name__": "feed_script"}
    exec(compile(src, "feed_script.py", "exec"), ns)
    return ns


class Script(unittest.TestCase):
    def test_it_compiles(self):
        for filters in ({}, {"types": ["ip-dst", "domain"], "to_ids": "yes", "published": "no",
                             "enforce_warninglist": "yes", "orgs_include": ["CIRCL"],
                             "orgs_exclude": ["Bad"], "tags_include": ["tlp:clear"],
                             "tags_exclude": ["false-positive"], "events_include": ["12"],
                             "attr_after": "2026-01-01", "event_before": "2026-02-01",
                             "limit": 500}):
            with self.subTest(filters=filters):
                compile(misp_store.pymisp_script(filters, _feed()), "x", "exec")

    def test_it_runs_the_search_the_feed_runs(self):
        filters = {"types": ["ip-dst"], "tags_include": ["tlp:clear", "apt"],
                   "tags_exclude": ["fp"], "orgs_exclude": ["Bad"], "limit": 250}
        misp = _FakeMISP()
        _load(misp_store.pymisp_script(filters, _feed()))["search"](misp)
        self.assertEqual(misp.searched, misp_store._indicator_search_kwargs(filters))

    def test_a_hostile_name_and_query_stay_strings(self):
        filters = {"types": [_HOSTILE], "tags_include": [_HOSTILE], "tags_exclude": [_HOSTILE],
                   "orgs_include": [_HOSTILE], "events_include": [_HOSTILE],
                   "attr_after": _HOSTILE, "event_after": _HOSTILE}
        feed = _feed(feed_id=_HOSTILE, name=_HOSTILE, tlp=_HOSTILE)
        src = misp_store.pymisp_script(filters, feed)
        compile(src, "x", "exec")
        ns = _load(src)
        self.assertEqual(ns["FEED"], {"id": _HOSTILE, "name": _HOSTILE, "tlp": _HOSTILE})
        misp = _FakeMISP()
        ns["search"](misp)
        self.assertEqual(misp.searched, misp_store._indicator_search_kwargs(filters))
        # The value never appears raw, so it cannot have become code or a comment.
        self.assertNotIn(_HOSTILE, src)

    def test_it_carries_no_credential_or_feed_token(self):
        with mock.patch.object(misp_store.config, "MISP_URL", "https://misp.internal", create=True), \
                mock.patch.object(misp_store.config, "MISP_KEY", "k" * 40, create=True):
            src = misp_store.pymisp_script({"types": ["ip-dst"]}, _feed())
        self.assertNotIn("secret-feed-token", src)
        self.assertNotIn("misp.internal", src)
        self.assertNotIn("k" * 40, src)
        self.assertIn('os.environ.get("MISP_KEY")', src)

    def test_relative_ranges_are_worked_out_when_it_runs(self):
        filters = {"event_last": "7", "attr_last": "today"}
        src = misp_store.pymisp_script(filters, _feed())
        self.assertIn("timedelta(days=7)", src)
        misp = _FakeMISP()
        _load(src)["search"](misp)
        self.assertEqual(misp.searched["date_from"], (date.today() - timedelta(days=7)).isoformat())
        self.assertEqual(misp.searched["timestamp"], date.today().isoformat())

    def _main(self, *argv, env=None, tlp="amber"):
        ns = _load(misp_store.pymisp_script({"types": ["ip-dst"]}, _feed(tlp=tlp)))
        made = []
        ns["PyMISP"] = lambda *a, **k: made.append(_FakeMISP(*a, **k)) or made[-1]
        out, self.err = io.StringIO(), io.StringIO()
        env = {"MISP_URL": "https://misp.example", "MISP_KEY": "key"} if env is None else env
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("sys.argv", ["feed.py", *argv]), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(self.err):
            ns["main"]()
        return out.getvalue(), made

    def test_it_prints_each_value_once_newest_first(self):
        out, made = self._main()
        self.assertEqual(out.splitlines(), ["1.2.3.4", "evil.example"])
        self.assertEqual(made[0].args, ("https://misp.example", "key"))
        self.assertEqual(made[0].kwargs, {"ssl": True})

    def test_csv_lists_every_attribute(self):
        out, _ = self._main("--csv")
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("Event ID,"))
        self.assertEqual(len(lines), 4)

    def test_the_certificate_check_can_be_turned_off(self):
        _, made = self._main(env={"MISP_URL": "u", "MISP_KEY": "k", "MISP_VERIFY_CERT": "false"})
        self.assertEqual(made[0].kwargs, {"ssl": False})

    def test_it_states_the_feed_tlp_on_stderr(self):
        for argv in ((), ("--csv",)):
            with self.subTest(argv=argv):
                out, _ = self._main(*argv, tlp="amber+strict")
                self.assertIn("TLP:AMBER+STRICT", self.err.getvalue())
                self.assertNotIn("TLP", out)

    def test_a_feed_without_a_tlp_prints_no_marking(self):
        self._main(tlp="")
        self.assertEqual(self.err.getvalue(), "")

    def test_it_refuses_to_run_without_a_server_and_key(self):
        with self.assertRaises(SystemExit):
            self._main(env={})


def _client():
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(indicator_feed.bp)
    return app.test_client()


class Route(unittest.TestCase):
    def setUp(self):
        self.client = _client()
        self.search = mock.patch.object(misp_store, "search_indicators").start()
        self.addCleanup(mock.patch.stopall)

    def test_a_saved_feed_downloads_as_a_python_file_without_searching(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=_feed()):
            r = self.client.get(f"/products/indicator-feed/{_UUID}/pymisp.py")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "text/x-python")
        self.assertIn('filename="ports-terminals.py"', r.headers["Content-Disposition"])
        compile(r.data.decode(), "x", "exec")
        self.assertIn("type_attribute=['ip-dst']", r.data.decode())
        self.search.assert_not_called()

    def test_an_unknown_feed_is_not_found(self):
        with mock.patch.object(misp_store, "get_indicator_feed", return_value=None):
            self.assertEqual(self.client.get(f"/products/indicator-feed/{_UUID}/pymisp.py").status_code, 404)

    def test_an_unsaved_query_downloads_from_its_filters(self):
        r = self.client.get("/products/indicator-feed/pymisp.py?types=domain&limit=5")
        self.assertIn("type_attribute=['domain']", r.data.decode())
        self.assertIn("limit=5", r.data.decode())

    def test_it_is_not_one_of_the_feed_formats(self):
        # The public URL and the cache serve INDICATOR_FORMATS: a script is neither.
        self.assertNotIn("py", misp_store.INDICATOR_FORMATS)


if __name__ == "__main__":
    unittest.main()
