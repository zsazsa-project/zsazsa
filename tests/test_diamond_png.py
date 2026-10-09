"""The Diamond Model image is served without a session only on a signed URL (GHSA-x326-2rwv-jc78).

Mattermost and the chat clients showing a notification fetch the image by URL,
so the route skips login. It used to take any id and hand it to MISP, which
also resolves numeric event ids, so anyone could walk 1, 2, 3 and get every
threat actor profile, drafts and TLP:RED included. Now the URL carries an HMAC
of the profile UUID, checked before MISP is asked, and only a published
profile is served.

    python -m unittest tests.test_diamond_png
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlsplit

import config as _config
from webapp import collection_cache, create_app, misp_session, misp_store
from webapp.routes import threat_actor_profile

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
OTHER_UUID = "0e1d2c3b-4a59-4687-9a0b-c1d2e3f40516"
def _profile(status):
    return SimpleNamespace(uuid=UUID, id=UUID, tap_id="TAP-001", status=status,
                           tlp="red", audience=[], linked_pir_uuid="")


PUBLISHED = _profile("Published")
DRAFT = _profile("Draft")


class AppCase(unittest.TestCase):
    # Whether single sign-on is on, with the redirect to the MISP login.
    sso = True

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cookie_name = "MISP-test" if self.sso else ""
        patches = [
            mock.patch.multiple(_config, create=True,
                                DB_FILE=str(Path(tmp.name) / "test.db"),
                                LOG_FILE=str(Path(tmp.name) / "test.log"),
                                MISP_SESSION_REDIRECT_TO_LOGIN=self.sso,
                                MISP_SESSION_COOKIE_NAME=cookie_name),
            mock.patch.object(misp_session, "_session_cookie_name", return_value=cookie_name),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(threat_actor_profile, "render_diamond_png", return_value=b"\x89PNG"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.app = create_app()
        self.client = self.app.test_client()

    def signature(self, uuid):
        with self.app.test_request_context():
            return threat_actor_profile._diamond_signature(uuid)

    def profile(self, tap):
        patcher = mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap)
        lookup = patcher.start()
        self.addCleanup(patcher.stop)
        return lookup


class SignedImageUrl(AppCase):
    """Single sign-on with the login redirect on, so a request without a session
    reaching the image at all shows the route is still public."""

    def get(self, id, sig=None):
        query = {} if sig is None else {"sig": sig}
        return self.client.get(f"/products/threat-actor-profile/{id}/diamond.png", query_string=query)

    def test_walking_event_ids_gets_nothing(self):
        """The advisory's reproduction: no session, sequential MISP event ids."""
        lookup = self.profile(PUBLISHED)
        for event_id in range(1, 6):
            with self.subTest(event_id=event_id):
                self.assertEqual(self.get(event_id).status_code, 404)
        lookup.assert_not_called()

    def test_a_published_profile_is_served_on_its_signed_url(self):
        self.profile(PUBLISHED)
        resp = self.get(UUID, self.signature(UUID))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "image/png")

    def test_refused_before_misp_is_asked(self):
        cases = {
            "a numeric event id": ("1", self.signature("1")),
            "no signature": (UUID, None),
            "an empty signature": (UUID, ""),
            "a wrong signature": (UUID, "0" * 64),
            "another profile's signature": (UUID, self.signature(OTHER_UUID)),
            "a signature that is not ASCII": (UUID, "é" * 64),
        }
        lookup = self.profile(PUBLISHED)
        for case, (id, sig) in cases.items():
            with self.subTest(case):
                self.assertEqual(self.get(id, sig).status_code, 404)
        lookup.assert_not_called()

    def test_a_draft_is_not_served(self):
        self.profile(DRAFT)
        self.assertEqual(self.get(UUID, self.signature(UUID)).status_code, 404)

    def test_a_missing_profile_is_not_served(self):
        self.profile(None)
        self.assertEqual(self.get(UUID, self.signature(UUID)).status_code, 404)

    def test_every_refusal_looks_the_same(self):
        """A caller must not learn which ids exist from the answer."""
        self.profile(None)
        missing = self.get(UUID, self.signature(UUID))
        unsigned = self.get(UUID)
        self.assertEqual((missing.status_code, missing.data), (unsigned.status_code, unsigned.data))

    def test_another_secret_key_gives_another_signature(self):
        signature = self.signature(UUID)
        with mock.patch.dict(self.app.config, SECRET_KEY="rotated"):
            self.assertNotEqual(self.signature(UUID), signature)


class NotificationUrl(AppCase):
    """The URL a notification sends to Mattermost is one the route accepts.
    Without single sign-on, so the request may notify as the trusted identity."""

    sso = False

    def test_the_mattermost_image_url_works(self):
        self.profile(PUBLISHED)
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "token"
        with mock.patch("webapp.notify_jobs.start") as start:
            self.client.post(f"/products/threat-actor-profile/{UUID}/notify",
                             headers={"X-CSRF-Token": "token"})
        deliver = start.call_args.args[2]

        with mock.patch.object(misp_store, "recipient_preview", return_value=[]), \
             mock.patch.object(misp_store, "list_stakeholders", return_value=[]), \
             mock.patch.object(threat_actor_profile, "_markdown", return_value=""), \
             mock.patch.object(threat_actor_profile, "_linked_feeds_markdown", return_value=""), \
             mock.patch.object(threat_actor_profile.dispatcher, "send_threat_actor_profile",
                               return_value={}) as send:
            deliver(lambda message: None)
        url = urlsplit(send.call_args.kwargs["diamond_url"])

        self.assertIn("sig=", url.query)
        resp = self.client.get(f"{url.path}?{url.query}")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
