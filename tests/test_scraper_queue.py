"""Tests for the misp-scraper Redis publisher and the RESP helpers.

A fake socket captures the bytes sent and feeds canned replies, so the tests
run with no network and no real Redis.

    python -m unittest tests.test_scraper_queue
"""

import json
import unittest
from unittest import mock

import config
from webapp import redis_client, scraper_queue


class FakeSocket:
    def __init__(self, reply: bytes):
        self.sent = b""
        self._reply = reply
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        chunk, self._reply = self._reply[:n], self._reply[n:]
        return chunk

    def close(self):
        self.closed = True


class RespHelpers(unittest.TestCase):
    def test_send_command_encodes_resp_array(self):
        sock = FakeSocket(b"")
        redis_client.send_command(sock, "PUBLISH", "urls", "hi")
        self.assertEqual(sock.sent, b"*3\r\n$7\r\nPUBLISH\r\n$4\r\nurls\r\n$2\r\nhi\r\n")

    def test_read_reply_integer(self):
        self.assertEqual(redis_client.read_reply(FakeSocket(b":2\r\n")), 2)

    def test_read_reply_simple_string(self):
        self.assertEqual(redis_client.read_reply(FakeSocket(b"+OK\r\n")), b"OK")

    def test_read_reply_error_raises(self):
        with self.assertRaises(redis_client.RedisError):
            redis_client.read_reply(FakeSocket(b"-NOAUTH required\r\n"))

    def test_read_reply_closed_socket_raises(self):
        with self.assertRaises(redis_client.RedisError):
            redis_client.read_reply(FakeSocket(b""))


class Publish(unittest.TestCase):
    def setUp(self):
        self._orig = (config.SCRAPER_REDIS_HOST, config.SCRAPER_REDIS_PORT,
                      config.SCRAPER_REDIS_PASSWORD, config.SCRAPER_REDIS_CHANNEL)
        config.SCRAPER_REDIS_HOST = "redis.test"
        config.SCRAPER_REDIS_PORT = 6379
        config.SCRAPER_REDIS_PASSWORD = ""
        config.SCRAPER_REDIS_CHANNEL = "urls"
        self.fake = FakeSocket(b":1\r\n")  # one subscriber received it
        self._created = []

        def fake_create_connection(addr, timeout=None):
            self._created.append(addr)
            return self.fake

        self._orig_conn = scraper_queue.socket.create_connection
        scraper_queue.socket.create_connection = fake_create_connection

    def tearDown(self):
        scraper_queue.socket.create_connection = self._orig_conn
        (config.SCRAPER_REDIS_HOST, config.SCRAPER_REDIS_PORT,
         config.SCRAPER_REDIS_PASSWORD, config.SCRAPER_REDIS_CHANNEL) = self._orig

    def test_publish_returns_subscriber_count_and_sends_payload(self):
        message = {"link": "https://x", "title": "T", "feed_title": "ETDA CTI Robot",
                   "feed": "ETDA CTI Robot", "feed_tags": ['zsazsa:newsletter-priority="critical"']}
        received = scraper_queue.publish(message)

        self.assertEqual(received, 1)
        self.assertEqual(self._created, [("redis.test", 6379)])
        self.assertTrue(self.fake.closed)
        # The PUBLISH carries the channel and the JSON payload verbatim.
        self.assertIn(b"PUBLISH", self.fake.sent)
        self.assertIn(b"urls", self.fake.sent)
        self.assertIn(json.dumps(message).encode(), self.fake.sent)

    def test_publish_with_no_subscriber_returns_zero(self):
        self.fake = FakeSocket(b":0\r\n")
        scraper_queue.socket.create_connection = lambda addr, timeout=None: self.fake
        self.assertEqual(scraper_queue.publish({"link": "https://x"}), 0)

    def test_publish_authenticates_when_password_set(self):
        config.SCRAPER_REDIS_PASSWORD = "pw"
        self.fake = FakeSocket(b"+OK\r\n:1\r\n")  # AUTH reply, then PUBLISH reply
        scraper_queue.socket.create_connection = lambda addr, timeout=None: self.fake
        self.assertEqual(scraper_queue.publish({"link": "https://x"}), 1)
        self.assertIn(b"AUTH", self.fake.sent)
        self.assertIn(b"pw", self.fake.sent)


class Target(unittest.TestCase):
    """The delivery warning names where it published, because a PUBLISH that
    reached nobody looks the same whether the scraper is down or subscribed to
    a different Redis."""

    def test_it_names_the_channel_and_the_instance(self):
        with mock.patch.object(scraper_queue.config, "SCRAPER_REDIS_HOST", "10.0.0.9"), \
             mock.patch.object(scraper_queue.config, "SCRAPER_REDIS_PORT", 6380), \
             mock.patch.object(scraper_queue.config, "SCRAPER_REDIS_CHANNEL", "urls"):
            self.assertEqual(scraper_queue.target(), "channel 'urls' on 10.0.0.9:6380")


if __name__ == "__main__":
    unittest.main()
