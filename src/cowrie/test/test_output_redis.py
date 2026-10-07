# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The redis output plugin must send events on the reactor through txredisapi,
# ABOUTME: in order, hold them while the server is away, and never block.

from __future__ import annotations

import json
import os
import tempfile
import unittest
from configparser import NoOptionError
from typing import Any
from unittest.mock import Mock, patch

import txredisapi
from twisted.internet import error
from twisted.internet.address import IPv4Address
from twisted.internet.testing import MemoryReactorClock, StringTransport
from twisted.python.failure import Failure

from cowrie.output import redis

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

BASE_CONFIG: dict[str, Any] = {
    "host": "redis.example",
    "port": 6380,
    "keyname": "events",
}


def _config(options: dict[str, Any]) -> Mock:
    def get(section: str, key: str, **kwargs: Any) -> Any:
        if key not in options:
            raise NoOptionError(key, section)
        return options[key]

    config = Mock()
    config.get.side_effect = get
    config.getint.side_effect = get
    return config


def _parse_commands(data: bytes) -> list[list[str]]:
    """Decode RESP arrays of bulk strings, as a Redis client sends them."""
    commands = []
    lines = data.split(b"\r\n")
    i = 0
    while i < len(lines) - 1:
        count = int(lines[i][1:])
        i += 1
        args = []
        for _ in range(count):
            args.append(lines[i + 1].decode())
            i += 2
        commands.append(args)
    return commands


class Server:
    """The server side of one Redis connection, scripted command by command."""

    def __init__(self, reactor: MemoryReactorClock) -> None:
        factory: Any = reactor.tcpClients[0][2]
        factory.clock = reactor
        proto = factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 6380))
        assert proto is not None
        self.proto = proto
        self.transport = StringTransport()
        self.proto.makeConnection(self.transport)

    def commands(self, reply: bytes = b":1\r\n") -> list[list[str]]:
        """Answer every command sent since last call; return them in order."""
        commands = _parse_commands(self.transport.value())
        self.transport.clear()
        for _ in commands:
            self.proto.dataReceived(reply)
        return commands

    def lose(self) -> None:
        self.proto.connectionLost(Failure(error.ConnectionDone()))


class RedisOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = MemoryReactorClock()
        target = patch.object(txredisapi, "reactor", self.reactor)
        target.start()
        self.addCleanup(target.stop)

    def start(self, **options: Any) -> Any:
        with patch.object(redis.Output, "start", lambda self: None):
            out = redis.Output()
        with patch.object(redis, "CowrieConfig", _config(BASE_CONFIG | options)):
            out.start()
        self.addCleanup(out.stop)
        return out

    def connected(self) -> Server:
        server = Server(self.reactor)
        self.assertEqual(server.commands(reply=b"+OK\r\n"), [["SELECT", "0"]])
        return server

    def test_connects_to_configured_host_and_port(self) -> None:
        self.start()
        host, port, _, _, _ = self.reactor.tcpClients[0]
        self.assertEqual((host, port), ("redis.example", 6380))

    def test_authenticates_and_selects_configured_db(self) -> None:
        self.start(password="secret", db=3)
        server = Server(self.reactor)
        self.assertEqual(server.commands(reply=b"+OK\r\n"), [["AUTH", "secret"]])
        self.assertEqual(server.commands(reply=b"+OK\r\n"), [["SELECT", "3"]])

    def test_lpush_is_the_default_send_method(self) -> None:
        out = self.start()
        server = self.connected()
        out.write({"eventid": "cowrie.session.connect", "log_level": "info"})
        ((command, key, message),) = server.commands()
        self.assertEqual((command, key), ("LPUSH", "events"))
        self.assertEqual(json.loads(message), {"eventid": "cowrie.session.connect"})

    def test_configured_send_methods(self) -> None:
        for method in ("rpush", "publish"):
            with self.subTest(method=method):
                self.reactor.tcpClients.clear()
                out = self.start(send_method=method)
                server = self.connected()
                out.write({"eventid": "e"})
                ((command, key, _),) = server.commands()
                self.assertEqual((command, key), (method.upper(), "events"))

    def test_unknown_send_method_falls_back_to_lpush(self) -> None:
        out = self.start(send_method="sadd")
        server = self.connected()
        out.write({"eventid": "e"})
        self.assertEqual(server.commands()[0][0], "LPUSH")

    def test_events_before_connection_are_sent_in_order(self) -> None:
        out = self.start()
        for eventid in ("a", "b", "c"):
            out.write({"eventid": eventid})
        server = self.connected()
        self.assertEqual(
            [json.loads(c[2])["eventid"] for c in server.commands()], ["a", "b", "c"]
        )

    def test_events_after_connection_loss_are_sent_after_reconnect(self) -> None:
        out = self.start()
        first = self.connected()
        first.lose()
        out.write({"eventid": "during-outage"})
        self.assertEqual(first.transport.value(), b"")
        second = self.connected()
        self.assertEqual(
            [json.loads(c[2])["eventid"] for c in second.commands()], ["during-outage"]
        )

    def test_pending_writes_are_bounded(self) -> None:
        out = self.start()
        out.max_pending = 2
        for eventid in ("a", "b", "c"):
            out.write({"eventid": eventid})
        self.assertEqual(out.dropped, 1)
        server = self.connected()
        self.assertEqual(
            [json.loads(c[2])["eventid"] for c in server.commands()], ["a", "b"]
        )
        self.assertEqual(out.pending, 0)
        self.assertEqual(out.dropped, 0)

    def test_error_reply_is_logged_and_released(self) -> None:
        out = self.start()
        server = self.connected()
        out.write({"eventid": "a"})
        with patch.object(out, "_log") as log:
            server.commands(reply=b"-WRONGTYPE Operation against a key\r\n")
        self.assertEqual(out.pending, 0)
        log.warn.assert_called_once()
        self.assertIn("WRONGTYPE", log.warn.call_args.kwargs["reason"])

    def test_stop_disconnects(self) -> None:
        out = self.start()
        server = self.connected()
        out.stop()
        self.assertTrue(server.transport.disconnecting)


class OutputRedisHardeningTests(unittest.TestCase):
    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never connected."""
        with patch.object(redis.Output, "start", lambda self: None):
            out = redis.Output()
        out.stop()


if __name__ == "__main__":
    unittest.main()
