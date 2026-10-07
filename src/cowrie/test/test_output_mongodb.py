# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The mongodb output plugin must write events on the reactor through txmongo,
# ABOUTME: one server-side operation per event, in order, and never block.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import Mock, patch

import bson
import txmongo.connection
import txmongo.utils
from twisted.internet import error
from twisted.internet.address import IPv4Address
from twisted.internet.testing import MemoryReactorClock, StringTransport
from twisted.python.failure import Failure
from txmongo.protocol import MongoDecoder, Msg, Query, Reply

from cowrie.output import mongodb

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

CONFIG = {
    "connection_string": "mongodb://db.example:27018/",
    "database": "honeypot",
}


def _config() -> Mock:
    config = Mock()
    config.get.side_effect = lambda section, key, **kwargs: CONFIG[key]
    return config


class Server:
    """
    The server side of one MongoDB connection, scripted message by
    message with txmongo's own wire codec: an ismaster handshake over
    OP_QUERY, then commands over OP_MSG.
    """

    def __init__(self, reactor: MemoryReactorClock) -> None:
        factory: Any = reactor.tcpClients[0][2]
        factory.clock = reactor
        proto = factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 27018))
        assert proto is not None
        self.proto = proto
        self.transport = StringTransport()
        self.proto.makeConnection(self.transport)
        self.decoder = MongoDecoder()
        self.next_id = 1

    def _messages(self) -> list[Any]:
        self.decoder.feed(self.transport.value())
        self.transport.clear()
        messages = []
        while (message := next(self.decoder)) is not None:
            messages.append(message)
        return messages

    def _send(self, message: Any) -> None:
        self.next_id += 1
        self.proto.dataReceived(message.encode(self.next_id))

    def hello(self) -> None:
        (query,) = self._messages()
        assert isinstance(query, Query)
        hello = {"ok": 1, "ismaster": True, "minWireVersion": 0, "maxWireVersion": 21}
        self._send(Reply(response_to=query.request_id, documents=[bson.encode(hello)]))

    def commands(self, reply: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Answer every command sent since last call; return them in order."""
        result = []
        for message in self._messages():
            assert isinstance(message, Msg)
            command = message.to_dict()
            self._send(
                Msg.create(reply or {"ok": 1, "n": 1}, response_to=message.request_id)
            )
            result.append(command)
        return result

    def writes(self) -> list[tuple[str, str, Any]]:
        """Return (operation, collection, document or update) per command."""
        result: list[tuple[str, str, Any]] = []
        for command in self.commands():
            if "insert" in command:
                for document in command["documents"]:
                    document.pop("_id")
                    result.append(("insert", command["insert"], document))
            elif "update" in command:
                for update in command["updates"]:
                    result.append(("update", command["update"], update))
        return result

    def lose(self) -> None:
        self.proto.connectionLost(Failure(error.ConnectionDone()))


class MongoDBOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = MemoryReactorClock()
        for target in (
            patch.object(txmongo.connection, "reactor", self.reactor),
            patch.object(txmongo.utils, "reactor", self.reactor),
        ):
            target.start()
            self.addCleanup(target.stop)
        with patch.object(mongodb.Output, "start", lambda self: None):
            self.out = mongodb.Output()
        with patch.object(mongodb, "CowrieConfig", _config()):
            self.out.start()
        self.addCleanup(self.out.stop)

    def connected(self) -> Server:
        server = Server(self.reactor)
        server.hello()
        return server

    def test_connects_to_host_in_connection_string(self) -> None:
        host, port, _, _, _ = self.reactor.tcpClients[0]
        self.assertEqual((host, port), ("db.example", 27018))

    def test_session_connect_upserts_sensor_and_inserts_session(self) -> None:
        server = self.connected()
        self.out.write(
            {
                "eventid": "cowrie.session.connect",
                "session": "s1",
                "sensor": self.out.sensor,
                "timestamp": "t0",
            }
        )
        sensor, session = server.writes()
        self.assertEqual(
            sensor,
            (
                "update",
                "sensors",
                {
                    "q": {"sensor": self.out.sensor},
                    "u": {
                        "$setOnInsert": {
                            "eventid": "cowrie.session.connect",
                            "session": "s1",
                            "timestamp": "t0",
                        }
                    },
                    "upsert": True,
                    "multi": False,
                },
            ),
        )
        self.assertEqual(
            session,
            (
                "insert",
                "sessions",
                {
                    "eventid": "cowrie.session.connect",
                    "session": "s1",
                    "sensor": self.out.sensor,
                    "timestamp": "t0",
                    "starttime": "t0",
                    "endtime": None,
                    "sshversion": None,
                    "termsize": None,
                },
            ),
        )

    def test_session_updates_set_fields_without_reading_first(self) -> None:
        server = self.connected()
        self.out.write(
            {"eventid": "cowrie.client.version", "session": "s1", "version": "SSH-2.0"}
        )
        self.out.write(
            {
                "eventid": "cowrie.client.size",
                "session": "s1",
                "width": 80,
                "height": 24,
            }
        )
        self.out.write(
            {"eventid": "cowrie.session.closed", "session": "s1", "timestamp": "t9"}
        )
        self.assertEqual(
            [(op, col, u["q"], u["u"]) for op, col, u in server.writes()],
            [
                (
                    "update",
                    "sessions",
                    {"session": "s1"},
                    {"$set": {"sshversion": "SSH-2.0"}},
                ),
                (
                    "update",
                    "sessions",
                    {"session": "s1"},
                    {"$set": {"termsize": "80x24"}},
                ),
                ("update", "sessions", {"session": "s1"}, {"$set": {"endtime": "t9"}}),
            ],
        )

    def test_events_go_to_their_collections_without_legacy_keys(self) -> None:
        server = self.connected()
        for eventid in (
            "cowrie.login.success",
            "cowrie.login.failed",
            "cowrie.command.input",
            "cowrie.command.failed",
            "cowrie.session.file_download",
            "cowrie.client.fingerprint",
            "cowrie.direct-tcpip.request",
            "cowrie.direct-tcpip.data",
            "cowrie.something.else",
        ):
            self.out.write({"eventid": eventid, "log_level": "info"})
        self.assertEqual(
            [(col, doc) for _, col, doc in server.writes()],
            [
                ("auth", {"eventid": "cowrie.login.success"}),
                ("auth", {"eventid": "cowrie.login.failed"}),
                ("input", {"eventid": "cowrie.command.input"}),
                ("input", {"eventid": "cowrie.command.failed"}),
                ("downloads", {"eventid": "cowrie.session.file_download"}),
                ("keyfingerprints", {"eventid": "cowrie.client.fingerprint"}),
                ("ipforwards", {"eventid": "cowrie.direct-tcpip.request"}),
                ("ipforwardsdata", {"eventid": "cowrie.direct-tcpip.data"}),
                ("event", {"eventid": "cowrie.something.else"}),
            ],
        )

    def test_events_before_connection_are_written_in_order(self) -> None:
        self.out.write(
            {"eventid": "cowrie.session.connect", "session": "s1", "timestamp": "t0"}
        )
        self.out.write(
            {"eventid": "cowrie.client.version", "session": "s1", "version": "v"}
        )
        server = self.connected()
        self.assertEqual(
            [(op, col) for op, col, _ in server.writes()],
            [("update", "sensors"), ("insert", "sessions"), ("update", "sessions")],
        )

    def test_events_after_connection_loss_are_written_after_reconnect(self) -> None:
        first = self.connected()
        first.lose()
        self.out.write({"eventid": "cowrie.login.success"})
        self.assertEqual(first.transport.value(), b"")
        second = self.connected()
        self.assertEqual(
            second.writes(), [("insert", "auth", {"eventid": "cowrie.login.success"})]
        )

    def test_pending_writes_are_bounded(self) -> None:
        self.out.max_pending = 2
        for eventid in ("a", "b", "c"):
            self.out.write({"eventid": eventid})
        self.assertEqual(self.out.dropped, 1)
        server = self.connected()
        self.assertEqual([doc["eventid"] for _, _, doc in server.writes()], ["a", "b"])
        self.assertEqual(self.out.pending, 0)
        self.assertEqual(self.out.dropped, 0)

    def test_failed_write_is_logged_and_released(self) -> None:
        server = self.connected()
        self.out.write({"eventid": "a"})
        with patch.object(self.out, "_log") as log:
            server.commands(reply={"ok": 0, "errmsg": "no space", "code": 14031})
        self.assertEqual(self.out.pending, 0)
        log.warn.assert_called_once()
        self.assertIn("no space", log.warn.call_args.kwargs["reason"])

    def test_stop_disconnects(self) -> None:
        server = self.connected()
        self.out.stop()
        self.assertTrue(server.transport.disconnecting)


class OutputMongodbHardeningTests(unittest.TestCase):
    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never connected."""
        with patch.object(mongodb.Output, "start", lambda self: None):
            out = mongodb.Output()
        out.stop()


if __name__ == "__main__":
    unittest.main()
