# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The rethinkdblog output plugin must insert events on the reactor through
# ABOUTME: the driver's Twisted mode, queue them while the server is away, and never block.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import tempfile
import unittest
import warnings
from collections import deque
from typing import Any
from unittest.mock import Mock, patch

from rethinkdb import ql2_pb2
from rethinkdb.twisted_net import net_twisted
from twisted.internet import error
from twisted.internet.address import IPv4Address
from twisted.internet.testing import MemoryReactorClock, StringTransport
from twisted.python.failure import Failure

from cowrie.output import rethinkdblog

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

CONFIG: dict[str, Any] = {
    "host": "db.example",
    "port": 28016,
    "db": "honeypot",
    "table": "events",
    "password": "secret",
}

Term = ql2_pb2.Term.TermType
SUCCESS_ATOM = ql2_pb2.Response.ResponseType.SUCCESS_ATOM
RUNTIME_ERROR = ql2_pb2.Response.ResponseType.RUNTIME_ERROR
OP_FAILED = ql2_pb2.Response.ErrorType.OP_FAILED


def _config() -> Mock:
    config = Mock()
    config.get.side_effect = lambda section, key, **kwargs: CONFIG[key]
    config.getint.side_effect = lambda section, key, **kwargs: CONFIG[key]
    return config


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


class Server:
    """
    The server side of one RethinkDB connection, scripted message by
    message: a SCRAM-SHA-256 handshake that checks the client's proof,
    then queries framed as token, length and JSON.
    """

    salt = b"cowrie-test-salt"

    def __init__(self, reactor: MemoryReactorClock, password: str) -> None:
        _, _, factory, _, _ = reactor.tcpClients[-1]
        self.password = password.encode()
        proto = factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 28015))
        assert proto is not None
        self.proto = proto
        self.transport = StringTransport()
        self.proto.makeConnection(self.transport)
        self.authenticated = False

    def _read(self) -> bytes:
        data: bytes = self.transport.value()
        self.transport.clear()
        return data

    def handshake(self) -> None:
        first = self._read()
        client_first = json.loads(first[4:-1])["authentication"]
        client_first_bare = client_first[len("n,,") :]
        client_nonce = dict(f.split("=", 1) for f in client_first_bare.split(","))["r"]
        server_first = (
            f"r={client_nonce}server,s={base64.b64encode(self.salt).decode()},i=1"
        )
        self.proto.dataReceived(
            b'{"success":true,"min_protocol_version":0,"max_protocol_version":0}\0'
            + json.dumps({"success": True, "authentication": server_first}).encode()
            + b"\0"
        )

        client_final = json.loads(self._read()[:-1])["authentication"]
        without_proof, proof = client_final.rsplit(",p=", 1)
        auth_message = f"{client_first_bare},{server_first},{without_proof}".encode()
        salted = hashlib.pbkdf2_hmac("sha256", self.password, self.salt, 1)
        stored_key = hashlib.sha256(_hmac(salted, b"Client Key")).digest()
        signature = _hmac(stored_key, auth_message)
        client_key = bytes(
            a ^ b for a, b in zip(base64.b64decode(proof), signature, strict=True)
        )
        self.authenticated = hashlib.sha256(client_key).digest() == stored_key
        server_signature = _hmac(_hmac(salted, b"Server Key"), auth_message)
        self.proto.dataReceived(
            json.dumps(
                {
                    "success": True,
                    "authentication": "v="
                    + base64.b64encode(server_signature).decode(),
                }
            ).encode()
            + b"\0"
        )

    def queries(self) -> list[tuple[int, Any]]:
        """Decode the (token, term) of every query sent since last call."""
        data = self._read()
        result = []
        while data:
            token, length = struct.unpack("<qL", data[:12])
            result.append((token, json.loads(data[12 : 12 + length])[1]))
            data = data[12 + length :]
        return result

    def reply(self, token: int, response: dict[str, Any]) -> None:
        body = json.dumps(response).encode()
        self.proto.dataReceived(struct.pack("<qL", token, len(body)) + body)

    def answer_all(self) -> list[Any]:
        """Reply success to every pending query; return their terms."""
        terms = []
        for token, term in self.queries():
            self.reply(token, {"t": SUCCESS_ATOM, "r": [{}]})
            terms.append(term)
        return terms

    def ready(self) -> None:
        """Complete the handshake, table creation and readiness wait."""
        self.handshake()
        self.answer_all()
        self.answer_all()
        self.answer_all()

    def inserts(self) -> list[tuple[str, dict[str, Any]]]:
        """Return (table, document) for every insert since last call."""
        result = []
        for termtype, args in self.answer_all():
            if termtype == Term.INSERT:
                table, document = args
                result.append((table[1][0], document))
        return result

    def lose(self) -> None:
        self.proto.connectionLost(Failure(error.ConnectionDone()))


class RethinkDBOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        # The driver's Twisted module still uses defer.returnValue.
        quiet = warnings.catch_warnings()
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.filterwarnings(
            "ignore",
            message=".*returnValue was deprecated",
            category=DeprecationWarning,
            module="rethinkdb.twisted_net",
        )
        self.reactor = MemoryReactorClock()
        for target in (
            patch.object(net_twisted, "reactor", self.reactor),
            patch.object(rethinkdblog, "reactor", self.reactor),
        ):
            target.start()
            self.addCleanup(target.stop)
        with patch.object(rethinkdblog.Output, "start", lambda self: None):
            self.out = rethinkdblog.Output()
        with patch.object(rethinkdblog, "CowrieConfig", _config()):
            self.out.start()
        self.addCleanup(self.out.stop)

    def _attempt(self, index: int) -> tuple[Any, Any]:
        """The factory and connector of the index-th connection attempt."""
        return self.reactor.tcpClients[index][2], self.reactor.connectors[index]

    def server(self) -> Server:
        return Server(self.reactor, CONFIG["password"])

    def test_connects_to_configured_host_and_port(self) -> None:
        host, port, _, _, _ = self.reactor.tcpClients[0]
        self.assertEqual((host, port), ("db.example", 28016))

    def test_authenticates_with_configured_password(self) -> None:
        server = self.server()
        server.handshake()
        self.assertTrue(server.authenticated)

    def test_creates_database_then_table(self) -> None:
        server = self.server()
        server.handshake()
        ((db_create),) = server.answer_all()
        self.assertEqual(db_create, [Term.DB_CREATE, ["honeypot"]])
        ((table_create),) = server.answer_all()
        self.assertEqual(
            table_create, [Term.TABLE_CREATE, [[Term.DB, ["honeypot"]], "events"]]
        )

    def test_waits_for_table_readiness_before_inserting(self) -> None:
        self.out.write({"eventid": "queued"})
        server = self.server()
        server.handshake()
        server.answer_all()
        server.answer_all()
        ((token, wait),) = server.queries()
        self.assertEqual(
            wait, [Term.WAIT, [[Term.TABLE, [[Term.DB, ["honeypot"]], "events"]]]]
        )
        self.assertEqual(server.queries(), [])
        server.reply(token, {"t": SUCCESS_ATOM, "r": [{"ready": 1}]})
        self.assertEqual([d["eventid"] for _, d in server.inserts()], ["queued"])

    def test_creates_table_when_database_already_exists(self) -> None:
        server = self.server()
        server.handshake()
        ((token, _),) = server.queries()
        server.reply(
            token,
            {"t": RUNTIME_ERROR, "e": OP_FAILED, "r": ["Database exists."], "b": []},
        )
        ((_, table_create),) = server.queries()
        self.assertEqual(table_create[0], Term.TABLE_CREATE)

    def test_event_is_inserted_without_legacy_keys(self) -> None:
        server = self.server()
        server.ready()
        self.out.write(
            {
                "eventid": "cowrie.session.connect",
                "log_level": "info",
                "timestamp": "2026-10-06T08:00:00.000000Z",
            }
        )
        ((table, document),) = server.inserts()
        self.assertEqual(table, "events")
        self.assertEqual(
            document, {"eventid": "cowrie.session.connect", "timestamp": 1791273600.0}
        )

    def test_timestamp_with_utc_offset_is_stored_as_the_same_instant(self) -> None:
        """Hosts not running with TZ=UTC log timestamps with a numeric offset."""
        server = self.server()
        server.ready()
        self.out.write({"eventid": "e", "timestamp": "2026-10-06T16:00:00.000000+0800"})
        ((_, document),) = server.inserts()
        self.assertEqual(document["timestamp"], 1791273600.0)

    def test_events_before_server_is_ready_are_inserted_in_order(self) -> None:
        self.out.write({"eventid": "a"})
        server = self.server()
        self.out.write({"eventid": "b"})
        server.ready()
        self.assertEqual([d["eventid"] for _, d in server.inserts()], ["a", "b"])

    def test_events_after_connection_loss_are_inserted_after_reconnect(self) -> None:
        first = self.server()
        first.ready()
        first.lose()
        self.out.write({"eventid": "during-outage"})
        self.assertEqual(first.transport.value(), b"")
        self.assertEqual(len(self.reactor.tcpClients), 2)

        second = self.server()
        second.ready()
        self.assertEqual([d["eventid"] for _, d in second.inserts()], ["during-outage"])

    def test_failed_connect_is_retried_with_backoff(self) -> None:
        factory, connector = self._attempt(0)
        factory.clientConnectionFailed(
            connector, Failure(error.ConnectionRefusedError())
        )
        self.reactor.advance(0.9)
        self.assertEqual(len(self.reactor.tcpClients), 1)
        self.reactor.advance(0.1)
        self.assertEqual(len(self.reactor.tcpClients), 2)

        factory, connector = self._attempt(1)
        factory.clientConnectionFailed(
            connector, Failure(error.ConnectionRefusedError())
        )
        self.reactor.advance(1.9)
        self.assertEqual(len(self.reactor.tcpClients), 2)
        self.reactor.advance(0.1)
        self.assertEqual(len(self.reactor.tcpClients), 3)

    def test_queue_drops_oldest_events_when_full(self) -> None:
        self.out.queue = deque(maxlen=2)
        for eventid in ("a", "b", "c"):
            self.out.write({"eventid": eventid})
        self.assertEqual(self.out.dropped, 1)
        server = self.server()
        server.ready()
        self.assertEqual([d["eventid"] for _, d in server.inserts()], ["b", "c"])
        self.assertEqual(self.out.dropped, 0)

    def test_stop_closes_the_connection(self) -> None:
        server = self.server()
        server.ready()
        self.out.stop()
        self.assertTrue(server.transport.disconnecting)

    def test_stop_cancels_pending_retry(self) -> None:
        factory, connector = self._attempt(0)
        factory.clientConnectionFailed(
            connector, Failure(error.ConnectionRefusedError())
        )
        self.out.stop()
        self.reactor.advance(60)
        self.assertEqual(len(self.reactor.tcpClients), 1)


class OutputRethinkdblogHardeningTests(unittest.TestCase):
    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never connected."""
        with patch.object(rethinkdblog.Output, "start", lambda self: None):
            out = rethinkdblog.Output()
        out.stop()


if __name__ == "__main__":
    unittest.main()
