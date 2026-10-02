# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The socketlog output plugin must send events on the reactor, queue
# ABOUTME: them while the collector is away, and never block in write().

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import Mock, patch

from twisted.internet.address import IPv4Address
from twisted.internet.testing import MemoryReactorClock, StringTransport

from cowrie.output import socketlog

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def _config() -> Mock:
    config = Mock()
    config.get.return_value = "collector.example:9000"
    config.getint.return_value = 7
    return config


def _started(reactor: MemoryReactorClock) -> Any:
    """Construct the plugin and run start() against a memory reactor."""
    with patch.object(socketlog.Output, "start", lambda self: None):
        out = socketlog.Output()
    with (
        patch.object(socketlog, "CowrieConfig", _config()),
        patch.object(socketlog, "reactor", reactor),
    ):
        out.start()
    return out


def _connect(out: Any) -> StringTransport:
    """Bring up a collector connection on a fake transport."""
    proto = out.factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 9000))
    transport = StringTransport()
    proto.makeConnection(transport)
    return transport


class SocketLogOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = MemoryReactorClock()
        self.out = _started(self.reactor)

    def tearDown(self) -> None:
        self.out.stop()

    def test_start_connects_on_the_reactor(self) -> None:
        host, port, factory, timeout, _ = self.reactor.tcpClients[0]
        self.assertEqual((host, port, timeout), ("collector.example", 9000, 7))
        self.assertIs(factory, self.out.factory)

    def test_events_go_out_as_json_lines(self) -> None:
        transport = _connect(self.out)
        self.out.write({"eventid": "cowrie.session.connect", "session": "a"})
        self.out.write({"eventid": "cowrie.session.closed", "session": "a"})
        self.assertEqual(
            transport.value(),
            b'{"eventid": "cowrie.session.connect", "session": "a"}\n'
            b'{"eventid": "cowrie.session.closed", "session": "a"}\n',
        )

    def test_legacy_log_keys_are_dropped(self) -> None:
        transport = _connect(self.out)
        self.out.write({"eventid": "t", "log_namespace": "x", "log_time": 1})
        self.assertEqual(transport.value(), b'{"eventid": "t"}\n')

    def test_events_before_connection_are_queued_in_order(self) -> None:
        self.out.write({"eventid": "first"})
        self.out.write({"eventid": "second"})
        transport = _connect(self.out)
        self.out.write({"eventid": "third"})
        self.assertEqual(
            transport.value(),
            b'{"eventid": "first"}\n{"eventid": "second"}\n{"eventid": "third"}\n',
        )

    def test_events_while_disconnected_wait_for_the_next_connection(self) -> None:
        first = _connect(self.out)
        self.out.write({"eventid": "a"})
        self.out.factory.proto.connectionLost()
        self.out.write({"eventid": "b"})
        self.assertEqual(first.value(), b'{"eventid": "a"}\n')
        second = _connect(self.out)
        self.out.write({"eventid": "c"})
        self.assertEqual(second.value(), b'{"eventid": "b"}\n{"eventid": "c"}\n')

    def test_queue_keeps_the_newest_events(self) -> None:
        self.out.factory.queue = type(self.out.factory.queue)(maxlen=2)
        for eventid in ("a", "b", "c"):
            self.out.write({"eventid": eventid})
        transport = _connect(self.out)
        self.assertEqual(transport.value(), b'{"eventid": "b"}\n{"eventid": "c"}\n')

    def test_a_stale_disconnect_does_not_drop_the_live_connection(self) -> None:
        old = self.out.factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 9000))
        transport = _connect(self.out)
        self.out.factory.disconnected(old)
        self.out.write({"eventid": "still-live"})
        self.assertEqual(transport.value(), b'{"eventid": "still-live"}\n')

    def test_stop_stops_reconnecting_and_disconnects(self) -> None:
        connector = Mock()
        self.out.connector = connector
        self.out.stop()
        self.assertFalse(self.out.factory.continueTrying)
        connector.disconnect.assert_called_once_with()
