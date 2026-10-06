# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The rmq output plugin must publish events on the reactor through
# ABOUTME: pika's Twisted adapter, queue them while the broker is away, and never block.

from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections import deque
from typing import Any
from unittest.mock import Mock, patch

from pika import frame, spec
from twisted.internet.address import IPv4Address
from twisted.internet.error import ConnectionLost
from twisted.internet.testing import MemoryReactorClock, StringTransport
from twisted.python.failure import Failure

from cowrie.output import rmq

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

CONFIG = {
    "host": "broker.example",
    "port": 5673,
    "username": "user",
    "password": "secret",
    "vhost": "/honeypot",
    "exchange": "events",
    "exchange_type": "fanout",
}


def _config() -> Mock:
    config = Mock()
    config.get.side_effect = lambda section, key, fallback=None: CONFIG[key]
    config.getint.side_effect = lambda section, key, fallback=None: CONFIG[key]
    return config


def _started(reactor: MemoryReactorClock) -> Any:
    """Construct the plugin and run start() against a memory reactor."""
    with patch.object(rmq.Output, "start", lambda self: None):
        out = rmq.Output()
    with (
        patch.object(rmq, "CowrieConfig", _config()),
        patch.object(rmq, "reactor", reactor),
    ):
        out.start()
    return out


class Broker:
    """
    The server side of one AMQP connection, scripted frame by frame. It
    speaks real AMQP 0-9-1 encoded by pika's own spec module.
    """

    def __init__(self, out: Any) -> None:
        self.conn = out.factory.buildProtocol(IPv4Address("TCP", "10.0.0.1", 5672))
        self.transport = StringTransport()
        self.conn.makeConnection(self.transport)

    def send(self, channel: int, method: Any) -> None:
        self.conn.dataReceived(frame.Method(channel, method).marshal())

    def received(self) -> list[Any]:
        """Decode and return everything the client wrote since last call."""
        data = self.transport.value()
        self.transport.clear()
        frames = []
        while data:
            consumed, decoded = frame.decode_frame(data)
            frames.append(decoded)
            data = data[consumed:]
        return frames

    def methods(self) -> list[Any]:
        return [f.method for f in self.received() if isinstance(f, frame.Method)]

    def open_connection(self) -> None:
        self.send(0, spec.Connection.Start(server_properties={"capabilities": {}}))
        self.send(0, spec.Connection.Tune(channel_max=0, frame_max=131072))
        self.send(0, spec.Connection.OpenOk())

    def ready(self) -> None:
        """Complete the handshake, channel open and exchange declare."""
        self.open_connection()
        self.send(1, spec.Channel.OpenOk())
        self.send(1, spec.Exchange.DeclareOk())

    def publishes(self) -> list[tuple[str, str, Any, bytes]]:
        """Return (exchange, routing key, properties, body) per publish."""
        result = []
        for f in self.received():
            if isinstance(f, frame.Method) and isinstance(f.method, spec.Basic.Publish):
                result.append([f.method.exchange, f.method.routing_key, None, b""])
            elif isinstance(f, frame.Header):
                result[-1][2] = f.properties
            elif isinstance(f, frame.Body):
                result[-1][3] += f.fragment
        return [tuple(r) for r in result]


class RabbitMQOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reactor = MemoryReactorClock()
        self.out = _started(self.reactor)

    def tearDown(self) -> None:
        self.out.stop()

    def test_start_connects_on_the_reactor(self) -> None:
        host, port, factory, _, _ = self.reactor.tcpClients[0]
        self.assertEqual((host, port), ("broker.example", 5673))
        self.assertIs(factory, self.out.factory)

    def test_login_uses_configured_credentials_and_vhost(self) -> None:
        broker = Broker(self.out)
        broker.received()
        broker.send(0, spec.Connection.Start(server_properties={"capabilities": {}}))
        (start_ok,) = broker.methods()
        self.assertEqual(start_ok.response, b"\x00user\x00secret")
        broker.send(0, spec.Connection.Tune(channel_max=0, frame_max=131072))
        _, connection_open = broker.methods()
        self.assertEqual(connection_open.virtual_host, "/honeypot")

    def test_declares_configured_exchange_once_connected(self) -> None:
        broker = Broker(self.out)
        broker.open_connection()
        broker.received()
        broker.send(1, spec.Channel.OpenOk())
        (declare,) = broker.methods()
        self.assertIsInstance(declare, spec.Exchange.Declare)
        self.assertEqual(
            (declare.exchange, declare.type, declare.durable),
            ("events", "fanout", True),
        )

    def test_event_is_published_as_json_with_eventid_routing_key(self) -> None:
        broker = Broker(self.out)
        broker.ready()
        broker.received()
        self.out.write({"eventid": "cowrie.session.connect", "src_ip": b"1.2.3.4"})
        ((exchange, key, props, body),) = broker.publishes()
        self.assertEqual((exchange, key), ("events", "cowrie.session.connect"))
        self.assertEqual(props.content_type, "application/json")
        self.assertEqual(
            json.loads(body),
            {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"},
        )

    def test_event_without_eventid_uses_fallback_routing_key(self) -> None:
        broker = Broker(self.out)
        broker.ready()
        broker.received()
        self.out.write({"message": "x"})
        ((_, key, _, _),) = broker.publishes()
        self.assertEqual(key, "cowrie.unknown")

    def test_events_before_broker_is_ready_are_published_in_order(self) -> None:
        self.out.write({"eventid": "a"})
        broker = Broker(self.out)
        self.out.write({"eventid": "b"})
        broker.ready()
        self.assertEqual([p[1] for p in broker.publishes()], ["a", "b"])

    def test_events_during_outage_are_published_after_reconnect(self) -> None:
        first = Broker(self.out)
        first.ready()
        first.received()
        first.conn.connectionLost(Failure(ConnectionLost()))
        self.out.write({"eventid": "during-outage"})
        self.assertEqual(first.transport.value(), b"")

        second = Broker(self.out)
        second.ready()
        self.assertEqual([p[1] for p in second.publishes()], ["during-outage"])

    def test_queue_drops_oldest_events_when_full(self) -> None:
        self.out.factory.queue = deque(maxlen=2)
        for eventid in ("a", "b", "c"):
            self.out.write({"eventid": eventid})
        self.assertEqual(self.out.factory.dropped, 1)
        broker = Broker(self.out)
        broker.ready()
        self.assertEqual([p[1] for p in broker.publishes()], ["b", "c"])
        self.assertEqual(self.out.factory.dropped, 0)

    def test_refused_exchange_declare_closes_connection_and_keeps_events(
        self,
    ) -> None:
        broker = Broker(self.out)
        broker.open_connection()
        broker.send(1, spec.Channel.OpenOk())
        broker.received()
        broker.send(
            1,
            spec.Channel.Close(
                reply_code=406,
                reply_text="PRECONDITION_FAILED - inequivalent arg 'type'",
                class_id=40,
                method_id=10,
            ),
        )
        self.out.write({"eventid": "kept"})
        methods = broker.methods()
        self.assertIsInstance(methods[0], spec.Channel.CloseOk)
        self.assertIsInstance(methods[-1], spec.Connection.Close)
        self.assertEqual(next(iter(self.out.factory.queue))[0], "kept")

    def test_stop_closes_the_amqp_connection_and_stops_retrying(self) -> None:
        broker = Broker(self.out)
        broker.ready()
        broker.received()
        self.out.stop()
        (channel_close,) = broker.methods()
        self.assertIsInstance(channel_close, spec.Channel.Close)
        broker.send(1, spec.Channel.CloseOk())
        (connection_close,) = broker.methods()
        self.assertIsInstance(connection_close, spec.Connection.Close)
        self.assertFalse(self.out.factory.continueTrying)
