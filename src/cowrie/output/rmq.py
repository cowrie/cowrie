# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: RabbitMQ output plugin: publishes each event as JSON to an exchange,
# ABOUTME: routed by eventid, through pika's Twisted adapter with reconnects.

from __future__ import annotations

import json
from collections import deque
from typing import TYPE_CHECKING, Any

import pika
from constantly import NamedConstant, ValueConstant
from pika.adapters.twisted_connection import TwistedProtocolConnection
from twisted.internet import reactor
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import inlineCallbacks
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from twisted.internet.interfaces import IAddress, IConnector
    from twisted.python.failure import Failure


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        match o:
            case NamedConstant() | ValueConstant():
                return str(o)
            case IPv4Address() | IPv6Address():
                return o.host  # Extract the IP address as a string
            case bytes():
                return o.decode("utf-8", errors="replace")  # Convert bytes to string
            case _:
                return super().default(o)


class RabbitMQFactory(ReconnectingClientFactory):
    """
    Keeps one AMQP connection and channel to the broker, retries with
    backoff when it goes away, and queues events in the meantime so that
    write() never blocks and events are published in order.
    """

    _log = Logger()

    maxDelay = 60
    # Events kept while the broker is unreachable. The oldest ones go
    # first, so a broker that is down for a long time can't grow the
    # honeypot's memory without bound.
    max_queued = 10000

    def __init__(
        self,
        parameters: Any,
        exchange: str,
        exchange_type: str,
        clock: Any,
    ) -> None:
        self.parameters = parameters
        self.exchange = exchange
        self.exchange_type = exchange_type
        self.clock = clock
        # pika ships no type information, so its objects are typed Any.
        self.connection: Any = None
        self.channel: Any = None
        self.queue: deque[tuple[str, bytes]] = deque(maxlen=self.max_queued)
        self.dropped: int = 0
        self.properties = pika.BasicProperties(content_type="application/json")

    def buildProtocol(self, addr: IAddress | None) -> Any:
        connection = TwistedProtocolConnection(self.parameters, self.clock)
        connection.factory = self
        self.connection = connection
        connection.ready.addCallback(self._open_channel)
        connection.ready.addErrback(self._setup_failed, connection)
        return connection

    @inlineCallbacks
    def _open_channel(self, connection: Any) -> Any:
        channel = yield connection.channel()
        yield channel.exchange_declare(
            exchange=self.exchange,
            exchange_type=self.exchange_type,
            durable=True,
        )
        channel.on_closed.addBoth(self._channel_closed, channel, connection)
        self.resetDelay()
        self.channel = channel
        self._log.info("Connected to RabbitMQ")
        if self.dropped:
            self._log.warn(
                "rmq: dropped {dropped} events while disconnected",
                dropped=self.dropped,
            )
            self.dropped = 0
        while self.queue:
            self._publish(*self.queue.popleft())

    def _setup_failed(self, reason: Failure, connection: Any) -> None:
        self._log.warn(
            "rmq: could not set up RabbitMQ connection: {reason}",
            reason=reason.getErrorMessage(),
        )
        if connection.is_open:
            connection.close()

    def _channel_closed(
        self,
        reason: Any,
        channel: Any,
        connection: Any,
    ) -> None:
        """
        The connection is only useful with its channel; when the broker
        closes the channel, drop the connection so the reconnect sets
        both up again.
        """
        if self.channel is channel:
            self.channel = None
        if connection.is_open:
            self._log.warn("rmq: channel closed: {reason}", reason=reason)
            connection.close()

    def _publish(self, routing_key: str, body: bytes) -> None:
        assert self.channel is not None
        self.channel.basic_publish(
            exchange=self.exchange,
            routing_key=routing_key,
            body=body,
            properties=self.properties,
        )

    def send(self, routing_key: str, body: bytes) -> None:
        if self.channel is not None and self.channel.is_open:
            self._publish(routing_key, body)
            return
        if len(self.queue) == self.queue.maxlen:
            self.dropped += 1
        self.queue.append((routing_key, body))

    def close(self) -> None:
        self.stopTrying()
        if self.connection is not None and self.connection.is_open:
            self.connection.close()

    def clientConnectionFailed(self, connector: IConnector, reason: Failure) -> None:
        self._log.warn(
            "rmq: could not connect to RabbitMQ: {reason}",
            reason=reason.getErrorMessage(),
        )
        super().clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure) -> None:
        self.channel = None
        self.connection = None
        if self.continueTrying:
            self._log.info(
                "rmq: connection to RabbitMQ lost, reconnecting: {reason}",
                reason=reason.getErrorMessage(),
            )
        super().clientConnectionLost(connector, reason)


class Output(cowrie.core.output.Output):
    """
    RabbitMQ output plugin for Cowrie using event types as routing keys.
    """

    def start(self) -> None:
        host = CowrieConfig.get("output_rmq", "host", fallback="localhost")
        port = CowrieConfig.getint("output_rmq", "port", fallback=5672)
        username = CowrieConfig.get("output_rmq", "username", fallback="guest")
        password = CowrieConfig.get("output_rmq", "password", fallback="guest")
        vhost = CowrieConfig.get("output_rmq", "vhost", fallback="/")
        exchange = CowrieConfig.get("output_rmq", "exchange", fallback="cowrie")
        exchange_type = CowrieConfig.get(
            "output_rmq", "exchange_type", fallback="topic"
        )

        # pika's Twisted adapter ignores host and port here; Twisted
        # makes the TCP connection below.
        parameters = pika.ConnectionParameters(
            virtual_host=vhost,
            credentials=pika.PlainCredentials(username, password),
            heartbeat=600,
        )
        self.factory = RabbitMQFactory(parameters, exchange, exchange_type, reactor)
        self.connector: IConnector = reactor.connectTCP(host, port, self.factory)

    def stop(self) -> None:
        self.factory.close()
        self.connector.disconnect()

    def write(self, event: dict[str, Any]) -> None:
        message = json.dumps(event, cls=CustomJSONEncoder)
        routing_key = event.get("eventid", "cowrie.unknown")
        self.factory.send(routing_key, message.encode("utf-8"))
