# SPDX-FileCopyrightText: 2017 grzegorzpro <grzegorz.prokopczyk@gmail.com>
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: socketlog output plugin: sends each event as one JSON line to a TCP
# ABOUTME: log collector, on the reactor, with reconnects and no blocking I/O.

from __future__ import annotations

import json
from collections import deque
from typing import TYPE_CHECKING, Any

from twisted.internet import reactor
from twisted.internet.protocol import (
    Protocol,
    ReconnectingClientFactory,
    connectionDone,
)
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from twisted.internet.interfaces import IAddress, IConnector, ITransport
    from twisted.python.failure import Failure


class SocketLogProtocol(Protocol):
    """
    One connection to the log collector. It only tells the factory when
    it is up or gone; the factory decides what to send.
    """

    def __init__(self, logfactory: SocketLogFactory) -> None:
        self.logfactory = logfactory

    def connectionMade(self) -> None:
        self.logfactory.connected(self)

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        self.logfactory.disconnected(self)


class SocketLogFactory(ReconnectingClientFactory):
    """
    Keeps one connection to the collector, retries with backoff when it
    goes away, and queues events in the meantime so that write() never
    blocks and events are delivered in order.
    """

    _log = Logger()

    maxDelay = 60
    # Events kept while the collector is unreachable. The oldest ones go
    # first, so a collector that is down for a long time can't grow the
    # honeypot's memory without bound.
    max_queued = 10000

    def __init__(self) -> None:
        self.proto: SocketLogProtocol | None = None
        self.transport: ITransport | None = None
        self.queue: deque[bytes] = deque(maxlen=self.max_queued)
        self.dropped: int = 0

    def buildProtocol(self, addr: IAddress | None) -> SocketLogProtocol:
        proto = SocketLogProtocol(self)
        proto.factory = self
        return proto

    def connected(self, proto: SocketLogProtocol) -> None:
        if proto.transport is None:
            return
        self.resetDelay()
        self.proto = proto
        self.transport = proto.transport
        if self.dropped:
            self._log.warn(
                "socketlog: dropped {dropped} events while disconnected",
                dropped=self.dropped,
            )
            self.dropped = 0
        while self.queue:
            self.transport.write(self.queue.popleft())

    def disconnected(self, proto: SocketLogProtocol) -> None:
        if self.proto is proto:
            self.proto = None
            self.transport = None

    def send(self, data: bytes) -> None:
        if self.transport is not None:
            self.transport.write(data)
            return
        if len(self.queue) == self.queue.maxlen:
            self.dropped += 1
        self.queue.append(data)

    def clientConnectionFailed(self, connector: IConnector, reason: Failure) -> None:
        self._log.warn(
            "socketlog: could not connect to collector: {reason}",
            reason=reason.getErrorMessage(),
        )
        super().clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure) -> None:
        if self.continueTrying:
            self._log.info(
                "socketlog: connection to collector lost, reconnecting: {reason}",
                reason=reason.getErrorMessage(),
            )
        super().clientConnectionLost(connector, reason)


class Output(cowrie.core.output.Output):
    """
    socketlog output
    """

    def start(self) -> None:
        self.timeout: int = CowrieConfig.getint("output_socketlog", "timeout")
        addr: str = CowrieConfig.get("output_socketlog", "address")
        self.host, port = addr.rsplit(":", 1)
        self.port = int(port)

        self.factory = SocketLogFactory()
        self.connector: IConnector = reactor.connectTCP(
            self.host, self.port, self.factory, timeout=self.timeout
        )

    def stop(self) -> None:
        self.factory.stopTrying()
        self.connector.disconnect()

    def write(self, event: dict[str, Any]) -> None:
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        message = json.dumps(event) + "\n"
        self.factory.send(message.encode())
