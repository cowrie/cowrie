"""
Async transport layer for communicating with checkpointed environments.

Provides Twisted-based TCP, telnet, and HTTP transports used by the
environment adapters to communicate with running instances.
"""

from __future__ import annotations

import json
from typing import Any

from twisted.internet import defer, protocol, reactor
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.conch.telnet import TelnetTransport, StatefulTelnetProtocol
from twisted.python import failure as tw_failure, log
from twisted.web.client import Agent, HTTPConnectionPool, _HTTP11ClientFactory
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer
from zope.interface import implementer


# -- TCP line-based transport --


class LineBuffer(protocol.Protocol):
    """
    Accumulates lines from a TCP connection and fires a deferred
    when a prompt pattern or timeout is reached.
    """

    def __init__(self) -> None:
        self.buffer = b""
        self.lines: list[str] = []
        self._waiting: Deferred | None = None
        self._prompt_patterns: list[bytes] = []
        self._timeout_call = None

    def dataReceived(self, data: bytes) -> None:
        self.buffer += data
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            decoded = line.rstrip(b"\r").decode("utf-8", errors="replace")
            self.lines.append(decoded)
        # Check if current buffer matches a prompt (no trailing newline)
        if self._waiting and self._prompt_patterns:
            for pattern in self._prompt_patterns:
                if self.buffer.rstrip().endswith(pattern):
                    self._fire_waiting()
                    break

    def connectionLost(self, reason: tw_failure.Failure = protocol.connectionDone) -> None:
        if self._waiting:
            self._fire_waiting()

    def send(self, data: str) -> None:
        if self.transport:
            self.transport.write(data.encode("utf-8"))

    def send_line(self, line: str) -> None:
        self.send(line + "\n")

    def wait_for_prompt(
        self,
        prompt_patterns: list[str],
        timeout_ms: int = 5000,
    ) -> Deferred[list[str]]:
        """
        Wait until output matches one of the prompt patterns or timeout.
        Returns accumulated lines since last wait.
        """
        self.lines.clear()
        self._prompt_patterns = [p.encode("utf-8") for p in prompt_patterns]
        self._waiting = Deferred()

        if timeout_ms > 0:
            self._timeout_call = reactor.callLater(
                timeout_ms / 1000.0, self._fire_waiting
            )

        return self._waiting

    def _fire_waiting(self) -> None:
        if self._timeout_call and self._timeout_call.active():
            self._timeout_call.cancel()
        self._timeout_call = None

        # Flush any remaining buffer content as a partial line
        if self.buffer:
            self.lines.append(
                self.buffer.decode("utf-8", errors="replace")
            )
            self.buffer = b""

        d = self._waiting
        self._waiting = None
        self._prompt_patterns = []
        if d and not d.called:
            d.callback(list(self.lines))
        self.lines.clear()


class TCPTransportFactory(protocol.ClientFactory):
    """Factory that creates LineBuffer protocol instances."""

    def __init__(self) -> None:
        self.protocol_instance: LineBuffer | None = None
        self._on_connection: Deferred = Deferred()

    def buildProtocol(self, addr) -> LineBuffer:
        self.protocol_instance = LineBuffer()
        if not self._on_connection.called:
            self._on_connection.callback(self.protocol_instance)
        return self.protocol_instance

    def clientConnectionFailed(self, connector, reason):
        if not self._on_connection.called:
            self._on_connection.errback(reason)

    def clientConnectionLost(self, connector, reason):
        pass


@inlineCallbacks
def connect_tcp(
    host: str, port: int, timeout: int = 10
) -> Deferred[LineBuffer]:
    """
    Establish a TCP connection and return a LineBuffer for communication.
    """
    factory = TCPTransportFactory()
    reactor.connectTCP(host, port, factory, timeout=timeout)
    proto = yield factory._on_connection
    return proto


# -- HTTP transport --


@implementer(IBodyProducer)
class _HTTPBodyProducer:
    """Feeds a request body to the Twisted HTTP client."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self) -> None:
        pass

    def resumeProducing(self) -> None:
        pass

    def stopProducing(self) -> None:
        pass


class _HTTPResponseCollector(protocol.Protocol):
    """Collects the full response body."""

    def __init__(self, d: Deferred) -> None:
        self.buf = b""
        self.d = d

    def dataReceived(self, data: bytes) -> None:
        self.buf += data

    def connectionLost(self, reason=protocol.connectionDone) -> None:
        if not self.d.called:
            self.d.callback(self.buf)


class _QuietHTTPFactory(_HTTP11ClientFactory):
    noisy = False


class HTTPTransport:
    """
    Async HTTP client for environments with HTTP/REST APIs.
    Used by the Smalltalk adapter (PharoSmalltalkInteropServer)
    and ToastStunt's REST interface.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._pool = HTTPConnectionPool(reactor)
        self._pool._factory = _QuietHTTPFactory
        self._agent = Agent(reactor, pool=self._pool)

    @inlineCallbacks
    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Deferred[tuple[int, dict[str, Any] | str]]:
        """
        Make an HTTP request. Returns (status_code, parsed_body).
        Body is parsed as JSON if Content-Type indicates JSON.
        """
        url = f"{self.base_url}{path}"
        h = Headers({})
        if headers:
            for k, v in headers.items():
                h.addRawHeader(k.encode(), v.encode())

        producer = None
        if body is not None:
            h.addRawHeader(b"Content-Type", b"application/json")
            producer = _HTTPBodyProducer(json.dumps(body).encode("utf-8"))

        try:
            response = yield self._agent.request(
                method.encode(), url.encode(), headers=h, bodyProducer=producer
            )
        except Exception as e:
            log.err(f"HTTP request failed: {e}")
            return (0, str(e))

        body_d: Deferred = Deferred()
        response.deliverBody(_HTTPResponseCollector(body_d))
        raw_body: bytes = yield body_d

        ct = response.headers.getRawHeaders(b"content-type", [b""])[0]
        if b"json" in ct:
            try:
                parsed = json.loads(raw_body)
                return (response.code, parsed)
            except json.JSONDecodeError:
                pass

        return (response.code, raw_body.decode("utf-8", errors="replace"))

    @inlineCallbacks
    def get(self, path: str) -> Deferred[tuple[int, Any]]:
        return (yield self.request("GET", path))

    @inlineCallbacks
    def post(self, path: str, body: dict[str, Any]) -> Deferred[tuple[int, Any]]:
        return (yield self.request("POST", path, body=body))
