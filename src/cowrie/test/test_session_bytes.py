# SPDX-FileCopyrightText: 2026 sudu787
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that cowrie.session.closed reports the bytes each connection
# ABOUTME: received and sent, for SSH, Telnet and both proxy front-ends.

from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from twisted.conch.telnet import IAC, WILL
from twisted.internet.testing import StringTransport
from twisted.protocols.policies import ProtocolWrapper

from cowrie.core.events import EventDispatcher
from cowrie.core.traffic import CountingTransport
from cowrie.ssh import transport as ssh_transport
from cowrie.ssh_proxy import server_transport as ssh_proxy_transport
from cowrie.telnet import transport as telnet_transport
from cowrie.telnet_proxy import server_transport as telnet_proxy_transport
from cowrie.test.eventcapture import CaptureSink, capture_events, events_of


def _factory(sink: CaptureSink) -> Any:
    dispatcher = EventDispatcher([sink], logmsg=lambda *a, **k: None)
    return SimpleNamespace(tac=SimpleNamespace(dispatcher=dispatcher))


def _closed(events: list[dict[str, Any]]) -> dict[str, Any]:
    closed = events_of(events, "cowrie.session.closed")
    assert len(closed) == 1, closed
    return closed[0]


class CountingTransportTests(unittest.TestCase):
    def test_counts_writes_and_passes_them_through(self) -> None:
        owner = SimpleNamespace(bytes_out=0)
        wire = StringTransport()
        t = CountingTransport(wire, owner)
        t.write(b"abc")
        t.writeSequence([b"de", b"f"])
        self.assertEqual(owner.bytes_out, 6)
        self.assertEqual(wire.value(), b"abcdef")

    def test_other_attributes_reach_the_wrapped_transport(self) -> None:
        wire = StringTransport()
        t = CountingTransport(wire, SimpleNamespace(bytes_out=0))
        self.assertEqual(t.getPeer(), wire.getPeer())
        t.loseConnection()
        self.assertTrue(wire.disconnecting)


class SSHSessionBytesTests(unittest.TestCase):
    def test_closed_event_reports_wire_bytes(self) -> None:
        sink = CaptureSink()
        t = ssh_transport.HoneyPotSSHTransport()
        t.factory = _factory(sink)
        wire = StringTransport()
        t.transport = wire
        t.ourVersionString = b"SSH-2.0-OpenSSH_9.6"
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()
        # A newline-less banner is buffered without a reply.
        t.dataReceived(b"SSH-2.0-Client")
        sent = len(wire.value())
        with (
            patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"),
            patch("twisted.conch.ssh.transport.SSHServerTransport.connectionLost"),
        ):
            t.connectionLost()
        event = _closed(sink.events)
        self.assertEqual(sent, len(b"SSH-2.0-OpenSSH_9.6\r\n"))
        self.assertEqual((event["bytes_in"], event["bytes_out"]), (14, sent))

    def test_proxy_protocol_is_still_detected(self) -> None:
        # The counting wrapper goes on after the PROXY check, so a wrapped
        # connection still defers cowrie.session.connect.
        sink = CaptureSink()
        t = ssh_transport.HoneyPotSSHTransport()
        t.factory = _factory(sink)
        t.transport = MagicMock(spec=ProtocolWrapper)
        t.ourVersionString = b"SSH-2.0-OpenSSH_9.6"
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()
        self.assertEqual(events_of(sink.events, "cowrie.session.connect"), [])
        self.assertEqual(t.bytes_out, len(b"SSH-2.0-OpenSSH_9.6\r\n"))


class TelnetSessionBytesTests(unittest.TestCase):
    def test_closed_event_reports_wire_bytes(self) -> None:
        sink = CaptureSink()
        t = telnet_transport.CowrieTelnetTransport()
        t.factory = _factory(sink)
        wire = StringTransport()
        t.transport = wire
        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionMade"),
        ):
            t.connectionMade()
        # Application output and Twisted's own option negotiation both count.
        t.write(b"login: ")
        t._write(IAC + WILL + b"\x01")
        with patch("twisted.conch.telnet.TelnetTransport.dataReceived"):
            t.dataReceived(b"root\r\n")
        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionLost"),
        ):
            t.connectionLost()
        event = _closed(sink.events)
        self.assertEqual(event["bytes_in"], 6)
        self.assertEqual(event["bytes_out"], len(wire.value()))
        self.assertEqual(event["bytes_out"], 10)


class ProxySessionBytesTests(unittest.TestCase):
    """The proxy front-ends pass their counts to cowrie.session.closed."""

    def test_ssh_proxy(self) -> None:
        t = ssh_proxy_transport.FrontendSSHTransport()
        t.transport = MagicMock()
        t.sshParse = SimpleNamespace(client=None)
        t.startTime = time.time()
        t.bytes_in, t.bytes_out = 7, 11
        events = capture_events(t)
        with (
            patch.object(ssh_proxy_transport.FrontendSSHTransport, "setTimeout"),
            patch("twisted.conch.ssh.transport.SSHServerTransport.connectionLost"),
        ):
            t.connectionLost()
        event = _closed(events)
        self.assertEqual((event["bytes_in"], event["bytes_out"]), (7, 11))

    def test_telnet_proxy(self) -> None:
        t = telnet_proxy_transport.FrontendTelnetTransport()
        t.telnetHandler = MagicMock()
        t.startTime = time.time()
        t.bytes_in, t.bytes_out = 7, 11
        events = capture_events(t)
        with (
            patch.object(telnet_proxy_transport.FrontendTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionLost"),
        ):
            t.connectionLost(None)
        event = _closed(events)
        self.assertEqual((event["bytes_in"], event["bytes_out"]), (7, 11))


if __name__ == "__main__":
    unittest.main()
