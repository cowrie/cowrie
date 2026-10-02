# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for HAProxy PROXY-protocol support: the session.connect event
# ABOUTME: is deferred until the PROXY header is parsed so it carries the real IP.

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from twisted.internet import endpoints, reactor
from twisted.protocols.policies import ProtocolWrapper

from cowrie.core.events import EventDispatcher
from cowrie.ssh import transport as ssh_transport
from cowrie.telnet import transport as telnet_transport
from cowrie.test.eventcapture import CaptureSink, events_of


def _fake_factory(sink: CaptureSink) -> Any:
    dispatcher = EventDispatcher([sink], logmsg=lambda *a, **k: None)
    return SimpleNamespace(tac=SimpleNamespace(dispatcher=dispatcher))


def _fake_transport(peer_host: str, *, wrapped: bool) -> Any:
    # A PROXY-wrapped connection presents a policies.ProtocolWrapper as the
    # protocol's transport; a direct connection does not.
    tr = MagicMock(spec=ProtocolWrapper) if wrapped else MagicMock()
    tr.getPeer.return_value = SimpleNamespace(host=peer_host, port=5555)
    tr.getHost.return_value = SimpleNamespace(host="10.0.0.2", port=2222)
    return tr


class SSHProxyProtocolTests(unittest.TestCase):
    def _make(
        self, peer_host: str, *, wrapped: bool
    ) -> tuple[ssh_transport.HoneyPotSSHTransport, CaptureSink]:
        sink = CaptureSink()
        t = ssh_transport.HoneyPotSSHTransport()
        t.factory = _fake_factory(sink)
        t.transport = _fake_transport(peer_host, wrapped=wrapped)
        t.ourVersionString = b"SSH-2.0-OpenSSH_9.6"
        return t, sink

    def test_direct_connection_emits_connect_in_connection_made(self) -> None:
        t, sink = self._make("9.9.9.9", wrapped=False)
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()
        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "9.9.9.9")

    def test_proxied_connection_defers_connect_until_first_data(self) -> None:
        # At connect time getPeer() still returns the proxy's address.
        t, sink = self._make("10.0.0.9", wrapped=True)
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()

        self.assertEqual(events_of(sink.events, "cowrie.session.connect"), [])
        self.assertIsNone(t.events)

        # The wrapper parses the PROXY header before our dataReceived fires, so
        # getPeer() now returns the real client. A newline-less banner triggers
        # the deferred emit and returns before the SSH handshake.
        t.transport.getPeer.return_value = SimpleNamespace(
            host="203.0.113.7", port=5555
        )
        t.dataReceived(b"SSH-2.0-RealClient")

        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "203.0.113.7")
        self.assertIsNotNone(t.events)

    def test_ipv4_mapped_real_client_is_normalized(self) -> None:
        t, sink = self._make("10.0.0.9", wrapped=True)
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()
        t.transport.getPeer.return_value = SimpleNamespace(
            host="::ffff:203.0.113.7", port=5555
        )
        t.dataReceived(b"SSH-2.0-RealClient")
        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(connects[0]["src_ip"], "203.0.113.7")

    def test_proxied_connection_closed_without_data_is_still_logged(self) -> None:
        # A PROXY header with no trailing payload never reaches dataReceived();
        # the connection must still be announced (and closed) at teardown, not
        # vanish, as a direct no-data connection would be logged.
        t, sink = self._make("203.0.113.7", wrapped=True)
        with patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"):
            t.connectionMade()
        self.assertEqual(events_of(sink.events, "cowrie.session.connect"), [])
        with patch("twisted.conch.ssh.transport.SSHServerTransport.connectionLost"):
            t.connectionLost()
        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "203.0.113.7")
        self.assertEqual(len(events_of(sink.events, "cowrie.session.closed")), 1)


class TelnetProxyProtocolTests(unittest.TestCase):
    def _make(
        self, peer_host: str, *, wrapped: bool
    ) -> tuple[telnet_transport.CowrieTelnetTransport, CaptureSink]:
        sink = CaptureSink()
        t = telnet_transport.CowrieTelnetTransport()
        t.factory = _fake_factory(sink)
        t.transport = _fake_transport(peer_host, wrapped=wrapped)
        return t, sink

    def test_direct_connection_emits_connect_in_connection_made(self) -> None:
        t, sink = self._make("9.9.9.9", wrapped=False)
        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionMade"),
        ):
            t.connectionMade()
        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "9.9.9.9")

    def test_proxied_connection_defers_connect_until_first_data(self) -> None:
        t, sink = self._make("10.0.0.9", wrapped=True)
        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionMade"),
        ):
            t.connectionMade()

        self.assertEqual(events_of(sink.events, "cowrie.session.connect"), [])
        self.assertIsNone(t.events)

        # PROXY header parsed: getPeer() now reflects the real client.
        t.transport = _fake_transport("203.0.113.7", wrapped=True)
        with patch("twisted.conch.telnet.TelnetTransport.dataReceived"):
            t.dataReceived(b"anything")

        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "203.0.113.7")

    def test_proxied_connection_closed_without_data_is_still_logged(self) -> None:
        t, sink = self._make("203.0.113.7", wrapped=True)
        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionMade"),
        ):
            t.connectionMade()
        self.assertEqual(events_of(sink.events, "cowrie.session.connect"), [])
        with patch("twisted.conch.telnet.TelnetTransport.connectionLost"):
            t.connectionLost()
        connects = events_of(sink.events, "cowrie.session.connect")
        self.assertEqual(len(connects), 1)
        self.assertEqual(connects[0]["src_ip"], "203.0.113.7")
        self.assertEqual(len(events_of(sink.events, "cowrie.session.closed")), 1)


class HAProxyEndpointTests(unittest.TestCase):
    def test_haproxy_endpoint_string_is_wrapped(self) -> None:
        # Cowrie relies on Twisted's registered haproxy: endpoint plugin to do
        # the PROXY parsing; a plain endpoint string is not wrapped.
        wrapped = endpoints.serverFromString(
            reactor, "haproxy:tcp:2222:interface=127.0.0.1"
        )
        plain = endpoints.serverFromString(reactor, "tcp:2222:interface=127.0.0.1")
        self.assertEqual(type(wrapped).__name__, "_WrapperServerEndpoint")
        self.assertNotEqual(type(plain).__name__, "_WrapperServerEndpoint")


if __name__ == "__main__":
    unittest.main()
