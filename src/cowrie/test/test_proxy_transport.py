# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the proxy frontend SSH transport's packet and version handling.
# ABOUTME: Covers fingerprintable responses, message framing and torn-down transports.

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from twisted.conch.ssh import transport

from cowrie.ssh_proxy.server_transport import FrontendSSHTransport


def _transport() -> tuple[FrontendSSHTransport, MagicMock]:
    """A frontend transport, and the mock standing in for its connection."""
    t = FrontendSSHTransport.__new__(FrontendSSHTransport)
    connection = MagicMock()
    t.transport = connection
    t._log = MagicMock()
    t.events = None
    return t, connection


class TestSendDisconnect(unittest.TestCase):
    """A bad packet length must not draw a fingerprintable reply."""

    def test_bad_packet_length_writes_nothing(self) -> None:
        # "Packet corrupt" is a documented Cowrie tell: no real SSH server
        # answers a bad packet length with it.
        t, connection = _transport()

        t.sendDisconnect(transport.DISCONNECT_PROTOCOL_ERROR, b"bad packet length")

        connection.write.assert_not_called()
        connection.loseConnection.assert_called_once()


class TestSendPacket(unittest.TestCase):
    """Packet framing must survive a torn-down transport and high message types."""

    def _ready(self) -> tuple[FrontendSSHTransport, MagicMock]:
        t, connection = _transport()
        t._keyExchangeState = t._KEY_EXCHANGE_NONE
        t.outgoingCompression = None
        t.currentEncryptions = MagicMock()
        t.currentEncryptions.encBlockSize = 8
        t.currentEncryptions.encrypt = lambda packet: packet
        t.currentEncryptions.makeMAC = lambda _seq, _packet: b""
        t.outgoingPacketSequence = 0
        return t, connection

    def test_no_transport_is_not_an_error(self) -> None:
        # Twisted keeps dispatching queued messages after the connection is
        # gone; writing to a None transport raises AttributeError.
        t, _connection = self._ready()
        t.transport = None

        t.sendPacket(transport.MSG_IGNORE, b"")

    def test_high_message_type_is_one_byte(self) -> None:
        # chr(200).encode() is two UTF-8 bytes, which shifts the whole
        # payload and corrupts every message type above 127.
        t, connection = self._ready()

        t.sendPacket(200, b"body")

        written = connection.write.call_args[0][0]
        # 4-byte length, 1-byte padding length, then the message type.
        self.assertEqual(written[5], 200)
        self.assertEqual(written[6:10], b"body")


class TestVersionParsing(unittest.TestCase):
    """A version string without a literal dot is a protocol mismatch."""

    def test_non_dot_separator_is_rejected(self) -> None:
        # An unescaped dot in the pattern matches any character, so
        # "SSH-2X0-x" parses as version "2X0" and reaches the
        # unsupported-version path instead of the mismatch path.
        t, connection = _transport()
        t.buf = b"SSH-2X0-libssh\n"
        t.gotVersion = False
        connection.getPeer.return_value = MagicMock(host="10.0.0.1", port=1234)

        t.dataReceived(b"")

        connection.write.assert_called_once_with(b"Protocol mismatch.\n")
        self.assertFalse(t.gotVersion)


if __name__ == "__main__":
    unittest.main()
