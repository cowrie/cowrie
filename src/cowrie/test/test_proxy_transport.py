# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the proxy frontend SSH transport's packet and version handling.
# ABOUTME: Covers fingerprintable responses, message framing and torn-down transports.

from __future__ import annotations

import struct
import unittest
from unittest.mock import MagicMock, patch

from twisted.conch.ssh import transport
from twisted.conch.ssh.factory import SSHFactory
from twisted.internet.testing import StringTransport

from cowrie.ssh_proxy.server_transport import FrontendSSHTransport
from cowrie.test.eventcapture import capture_events, events_of
from cowrie.test.test_ssh_transport import _kexinit_payload, _plain_packet


def _transport() -> tuple[FrontendSSHTransport, MagicMock]:
    """A frontend transport, and the mock standing in for its connection."""
    t = FrontendSSHTransport.__new__(FrontendSSHTransport)
    connection = MagicMock()
    t.transport = connection
    t._log = MagicMock()
    t.events = None
    return t, connection


class TestSendDisconnect(unittest.TestCase):
    """A bad packet length must not draw a fingerprintable reply, and every
    reason is logged on one line."""

    def test_bad_packet_length_writes_nothing(self) -> None:
        # "Packet corrupt" is a documented Cowrie tell: no real SSH server
        # answers a bad packet length with it.
        t, connection = _transport()

        t.sendDisconnect(transport.DISCONNECT_PROTOCOL_ERROR, b"bad packet length")

        connection.write.assert_not_called()
        connection.loseConnection.assert_called_once()

    def test_other_reasons_log_one_line_and_send_disconnect(self) -> None:
        # Twisted's own sendDisconnect() logs "code N\nreason: ..." so the
        # event lands in the log file as two physical lines.
        t, connection = _transport()
        t._log = log = MagicMock()

        with patch.object(t, "sendPacket") as send_packet:
            t.sendDisconnect(transport.DISCONNECT_PROTOCOL_ERROR, b"bad decryption")

        self.assertNotIn("\n", log.info.call_args.args[0])
        self.assertEqual(send_packet.call_args.args[0], transport.MSG_DISCONNECT)
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


class TestStopAfterDrop(unittest.TestCase):
    """Once a packet makes the frontend drop the connection, the packets that
    arrived with it in the same read must not be processed."""

    def test_pipelined_packet_after_failed_kexinit_is_ignored(self) -> None:
        t, _ = _transport()
        t.transport = StringTransport()
        t.buf = b""
        t.gotVersion = True
        t.currentEncryptions = transport.SSHCiphers(b"none", b"none", b"none", b"none")
        t.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")
        unmatched = _plain_packet(
            bytes((transport.MSG_KEXINIT,)) + _kexinit_payload([b"bogus-kex"])
        )

        with patch.object(t, "sendDisconnect", wraps=t.sendDisconnect) as disconnect:
            t.dataReceived(unmatched + unmatched)

        disconnect.assert_called_once()


class TestVersionStringCap(unittest.TestCase):
    """A client that never ends its identification line is cut off at 4 KiB."""

    def test_over_cap_without_newline_disconnects(self) -> None:
        t, connection = _transport()
        t.buf = b""

        with patch.object(t, "sendPacket") as send_packet:
            t.dataReceived(b"A" * 4097)

        self.assertEqual(send_packet.call_args.args[0], transport.MSG_DISCONNECT)
        connection.loseConnection.assert_called_once()


class TestUnexpectedKexMessage(unittest.TestCase):
    """The frontend transport answers a group-exchange request it cannot
    serve with SSH_MSG_UNIMPLEMENTED instead of raising out of Twisted."""

    def test_gex_request_before_kexinit_without_moduli(self) -> None:
        t, connection = _transport()
        t.incomingPacketSequence = 3
        t.currentEncryptions = transport.SSHCiphers(b"none", b"none", b"none", b"none")
        factory = SSHFactory()
        factory.primes = None
        t.factory = factory
        dispatched = capture_events(t)

        with patch.object(t, "sendPacket") as send_packet:
            t.dispatchMessage(
                transport.MSG_KEX_DH_GEX_REQUEST, struct.pack(">3L", 1024, 2048, 8192)
            )

        send_packet.assert_called_once_with(
            transport.MSG_UNIMPLEMENTED, struct.pack("!L", 3)
        )
        connection.loseConnection.assert_not_called()
        (event,) = events_of(dispatched, "cowrie.client.kex_unexpected")
        self.assertEqual(event["messagenum"], transport.MSG_KEX_DH_GEX_REQUEST)


if __name__ == "__main__":
    unittest.main()
