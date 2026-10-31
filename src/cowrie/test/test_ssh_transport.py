# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH transport's handling of untrusted client bytes.
# ABOUTME: Covers KEXINIT name-lists with non-printable bytes, disconnect logging
# ABOUTME: and the cap on an unterminated client identification line.

from __future__ import annotations

import struct
import unittest
from hashlib import md5
from unittest.mock import MagicMock, patch

from twisted.conch.ssh.common import NS
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.transport import (
    DISCONNECT_PROTOCOL_ERROR,
    MSG_DISCONNECT,
    MSG_KEX_DH_GEX_REQUEST,
    MSG_SERVICE_REQUEST,
)

from cowrie.ssh import transport as ssh_transport
from cowrie.test.eventcapture import capture_events


def _kexinit_payload(kex_algs: list[bytes]) -> bytes:
    """Build a minimal SSH_MSG_KEXINIT payload with the given kex name-list.

    Layout (RFC 4253): 16-byte cookie, then 10 name-list strings, then a
    boolean and a reserved uint32. ssh_KEXINIT only pulls the 10 name-lists.
    """
    cookie = b"\x00" * 16
    name_lists = [
        b",".join(kex_algs),  # kex algorithms
        b"ssh-rsa",  # server host key algorithms
        b"aes128-ctr",  # encryption client->server
        b"aes128-ctr",  # encryption server->client
        b"hmac-sha2-256",  # mac client->server
        b"hmac-sha2-256",  # mac server->client
        b"none",  # compression client->server
        b"none",  # compression server->client
        b"",  # languages client->server
        b"",  # languages server->client
    ]
    return cookie + b"".join(NS(n) for n in name_lists) + b"\x00" + b"\x00\x00\x00\x00"


class TestKexInitEscaping(unittest.TestCase):
    """A malformed KEXINIT must not crash and must not log raw control bytes."""

    def _kex_event(self, packet: bytes) -> dict:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        dispatched = capture_events(t)
        with patch("twisted.conch.ssh.transport.SSHServerTransport.ssh_KEXINIT"):
            t.ssh_KEXINIT(packet)
        for event in dispatched:
            if event.get("eventid") == "cowrie.client.kex":
                return event
        self.fail("no cowrie.client.kex event was emitted")

    def test_invalid_utf8_algorithm_name_does_not_crash(self) -> None:
        # A client offering a kex name with a non-UTF8 byte used to raise
        # UnicodeDecodeError out of ssh_KEXINIT.
        event = self._kex_event(_kexinit_payload([b"weird\xff-kex"]))
        self.assertIn("weird\\xff-kex", event["hasshAlgorithms"])

    def test_legitimate_client_hassh_is_stable(self) -> None:
        # The fingerprint must be byte-for-byte what the original plain
        # decode("utf-8") path produced, so historical hassh values still match.
        kex = [b"curve25519-sha256", b"ecdh-sha2-nistp256"]
        event = self._kex_event(_kexinit_payload(kex))

        ckex = ",".join(a.decode("utf-8") for a in kex)
        expected_algs = f"{ckex};aes128-ctr;hmac-sha2-256;none"
        expected_hassh = md5(expected_algs.encode("utf-8")).hexdigest()

        self.assertEqual(event["hasshAlgorithms"], expected_algs)
        self.assertEqual(event["hassh"], expected_hassh)


class TestMalformedPacket(unittest.TestCase):
    """A truncated message body must be logged and dropped, not crash."""

    def test_truncated_message_disconnects_and_logs(self) -> None:
        # A SERVICE_REQUEST whose body is too short for getNS()'s leading
        # uint32 underflows struct.unpack inside the handler. dispatchMessage
        # must catch that, emit a malformed_packet event, and drop the
        # connection (as OpenSSH does) rather than letting it escape.
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        dispatched = capture_events(t)

        t.dispatchMessage(MSG_SERVICE_REQUEST, b"\x00\x00\x00")

        t.transport.loseConnection.assert_called_once()

        event = next(
            (
                e
                for e in dispatched
                if e.get("eventid") == "cowrie.client.malformed_packet"
            ),
            None,
        )
        self.assertIsNotNone(event, "no malformed_packet event was emitted")
        assert event is not None
        self.assertEqual(event["messagenum"], MSG_SERVICE_REQUEST)
        self.assertEqual(event["datalen"], 3)


class TestSendDisconnect(unittest.TestCase):
    """Every disconnect reason is logged on one line and drops the connection."""

    def _disconnect(
        self, desc: bytes
    ) -> tuple[ssh_transport.HoneyPotSSHTransport, MagicMock, MagicMock]:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t._log = log = MagicMock()
        with patch.object(t, "sendPacket") as send_packet:
            t.sendDisconnect(DISCONNECT_PROTOCOL_ERROR, desc)
        return t, send_packet, log

    def test_bad_packet_mod_logs_one_line_and_sends_disconnect(self) -> None:
        # Twisted's own sendDisconnect() logs "code N\nreason: ..." so the
        # event lands in the log file as two physical lines.
        t, send_packet, log = self._disconnect(b"bad packet mod (444%8 == 4)")

        self.assertNotIn("\n", log.info.call_args.args[0])
        self.assertEqual(send_packet.call_args.args[0], MSG_DISCONNECT)
        t.transport.loseConnection.assert_called_once()

    def test_bad_packet_length_logs_one_line_and_sends_nothing(self) -> None:
        # Answering a bad packet length with SSH_MSG_DISCONNECT is a known
        # Cowrie tell, so that reason only drops the connection.
        t, send_packet, log = self._disconnect(b"bad packet length 1048577")

        self.assertNotIn("\n", log.info.call_args.args[0])
        send_packet.assert_not_called()
        t.transport.loseConnection.assert_called_once()


class TestVersionStringCap(unittest.TestCase):
    """A client that never ends its identification line is cut off at 4 KiB."""

    def _transport(self) -> ssh_transport.HoneyPotSSHTransport:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t._log = MagicMock()
        t.buf = b""
        return t

    def test_over_cap_without_newline_disconnects(self) -> None:
        t = self._transport()

        with patch.object(t, "sendPacket") as send_packet:
            t.dataReceived(b"A" * 4097)

        self.assertEqual(send_packet.call_args.args[0], MSG_DISCONNECT)
        t.transport.loseConnection.assert_called_once()


class TestGexWithoutModuli(unittest.TestCase):
    """A group-exchange request with no moduli loaded is dropped, not a crash.

    Regression test for issue #40178. Without a moduli file the factory stops
    offering the group-exchange key exchanges, but a client can still send
    MSG_KEX_DH_GEX_REQUEST. Twisted then asserts inside getDHPrime(), and the
    AssertionError used to escape the transport.
    """

    REQUEST = struct.pack(">3L", 1024, 2048, 8192)

    def _transport(
        self, primes: dict[int, list[tuple[int, int]]] | None
    ) -> ssh_transport.HoneyPotSSHTransport:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t._log = MagicMock()
        # The real Twisted factory, so the real getDHPrime() runs.
        factory = SSHFactory()
        factory.primes = primes
        t.factory = factory
        return t

    def test_request_without_moduli_drops_connection(self) -> None:
        cases: list[dict[int, list[tuple[int, int]]] | None] = [None, {}]
        for primes in cases:
            with self.subTest(primes=primes):
                t = self._transport(primes)

                t.dispatchMessage(MSG_KEX_DH_GEX_REQUEST, self.REQUEST)

                t.transport.loseConnection.assert_called_once_with()

    def test_request_with_moduli_is_still_served(self) -> None:
        # With primes loaded the request is answered with a group, as before.
        t = self._transport({2048: [(2, 23)]})

        with (
            patch.object(t, "sendPacket") as send_packet,
            patch.object(t, "_startEphemeralDH"),
        ):
            t.dispatchMessage(MSG_KEX_DH_GEX_REQUEST, self.REQUEST)

        send_packet.assert_called_once()
        t.transport.loseConnection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
