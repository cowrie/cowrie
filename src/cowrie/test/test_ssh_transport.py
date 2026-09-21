# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH transport's handling of untrusted client bytes.
# ABOUTME: Covers KEXINIT algorithm name-lists carrying non-printable bytes.
# ABOUTME: Covers sendDisconnect() single-line logging and dataReceived() 4KB buffer cap.

from __future__ import annotations

import unittest
from hashlib import md5
from unittest.mock import MagicMock, patch

from twisted.conch.ssh.common import NS
from twisted.conch.ssh.transport import MSG_SERVICE_REQUEST

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
    """sendDisconnect() must log every reason as a single line/event."""

    def _make_transport(self):
        """Build a minimal HoneyPotSSHTransport with mocked internals."""
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        # sendPacket needs currentEncryptions to be set up
        from twisted.conch.ssh import transport as _transport

        t.currentEncryptions = _transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        t.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")
        t.outgoingCompression = None
        t._keyExchangeState = t._KEY_EXCHANGE_NONE
        t._blockedByKeyExchange = []
        t.outgoingPacketSequence = 0
        return t

    def _capture_logs(self, t, reason, desc):
        """Call sendDisconnect and return captured Twisted log events."""
        from twisted.logger import globalLogPublisher

        captured = []

        def observer(event):
            captured.append(event)

        globalLogPublisher.addObserver(observer)
        try:
            t.sendDisconnect(reason, desc)
        finally:
            globalLogPublisher.removeObserver(observer)
        return captured

    def test_non_bad_packet_length_logs_single_line(self) -> None:
        """A disconnect reason other than 'bad packet length' must produce
        a single-line log entry and call loseConnection."""
        t = self._make_transport()

        captured = self._capture_logs(t, 2, b"bad packet mod (444%8 == 4)")

        t.transport.loseConnection.assert_called_once()
        # Find the disconnect log event
        disconnect_events = [
            e for e in captured
            if "log_format" in e and "Disconnecting" in e["log_format"]
        ]
        self.assertEqual(len(disconnect_events), 1, "expected exactly one disconnect log")
        fmt = disconnect_events[0]["log_format"]
        self.assertNotIn("\n", fmt, "log format must not contain a newline")

    def test_bad_packet_length_skips_disconnect_packet(self) -> None:
        """The 'bad packet length' workaround must NOT send
        SSH_MSG_DISCONNECT but must still log and disconnect."""
        t = self._make_transport()

        with patch.object(t, "sendPacket") as mock_send:
            captured = self._capture_logs(t, 2, b"bad packet length 999999")

        # No MSG_DISCONNECT packet should be sent (fingerprinting workaround)
        mock_send.assert_not_called()
        t.transport.loseConnection.assert_called_once()
        # Still must have logged
        disconnect_events = [
            e for e in captured
            if "log_format" in e and "Disconnecting" in e["log_format"]
        ]
        self.assertEqual(len(disconnect_events), 1)

    def test_all_twisted_error_reasons_log_single_line(self) -> None:
        """Every disconnect reason that Twisted's getPacket() triggers must
        be logged as a single line."""
        reasons = [
            (2, b"bad packet mod (444%8 == 4)"),
            (2, b"bad decryption"),
            (5, b"bad MAC"),
            (6, b"compression error"),
        ]
        for code, desc in reasons:
            t = self._make_transport()
            captured = self._capture_logs(t, code, desc)
            disconnect_events = [
                e for e in captured
                if "log_format" in e and "Disconnecting" in e["log_format"]
            ]
            self.assertEqual(
                len(disconnect_events), 1,
                f"expected one disconnect log for reason {desc!r}",
            )
            fmt = disconnect_events[0]["log_format"]
            self.assertNotIn(
                "\n", fmt,
                f"log for reason {desc!r} must not contain a newline",
            )
            t.transport.loseConnection.assert_called_once()


class TestVersionStringBufferCap(unittest.TestCase):
    """dataReceived() must enforce a 4096-byte cap on the version buffer."""

    def _make_transport(self):
        """Build a minimal HoneyPotSSHTransport ready for dataReceived."""
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t.buf = b""
        t.gotVersion = False
        t._emit_connect_pending = False
        # sendDisconnect needs these for sendPacket
        from twisted.conch.ssh import transport as _transport

        t.currentEncryptions = _transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        t.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")
        t.outgoingCompression = None
        t._keyExchangeState = t._KEY_EXCHANGE_NONE
        t._blockedByKeyExchange = []
        t.outgoingPacketSequence = 0
        return t

    def test_buffer_over_4096_disconnects(self) -> None:
        """A client sending >4096 bytes without \\n must be disconnected."""
        t = self._make_transport()

        # Send 4097 bytes of 'A' with no newline
        t.dataReceived(b"A" * 4097)

        t.transport.loseConnection.assert_called_once()
        # The buffer should not keep growing — connection is dropped
        self.assertFalse(t.gotVersion)

    def test_buffer_under_4096_does_not_disconnect(self) -> None:
        """A client sending <4096 bytes without \\n must NOT be disconnected;
        the transport waits for more data."""
        t = self._make_transport()

        t.dataReceived(b"A" * 4000)

        t.transport.loseConnection.assert_not_called()
        self.assertFalse(t.gotVersion)
        self.assertEqual(len(t.buf), 4000)

    def test_normal_version_string_proceeds(self) -> None:
        """A well-formed SSH version string under 4096 bytes must be accepted
        and gotVersion set to True."""
        t = self._make_transport()
        t.supportedVersions = (b"2.0",)

        with patch.object(t, "sendKexInit"):
            t.dataReceived(b"SSH-2.0-TestClient\r\n")

        self.assertTrue(t.gotVersion)
        self.assertEqual(t.otherVersionString, b"SSH-2.0-TestClient")
        t.transport.loseConnection.assert_not_called()


if __name__ == "__main__":
    unittest.main()

