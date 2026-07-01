# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH transport's handling of untrusted client bytes.
# ABOUTME: Covers KEXINIT algorithm name-lists carrying non-printable bytes.

from __future__ import annotations

import unittest
from hashlib import md5
from unittest.mock import MagicMock, patch

from twisted.conch.ssh.common import NS
from twisted.conch.ssh.transport import MSG_SERVICE_REQUEST

from cowrie.ssh import transport as ssh_transport


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
        with (
            patch("cowrie.ssh.transport.log.msg") as mock_msg,
            patch("twisted.conch.ssh.transport.SSHServerTransport.ssh_KEXINIT"),
        ):
            t.ssh_KEXINIT(packet)
        for call in mock_msg.call_args_list:
            if call.kwargs.get("eventid") == "cowrie.client.kex":
                return dict(call.kwargs)
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

        with patch("cowrie.ssh.transport.log.msg") as mock_msg:
            t.dispatchMessage(MSG_SERVICE_REQUEST, b"\x00\x00\x00")

        t.transport.loseConnection.assert_called_once()

        event = next(
            (
                dict(c.kwargs)
                for c in mock_msg.call_args_list
                if c.kwargs.get("eventid") == "cowrie.client.malformed_packet"
            ),
            None,
        )
        self.assertIsNotNone(event, "no malformed_packet event was emitted")
        assert event is not None
        self.assertEqual(event["messagenum"], MSG_SERVICE_REQUEST)
        self.assertEqual(event["datalen"], 3)


if __name__ == "__main__":
    unittest.main()
