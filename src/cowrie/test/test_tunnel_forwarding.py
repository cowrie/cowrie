# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts TCPTunnelForwardingChannel.write() reads the proxy's whole CONNECT
# ABOUTME: reply, however it is split, and closes without forwarding it unless it is a 200.

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from twisted.conch.ssh import forwarding as conchforwarding

from cowrie.ssh import forwarding

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class TunnelForwardingWriteTests(unittest.TestCase):
    def _channel(self) -> forwarding.TCPTunnelForwardingChannel:
        return forwarding.TCPTunnelForwardingChannel(
            ("127.0.0.1", 8080), ("198.51.100.7", 443)
        )

    def test_non_200_response_closes_without_forwarding(self) -> None:
        channel = self._channel()
        with (
            patch.object(channel, "_close") as close,
            patch.object(conchforwarding.SSHConnectForwardingChannel, "write") as write,
        ):
            channel.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")

        close.assert_called_once_with("Connection refused")
        write.assert_not_called()
        self.assertFalse(channel.tunnel_established)

    def test_malformed_response_closes_without_indexerror(self) -> None:
        channel = self._channel()
        with (
            patch.object(channel, "_close") as close,
            patch.object(conchforwarding.SSHConnectForwardingChannel, "write") as write,
        ):
            channel.write(b"http\r\n\r\n")

        close.assert_called_once_with("Connection refused")
        write.assert_not_called()

    def _feed(
        self, *chunks: bytes
    ) -> tuple[forwarding.TCPTunnelForwardingChannel, list[bytes], int]:
        """Write each chunk to a new channel; return it, the data forwarded to
        the SSH client, and how often the channel was closed."""
        channel = self._channel()
        with (
            patch.object(channel, "_close") as close,
            patch.object(conchforwarding.SSHConnectForwardingChannel, "write") as write,
        ):
            for chunk in chunks:
                channel.write(chunk)
        return channel, [c.args[1] for c in write.call_args_list], close.call_count

    def test_200_reply_split_across_packets_is_not_forwarded(self) -> None:
        channel, forwarded, closed = self._feed(
            b"HTTP/1.1 200 Conn", b"ection established\r\n\r\npay", b"load"
        )

        self.assertEqual(forwarded, [b"pay", b"load"])
        self.assertEqual(closed, 0)
        self.assertTrue(channel.tunnel_established)

    def test_tunneled_traffic_of_any_protocol_is_forwarded(self) -> None:
        # Only the proxy's reply has to be HTTP. A server-first protocol such
        # as SMTP sends its banner after it, in the same packet or a later one.
        banner = b"220 mail.example.com ESMTP Postfix\r\n"
        established = b"HTTP/1.1 200 Connection established\r\n\r\n"
        for chunks in ((established + banner,), (established, banner)):
            with self.subTest(chunks=chunks):
                channel, forwarded, closed = self._feed(*chunks)

                self.assertEqual(forwarded, [banner])
                self.assertEqual(closed, 0)
                self.assertTrue(channel.tunnel_established)

    def test_rejection_split_across_packets_closes(self) -> None:
        channel, forwarded, closed = self._feed(
            b"HTTP/1.1 40", b"3 Forbidden\r\n\r\nbody", b"more body"
        )

        self.assertEqual(forwarded, [])
        self.assertEqual(closed, 1)
        self.assertFalse(channel.tunnel_established)

    def test_reply_that_is_not_http_closes(self) -> None:
        for reply in (b"SSH-2.0-OpenSSH_9.2\r\n", b"\x16\x03\x01\x00\x05"):
            with self.subTest(reply=reply):
                channel, forwarded, closed = self._feed(reply)

                self.assertEqual(forwarded, [])
                self.assertEqual(closed, 1)
                self.assertFalse(channel.tunnel_established)

    def test_reply_header_without_end_is_capped(self) -> None:
        channel, forwarded, closed = self._feed(
            b"HTTP/1.1 200 OK\r\n", b"X-Pad: " + b"a" * 65536
        )

        self.assertEqual(forwarded, [])
        self.assertEqual(closed, 1)
        self.assertFalse(channel.tunnel_established)

    def test_200_response_establishes_and_strips_header(self) -> None:
        channel = self._channel()
        with (
            patch.object(channel, "_close") as close,
            patch.object(conchforwarding.SSHConnectForwardingChannel, "write") as write,
        ):
            channel.write(b"HTTP/1.1 200 Connection established\r\n\r\npayload")

        close.assert_not_called()
        write.assert_called_once_with(channel, b"payload")
        self.assertTrue(channel.tunnel_established)


if __name__ == "__main__":
    unittest.main()
