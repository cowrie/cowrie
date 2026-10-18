# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts TCPTunnelForwardingChannel.write() closes on a rejected
# ABOUTME: or malformed CONNECT response without forwarding its data.

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
            channel.write(b"http")

        close.assert_called_once_with("Connection refused")
        write.assert_not_called()

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
