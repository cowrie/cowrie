# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/insults/insults.py output handling.
# ABOUTME: Verifies line-ending behaviour differs between exec and interactive channels.

from __future__ import annotations

import unittest

from cowrie.insults.insults import LoggingServerProtocol


class FakeTransport:
    """Minimal transport capturing bytes written to it."""

    def __init__(self) -> None:
        self.written: bytes = b""

    def write(self, data: bytes) -> None:
        self.written += data


def make_protocol(channel_type: str) -> LoggingServerProtocol:
    lsp = LoggingServerProtocol.__new__(LoggingServerProtocol)
    lsp.type = channel_type
    lsp.bytesSent = 0
    lsp.ttylogEnabled = False
    lsp.ttylogOpen = False
    lsp.transport = FakeTransport()
    return lsp


class WriteLineEndingTestCase(unittest.TestCase):
    """Tests for LoggingServerProtocol.write() line-ending handling."""

    def test_exec_channel_keeps_bare_newline(self) -> None:
        """Exec channels have no PTY, so \\n must not be rewritten to \\r\\n."""
        lsp = make_protocol("e")
        lsp.write(b"Linux server01 5.10.0 armv7l\n")
        self.assertEqual(lsp.transport.written, b"Linux server01 5.10.0 armv7l\n")

    def test_interactive_channel_translates_newline(self) -> None:
        """Interactive PTY sessions still rewrite \\n to \\r\\n."""
        lsp = make_protocol("i")
        lsp.write(b"Linux server01 5.10.0 armv7l\n")
        self.assertEqual(lsp.transport.written, b"Linux server01 5.10.0 armv7l\r\n")
