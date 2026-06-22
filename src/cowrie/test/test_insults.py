# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/insults/insults.py output handling.
# ABOUTME: Verifies line-ending behaviour differs between exec and interactive channels.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from twisted.python import log

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


class ConnectionLostStdinTestCase(unittest.TestCase):
    """Tests for stdin-log cleanup in LoggingServerProtocol.connectionLost()."""

    def test_no_stdin_data_does_not_open_missing_file(self) -> None:
        """An exec session that received no stdin has no log file to hash.

        connectionMade() sets stdinlogOpen unconditionally for exec channels,
        but the file is only created once dataReceived() writes to it. A session
        that closes without sending stdin must not attempt to open the missing
        file just to have the open fail.
        """
        with tempfile.TemporaryDirectory() as downloadPath:
            lsp = make_protocol("e")
            lsp.stdinlogOpen = True
            lsp.stdinlogFile = os.path.join(downloadPath, "never-written-stdin.log")
            lsp.downloadPath = downloadPath
            lsp.redirFiles = set()
            lsp.terminalProtocol = None

            opened: list[str] = []
            real_open = open

            def tracking_open(path, *args, **kwargs):
                opened.append(path)
                return real_open(path, *args, **kwargs)

            with mock.patch("builtins.open", tracking_open):
                lsp.connectionLost()

            self.assertNotIn(lsp.stdinlogFile, opened)
            self.assertFalse(lsp.stdinlogOpen)
            self.assertFalse(os.path.exists(lsp.stdinlogFile))

    def test_failure_saving_existing_stdin_log_is_logged(self) -> None:
        """A genuine I/O failure on an existing stdin log must not be silent.

        The missing-file case is now skipped, so any OSError that reaches the
        handler is unexpected and must be logged rather than swallowed.
        """
        with tempfile.TemporaryDirectory() as downloadPath:
            lsp = make_protocol("e")
            lsp.stdinlogOpen = True
            lsp.stdinlogFile = os.path.join(downloadPath, "stdin.log")
            lsp.downloadPath = downloadPath
            lsp.redirFiles = set()
            lsp.terminalProtocol = None
            with open(lsp.stdinlogFile, "wb") as f:
                f.write(b"id\n")

            def failing_open(*args, **kwargs):
                raise OSError

            events: list[dict] = []
            log.addObserver(events.append)
            try:
                with mock.patch("builtins.open", failing_open):
                    lsp.connectionLost()
            finally:
                log.removeObserver(events.append)

            messages = [log.textFromEventDict(e) or "" for e in events]
            self.assertTrue(any("Failed to save stdin contents" in m for m in messages))
            self.assertFalse(lsp.stdinlogOpen)
