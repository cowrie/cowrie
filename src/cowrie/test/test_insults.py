# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/insults/insults.py output handling.
# ABOUTME: Verifies line-ending behaviour differs between exec and interactive channels.

from __future__ import annotations

import errno
import os
import shutil
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from twisted.python import log

from cowrie.core import ttylog
from cowrie.insults.insults import FREE_SPACE_CHECK_INTERVAL, LoggingServerProtocol
from cowrie.test.eventcapture import capture_events


class FakeTransport:
    """Minimal transport capturing bytes written to it."""

    def __init__(self) -> None:
        self.written: bytes = b""
        self.lost: bool = False

    def write(self, data: bytes) -> None:
        self.written += data

    def loseConnection(self) -> None:
        self.lost = True


def make_protocol(channel_type: str) -> LoggingServerProtocol:
    lsp = LoggingServerProtocol.__new__(LoggingServerProtocol)
    lsp.type = channel_type
    lsp.bytesSent = 0
    lsp.ttylogEnabled = False
    lsp.ttylogOpen = False
    lsp.ttylogRecording = False
    lsp.ttylogSize = 0
    lsp.transport = FakeTransport()
    return lsp


class TtylogRecordingTestCase(unittest.TestCase):
    """The TTY log stops recording at its size limit or when the disk refuses
    it; the session itself goes on either way."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.events: list[dict] = []
        log.addObserver(self.events.append)
        self.addCleanup(log.removeObserver, self.events.append)

    def messages(self) -> list[str]:
        return [log.textFromEventDict(e) or "" for e in self.events]

    def make_recording(self, limit: int) -> LoggingServerProtocol:
        lsp = make_protocol("e")
        lsp.ttylogEnabled = True
        lsp.ttylogPath = self.tmpdir.name
        lsp.ttylogFile = os.path.join(self.tmpdir.name, "session.log")
        lsp.ttylogSizeLimit = limit
        lsp.ttylogMinFree = 0
        lsp.ttylogSize = 0
        lsp.startTime = 0.0
        lsp.ttylogWritten = 0
        lsp.stdinlogOpen = False
        lsp.bytesReceived = 0
        lsp.terminalProtocol = None
        lsp.redirFiles = set()
        self.dispatched = capture_events(lsp)
        ttylog.ttylog_open(lsp.ttylogFile, 0.0)
        lsp.ttylogOpen = True
        lsp.ttylogRecording = True
        return lsp

    def recorded(self, lsp: LoggingServerProtocol) -> bytes:
        """The data of every write record in the log, in order."""
        data = b""
        with open(lsp.ttylogFile, "rb") as f:
            while header := f.read(struct.calcsize(ttylog.TTYSTRUCT)):
                length = struct.unpack(ttylog.TTYSTRUCT, header)[2]
                data += f.read(length)
        return data

    def test_output_past_the_size_limit_closes_the_session(self) -> None:
        lsp = self.make_recording(limit=8)
        lsp.write(b"12345")
        self.assertFalse(lsp.transport.lost)
        lsp.write(b"6789")
        lsp.write(b"x")
        self.assertTrue(lsp.transport.lost)
        self.assertEqual(self.recorded(lsp), b"12345")
        self.assertEqual(lsp.ttylogSize, 5)
        self.assertFalse(lsp.ttylogRecording)
        self.assertTrue(
            any("TTY log size limit reached" in m for m in self.messages()),
            self.messages(),
        )

    def test_input_counts_toward_the_size_limit(self) -> None:
        lsp = self.make_recording(limit=8)
        lsp.terminalProtocol = SimpleNamespace(keystrokeReceived=lambda ch, mod: None)
        lsp.state = b"data"
        lsp.dataReceived(b"typed")
        lsp.write(b"echo")
        self.assertEqual(self.recorded(lsp), b"typed")
        self.assertEqual(lsp.transport.written, b"echo")
        self.assertFalse(lsp.ttylogRecording)
        self.assertTrue(lsp.transport.lost)

    def test_no_limit_records_everything(self) -> None:
        lsp = self.make_recording(limit=0)
        lsp.write(b"1" * 100)
        self.assertEqual(self.recorded(lsp), b"1" * 100)
        self.assertTrue(lsp.ttylogRecording)

    def test_free_space_below_the_floor_stops_recording(self) -> None:
        """Free space is checked once per FREE_SPACE_CHECK_INTERVAL bytes of
        log; below ttylog_min_free the session goes on unrecorded."""
        lsp = self.make_recording(limit=0)
        lsp.ttylogMinFree = 1000
        usage = SimpleNamespace(total=10**9, used=10**9 - 500, free=500)
        with mock.patch.object(shutil, "disk_usage", return_value=usage):
            lsp.write(b"a" * (FREE_SPACE_CHECK_INTERVAL - 1))
            lsp.write(b"bb")
            lsp.write(b"c")
        self.assertEqual(self.recorded(lsp), b"a" * (FREE_SPACE_CHECK_INTERVAL - 1))
        self.assertFalse(lsp.ttylogRecording)
        self.assertFalse(lsp.transport.lost)
        self.assertEqual(
            lsp.transport.written, b"a" * (FREE_SPACE_CHECK_INTERVAL - 1) + b"bbc"
        )
        self.assertTrue(
            any("free space below ttylog_min_free" in m for m in self.messages()),
            self.messages(),
        )

    def test_free_space_above_the_floor_keeps_recording(self) -> None:
        lsp = self.make_recording(limit=0)
        lsp.ttylogMinFree = 1000
        usage = SimpleNamespace(total=10**9, used=0, free=10**9)
        with mock.patch.object(shutil, "disk_usage", return_value=usage):
            lsp.write(b"a" * FREE_SPACE_CHECK_INTERVAL)
            lsp.write(b"b")
        self.assertEqual(self.recorded(lsp), b"a" * FREE_SPACE_CHECK_INTERVAL + b"b")
        self.assertTrue(lsp.ttylogRecording)

    def test_write_failure_stops_recording_and_keeps_the_session(self) -> None:
        lsp = self.make_recording(limit=0)
        calls: list[bytes] = []

        def refusing_write(
            logfile: str, length: int, direction: int, stamp: float, data: bytes
        ) -> None:
            calls.append(data)
            raise OSError(errno.ENOSPC, "No space left on device")

        with mock.patch.object(ttylog, "ttylog_write", refusing_write):
            lsp.write(b"first")
            lsp.write(b"second")
        self.assertEqual(lsp.transport.written, b"firstsecond")
        self.assertEqual(calls, [b"first"])
        self.assertFalse(lsp.ttylogRecording)
        self.assertTrue(
            any("Failed to write TTY log" in m for m in self.messages()),
            self.messages(),
        )

    def test_log_that_stopped_recording_is_still_closed(self) -> None:
        lsp = self.make_recording(limit=8)
        lsp.write(b"123456789")
        lsp.connectionLost()
        self.assertEqual(len(self.dispatched), 1)
        self.assertEqual(self.dispatched[0]["size"], 0)
        self.assertTrue(os.path.exists(self.dispatched[0]["ttylog"]))

    def test_close_failure_is_logged_and_not_raised(self) -> None:
        lsp = self.make_recording(limit=0)
        lsp.write(b"out")

        def refusing_hash(logfile: str) -> str:
            raise OSError(errno.ENOSPC, "No space left on device")

        with mock.patch.object(ttylog, "ttylog_inputhash", refusing_hash):
            lsp.connectionLost()
        self.assertFalse(lsp.ttylogOpen)
        self.assertEqual(self.dispatched, [])
        self.assertTrue(
            any("Failed to close TTY log" in m for m in self.messages()),
            self.messages(),
        )


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


class DataReceivedAfterTeardownTestCase(unittest.TestCase):
    """dataReceived must discard data once the terminal protocol is gone."""

    def test_data_after_teardown_is_discarded(self) -> None:
        # connectionLost() clears terminalProtocol; a final data packet
        # delivered in the same reactor iteration must be dropped rather than
        # crashing in ServerProtocol.dataReceived (issue #40225).
        lsp = make_protocol("i")
        lsp.terminalProtocol = None
        lsp.stdinlogOpen = False
        lsp.bytesReceived = 0
        lsp.dataReceived(b"late keystrokes")  # must not raise
        # Discarded before being counted or delegated to the parent.
        self.assertEqual(lsp.bytesReceived, 0)

    def test_teardown_during_iteration_is_discarded(self) -> None:
        # A keystroke handler can synchronously tear the session down (in-process
        # session channels close without a reactor round-trip), clearing
        # terminalProtocol mid-way through the parent's byte-by-byte loop. The
        # next byte then dereferences None inside ServerProtocol.dataReceived
        # (issue #40248). The top-of-method guard cannot catch this because the
        # reference is still set on entry.
        lsp = make_protocol("i")
        lsp.stdinlogOpen = False
        lsp.bytesReceived = 0
        lsp.state = b"data"  # parent loop's initial state

        class _TeardownOnFirstKeystroke:
            """Nulls terminalProtocol on the first keystroke, as an in-process
            channel teardown does."""

            def __init__(self) -> None:
                self.received: list[bytes] = []

            def keystrokeReceived(self, ch: bytes, modifier: object) -> None:
                self.received.append(ch)
                lsp.terminalProtocol = None

        term = _TeardownOnFirstKeystroke()
        lsp.terminalProtocol = term

        lsp.dataReceived(b"ab")  # must not raise on the second byte

        self.assertEqual(term.received, [b"a"])
        self.assertIsNone(lsp.terminalProtocol)


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
