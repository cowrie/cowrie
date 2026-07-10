# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for input typed while a foreground command is running: the
# ABOUTME: command queues it and the shell runs it after the command exits.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class QueuedInputTests(unittest.TestCase):
    """Lines sent while a command holds the terminal run once it exits."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _finish_sleep(self) -> None:
        """End the pending sleep command as if its timer fired."""
        cmd = self.proto.cmdstack[-1]
        cmd.scheduled.cancel()
        cmd.done()

    def test_queued_line_runs_after_command_exits(self) -> None:
        self.proto.lineReceived(b"sleep 100\n")
        self.proto.lineReceived(b"echo hello\n")
        self._finish_sleep()
        self.assertEqual(self.tr.value(), b"hello\n" + PROMPT)

    def test_queued_line_with_multiple_statements(self) -> None:
        self.proto.lineReceived(b"sleep 100\n")
        self.proto.lineReceived(b"echo one; echo two\n")
        self._finish_sleep()
        self.assertEqual(self.tr.value(), b"one\ntwo\n" + PROMPT)

    def test_queued_line_dispatches_input_event(self) -> None:
        self.proto.lineReceived(b"sleep 100\n")
        self.proto.lineReceived(b"echo hello\n")
        self._finish_sleep()
        events = [
            e
            for e in self.tr.dispatchedEvents
            if e["eventid"] == "cowrie.command.input"
            and e["input"].strip() == "echo hello"
        ]
        self.assertEqual(
            len(events), 1, f"expected one CMD event for the queued line: {events!r}"
        )
        self.assertEqual(events[0]["session"], "test-suite")

    def test_queued_exit_ends_session_without_error(self) -> None:
        self.proto.lineReceived(b"sleep 100\n")
        self.proto.lineReceived(b"echo bye\n")
        self.proto.lineReceived(b"exit\n")
        self._finish_sleep()
        self.assertEqual(self.tr.value(), b"bye\n")
