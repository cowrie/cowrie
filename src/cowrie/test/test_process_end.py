# SPDX-FileCopyrightText: 2026 sudu787
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a session's process ends exactly once, whatever ends it:
# ABOUTME: a late channel EOF, input after exit, a timeout, or a disconnect.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from twisted.internet import task
from twisted.internet.protocol import connectionDone

from cowrie.commands import base as base_command
from cowrie.commands import sleep as sleep_command
from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.test.eventcapture import CaptureSink, make_exec_transport
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def exit_code(reason: Any) -> int:
    """The exit status carried by a processEnded reason."""
    code: int = reason.value.exitCode
    return code


class ExecProcessEndTests(unittest.TestCase):
    """An exec session reports its exit status once. Conch only records the
    session's client after execCommand() returns, so a command that finishes
    during it cannot tear the protocol down: the finished shell stays on the
    cmdstack, and the client's channel EOF, which usually arrives next,
    reaches it."""

    def start(self, cmd: bytes) -> tuple[insults.LoggingServerProtocol, list[int]]:
        """Open an exec channel running ``cmd``; the returned list collects
        the exit status of every processEnded the channel receives."""
        ended: list[int] = []
        transport = make_exec_transport(
            CaptureSink(),
            processEnded=lambda reason=None: ended.append(exit_code(reason)),
        )
        lsp = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, FakeAvatar(FakeServer()), cmd
        )
        lsp.makeConnection(transport)
        self.addCleanup(self.close, lsp)
        return lsp, ended

    @staticmethod
    def close(lsp: insults.LoggingServerProtocol) -> None:
        if lsp.terminalProtocol is not None:
            lsp.connectionLost(connectionDone)

    def test_late_eof_does_not_end_again(self) -> None:
        lsp, ended = self.start(b"echo hi")
        self.assertEqual(ended, [0])
        lsp.eofReceived()
        self.assertEqual(ended, [0])

    def test_late_eof_keeps_a_failing_status(self) -> None:
        lsp, ended = self.start(b"false")
        lsp.eofReceived()
        self.assertEqual(ended, [1])

    def test_late_eof_after_exit_keeps_its_status(self) -> None:
        # `exit` leaves the cmdstack empty, and the EOF used to end the
        # process a second time with status 0.
        lsp, ended = self.start(b"exit 3")
        lsp.eofReceived()
        self.assertEqual(ended, [3])

    def test_late_eof_after_exec_keeps_its_status(self) -> None:
        lsp, ended = self.start(b"exec false")
        lsp.eofReceived()
        self.assertEqual(ended, [1])

    def test_timeout_after_the_end_does_not_end_again(self) -> None:
        lsp, ended = self.start(b"echo hi")
        lsp.terminalProtocol.timeoutConnection()
        self.assertEqual(ended, [0])

    def test_timeout_ends_a_running_command(self) -> None:
        clock = task.Clock()
        with patch.object(sleep_command, "reactor", clock):
            lsp, ended = self.start(b"sleep 5")
        self.assertEqual(ended, [])
        lsp.terminalProtocol.timeoutConnection()
        self.assertEqual(ended, [1])

    def test_command_finishing_after_disconnect_is_quiet(self) -> None:
        # A command that outlives the client (here a sleep, as a download
        # would) finishes with no channel left to report its status to.
        clock = task.Clock()
        with patch.object(sleep_command, "reactor", clock):
            lsp, ended = self.start(b"sleep 1")
        lsp.connectionLost(connectionDone)
        clock.advance(1)
        self.assertEqual(ended, [])


class InteractiveProcessEndTests(unittest.TestCase):
    """An interactive session ends once. A telnet connection closes after the
    process ended, not during, so input already received is still read."""

    def setUp(self) -> None:
        self.proto = protocol.HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.ended: list[int] = []
        self.tr.transport.processEnded = lambda reason: self.ended.append(
            exit_code(reason)
        )

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_input_after_exit_does_not_end_again(self) -> None:
        self.proto.lineReceived(b"exit 3")
        self.proto.lineReceived(b"uname")
        self.proto.eofReceived()
        self.assertEqual(self.ended, [3])

    def test_repeated_eof_ends_once(self) -> None:
        self.proto.lineReceived(b"false")
        self.proto.eofReceived()
        self.proto.eofReceived()
        self.assertEqual(self.ended, [1])

    def test_exit_in_a_nested_shell_does_not_end_the_session(self) -> None:
        self.proto.lineReceived(b"bash")
        self.proto.lineReceived(b"exit 4")
        self.assertEqual(self.ended, [])
        self.proto.lineReceived(b"exit")
        self.assertEqual(self.ended, [4])

    def test_end_after_disconnect_is_quiet(self) -> None:
        self.proto.connectionLost()
        self.proto.end_process(0)
        self.assertEqual(self.ended, [])


class DelayedShutdownTests(unittest.TestCase):
    """reboot and shutdown end the session after a delay, during which the
    client may disconnect."""

    LINES = (b"reboot", b"shutdown -h now", b"shutdown -r now")

    def setUp(self) -> None:
        self.clock = task.Clock()
        reactor_patch = patch.object(base_command, "reactor", self.clock)
        reactor_patch.start()
        self.addCleanup(reactor_patch.stop)

    def run_line(
        self, line: bytes
    ) -> tuple[protocol.HoneyPotInteractiveProtocol, list[int]]:
        proto = protocol.HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        tr.clear()
        ended: list[int] = []
        tr.transport.processEnded = lambda reason: ended.append(exit_code(reason))
        self.addCleanup(proto.connectionLost)
        proto.lineReceived(line)
        return proto, ended

    def test_ends_the_session_after_the_delay(self) -> None:
        for line in self.LINES:
            with self.subTest(line=line):
                _proto, ended = self.run_line(line)
                self.assertEqual(ended, [])
                self.clock.advance(3)
                self.assertEqual(ended, [0])

    def test_disconnect_during_the_delay_is_quiet(self) -> None:
        for line in self.LINES:
            with self.subTest(line=line):
                proto, ended = self.run_line(line)
                proto.connectionLost()
                self.clock.advance(3)
                self.assertEqual(ended, [])


if __name__ == "__main__":
    unittest.main()
