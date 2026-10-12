# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/shell/command.py, the command base class.
# ABOUTME: Verifies exit() semantics and that disconnecting stops a command's timers.

from __future__ import annotations

import os
import unittest
from typing import Any

from twisted.internet import reactor

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class ExitTests(unittest.TestCase):
    """exit() hands control back to the shell exactly once.

    An async command (wget, curl) can exit early (size limit, CTRL-C) while
    its download deferred is still pending; when the download later completes,
    its callback calls exit() again. That late call must be a no-op: it must
    not crash on the cmdstack and must not resume the shell a second time.
    """

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_second_exit_is_noop(self) -> None:
        # Bypass HoneyPotCommand.__init__: its stdout/stderr wiring needs a
        # running process protocol (self.protocol.pp), which is irrelevant to
        # the exit bookkeeping under test here.
        cmd = HoneyPotCommand.__new__(HoneyPotCommand)
        cmd.protocol = self.proto
        cmd.exit_code = 0
        shell = self.proto.cmdstack[0]
        self.proto.cmdstack.append(cmd)

        cmd.exit()
        self.assertEqual(self.proto.cmdstack, [shell])
        output_after_first_exit = self.tr.value()

        cmd.exit()
        self.assertEqual(self.proto.cmdstack, [shell])
        self.assertEqual(
            self.tr.value(),
            output_after_first_exit,
            "a late second exit() must not resume the shell again",
        )


class ConnectionLostTests(unittest.TestCase):
    """Disconnecting stops every timer a running command holds.

    A command that paces itself with the reactor is never sent Ctrl-C when the
    client goes away. Without teardown its scheduled call keeps firing into the
    dead session: ping without -c once a second and yes a hundred times a
    second, each tick logging a failed terminal write, for as long as the
    process runs.
    """

    def setUp(self) -> None:
        self.baseline = self.active_calls()
        self.sessions: list[HoneyPotInteractiveProtocol] = []

    def tearDown(self) -> None:
        for proto in self.sessions:
            proto.connectionLost()
        for call in self.new_calls():
            call.cancel()

    def active_calls(self) -> set[Any]:
        return {call for call in reactor.getDelayedCalls() if call.active()}

    def new_calls(self) -> set[Any]:
        return self.active_calls() - self.baseline

    def session(self, *lines: str) -> HoneyPotInteractiveProtocol:
        proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        proto.makeConnection(FakeTransport("", "31337"))
        self.sessions.append(proto)
        # The idle timeout is the session's own timer, not a command's.
        self.baseline |= self.active_calls()
        for line in lines:
            proto.lineReceived(line.encode())
        return proto

    def test_disconnect_cancels_command_timers(self) -> None:
        for lines in (
            ("ping 1.1.1.1",),
            ("yes",),
            ("sleep 100",),
            ("adduser bob",),
            ("shutdown -h now",),
            ("reboot",),
            ("apt-get install nano",),
            ("yum install nano",),
            ("ssh root@1.2.3.4", "yes", "secret"),
        ):
            with self.subTest(command=lines[0]):
                proto = self.session(*lines)
                self.assertTrue(self.new_calls(), "command scheduled nothing")
                proto.connectionLost()
                self.assertEqual(self.new_calls(), set())

    def test_disconnect_after_timer_fired_is_safe(self) -> None:
        proto = self.session("sleep 0")
        reactor.runUntilCurrent()  # type: ignore[attr-defined]
        self.assertEqual(self.new_calls(), set())
        proto.connectionLost()
