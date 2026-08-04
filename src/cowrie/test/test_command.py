# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/shell/command.py, the command base class.
# ABOUTME: Verifies exit() semantics, in particular that a late second exit is safe.

from __future__ import annotations

import os
import unittest

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
