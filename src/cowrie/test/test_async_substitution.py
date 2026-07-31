# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests command substitution around commands that finish via a
# ABOUTME: Deferred (wget/curl): the shell must block and capture their output.

from __future__ import annotations

import os
import unittest
from typing import ClassVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class FakeAsyncCommand(HoneyPotCommand):
    """A command that, like wget/curl, returns from start() and only writes
    its output and exits when an external event (here: finish()) fires."""

    pending: ClassVar[list[FakeAsyncCommand]] = []

    def start(self) -> None:
        FakeAsyncCommand.pending.append(self)

    def finish(self, output: str = "async-output", code: int = 0) -> None:
        FakeAsyncCommand.pending.remove(self)
        self.write(f"{output}\n")
        self.exit(code)


class AsyncSubstitutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.commands["fakeasync"] = FakeAsyncCommand
        FakeAsyncCommand.pending = []
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def finish_one(self, output: str = "async-output", code: int = 0) -> None:
        self.assertTrue(FakeAsyncCommand.pending, "no async command is running")
        FakeAsyncCommand.pending[0].finish(output, code)

    def test_substitution_blocks_until_command_finishes(self) -> None:
        self.proto.lineReceived(b"echo A $(fakeasync) B\n")
        self.assertEqual(self.tr.value(), b"")

    def test_substitution_captures_async_output(self) -> None:
        self.proto.lineReceived(b"echo A $(fakeasync) B\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"A async-output B\n" + PROMPT)

    def test_backtick_captures_async_output(self) -> None:
        self.proto.lineReceived(b"echo `fakeasync`\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"async-output\n" + PROMPT)

    def test_assignment_captures_async_output(self) -> None:
        self.proto.lineReceived(b"x=$(fakeasync); echo $x\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"async-output\n" + PROMPT)

    def test_shell_usable_after_async_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(fakeasync)\n")
        self.finish_one()
        self.tr.clear()
        self.proto.lineReceived(b"echo done\n")
        self.assertEqual(self.tr.value(), b"done\n" + PROMPT)

    def test_sync_substitution_still_inline(self) -> None:
        self.proto.lineReceived(b"echo $(echo inner)\n")
        self.assertEqual(self.tr.value(), b"inner\n" + PROMPT)

    def test_exit_inside_substitution(self) -> None:
        self.proto.lineReceived(b"echo a$(exit)b\n")
        self.assertEqual(self.tr.value(), b"ab\n" + PROMPT)

    def test_exit_stops_substitution_statements(self) -> None:
        self.proto.lineReceived(b"echo $(echo x; exit; echo y)\n")
        self.assertEqual(self.tr.value(), b"x\n" + PROMPT)

    def test_nested_async_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(echo $(fakeasync))\n")
        self.assertEqual(self.tr.value(), b"")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"async-output\n" + PROMPT)

    def test_conditional_after_async_inside_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(fakeasync && echo ok)\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"async-output\nok\n" + PROMPT)

    def test_failed_async_skips_and_arm(self) -> None:
        self.proto.lineReceived(b"echo $(fakeasync && echo ok)\n")
        self.finish_one(code=1)
        self.assertEqual(self.tr.value(), b"async-output\n" + PROMPT)

    def test_loop_inside_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(for i in a b; do echo $i; done)\n")
        self.assertEqual(self.tr.value(), b"a\nb\n" + PROMPT)

    def test_line_typed_during_substitution_runs_after(self) -> None:
        # The typed line is stdin data buffered for the next reader, never a
        # command inside the subshell: "later" must reach the terminal, not
        # the capture buffer (x would swallow it).
        self.proto.lineReceived(b"x=$(fakeasync)\n")
        self.proto.lineReceived(b"echo later\n")
        self.assertEqual(self.tr.value(), b"")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"later\n" + PROMPT)

    def test_async_substitution_status_reaches_assignment(self) -> None:
        self.proto.lineReceived(b"x=$(fakeasync)\n")
        self.finish_one(code=3)
        self.tr.clear()
        self.proto.lineReceived(b"echo $?\n")
        self.assertEqual(self.tr.value(), b"3\n" + PROMPT)

    def test_sync_substitution_status_reaches_assignment(self) -> None:
        self.proto.lineReceived(b"x=$(exit 5)\n")
        self.tr.clear()
        self.proto.lineReceived(b"echo $?\n")
        self.assertEqual(self.tr.value(), b"5\n" + PROMPT)

    def test_command_status_wins_over_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(exit 5)\n")
        self.tr.clear()
        self.proto.lineReceived(b"echo $?\n")
        self.assertEqual(self.tr.value(), b"0\n" + PROMPT)
