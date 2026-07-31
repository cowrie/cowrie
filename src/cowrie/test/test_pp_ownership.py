# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a command keeps its own stdio wiring: a pipeline stage
# ABOUTME: that finishes late must still see its own fds, not a later command's.

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
    """Like wget/curl: start() returns and the command only writes its output
    and exits when an external event (here: finish()) fires."""

    pending: ClassVar[list[FakeAsyncCommand]] = []

    def start(self) -> None:
        FakeAsyncCommand.pending.append(self)

    def finish(self) -> None:
        FakeAsyncCommand.pending.remove(self)
        self.errorWrite("stderr-payload\n")
        self.exit(0)


class CommandOwnsItsPipeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.commands["fakeasync"] = FakeAsyncCommand
        FakeAsyncCommand.pending = []
        self.created: list[str] = []
        self.before = set(self.proto.terminal.redirFiles)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()
        for real in self.created:
            if os.path.exists(real):
                os.remove(real)

    def new_redir_files(self) -> set[tuple[str, str]]:
        new: set[tuple[str, str]] = set(self.proto.terminal.redirFiles) - self.before
        self.created.extend(real for real, _virtual in new)
        return new

    def test_async_stage_registers_its_own_redirect(self) -> None:
        # The async stage's stderr redirect must be registered for hashing when
        # it finishes, even though a downstream stage started meanwhile. Losing
        # it orphans the attacker's captured bytes in the download directory
        # with no file_download event.
        self.proto.lineReceived(b"fakeasync 2> /tmp/pp_async_err.log | cat\n")
        FakeAsyncCommand.pending[0].finish()
        self.assertIn(
            "/tmp/pp_async_err.log",
            {virtual for _real, virtual in self.new_redir_files()},
        )

    def test_sync_redirect_still_registers(self) -> None:
        self.proto.lineReceived(b"echo hi > /tmp/pp_sync.log\n")
        self.assertIn(
            "/tmp/pp_sync.log",
            {virtual for _real, virtual in self.new_redir_files()},
        )

    def test_command_pipe_is_its_own(self) -> None:
        self.proto.lineReceived(b"fakeasync | cat\n")
        stage = FakeAsyncCommand.pending[0]
        self.assertIsNotNone(stage.pp)
        self.assertIs(stage.pp.cmd, FakeAsyncCommand)
