# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a command keeps its own stdio wiring: a pipeline stage
# ABOUTME: that finishes late must still see its own fds, not a later command's.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import ClassVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
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
        self.before = set(self.proto.fs.backing_files)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()
        for real in self.created:
            if os.path.exists(real):
                os.remove(real)

    def new_redir_paths(self) -> dict[str, str]:
        """Backing files this test's commands created, mapped to the
        emulated path each one holds."""
        paths = self.proto.fs.backing_file_paths()
        new = {real: path for real, path in paths.items() if real not in self.before}
        self.created.extend(new)
        return new

    def test_async_stage_writes_its_own_redirect(self) -> None:
        # The async stage's stderr goes to its own redirect file, even though
        # a downstream stage started meanwhile.
        self.proto.lineReceived(b"fakeasync 2> /tmp/pp_async_err.log | cat\n")
        FakeAsyncCommand.pending[0].finish()
        new = self.new_redir_paths()
        self.assertEqual(list(new.values()), ["/tmp/pp_async_err.log"])
        with open(next(iter(new)), "rb") as f:
            self.assertEqual(f.read(), b"stderr-payload\n")

    def test_sync_redirect_is_tracked(self) -> None:
        self.proto.lineReceived(b"echo hi > /tmp/pp_sync.log\n")
        self.assertIn("/tmp/pp_sync.log", self.new_redir_paths().values())

    def test_command_pipe_is_its_own(self) -> None:
        self.proto.lineReceived(b"fakeasync | cat\n")
        stage = FakeAsyncCommand.pending[0]
        self.assertIsNotNone(stage.pp)
        self.assertIs(stage.pp.cmd, FakeAsyncCommand)
