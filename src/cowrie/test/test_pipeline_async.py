# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a pipeline stage which finishes asynchronously still
# ABOUTME: feeds the next stage, as `wget URL | sh` does on a real shell.

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

    def finish(self, text: str = "payload") -> None:
        FakeAsyncCommand.pending.remove(self)
        self.write(f"{text}\n")
        self.exit(0)


class AsyncPipelineStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.commands["fakeasync"] = FakeAsyncCommand
        FakeAsyncCommand.pending = []
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def finish_one(self, text: str = "payload") -> None:
        self.assertTrue(FakeAsyncCommand.pending, "no async command is running")
        FakeAsyncCommand.pending[0].finish(text)

    def test_async_stage_output_reaches_next_stage(self) -> None:
        self.proto.lineReceived(b"fakeasync | cat\n")
        self.assertEqual(self.tr.value(), b"")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"payload\n" + PROMPT)

    def test_async_stage_feeds_grep(self) -> None:
        self.proto.lineReceived(b"fakeasync | grep payload\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"payload\n" + PROMPT)

    def test_async_stage_output_can_be_redirected_downstream(self) -> None:
        self.proto.lineReceived(b"fakeasync | cat > /tmp/pipeline_async.txt\n")
        self.finish_one()
        self.tr.clear()
        self.proto.lineReceived(b"cat /tmp/pipeline_async.txt\n")
        self.assertEqual(self.tr.value(), b"payload\n" + PROMPT)

    def test_statement_after_async_pipeline_runs_once(self) -> None:
        self.proto.lineReceived(b"fakeasync | cat; echo after\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"payload\nafter\n" + PROMPT)

    def test_downloaded_script_reaches_the_shell(self) -> None:
        # The staging idiom: `wget -qO- URL | sh` must run what was fetched.
        self.proto.lineReceived(b"fakeasync | sh\n")
        self.finish_one("echo staged")
        self.assertEqual(self.tr.value(), b"staged\n" + PROMPT)

    def test_sync_pipeline_unchanged(self) -> None:
        self.proto.lineReceived(b"echo hello | cat\n")
        self.assertEqual(self.tr.value(), b"hello\n" + PROMPT)

    def test_async_last_stage_writes_to_terminal(self) -> None:
        self.proto.lineReceived(b"echo seed | fakeasync\n")
        self.finish_one()
        self.assertEqual(self.tr.value(), b"payload\n" + PROMPT)
