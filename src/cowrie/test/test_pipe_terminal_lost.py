# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a command writing after its client has gone logs the lost
# ABOUTME: terminal once, not once per write.

from __future__ import annotations

import os
import tempfile
import unittest

from twisted.logger import ILogObserver, globalLogPublisher
from zope.interface import provider

from cowrie.shell.pipe import PipeProtocol
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

MESSAGE = "Connection was probably lost. Could not write to terminal"


class TerminalLostLogTests(unittest.TestCase):
    """A download that outlives its client keeps writing its progress meter;
    each command logs the lost terminal once."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)

        self.messages: list[object] = []

        @provider(ILogObserver)
        def record(event: dict[str, object]) -> None:
            self.messages.append(event.get("log_format"))

        globalLogPublisher.addObserver(record)
        self.addCleanup(globalLogPublisher.removeObserver, record)

    def make_pipe(self) -> PipeProtocol:
        return PipeProtocol(
            self.proto,
            cmd="wget",
            cmdargs=[],
            input_data=None,
            cwd="/root",
            user={"uid": 0, "gid": 0},
        )

    def lost_count(self) -> int:
        return self.messages.count(MESSAGE)

    def test_writes_reach_the_terminal_while_connected(self) -> None:
        pipe = self.make_pipe()
        self.tr.clear()
        pipe.write_stdout(b"out\n")
        pipe.write_stderr(b"err\n")
        self.assertEqual(self.tr.value(), b"out\nerr\n")
        self.assertEqual(self.lost_count(), 0)
        self.proto.connectionLost()

    def test_writes_after_disconnect_log_once(self) -> None:
        pipe = self.make_pipe()
        self.proto.connectionLost()
        for _ in range(1000):
            pipe.write_stderr(b"  1% [>    ]\r")
        pipe.write_stdout(b"done\n")
        self.assertEqual(self.lost_count(), 1)

    def test_each_command_logs_its_own_loss(self) -> None:
        pipes = [self.make_pipe(), self.make_pipe()]
        self.proto.connectionLost()
        for pipe in pipes:
            pipe.write_stderr(b"a")
            pipe.write_stderr(b"b")
        self.assertEqual(self.lost_count(), 2)


if __name__ == "__main__":
    unittest.main()
