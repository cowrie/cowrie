# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the gcc command: compiling takes a moment, then leaves an
# ABOUTME: output file and returns the prompt; Ctrl-C stops it.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from twisted.internet.task import Clock

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class GccTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        patcher = patch("cowrie.shell.command.reactor", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.addCleanup(self.proto.connectionLost)
        self.proto.lineReceived(b"echo 'int main(){}' > /tmp/x.c")
        self.tr.clear()

    def test_compile_leaves_output_file_then_prompt(self) -> None:
        self.proto.lineReceived(b"gcc /tmp/x.c")
        self.assertEqual(self.tr.value(), b"", "prompt came back before compiling")

        self.clock.advance(2)

        self.assertTrue(self.proto.fs.exists("/root/a.out"))
        self.assertEqual(self.tr.value(), PROMPT)

    def test_ctrl_c_stops_compile(self) -> None:
        self.proto.lineReceived(b"gcc /tmp/x.c")

        self.proto.handle_CTRL_C()
        self.clock.advance(2)

        self.assertFalse(self.proto.fs.exists("/root/a.out"))
        self.assertEqual(self.tr.value(), b"^C\n" + PROMPT)

    def test_no_input_files_returns_prompt(self) -> None:
        self.proto.lineReceived(b"gcc")

        self.assertEqual(
            self.tr.value(),
            b"gcc: fatal error: no input files\ncompilation terminated.\n" + PROMPT,
        )
