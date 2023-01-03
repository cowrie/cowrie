# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellTeeCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/tee.py."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost("tearDown From Unit Test")

    def setUp(self) -> None:
        self.tr.clear()

    def test_tee_command_001(self) -> None:
        self.proto.lineReceived(b"tee /a/b/c/d\n")
        self.assertEqual(self.tr.value(), b"tee: /a/b/c/d: No such file or directory\n")
        # tee still waiting input from stdin
        self.proto.handle_CTRL_C()

    def test_tee_command_002(self) -> None:
        self.proto.lineReceived(b"tee /a/b/c/d\n")
        self.proto.handle_CTRL_C()
        self.assertEqual(
            self.tr.value(), b"tee: /a/b/c/d: No such file or directory\n^C\n" + PROMPT
        )

    def test_tee_command_003(self) -> None:
        self.proto.lineReceived(b"tee a\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_tee_command_004(self) -> None:
        self.proto.lineReceived(b"echo test | tee\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_tee_command_005(self) -> None:
        self.proto.lineReceived(b"tee\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)
