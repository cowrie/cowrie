# Copyright (c) 2020 Peter Sufliarsky
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


class ShellUniqCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/uniq.py."""

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

    def test_uniq_command_001(self) -> None:
        self.proto.lineReceived(b"echo test | uniq\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_uniq_command_002(self) -> None:
        self.proto.lineReceived(b'echo -e "test\ntest\ntest" | uniq\n')
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_uniq_command_003(self) -> None:
        self.proto.lineReceived(b"uniq\n")
        self.proto.lineReceived(b"test\n")
        self.proto.lineReceived(b"test\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n\n" + PROMPT)
