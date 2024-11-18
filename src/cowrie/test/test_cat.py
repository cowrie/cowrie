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
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellCatCommandTests(unittest.TestCase):
    """Test for cowrie/commands/cat.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_cat_command_001(self) -> None:
        self.proto.lineReceived(b"cat nonExisting\n")
        self.assertEqual(
            self.tr.value(), b"cat: nonExisting: No such file or directory\n" + PROMPT
        )

    def test_cat_command_002(self) -> None:
        self.proto.lineReceived(b"echo test | cat -\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_cat_command_003(self) -> None:
        self.proto.lineReceived(b"echo 1 | cat\n")
        self.proto.lineReceived(b"echo 2\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"1\n" + PROMPT + b"2\n" + PROMPT)

    def test_cat_command_004(self) -> None:
        self.proto.lineReceived(b"cat\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_C()
        self.assertEqual(self.tr.value(), b"test\n^C\n" + PROMPT)
