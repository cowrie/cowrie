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


class ShellEchoCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/awk.py."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_awk_command_001(self) -> None:
        self.proto.lineReceived(b'echo "test test" | awk "{ print $0 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_002(self) -> None:
        self.proto.lineReceived(b'echo "test" | awk "{ print $1 }"\n')
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_awk_command_003(self) -> None:
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1 $2 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_004(self) -> None:
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1,$2 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_005(self) -> None:
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1$2 }"\n')
        self.assertEqual(self.tr.value(), b"testtest\n" + PROMPT)
