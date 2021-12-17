# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest
from typing import Optional

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellEchoCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/awk.py."""

    proto: Optional[HoneyPotInteractiveProtocol] = None
    tr: Optional[FakeTransport] = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        cls.tr = FakeTransport("1.1.1.1", "1111")
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost("tearDown From Unit Test")

    def setUp(self) -> None:
        self.tr.clear()

    def test_awk_command_001(self) -> None:
        """Test $0, full input line contents."""
        self.proto.lineReceived(b'echo "test test" | awk "{ print $0 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_002(self) -> None:
        """Test $1, first agument."""
        self.proto.lineReceived(b'echo "test" | awk "{ print $1 }"\n')
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_awk_command_003(self) -> None:
        """Test $1 $2 space separated."""
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1 $2 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_004(self) -> None:
        """Test $1,$2 comma separated."""
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1,$2 }"\n')
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_005(self) -> None:
        """Test $1$2 not separated."""
        self.proto.lineReceived(b'echo "test test" | awk "{ print $1$2 }"\n')
        self.assertEqual(self.tr.value(), b"testtest\n" + PROMPT)
