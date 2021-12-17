# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellTeeCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/tee.py."""

    def setUp(self) -> None:
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer())
        )
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost("tearDown From Unit Test")

    def test_tee_command_001(self) -> None:
        """No such file."""
        self.proto.lineReceived(b"tee /a/b/c/d\n")
        self.assertEqual(
            self.tr.value(), b"tee: /a/b/c/d: No such file or directory\n"  # TODO: Is PROMPT missing?..
        )

    def test_tee_command_002(self) -> None:
        """Argument - (stdin)."""
        self.proto.lineReceived(b"tee /a/b/c/d\n")  # TODO: Where is a -?..
        self.proto.handle_CTRL_C()
        self.assertEqual(
            self.tr.value(), b"tee: /a/b/c/d: No such file or directory\n^C\n" + PROMPT
        )

    def test_tee_command_003(self) -> None:
        """Test ignore stdin when called without '-'."""
        self.proto.lineReceived(b"tee a\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_tee_command_004(self) -> None:
        """Test handle of stdin."""
        self.proto.lineReceived(b"echo test | tee\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_tee_command_005(self) -> None:
        """Test handle of CTRL_C."""
        self.proto.lineReceived(b"tee\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)
