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


class ShellLsCommandTests(unittest.TestCase):
    """Test for cowrie/commands/ls.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_ls_command_001(self) -> None:
        self.proto.lineReceived(b"ls NonExisting\n")
        self.assertEqual(
            self.tr.value(),
            b"ls: cannot access /root/NonExisting: No such file or directory\n"
            + PROMPT,
        )

    def test_ls_command_002(self) -> None:
        self.proto.lineReceived(b"ls /\n")
        self.assertEqual(
            self.tr.value(),
            b"bin        boot       dev        etc        home       initrd.img lib        \nlost+found media      mnt        opt        proc       root       run        \nsbin       selinux    srv        sys        test2      tmp        usr        \nvar        vmlinuz    \n"
            + PROMPT,
        )

    def test_ls_command_003(self) -> None:
        self.proto.lineReceived(b"ls -l /\n")
        self.assertIsNotNone(
            self.tr.value(),
        )

    def test_ls_command_004(self) -> None:
        self.proto.lineReceived(b"ls -lh /\n")
        self.assertIsNotNone(
            self.tr.value(),
        )
