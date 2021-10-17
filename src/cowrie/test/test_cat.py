# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.

"""
Tests for general shell interaction and cat command
"""

from __future__ import annotations

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "../data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "../share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellCatCommandTests(unittest.TestCase):
    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer())
        )
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_cat_command_001(self):
        """
        No such file
        """
        self.proto.lineReceived(b"cat nonExisting\n")
        self.assertEqual(
            self.tr.value(), b"cat: nonExisting: No such file or directory\n" + PROMPT
        )

    def test_cat_command_002(self):
        """
        argument - (stdin)
        """
        self.proto.lineReceived(b"echo test | cat -\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_cat_command_003(self):
        """
        test without arguments, read stdin only and quit
        """
        self.proto.lineReceived(b"echo 1 | cat\n")
        self.proto.lineReceived(b"echo 2\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"1\n" + PROMPT + b"2\n" + PROMPT)

    def test_cat_command_004(self):
        """
        test handle of CTRL_C
        """
        self.proto.lineReceived(b"cat\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_C()
        self.assertEqual(self.tr.value(), b"test\n^C\n" + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
