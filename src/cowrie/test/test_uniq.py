# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.

"""
Tests for uniq command
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


class ShellUniqCommandTests(unittest.TestCase):
    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer())
        )
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_uniq_command_001(self):
        """
        echo test | uniq
        """
        self.proto.lineReceived(b"echo test | uniq\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_uniq_command_002(self):
        """
        echo -e "test\ntest\ntest" | uniq
        """
        self.proto.lineReceived(b'echo -e "test\ntest\ntest" | uniq\n')
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_uniq_command_003(self):
        """
        test without arguments, read stdin and quit after Ctrl+D
        """
        self.proto.lineReceived(b"uniq\n")
        self.proto.lineReceived(b"test\n")
        self.proto.lineReceived(b"test\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n\n" + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
