# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.

"""
Tests for general shell interaction and tee command
"""

from __future__ import absolute_import, division

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["SHELL_FILESYSTEM"] = "../share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellTeeCommandTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_tee_command_001(self):
        """
        No such file
        """
        self.proto.lineReceived(b'tee /a/b/c/d\n')
        self.assertEquals(self.tr.value(), b'tee: /a/b/c/d: No such file or directory\n')

    def test_tee_command_002(self):
        """
        argument - (stdin)
        """
        self.proto.lineReceived(b'tee /a/b/c/d\n')
        self.proto.handle_CTRL_C()
        self.assertEquals(self.tr.value(), b'tee: /a/b/c/d: No such file or directory\n^C\n' + PROMPT)

    def test_tee_command_003(self):
        """
        test ignore stdin when called without '-'
        """
        self.proto.lineReceived(b'tee a\n')
        self.proto.lineReceived(b'test\n')
        self.proto.handle_CTRL_D()
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_tee_command_004(self):
        """
        test handle of stdin
        """
        self.proto.lineReceived(b'echo test | tee\n')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_tee_command_005(self):
        """
        test handle of CTRL_C
        """
        self.proto.lineReceived(b'tee\n')
        self.proto.lineReceived(b'test\n')
        self.proto.handle_CTRL_D()
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
