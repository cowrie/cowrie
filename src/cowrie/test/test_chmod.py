# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.

"""
Tests for general shell interaction and chmod command
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

    def test_chmod_command_001(self):
        """
        Missing operand
        """
        self.proto.lineReceived(b"chmod")
        self.assertEquals(
            self.tr.value(),
            b"chmod: missing operand\nTry 'chmod --help' for more information.\n"
            + PROMPT
        )

    def test_chmod_command_002(self):
        """
        Missing operand after...
        """
        self.proto.lineReceived(b"chmod arg")
        self.assertEquals(
            self.tr.value(),
            b"chmod: missing operand after \xe2\x80\x98arg\xe2\x80\x99\nTry 'chmod --help' for more information.\n"
            + PROMPT
        )

    def test_chmod_command_003(self):
        """
        Missing operand
        """
        self.proto.lineReceived(b"chmod +x")
        self.assertEquals(
            self.tr.value(),
            b"chmod: missing operand after \xe2\x80\x98+x\xe2\x80\x99\nTry 'chmod --help' for more information.\n"
            + PROMPT
        )

    def test_chmod_command_004(self):
        """
        No such file or directory
        """
        self.proto.lineReceived(b"chmod +x abcd")
        self.assertEquals(self.tr.value(), b"chmod: cannot access 'abcd': No such file or directory\n" + PROMPT)

    # does not work properly
    # def test_chmod_command_005(self):
    #     """
    #     Invalid option
    #     """
    #     self.proto.lineReceived(b"chmod -A +x abcd")
    #     self.assertEquals(
    #         self.tr.value(),
    #         b"chmod: invalid option -- 'A'\nTry 'chmod --help' for more information.\n" + PROMPT
    #     )

    def test_chmod_command_006(self):
        """
        Invalid mode
        """
        self.proto.lineReceived(b"chmod abcd efgh")
        self.assertEquals(
            self.tr.value(),
            b"chmod: invalid mode: \xe2\x80\x98abcd\xe2\x80\x99\nTry 'chmod --help' for more information.\n"
            + PROMPT
        )

    def test_chmod_command_007(self):
        """
        Valid directory .ssh recursive
        """
        self.proto.lineReceived(b"chmod -R +x .ssh")
        self.assertEquals(self.tr.value(), PROMPT)

    def test_chmod_command_008(self):
        """
        Valid directory .ssh
        """
        self.proto.lineReceived(b"chmod +x .ssh")
        self.assertEquals(self.tr.value(), PROMPT)

    def test_chmod_command_009(self):
        """
        Valid directory /root/.ssh
        """
        self.proto.lineReceived(b"chmod +x /root/.ssh")
        self.assertEquals(self.tr.value(), PROMPT)

    def test_chmod_command_010(self):
        """
        Valid directory ~/.ssh
        """
        self.proto.lineReceived(b"chmod +x ~/.ssh")
        self.assertEquals(self.tr.value(), PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
