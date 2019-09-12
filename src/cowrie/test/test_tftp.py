# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.

"""
Tests for general shell interaction and echo command
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


class ShellTftpCommandTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(
          fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_echo_command_001(self):
        """
        Basic test
        """
        self.proto.lineReceived(b'tftp\n')
        self.assertEquals(
          self.tr.value(),
          b'usage: tftp [-h] [-c C C] [-l L] [-g G] [-p P] [-r R] [hostname]\n'
          + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
