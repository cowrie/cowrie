# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.

from __future__ import division, absolute_import
import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["HONEYPOT_FILESYSTEM_FILE"] = "../share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "

class ShellEchoCommandTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()


    def test_echo_command_1(self):
        """
        Basic test
        """
        self.proto.lineReceived(b'echo "test"\n')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)


    def test_echo_command_2(self):
        """
        argument splitting and recombining
        """
        self.proto.lineReceived(b'echo test  test\n')
        self.assertEquals(self.tr.value(), b'test test\n' + PROMPT)


    def test_echo_command_3(self):
        """
        echo -n 
        """
        self.proto.lineReceived(b'echo -n "test  test"\n')
        self.assertEquals(self.tr.value(), b'test  test' + PROMPT)


    def test_echo_command_4(self):
        """
        echo -n 
        """
        self.proto.lineReceived(b'echo -n "test  test"\n')
        self.assertEquals(self.tr.value(), b'test  test' + PROMPT)


    # def test_echo_command_5(self):
    #     """
    #     echo -n 
    #     """
    #     self.proto.lineReceived(b'echo \\n\n')
    #     self.assertEquals(self.tr.value(), b'n\n' + PROMPT)


    def test_echo_command_6(self):
        """
        echo -n 
        """
        self.proto.lineReceived(b'echo "\\n"\n')
        self.assertEquals(self.tr.value(), b'\\n\n' + PROMPT)


    # def test_echo_command_7(self):
    #     """
    #     echo -n 
    #     """
    #     self.proto.lineReceived(b'echo -e "\\n"\n')
    #     self.assertEquals(self.tr.value(), b'\n\n' + PROMPT)


    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
