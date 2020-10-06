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


class ShellEchoCommandTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_echo_command_001(self):
        """
        Basic test
        """
        self.proto.lineReceived(b'echo "test"\n')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_002(self):
        """
        argument splitting and recombining
        """
        self.proto.lineReceived(b'echo test  test\n')
        self.assertEquals(self.tr.value(), b'test test\n' + PROMPT)

    def test_echo_command_003(self):
        """
        echo -n
        """
        self.proto.lineReceived(b'echo -n "test  test"\n')
        self.assertEquals(self.tr.value(), b'test  test' + PROMPT)

    def test_echo_command_004(self):
        """
        echo -n
        """
        self.proto.lineReceived(b'echo -n "test  test"\n')
        self.assertEquals(self.tr.value(), b'test  test' + PROMPT)

    def test_echo_command_005(self):
        """
        echo test >> test; cat test
        """
        self.proto.lineReceived(b'echo test > test5; cat test5')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_006(self):
        """
        echo -n
        """
        self.proto.lineReceived(b'echo "\\n"\n')
        self.assertEquals(self.tr.value(), b'\\n\n' + PROMPT)

    def test_echo_command_007(self):
        """
        echo test >> test; cat test
        """
        self.proto.lineReceived(b'echo test >> test7; cat test7')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_008(self):
        """
        echo test > test; echo test >> test; cat test
        """
        self.proto.lineReceived(b'echo test > test8; echo test >> test8; cat test8')
        self.assertEquals(self.tr.value(), b'test\ntest\n' + PROMPT)

    def test_echo_command_009(self):
        """
        echo test | grep test
        """
        self.proto.lineReceived(b'echo test | grep test')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_010(self):
        """
        echo test | grep test
        """
        self.proto.lineReceived(b'echo test | grep test2')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_echo_command_011(self):
        """
        echo test > test011; cat test011 | grep test
        """
        self.proto.lineReceived(b'echo test > test011; cat test011 | grep test')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_012(self):
        """
        echo test > test012; grep test test012
        """
        self.proto.lineReceived(b'echo test > test012; grep test test012')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_013(self):
        """
        echo "ls""ls"
        """
        self.proto.lineReceived(b'echo "ls""ls"')
        self.assertEquals(self.tr.value(), b'lsls\n' + PROMPT)

    def test_echo_command_014(self):
        """
        echo '"ls"'
        """
        self.proto.lineReceived(b'echo \'"ls"\'')
        self.assertEquals(self.tr.value(), b'"ls"\n' + PROMPT)

    def test_echo_command_015(self):
        """
        echo "'ls'"
        """
        self.proto.lineReceived(b'echo "\'ls\'"')
        self.assertEquals(self.tr.value(), b'\'ls\'\n' + PROMPT)

    def test_echo_command_016(self):
        """
        echo -e "\x6b\x61\x6d\x69"
        """
        self.proto.lineReceived(b'echo -e "\x6b\x61\x6d\x69"')
        self.assertEquals(self.tr.value(), b'kami\n' + PROMPT)

    def test_echo_command_017(self):
        """
        echo -e "\x6b\x61\x6d\x69"
        """
        self.proto.lineReceived(b'echo echo test | bash')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_018(self):
        """
        echo $(echo test)
        """
        self.proto.lineReceived(b'echo $(echo test)')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_019(self):
        """
        echo $(echo $(echo test))
        """
        self.proto.lineReceived(b'echo $(echo $(echo test))')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def test_echo_command_020(self):
        """
        echo test_$(echo test)_test
        """
        self.proto.lineReceived(b'echo test_$(echo test)_test')
        self.assertEquals(self.tr.value(), b'test_test_test\n' + PROMPT)

    def test_echo_command_021(self):
        """
        echo test_$(echo test)_test_$(echo test)_test
        """
        self.proto.lineReceived(b'echo test_$(echo test)_test_$(echo test)_test')
        self.assertEquals(self.tr.value(), b'test_test_test_test_test\n' + PROMPT)

    def test_echo_command_022(self):
        """
        (echo test)
        """
        self.proto.lineReceived(b'(echo test)')
        self.assertEquals(self.tr.value(), b'test\n' + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
