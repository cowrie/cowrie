# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.

"""
Tests for uname command
"""

from __future__ import absolute_import, division

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["SHELL_FILESYSTEM"] = "../share/cowrie/fs.pickle"

KERNEL_NAME = "Linux"
HOSTNAME = "unitTest"
KERNEL_VERSION = "3.2.0-4-amd64"
KERNEL_BUILD_STRING = "#1 SMP Debian 3.2.68-1+deb7u1"
HARDWARE_PLATFORM = "x86_64"
OPERATING_SYSTEM = "GNU/Linux"
PROMPT = "root@unitTest:~# "


class ShellTeeCommandTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_uname_command_001(self):
        """
        Default output
        """
        self.proto.lineReceived(b"uname")
        self.assertEquals(self.tr.value(), (KERNEL_NAME + "\n" + PROMPT).encode())

    def test_uname_command_002(self):
        """
        All information
        """
        self.proto.lineReceived(b"uname -a")
        self.assertEquals(self.tr.value(),
                          "{} {} {} {} {} {} {} {}\n{}".format(KERNEL_NAME, HOSTNAME, KERNEL_VERSION,
                                                               KERNEL_BUILD_STRING, HARDWARE_PLATFORM,
                                                               HARDWARE_PLATFORM, HARDWARE_PLATFORM, OPERATING_SYSTEM,
                                                               PROMPT).encode())

    def test_uname_command_003(self):
        """
        uname -a -s
        Should return all information because of -a
        """
        self.proto.lineReceived(b"uname -a -s")
        self.assertEquals(self.tr.value(),
                          "{} {} {} {} {} {} {} {}\n{}".format(KERNEL_NAME, HOSTNAME, KERNEL_VERSION,
                                                               KERNEL_BUILD_STRING, HARDWARE_PLATFORM,
                                                               HARDWARE_PLATFORM, HARDWARE_PLATFORM, OPERATING_SYSTEM,
                                                               PROMPT).encode())

    def test_uname_command_004(self):
        """
        uname -s -n -r -v -m -o
        """
        self.proto.lineReceived(b"uname -s -n -r -v -m -o")
        self.assertEquals(self.tr.value(),
                          "{} {} {} {} {} {}\n{}".format(KERNEL_NAME, HOSTNAME, KERNEL_VERSION, KERNEL_BUILD_STRING,
                                                         HARDWARE_PLATFORM, OPERATING_SYSTEM, PROMPT).encode())

    def test_uname_command_005(self):
        """
        uname -o -m -v -r -n -s
        Should return the same output as the previous test
        """
        self.proto.lineReceived(b"uname -o -m -v -r -n -s")
        self.assertEquals(self.tr.value(),
                          "{} {} {} {} {} {}\n{}".format(KERNEL_NAME, HOSTNAME, KERNEL_VERSION, KERNEL_BUILD_STRING,
                                                         HARDWARE_PLATFORM, OPERATING_SYSTEM, PROMPT).encode())

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
