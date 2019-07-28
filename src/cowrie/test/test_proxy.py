# -*- test-case-name: Cowrie Proxy Test Cases -*-

# Copyright (c) 2019 Guilherme Borges
# See LICENSE for details.

from __future__ import absolute_import, division

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.ssh_proxy.server_transport import FrontendSSHTransport
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["SHELL_FILESYSTEM"] = "../share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellBaseCommandsTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

        self.transport = FrontendSSHTransport()
        self.transport.connectionMade()


    def test_whoami_command(self):
        self.proto.lineReceived(b'whoami\n')
        self.assertEqual(self.tr.value(), b'root\n' + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
