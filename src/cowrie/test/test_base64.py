# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

TRY_CHMOD_HELP_MSG = b"Try 'base64 --help' for more information.\n"
PROMPT = b"root@unitTest:~# "


class ShellBase64CommandTests(unittest.TestCase):
    """Tests for cowrie/commands/base64.py"""

    def setUp(self) -> None:
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer())
        )
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost("tearDown From Unit Test")

    def test_base64_command_001(self) -> None:
        self.proto.lineReceived(b"echo cowrie | base64")
        self.assertEqual(self.tr.value(), b"Y293cmllCg==\n" + PROMPT)

    def test_base64_command_002(self) -> None:
        self.proto.lineReceived(b"echo Y293cmllCg== | base64 -d")
        self.assertEqual(self.tr.value(), b"cowrie\n" + PROMPT)
