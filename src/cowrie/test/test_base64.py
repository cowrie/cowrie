# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

TRY_CHMOD_HELP_MSG = b"Try 'base64 --help' for more information.\n"
PROMPT = b"root@unitTest:~# "


class ShellBase64CommandTests(unittest.TestCase):
    """Tests for cowrie/commands/base64.py"""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_base64_command_001(self) -> None:
        self.proto.lineReceived(b"echo cowrie | base64")
        self.assertEqual(self.tr.value(), b"Y293cmllCg==\n" + PROMPT)

    def test_base64_command_002(self) -> None:
        self.proto.lineReceived(b"echo Y293cmllCg== | base64 -d")
        self.assertEqual(self.tr.value(), b"cowrie\n" + PROMPT)
