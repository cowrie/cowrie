# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellFtpGetCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/ftpget.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost("tearDown From Unit Test")

    def test_help_command(self):
        self.proto.lineReceived(b"ftpget\n")
        self.assertEqual(
            self.tr.value(),
            b"""BusyBox v1.20.2 (2016-06-22 15:12:53 EDT) multi-call binary.

Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE

Download a file via FTP

    -c Continue previous transfer
    -v Verbose
    -u USER     Username
    -p PASS     Password
    -P NUM      Port\n\n"""
            + PROMPT,
        )
