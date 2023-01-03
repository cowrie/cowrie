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

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost("tearDown From Unit Test")

    def setUp(self) -> None:
        self.tr.clear()

    def test_help_command(self) -> None:
        usage = (
            b"BusyBox v1.20.2 (2016-06-22 15:12:53 EDT) multi-call binary.\n"
            b"\n"
            b"Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n"
            b"\n"
            b"Download a file via FTP\n"
            b"\n"
            b"    -c Continue previous transfer\n"
            b"    -v Verbose\n"
            b"    -u USER     Username\n"
            b"    -p PASS     Password\n"
            b"    -P NUM      Port\n\n"
        )
        self.proto.lineReceived(b"ftpget\n")
        self.assertEqual(self.tr.value(), usage + PROMPT)
