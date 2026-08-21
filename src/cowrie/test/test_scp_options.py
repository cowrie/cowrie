# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for scp command option parsing.
# ABOUTME: Verifies `scp -d` with no target directory does not crash.

from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class ScpOptionTests(unittest.TestCase):
    """Tests for cowrie/commands/scp.py option handling."""

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

    def test_scp_dash_d_without_target_does_not_crash(self) -> None:
        """`scp -d` with no positional target directory used to read args[0]
        on an empty list, raising IndexError and killing the session before it
        wrote anything. It should now start cleanly and emit its null-byte
        handshake."""
        self.proto.lineReceived(b"scp -d\n")
        value = self.tr.value()
        # A crash left the transport empty; a clean start writes the scp
        # acknowledgement bytes.
        self.assertTrue(value, "scp -d produced no output (command crashed)")
        self.assertEqual(value, b"\x00" * len(value))
