# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for operator-provided txtcmds_path command output overrides.
# ABOUTME: Covers operator txtcmd precedence and bundled txtcmd fallback.

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

ENV_TXTCMDS = "COWRIE_HONEYPOT_TXTCMDS_PATH"
PROMPT = b"root@unitTest:~# "


class TxtcmdsPathTests(unittest.TestCase):
    """[honeypot] txtcmds_path is used before bundled command output."""

    def setUp(self) -> None:
        self.previous_txtcmds = os.environ.get(ENV_TXTCMDS)
        self.tmpdir = tempfile.TemporaryDirectory()
        os.environ[ENV_TXTCMDS] = self.tmpdir.name

        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()
        self.tmpdir.cleanup()

        if self.previous_txtcmds is None:
            os.environ.pop(ENV_TXTCMDS, None)
        else:
            os.environ[ENV_TXTCMDS] = self.previous_txtcmds

    def test_operator_txtcmds_path_overrides_bundled_command(self) -> None:
        """A command file under txtcmds_path takes precedence over bundled data."""
        command_path = Path(self.tmpdir.name) / "usr" / "bin" / "lscpu"
        command_path.parent.mkdir(parents=True)
        command_path.write_bytes(b"custom cpu output\n")

        self.proto.lineReceived(b"lscpu")

        self.assertEqual(self.tr.value(), b"custom cpu output\n" + PROMPT)

    def test_missing_operator_txtcmd_falls_back_to_bundled_data(self) -> None:
        """Missing operator command files keep the existing bundled fallback."""
        self.proto.lineReceived(b"lscpu")

        output = self.tr.value()
        self.assertIn(b"Architecture", output)
        self.assertIn(b"CPU", output)
        self.assertTrue(output.endswith(PROMPT))
