# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that free reports the emulated machine's /proc/meminfo, laid
# ABOUTME: out as procps-ng 4.0.2 (Debian 12) prints it for the same file.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellFreeCommandTests(unittest.TestCase):
    """Expected figures come from the /proc/meminfo in the bundled fs.pickle:
    MemTotal 4054744 kB, MemFree 997740 kB, SwapTotal 2097148 kB."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line)
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_reports_the_emulated_meminfo(self) -> None:
        lines = self.run_line(b"free\n").splitlines()
        mem = lines[1].split()
        swap = lines[2].split()
        self.assertEqual(mem[0], b"Mem:")
        self.assertEqual(mem[1], b"4054744")
        self.assertEqual(mem[3], b"997740")
        self.assertEqual(swap[0], b"Swap:")
        self.assertEqual(swap[1], b"2097148")

    def test_missing_meminfo_is_an_error(self) -> None:
        output = self.run_line(b"rm /proc/meminfo; free; echo $?\n")
        self.assertEqual(
            output,
            b"free: Memory information file /proc/meminfo does not exist\n1\n",
        )
