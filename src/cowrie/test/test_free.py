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
HEADER = b"               total        used        free      shared  buff/cache   available\n"


class ShellFreeCommandTests(unittest.TestCase):
    """Expected figures come from the /proc/meminfo in the bundled fs.pickle:
    MemTotal 4054744 kB, MemFree 997740 kB, SwapTotal 2097148 kB. The exact
    outputs are what free from Debian 12's procps 2:4.0.2-3 prints with that
    file mounted over /proc/meminfo."""

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

    def test_default_output_in_kibibytes(self) -> None:
        self.assertEqual(
            self.run_line(b"free\n"),
            HEADER
            + b"Mem:         4054744     3057004      997740       49908     2287068      997740\n"
            b"Swap:        2097148       70632     2026516\n",
        )

    def test_kibibytes(self) -> None:
        self.assertEqual(self.run_line(b"free -k\n"), self.run_line(b"free\n"))

    def test_bytes(self) -> None:
        self.assertEqual(
            self.run_line(b"free -b\n"),
            HEADER
            + b"Mem:      4152057856  3130372096  1021685760    51105792  2341957632  1021685760\n"
            b"Swap:     2147479552    72327168  2075152384\n",
        )

    def test_mebibytes(self) -> None:
        self.assertEqual(
            self.run_line(b"free -m\n"),
            HEADER
            + b"Mem:            3959        2985         974          48        2233         974\n"
            b"Swap:           2047          68        1979\n",
        )

    def test_gibibytes(self) -> None:
        self.assertEqual(
            self.run_line(b"free -g\n"),
            HEADER
            + b"Mem:               3           2           0           0           2           0\n"
            b"Swap:              1           0           1\n",
        )

    def test_human_readable(self) -> None:
        self.assertEqual(
            self.run_line(b"free -h\n"),
            HEADER
            + b"Mem:           3.9Gi       2.9Gi       974Mi        48Mi       2.2Gi       974Mi\n"
            b"Swap:          2.0Gi        68Mi       1.9Gi\n",
        )

    def test_bot_memory_probe(self) -> None:
        """The recon line a common SSH bot sends on every login."""
        self.assertEqual(
            self.run_line(
                b"free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'\n"
            ),
            b"3959 2985 974 48 2233 974\n",
        )

    def test_missing_meminfo_is_an_error(self) -> None:
        output = self.run_line(b"rm /proc/meminfo; free; echo $?\n")
        self.assertEqual(
            output,
            b"free: Memory information file /proc/meminfo does not exist\n1\n",
        )
