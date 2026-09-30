# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: head and tail must accept GNU coreutils' option forms (-NUM, -n -NUM,
# ABOUTME: +NUM) and read piped input with no arguments, matching GNU output.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class HeadTailTests(unittest.TestCase):
    """Expected output is what GNU coreutils 9 prints for the same line."""

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

    def test_head_reads_piped_input_without_arguments(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb\\n' | head"), b"a\nb\n")

    def test_head_obsolete_count(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb\\nc\\n' | head -2"), b"a\nb\n")

    def test_head_negative_count_drops_trailing_lines(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\nb\\nc\\n' | head -n -1"), b"a\nb\n"
        )

    def test_head_bytes(self) -> None:
        self.assertEqual(self.run_line(b"printf 'abcdef' | head -c 3"), b"abc")
        self.assertEqual(self.run_line(b"printf 'abcdef' | head -c -2"), b"abcd")

    def test_head_keeps_a_missing_final_newline_missing(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb' | head -n 5"), b"a\nb")

    def test_head_count_with_suffix(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\nb\\nc\\n' | head -n 2k"), b"a\nb\nc\n"
        )

    def test_head_invalid_count(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\n' | head -n x; echo rc=$?"),
            b"head: invalid number of lines: 'x'\nrc=1\n",
        )

    def test_head_missing_file(self) -> None:
        self.assertEqual(
            self.run_line(b"head -1 /nonexist; echo rc=$?"),
            b"head: cannot open '/nonexist' for reading: "
            b"No such file or directory\nrc=1\n",
        )

    def test_tail_reads_piped_input_without_arguments(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb\\n' | tail"), b"a\nb\n")

    def test_tail_obsolete_count(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb\\nc\\n' | tail -1"), b"c\n")

    def test_tail_from_line(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\nb\\nc\\n' | tail -n +2"), b"b\nc\n"
        )

    def test_tail_bytes(self) -> None:
        self.assertEqual(self.run_line(b"printf 'abcdef' | tail -c 2"), b"ef")

    def test_tail_keeps_a_missing_final_newline_missing(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb' | tail -n 1"), b"b")

    def test_tail_missing_file(self) -> None:
        self.assertEqual(
            self.run_line(b"tail /nonexist; echo rc=$?"),
            b"tail: cannot open '/nonexist' for reading: "
            b"No such file or directory\nrc=1\n",
        )


if __name__ == "__main__":
    unittest.main()
