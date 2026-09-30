# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The tr command must translate, delete and squeeze bytes as GNU
# ABOUTME: coreutils tr does, including ranges, classes and its error messages.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "

TRY_HELP = b"Try 'tr --help' for more information.\n"


class TrTests(unittest.TestCase):
    """Expected output is what GNU coreutils 9 tr prints in the C locale."""

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

    def test_delete(self) -> None:
        self.assertEqual(self.run_line(b"echo hello | tr -d 'l'"), b"heo\n")

    def test_delete_newlines(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\nb\\n' | tr -d '\\n'"), b"ab")

    def test_ranges(self) -> None:
        self.assertEqual(self.run_line(b"echo hello | tr 'a-z' 'A-Z'"), b"HELLO\n")
        self.assertEqual(self.run_line(b"echo hello | tr 'a-z' 'n-za-m'"), b"uryyb\n")

    def test_classes(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hello | tr '[:lower:]' '[:upper:]'"), b"HELLO\n"
        )
        self.assertEqual(self.run_line(b"echo a1b2 | tr -d '[:digit:]'"), b"ab\n")

    def test_escapes(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\tb' | tr '\\t' ' '"), b"a b")
        self.assertEqual(self.run_line(b"echo 'a:b' | tr ':' '\\n'"), b"a\nb\n")

    def test_short_second_set_repeats_its_last_character(self) -> None:
        self.assertEqual(self.run_line(b"echo abc | tr 'abc' 'x'"), b"xxx\n")

    def test_truncate_first_set(self) -> None:
        self.assertEqual(self.run_line(b"echo abc | tr -t 'abc' 'x'"), b"xbc\n")

    def test_squeeze(self) -> None:
        self.assertEqual(self.run_line(b"echo 'a   b' | tr -s ' '"), b"a b\n")
        self.assertEqual(self.run_line(b"echo hello | tr -s 'l' 'x'"), b"hexo\n")

    def test_complement(self) -> None:
        self.assertEqual(self.run_line(b"echo hello | tr -cd 'l\\n'"), b"ll\n")
        self.assertEqual(self.run_line(b"echo abc | tr -c 'a' 'z'"), b"azzz")

    def test_missing_operand(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hello | tr; echo rc=$?"),
            b"tr: missing operand\n" + TRY_HELP + b"rc=1\n",
        )

    def test_missing_second_set_when_translating(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hello | tr abc; echo rc=$?"),
            b"tr: missing operand after 'abc'\n"
            b"Two strings must be given when translating.\n" + TRY_HELP + b"rc=1\n",
        )

    def test_extra_operand_when_deleting(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hello | tr -d a b; echo rc=$?"),
            b"tr: extra operand 'b'\n"
            b"Only one string may be given when deleting without squeezing "
            b"repeats.\n" + TRY_HELP + b"rc=1\n",
        )

    def test_fallback_chain_uses_tr(self) -> None:
        """The recon script's `( tr ... || busybox tr ... || cat )` pattern."""
        self.assertEqual(
            self.run_line(
                b"printf 'x\\ny\\n' | ( tr -d '\\n' 2>/dev/null || cat ); echo"
            ),
            b"xy\n",
        )


if __name__ == "__main__":
    unittest.main()
