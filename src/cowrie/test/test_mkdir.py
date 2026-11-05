# SPDX-FileCopyrightText: 2026 Aryamann Srivastava
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: mkdir takes -p, -v and -m and treats the operands that follow like
# ABOUTME: GNU coreutils 9.7 does, instead of making directories named "-p".

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

PROMPT = b"root@unitTest:~# "


class ShellMkdirCommandTests(unittest.TestCase):
    """Expected output is what GNU coreutils 9.7 prints for the same line."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line + b"\n")
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_mkdir_parents_makes_every_missing_directory(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -p a/b/c; [ -d a/b/c ] && echo yes"), b"yes\n"
        )

    def test_mkdir_parents_ignores_a_directory_that_exists(self) -> None:
        self.run_line(b"mkdir a")
        self.assertEqual(self.run_line(b"mkdir -p a; echo $?"), b"0\n")
        self.assertEqual(self.run_line(b"mkdir -p a/b a/b; echo $?"), b"0\n")

    def test_mkdir_without_parents_needs_the_parent(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir a/b; echo $?"),
            b"mkdir: cannot create directory `a/b': No such file or directory\n1\n",
        )

    def test_mkdir_does_not_make_a_directory_called_dash_p(self) -> None:
        self.run_line(b"mkdir -p d")
        self.assertNotIn(b"-p", self.run_line(b"ls"))

    def test_mkdir_options_may_follow_the_operands(self) -> None:
        self.run_line(b"mkdir d -p")
        self.assertEqual(self.run_line(b"[ -d d ] && echo yes"), b"yes\n")
        self.assertEqual(self.run_line(b"[ -e -p ] || echo no"), b"no\n")

    def test_mkdir_double_dash_ends_the_options(self) -> None:
        self.run_line(b"mkdir -- -p")
        self.assertIn(b"-p", self.run_line(b"ls"))

    def test_mkdir_parents_on_a_file(self) -> None:
        self.run_line(b"touch f")
        self.assertEqual(
            self.run_line(b"mkdir -p f; echo $?"),
            b"mkdir: cannot create directory `f': File exists\n1\n",
        )
        self.assertEqual(
            self.run_line(b"mkdir -p f/x; echo $?"),
            b"mkdir: cannot create directory `f': Not a directory\n1\n",
        )

    def test_mkdir_under_a_file(self) -> None:
        self.run_line(b"touch f")
        self.assertEqual(
            self.run_line(b"mkdir f/x; echo $?"),
            b"mkdir: cannot create directory `f/x': Not a directory\n1\n",
        )

    def test_mkdir_verbose(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -v d e"),
            b"mkdir: created directory 'd'\nmkdir: created directory 'e'\n",
        )

    def test_mkdir_verbose_parents_names_each_directory_as_typed(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -pv ./a/b"),
            b"mkdir: created directory './a'\nmkdir: created directory './a/b'\n",
        )
        self.assertEqual(
            self.run_line(b"mkdir --parents --verbose /tmp/x/y"),
            b"mkdir: created directory '/tmp/x'\nmkdir: created directory '/tmp/x/y'\n",
        )

    def test_mkdir_mode(self) -> None:
        self.run_line(b"mkdir -m 700 d")
        self.assertEqual(self.run_line(b"ls -ld d | awk '{print $1}'"), b"drwx------\n")
        self.run_line(b"mkdir --mode=711 e")
        self.assertEqual(self.run_line(b"ls -ld e | awk '{print $1}'"), b"drwx--x--x\n")

    def test_mkdir_symbolic_mode(self) -> None:
        self.run_line(b"mkdir -m u=rwx,g=,o= d")
        self.assertEqual(self.run_line(b"ls -ld d | awk '{print $1}'"), b"drwx------\n")
        self.run_line(b"mkdir -m g+w e")
        self.assertEqual(self.run_line(b"ls -ld e | awk '{print $1}'"), b"drwxrwxrwx\n")

    def test_mkdir_mode_only_changes_the_last_directory(self) -> None:
        self.run_line(b"mkdir -pm 700 x/y")
        self.assertEqual(
            self.run_line(b"ls -ld x x/y | awk '{print $1}'"),
            b"drwxr-xr-x\ndrwx------\n",
        )

    def test_mkdir_invalid_mode(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -m 999 d; echo $?"),
            b"mkdir: invalid mode '999'\n1\n",
        )

    def test_mkdir_invalid_option(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -x d; echo $?"),
            b"mkdir: invalid option -- 'x'\nTry 'mkdir --help' for more information.\n1\n",
        )
        self.assertEqual(
            self.run_line(b"mkdir --foo d; echo $?"),
            b"mkdir: unrecognized option '--foo'\nTry 'mkdir --help' for more information.\n1\n",
        )

    def test_mkdir_missing_operand(self) -> None:
        self.assertEqual(
            self.run_line(b"mkdir -p; echo $?"),
            b"mkdir: missing operand\nTry 'mkdir --help' for more information.\n1\n",
        )


if __name__ == "__main__":
    unittest.main()
