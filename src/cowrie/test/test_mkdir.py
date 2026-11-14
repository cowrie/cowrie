# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
# ABOUTME: Tests for the mkdir command's options (-p, -v, -m) and errors.
# ABOUTME: Expected output follows GNU coreutils 9 mkdir.
from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.shell.fs import A_MODE
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellMkdirCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/fs.py mkdir."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: str) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line.encode())
        output: bytes = self.tr.value()
        return output

    def test_parents_existing_directory_is_silent(self) -> None:
        """mkdir -p on an existing directory prints nothing and succeeds."""
        self.assertEqual(self.run_line("mkdir -p /root; echo $?"), b"0\n" + PROMPT)

    def test_parents_option_is_not_created_as_directory(self) -> None:
        self.run_line("cd /tmp; mkdir -p /tmp/x")
        self.assertFalse(self.proto.fs.exists("/tmp/-p"))

    def test_parents_creates_missing_parents(self) -> None:
        self.assertEqual(self.run_line("mkdir -p /tmp/a/b/c"), PROMPT)
        self.assertTrue(self.proto.fs.isdir("/tmp/a/b/c"))

    def test_parents_long_option(self) -> None:
        self.assertEqual(self.run_line("mkdir --parents /tmp/l/m"), PROMPT)
        self.assertTrue(self.proto.fs.isdir("/tmp/l/m"))

    def test_parents_relative_path(self) -> None:
        self.run_line("cd /tmp; mkdir -p r/s")
        self.assertTrue(self.proto.fs.isdir("/tmp/r/s"))

    def test_parents_file_in_place_of_target(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -p /etc/passwd; echo $?"),
            b"mkdir: cannot create directory '/etc/passwd': File exists\n1\n" + PROMPT,
        )

    def test_parents_file_in_place_of_parent(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -p /etc/passwd/x; echo $?"),
            b"mkdir: cannot create directory '/etc/passwd': Not a directory\n1\n"
            + PROMPT,
        )

    def test_without_parents_missing_parent_fails(self) -> None:
        self.assertEqual(
            self.run_line("mkdir /tmp/no/such; echo $?"),
            b"mkdir: cannot create directory '/tmp/no/such': No such file or directory\n1\n"
            + PROMPT,
        )

    def test_verbose_reports_each_directory(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -pv /tmp/v/w"),
            b"mkdir: created directory '/tmp/v'\n"
            b"mkdir: created directory '/tmp/v/w'\n" + PROMPT,
        )

    def test_mode_sets_permissions(self) -> None:
        self.assertEqual(self.run_line("mkdir -m 700 -p /tmp/priv"), PROMPT)
        node = self.proto.fs.getfile("/tmp/priv")
        assert node is not None
        self.assertEqual(node[A_MODE] & 0o7777, 0o700)

    def test_invalid_mode(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -m xyz /tmp/bad; echo $?"),
            b"mkdir: invalid mode 'xyz'\n1\n" + PROMPT,
        )
        self.assertFalse(self.proto.fs.exists("/tmp/bad"))

    def test_double_dash_ends_options(self) -> None:
        self.run_line("cd /tmp; mkdir -p -- -x")
        self.assertTrue(self.proto.fs.isdir("/tmp/-x"))

    def test_invalid_option(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -z /tmp/z; echo $?"),
            b"mkdir: invalid option -- 'z'\n"
            b"Try 'mkdir --help' for more information.\n1\n" + PROMPT,
        )
        self.assertFalse(self.proto.fs.exists("/tmp/z"))

    def test_options_without_operand(self) -> None:
        self.assertEqual(
            self.run_line("mkdir -p; echo $?"),
            b"mkdir: missing operand\nTry 'mkdir --help' for more information.\n1\n"
            + PROMPT,
        )


if __name__ == "__main__":
    unittest.main()
