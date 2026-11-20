# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests how the shell finds a command: every path that reaches a file
# ABOUTME: in the fake filesystem, e.g. /bin/cat and /usr/bin/cat, runs its emulation.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class CommandLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        self.proto.lineReceived(line + b"\n")
        output: bytes = self.tr.value()
        self.tr.clear()
        return output

    # /bin is a symlink to usr/bin, so /usr/bin/echo is the same file as the
    # /bin/echo the emulation is registered under.
    def test_usr_bin_path_runs_the_emulation(self) -> None:
        self.assertEqual(self.run_line(b"/usr/bin/echo hi"), b"hi\n" + PROMPT)

    def test_usr_sbin_path_runs_the_emulation(self) -> None:
        self.assertEqual(
            self.run_line(b"/usr/sbin/useradd -h >/dev/null; echo $?"),
            self.run_line(b"/sbin/useradd -h >/dev/null; echo $?"),
        )

    def test_dotted_path_runs_the_emulation(self) -> None:
        self.assertEqual(self.run_line(b"/usr/bin/./echo hi"), b"hi\n" + PROMPT)

    # PATH lists /usr/bin before /bin, so a bare `df` resolves to /usr/bin/df;
    # its canned output is stored under bin/df.
    def test_path_lookup_finds_text_command_stored_under_bin(self) -> None:
        self.assertTrue(self.run_line(b"df").startswith(b"Filesystem"))

    def test_usr_bin_path_finds_text_command_stored_under_bin(self) -> None:
        self.assertTrue(self.run_line(b"/usr/bin/df").startswith(b"Filesystem"))
