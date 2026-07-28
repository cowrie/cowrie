# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellGrepCommandTests(unittest.TestCase):
    """Test for the grep command in cowrie/commands/fs.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_grep_pipe_match(self) -> None:
        self.proto.lineReceived(b"echo hello | grep hell\n")
        self.assertEqual(self.tr.value(), b"hello\n" + PROMPT)

    def test_grep_pipe_no_match(self) -> None:
        self.proto.lineReceived(b"echo hello | grep zzz\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_grep_pipe_exit_code_match(self) -> None:
        self.proto.lineReceived(b"echo hello | grep hell; echo $?\n")
        self.assertEqual(self.tr.value(), b"hello\n0\n" + PROMPT)

    def test_grep_pipe_exit_code_no_match(self) -> None:
        # grep returns 1 when nothing matched (issue: previously always 0).
        self.proto.lineReceived(b"echo hello | grep zzz; echo $?\n")
        self.assertEqual(self.tr.value(), b"1\n" + PROMPT)

    def test_grep_file(self) -> None:
        self.proto.lineReceived(b"grep root /etc/passwd\n")
        self.assertEqual(self.tr.value(), b"root:x:0:0:root:/root:/bin/bash\n" + PROMPT)

    def test_grep_stdin_match_then_ctrl_c(self) -> None:
        # With no file and no pipe, grep reads stdin: matching lines echo back,
        # non-matching lines are silent. CTRL-C interrupts.
        self.proto.lineReceived(b"grep foo\n")
        self.proto.lineReceived(b"foobar\n")
        self.proto.lineReceived(b"baz\n")
        self.proto.handle_CTRL_C()
        self.assertEqual(self.tr.value(), b"foobar\n^C\n" + PROMPT)

    def test_grep_stdin_ctrl_d_exit_code_match(self) -> None:
        self.proto.lineReceived(b"grep foo\n")
        self.proto.lineReceived(b"foobar\n")
        self.proto.handle_CTRL_D()
        self.proto.lineReceived(b"echo $?\n")
        self.assertEqual(self.tr.value(), b"foobar\n" + PROMPT + b"0\n" + PROMPT)

    def test_grep_stdin_ctrl_d_exit_code_no_match(self) -> None:
        self.proto.lineReceived(b"grep foo\n")
        self.proto.lineReceived(b"bar\n")
        self.proto.handle_CTRL_D()
        self.proto.lineReceived(b"echo $?\n")
        self.assertEqual(self.tr.value(), PROMPT + b"1\n" + PROMPT)

    def test_grep_no_args_shows_usage(self) -> None:
        self.proto.lineReceived(b"grep\n")
        value = self.tr.value()
        self.assertIn(b"usage: grep", value)
        self.assertTrue(value.endswith(PROMPT))


if __name__ == "__main__":
    unittest.main()
