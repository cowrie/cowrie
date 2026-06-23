# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for command exit status ($?) and && / || short-circuiting.
# ABOUTME: Covers true/false, not-found 127, syntax error 2, and Ctrl-C 130.

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


class ExitStatusTests(unittest.TestCase):
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
        out: bytes = self.tr.value()
        return out[: -len(PROMPT)] if out.endswith(PROMPT) else out

    def test_status_of_true_and_false(self) -> None:
        self.assertEqual(self.run_line(b"true; echo $?"), b"0\n")
        self.assertEqual(self.run_line(b"false; echo $?"), b"1\n")

    def test_status_of_successful_command(self) -> None:
        self.assertEqual(self.run_line(b"echo hi; echo $?"), b"hi\n0\n")

    def test_command_not_found_is_127(self) -> None:
        out = self.run_line(b"nosuchcmd; echo $?")
        self.assertTrue(out.endswith(b"127\n"), out)

    def test_status_persists_across_lines(self) -> None:
        self.run_line(b"false")
        self.assertEqual(self.run_line(b"echo $?"), b"1\n")

    def test_and_runs_second_only_on_success(self) -> None:
        self.assertEqual(self.run_line(b"true && echo ran"), b"ran\n")
        self.assertEqual(self.run_line(b"false && echo ran"), b"")

    def test_or_runs_second_only_on_failure(self) -> None:
        self.assertEqual(self.run_line(b"false || echo ran"), b"ran\n")
        self.assertEqual(self.run_line(b"true || echo ran"), b"")

    def test_and_or_are_left_associative(self) -> None:
        # false fails -> skip `echo a`; || sees the failure -> run `echo b`.
        self.assertEqual(self.run_line(b"false && echo a || echo b"), b"b\n")
        # true succeeds -> run `echo a` (0); || skipped.
        self.assertEqual(self.run_line(b"true && echo a || echo b"), b"a\n")

    def test_skipped_command_leaves_status_unchanged(self) -> None:
        # The `&&` branch is skipped, so $? stays at false's 1.
        self.assertEqual(self.run_line(b"false && echo x; echo $?"), b"1\n")

    def test_syntax_error_is_2(self) -> None:
        self.run_line(b"echo x >")
        self.assertEqual(self.run_line(b"echo $?"), b"2\n")

    def test_pipeline_status_is_last_stage(self) -> None:
        # A pipeline's status is its last stage's.
        self.assertEqual(self.run_line(b"true | false; echo $?"), b"1\n")
        self.assertEqual(self.run_line(b"false | true; echo $?"), b"0\n")

    def test_statement_after_pipeline_runs_in_order(self) -> None:
        # A statement after a pipeline runs after the pipeline finishes, and the
        # pipeline's output is not dropped.
        self.assertEqual(self.run_line(b"echo a | cat; echo done"), b"a\ndone\n")


if __name__ == "__main__":
    unittest.main()
