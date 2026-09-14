# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests pipelines and subshells run stage-per-child-shell like a real shell.
# ABOUTME: Covers group stages, exit status, isolation of cd/exit/variables, and capture.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellSessionTests(unittest.TestCase):
    """An interactive shell session on a fake transport."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: str) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line.encode() + b"\n")
        out: bytes = self.tr.value()
        # Every stage and child shell has left the stack once the line is done.
        self.assertEqual(len(self.proto.cmdstack), 1)
        return out


class PipelineTests(ShellSessionTests):
    def test_simple_pipeline(self) -> None:
        self.assertEqual(self.run_line("echo a | grep a | cat"), b"a\n" + PROMPT)

    def test_subshell_into_command(self) -> None:
        self.assertEqual(self.run_line("(echo a; echo b) | tail -n 1"), b"b\n" + PROMPT)

    def test_command_into_subshell(self) -> None:
        self.assertEqual(self.run_line("echo a | (cat)"), b"a\n" + PROMPT)

    def test_brace_group_stage(self) -> None:
        self.assertEqual(
            self.run_line("{ echo a; echo b; } | head -n 1"), b"a\n" + PROMPT
        )

    def test_loop_stage(self) -> None:
        self.assertEqual(
            self.run_line("for i in 1 2 3; do echo $i; done | tail -n 1"),
            b"3\n" + PROMPT,
        )

    def test_first_reader_consumes_the_pipe(self) -> None:
        # The group shares one stdin: the second cat sees EOF, like bash.
        self.assertEqual(self.run_line("echo a | (cat; cat)"), b"a\n" + PROMPT)

    def test_command_that_does_not_read_leaves_the_pipe(self) -> None:
        self.assertEqual(self.run_line("echo a | (whoami; cat)"), b"root\na\n" + PROMPT)

    def test_status_is_the_last_stage(self) -> None:
        self.assertEqual(self.run_line("(exit 3) | true; echo $?"), b"0\n" + PROMPT)
        self.assertEqual(self.run_line("true | (exit 3); echo $?"), b"3\n" + PROMPT)
        self.assertEqual(self.run_line("false | true; echo $?"), b"0\n" + PROMPT)

    def test_pipeline_join_operators(self) -> None:
        self.assertEqual(
            self.run_line("false || echo a | cat && echo b"), b"a\nb\n" + PROMPT
        )

    def test_stage_does_not_change_the_shell(self) -> None:
        # Each stage runs in its own child: cd and assignments do not persist.
        self.assertEqual(
            self.run_line("echo a | (cd /tmp; cat); pwd"), b"a\n/root\n" + PROMPT
        )
        self.assertEqual(self.run_line("x=1 | cat; echo x=$x"), b"x=\n" + PROMPT)

    def test_subshell_does_not_change_the_shell(self) -> None:
        self.assertEqual(self.run_line("(cd /tmp); pwd"), b"/root\n" + PROMPT)
        self.assertEqual(self.run_line("(x=1); echo x=$x"), b"x=\n" + PROMPT)

    def test_exit_in_subshell_ends_only_the_subshell(self) -> None:
        self.assertEqual(self.run_line("(exit 2); echo $?"), b"2\n" + PROMPT)
        self.assertEqual(
            self.run_line("(echo a; exit 2; echo b) | cat; echo $?"),
            b"a\n0\n" + PROMPT,
        )

    def test_pipeline_inside_command_substitution(self) -> None:
        self.assertEqual(
            self.run_line("echo $( (echo a; echo b) | tail -n 1 )"), b"b\n" + PROMPT
        )
        self.assertEqual(self.run_line("echo $(echo a | grep a)"), b"a\n" + PROMPT)

    def test_subshell_inside_command_substitution(self) -> None:
        self.assertEqual(self.run_line("echo $( (echo a) )"), b"a\n" + PROMPT)

    def test_function_as_stage(self) -> None:
        self.assertEqual(
            self.run_line("f() { echo hi; }; f | grep hi"), b"hi\n" + PROMPT
        )

    def test_long_pipeline_runs_flat(self) -> None:
        self.assertEqual(self.run_line("echo hi" + " | cat" * 600), b"hi\n" + PROMPT)


class WrapperCommandTests(ShellSessionTests):
    """busybox and sudo run their command in their own place, as the real
    ones exec into it, so it takes part in pipelines and redirections."""

    def test_busybox_applet_in_pipeline(self) -> None:
        self.assertEqual(self.run_line("busybox echo hi | cat"), b"hi\n" + PROMPT)
        self.assertEqual(self.run_line("echo hi | busybox cat"), b"hi\n" + PROMPT)

    def test_busybox_applet_status(self) -> None:
        self.assertEqual(self.run_line("busybox false; echo $?"), b"1\n" + PROMPT)
        self.assertEqual(self.run_line("busybox true; echo $?"), b"0\n" + PROMPT)

    def test_busybox_unknown_applet(self) -> None:
        self.assertEqual(
            self.run_line("busybox nosuchapplet"),
            b"nosuchapplet: applet not found\n" + PROMPT,
        )

    def test_sudo_command_in_pipeline(self) -> None:
        self.assertEqual(self.run_line("sudo echo hi | cat"), b"hi\n" + PROMPT)
        self.assertEqual(self.run_line("echo hi | sudo cat"), b"hi\n" + PROMPT)

    def test_sudo_command_status_and_redirection(self) -> None:
        self.assertEqual(self.run_line("sudo false; echo $?"), b"1\n" + PROMPT)
        self.assertEqual(self.run_line("sudo echo hi > sudofile"), PROMPT)
        self.assertEqual(self.run_line("cat sudofile"), b"hi\n" + PROMPT)


class CompoundRedirectionTests(ShellSessionTests):
    """A redirection after a compound command applies to the whole command,
    as in bash. Each test asserts what bash does."""

    def test_subshell_stdout_to_file(self) -> None:
        self.assertEqual(self.run_line("(echo a; echo b) > grpfile"), PROMPT)
        self.assertEqual(self.run_line("cat grpfile"), b"a\nb\n" + PROMPT)

    def test_brace_group_append_accumulates(self) -> None:
        self.assertEqual(self.run_line("{ echo one; } >> grpappend"), PROMPT)
        self.assertEqual(self.run_line("{ echo two; } >> grpappend"), PROMPT)
        self.assertEqual(self.run_line("cat grpappend"), b"one\ntwo\n" + PROMPT)

    def test_loop_stdout_to_file(self) -> None:
        self.assertEqual(
            self.run_line("for i in 1 2; do echo $i; done > loopfile"), PROMPT
        )
        self.assertEqual(self.run_line("cat loopfile"), b"1\n2\n" + PROMPT)
        self.assertEqual(
            self.run_line("while true; do echo w; break; done > whilefile"), PROMPT
        )
        self.assertEqual(self.run_line("cat whilefile"), b"w\n" + PROMPT)

    def test_subshell_stderr_to_devnull(self) -> None:
        self.assertEqual(self.run_line("(cat /nonexistent) 2> /dev/null"), PROMPT)

    def test_redirected_group_in_pipeline(self) -> None:
        # The redirection applies to the group stage, not the pipeline.
        self.assertEqual(self.run_line("(echo a) > pipefile | cat"), PROMPT)
        self.assertEqual(self.run_line("cat pipefile"), b"a\n" + PROMPT)


if __name__ == "__main__":
    unittest.main()
