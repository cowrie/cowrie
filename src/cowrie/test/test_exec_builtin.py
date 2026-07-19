# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the `exec` shell builtin: the command replaces the shell,
# ABOUTME: which ends when it finishes; redirection-only and failed exec differ.

from __future__ import annotations

import os
import unittest

from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import CaptureSink, make_exec_transport
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ExecInteractiveTests(unittest.TestCase):
    """`exec cmd` in an interactive shell runs cmd and ends the session."""

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

    def test_exec_runs_command_and_ends_session(self) -> None:
        out = self.run_line(b"exec echo hi")
        self.assertEqual(out, b"hi\n")
        self.assertEqual(self.proto.cmdstack, [])

    def test_exec_skips_rest_of_line(self) -> None:
        # The shell is replaced, so a `;`-joined statement never runs.
        out = self.run_line(b"exec echo hi; echo bye")
        self.assertEqual(out, b"hi\n")
        self.assertEqual(self.proto.cmdstack, [])

    def test_exec_with_redirect_ends_session(self) -> None:
        out = self.run_line(b"exec echo hi >/dev/null")
        self.assertEqual(out, b"")
        self.assertEqual(self.proto.cmdstack, [])

    def test_bare_exec_is_noop(self) -> None:
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"exec; echo $?"), b"0\n")
        self.assertIn(shell, self.proto.cmdstack)

    def test_exec_redirection_only_keeps_shell(self) -> None:
        # `exec 2>/dev/null` adjusts the shell's own fds: no command runs and
        # the shell survives.
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"exec 2>/dev/null; echo $?"), b"0\n")
        self.assertIn(shell, self.proto.cmdstack)

    def test_exec_not_found_keeps_interactive_shell(self) -> None:
        # An interactive shell survives a failed exec (bash without execfail).
        shell = self.proto.cmdstack[0]
        out = self.run_line(b"exec nosuchcmd")
        self.assertEqual(out, b"-bash: exec: nosuchcmd: not found\n")
        self.assertIn(shell, self.proto.cmdstack)
        self.assertEqual(self.run_line(b"echo $?"), b"127\n")

    def test_exec_backgrounded_keeps_shell(self) -> None:
        # `exec cmd &` replaces a backgrounded subshell, not this shell. The
        # parser passes a trailing `&` through as a literal argument.
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"exec echo hi &"), b"hi &\n")
        self.assertIn(shell, self.proto.cmdstack)

    def test_exec_backgrounded_not_found_keeps_shell(self) -> None:
        shell = self.proto.cmdstack[0]
        out = self.run_line(b"exec nosuchcmd &")
        self.assertEqual(out, b"-bash: exec: nosuchcmd: not found\n")
        self.assertIn(shell, self.proto.cmdstack)
        self.assertEqual(self.run_line(b"echo $?"), b"127\n")

    def test_exec_in_pipeline_keeps_shell(self) -> None:
        # A pipeline stage runs in a subshell, so `exec` there does not
        # replace the interactive shell.
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"exec echo hi | cat"), b"hi\n")
        self.assertIn(shell, self.proto.cmdstack)

    def test_exec_in_nested_shell_ends_only_that_shell(self) -> None:
        out = self.run_line(b'sh -c "exec echo hi"; echo after')
        self.assertEqual(out, b"hi\nafter\n")
        self.assertNotEqual(self.proto.cmdstack, [])

    def test_exec_not_found_in_nested_shell_is_127(self) -> None:
        out = self.run_line(b'sh -c "exec nosuchcmd"; echo $?')
        self.assertEqual(out, b"-bash: exec: nosuchcmd: not found\n127\n")
        self.assertNotEqual(self.proto.cmdstack, [])

    def test_exec_in_substitution_ends_only_capture_shell(self) -> None:
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"echo a$(exec echo b; echo c)"), b"ab\n")
        self.assertEqual(self.proto.cmdstack, [shell])
        self.assertEqual(self.run_line(b"echo ok"), b"ok\n")

    def test_exec_dash_a_sets_argv0_and_runs_command(self) -> None:
        out = self.run_line(b"exec -a daemon echo hi")
        self.assertEqual(out, b"hi\n")
        self.assertEqual(self.proto.cmdstack, [])

    def test_exec_assignment_persists_in_shell(self) -> None:
        # exec is a POSIX special builtin: a prefix assignment on a bare
        # `exec` persists in the shell.
        self.assertEqual(self.run_line(b"A=1 exec; echo $A"), b"1\n")


def run_exec(cmd: bytes) -> int:
    """Run `cmd` over an exec channel and return the exit status the session
    would report to the SSH client via processEnded."""
    captured: dict[str, int] = {}

    def process_ended(reason: object = None) -> None:
        value = getattr(reason, "value", None)
        captured["code"] = getattr(value, "exitCode", 0) if value is not None else 0

    transport = make_exec_transport(CaptureSink(), processEnded=process_ended)

    avatar = FakeAvatar(FakeServer())
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, avatar, cmd)
    lsp.makeConnection(transport)
    return captured.get("code", 0)


class ExecChannelTests(unittest.TestCase):
    """`exec` over an SSH exec channel reports the command's exit status."""

    def test_exec_propagates_command_status(self) -> None:
        self.assertEqual(run_exec(b"exec true"), 0)
        self.assertEqual(run_exec(b"exec false"), 1)

    def test_exec_not_found_exits_127(self) -> None:
        # A non-interactive shell exits when exec fails.
        self.assertEqual(run_exec(b"exec nosuchcmd"), 127)

    def test_exec_skips_following_statement(self) -> None:
        # The `false` after exec never runs; the status is echo's.
        self.assertEqual(run_exec(b"exec echo hi; false"), 0)

    def test_backgrounded_exec_failure_does_not_end_shell(self) -> None:
        # The failed exec ends only the backgrounded subshell; the script
        # carries on and reports the last statement's status.
        self.assertEqual(run_exec(b"exec nosuchcmd &\ntrue"), 0)


if __name__ == "__main__":
    unittest.main()
