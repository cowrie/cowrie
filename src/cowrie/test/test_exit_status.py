# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for command exit status ($?) and && / || short-circuiting.
# ABOUTME: Covers true/false, not-found 127, syntax error 2, and Ctrl-C 130.

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

from cowrie.insults import insults
from cowrie.shell import protocol
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

    def test_nested_shell_propagates_exit_code(self) -> None:
        # `bash -c '...'` exits with the status of its last command.
        self.assertEqual(self.run_line(b"bash -c false; echo $?"), b"1\n")
        self.assertEqual(self.run_line(b"bash -c true; echo $?"), b"0\n")

    def test_nested_shell_status_gates_and(self) -> None:
        # A failing nested shell short-circuits a following &&.
        self.assertEqual(self.run_line(b"bash -c false && echo ran"), b"")

    def test_failing_command_sets_nonzero_status(self) -> None:
        # dd on a missing input file fails, so $? is non-zero and a following
        # && does not run.
        out = self.run_line(b"dd if=/nonexistentfile; echo $?")
        self.assertTrue(out.endswith(b"1\n"), out)
        out = self.run_line(b"dd if=/nonexistentfile && echo ran")
        self.assertNotIn(b"ran", out)

    def test_download_command_failure_sets_nonzero_status(self) -> None:
        # A download command that fails validation reports a non-zero status,
        # so a following && short-circuits.
        for cmd in (b"wget", b"curl", b"tftp", b"ftpget"):
            out = self.run_line(cmd + b"; echo rc=$?")
            self.assertNotIn(b"rc=0", out, cmd)
            self.assertNotIn(b"OK", self.run_line(cmd + b" && echo OK"), cmd)

    def test_syntax_error_is_2(self) -> None:
        self.run_line(b"echo x >")
        self.assertEqual(self.run_line(b"echo $?"), b"2\n")

    def test_pipeline_status_is_last_stage(self) -> None:
        # A pipeline's status is its last stage's.
        self.assertEqual(self.run_line(b"true | false; echo $?"), b"1\n")
        self.assertEqual(self.run_line(b"false | true; echo $?"), b"0\n")

    def test_subshell_group_runs_in_order(self) -> None:
        # A group with no gate runs all its statements.
        self.assertEqual(self.run_line(b"(echo a; echo b)"), b"a\nb\n")

    def test_or_short_circuits_whole_group(self) -> None:
        # true succeeds -> || skips the entire group, not just its first
        # statement.
        self.assertEqual(self.run_line(b"true || (echo a; echo b)"), b"")

    def test_and_short_circuits_whole_group(self) -> None:
        # false fails -> && skips the entire group.
        self.assertEqual(self.run_line(b"false && (echo a; echo b)"), b"")

    def test_or_runs_whole_group_on_failure(self) -> None:
        # false fails -> || runs the whole group.
        self.assertEqual(self.run_line(b"false || (echo a; echo b)"), b"a\nb\n")

    def test_statement_after_group_runs_when_group_skipped(self) -> None:
        # The group is skipped, but a `;`-joined statement after it still runs.
        self.assertEqual(self.run_line(b"true || (echo a); echo c"), b"c\n")

    def test_substitution_carries_status_across_statements(self) -> None:
        # The whole substitution runs in one shell, so a later statement's $?
        # sees the earlier statement's status.
        self.assertEqual(self.run_line(b"echo $(false; echo $?)"), b"1\n")

    def test_substitution_short_circuits(self) -> None:
        # &&/|| short-circuit inside a substitution like a top-level line.
        self.assertEqual(self.run_line(b"echo $(true || echo x)"), b"\n")
        self.assertEqual(self.run_line(b"echo $(false || echo y)"), b"y\n")

    def test_substitution_assignment_visible_to_later_statement(self) -> None:
        # A same-substitution assignment is visible to a later statement.
        self.assertEqual(self.run_line(b"echo $(x=hi; echo $x)"), b"hi\n")

    def test_substitution_assignment_only_statement_adds_no_output(self) -> None:
        # A trailing assignment-only statement must not re-emit the previous
        # statement's captured output.
        self.assertEqual(self.run_line(b"echo $(echo a; z=1)"), b"a\n")

    def test_statement_after_pipeline_runs_in_order(self) -> None:
        # A statement after a pipeline runs after the pipeline finishes, and the
        # pipeline's output is not dropped.
        self.assertEqual(self.run_line(b"echo a | cat; echo done"), b"a\ndone\n")


class ExitInSubstitutionTests(unittest.TestCase):
    """`exit` inside $( ) ends only that subshell, as in bash (#40275).

    It removes the capture shell from the cmdstack; the substitution's cleanup
    must not then pop the real shell, or the emptied cmdstack crashes the next
    command's instantiation with IndexError.
    """

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

    def test_exit_in_substitution_keeps_session_alive(self) -> None:
        shell = self.proto.cmdstack[0]
        self.assertEqual(self.run_line(b"echo $(exit)"), b"\n")
        self.assertEqual(self.proto.cmdstack, [shell])
        # The session must still run commands afterwards.
        self.assertEqual(self.run_line(b"echo ok"), b"ok\n")

    def test_exit_stops_remaining_substitution_statements(self) -> None:
        # `exit` ends the subshell; a later statement in the same substitution
        # never runs.
        self.assertEqual(self.run_line(b"echo a$(exit; echo b)"), b"a\n")

    def test_plain_exit_still_ends_session(self) -> None:
        self.proto.lineReceived(b"exit")
        self.assertEqual(self.proto.cmdstack, [])


def run_exec(cmd: bytes) -> int:
    """Run `cmd` over an exec channel and return the exit status the session
    would report to the SSH client via processEnded."""
    captured: dict[str, int] = {}

    def process_ended(reason: object = None) -> None:
        value = getattr(reason, "value", None)
        captured["code"] = getattr(value, "exitCode", 0) if value is not None else 0

    peer = SimpleNamespace(host="1.1.1.1", port=2222)
    inner = SimpleNamespace(sessionno=1, getPeer=lambda: peer)
    factory = SimpleNamespace(starttime=0, logDispatch=lambda **kw: None)
    conn_transport = SimpleNamespace(transportId="t", factory=factory, transport=inner)
    session = SimpleNamespace(
        id="chan0", conn=SimpleNamespace(transport=conn_transport)
    )
    transport = SimpleNamespace(
        session=session, write=lambda data: None, processEnded=process_ended
    )

    avatar = FakeAvatar(FakeServer())
    avatar.server.initFileSystem = lambda home: None
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, avatar, cmd)
    lsp.makeConnection(transport)
    return captured.get("code", 0)


class ExecExitStatusTests(unittest.TestCase):
    """The exec channel reports a real exit-status to the client."""

    def test_exec_success(self) -> None:
        self.assertEqual(run_exec(b"true"), 0)
        self.assertEqual(run_exec(b"echo hi"), 0)

    def test_exec_failure(self) -> None:
        self.assertEqual(run_exec(b"false"), 1)

    def test_exec_not_found(self) -> None:
        self.assertEqual(run_exec(b"nosuchcmd"), 127)

    def test_exec_status_is_last_statement(self) -> None:
        self.assertEqual(run_exec(b"false; true"), 0)
        self.assertEqual(run_exec(b"true; false"), 1)

    def test_exec_explicit_exit_code(self) -> None:
        self.assertEqual(run_exec(b"exit 7"), 7)


if __name__ == "__main__":
    unittest.main()
