# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests `bash` exec'd as the SSH command reading commands from channel
# ABOUTME: stdin until EOF, with a prompt only when the client requested a pty.

from __future__ import annotations

import os
import tempfile
import unittest

from twisted.internet.protocol import connectionDone

from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.test.eventcapture import CaptureSink, make_exec_transport
from cowrie.test.fake_server import FakeAvatar, FakeServer

_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_exec_shell_")
os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = _DOWNLOAD_DIR
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

insults.LoggingServerProtocol.downloadPath = _DOWNLOAD_DIR

PROMPT = b"root@unitTest:~# "


def start_exec_session(
    cmd: bytes, term: str | None = None
) -> tuple[insults.LoggingServerProtocol, bytearray, dict[str, int]]:
    """Open an SSH exec channel running `cmd`.

    Returns the logging protocol, a buffer collecting channel output, and a
    dict that gains a "code" key once the session reports its exit status.
    A pty request is simulated by `term`, which sets TERM in the session
    environment as SSHSessionForCowrieUser.getPty does.
    """
    avatar = FakeAvatar(FakeServer())
    if term is not None:
        avatar.environ["TERM"] = term

    out = bytearray()
    ended: dict[str, int] = {}

    def process_ended(reason: object = None) -> None:
        value = getattr(reason, "value", None)
        ended["code"] = getattr(value, "exitCode", 0) if value is not None else 0

    transport = make_exec_transport(CaptureSink(), processEnded=process_ended)
    transport.write = out.extend
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, avatar, cmd)
    lsp.makeConnection(transport)
    return lsp, out, ended


class ExecShellStdinTests(unittest.TestCase):
    """`ssh host bash` runs a shell fed by channel stdin, as real sshd does."""

    def drive(
        self, cmd: bytes, term: str | None = None
    ) -> tuple[insults.LoggingServerProtocol, bytearray, dict[str, int]]:
        lsp, out, ended = start_exec_session(cmd, term)
        self.addCleanup(lsp.connectionLost, connectionDone)
        return lsp, out, ended

    def test_bash_waits_for_stdin(self) -> None:
        _lsp, out, ended = self.drive(b"bash")
        self.assertEqual(ended, {})
        self.assertEqual(bytes(out), b"")

    def test_lines_run_as_commands_and_eof_exits(self) -> None:
        lsp, out, ended = self.drive(b"bash")
        lsp.dataReceived(b"echo hello\n")
        self.assertEqual(bytes(out), b"hello\n")
        lsp.eofReceived()
        self.assertEqual(ended.get("code"), 0)

    def test_sh_behaves_like_bash(self) -> None:
        lsp, out, ended = self.drive(b"sh")
        lsp.dataReceived(b"echo hello\n")
        self.assertEqual(bytes(out), b"hello\n")
        lsp.eofReceived()
        self.assertEqual(ended.get("code"), 0)

    def test_variables_persist_across_lines(self) -> None:
        lsp, out, _ended = self.drive(b"bash")
        lsp.dataReceived(b"A=5\n")
        lsp.dataReceived(b"echo $A\n")
        self.assertEqual(bytes(out), b"5\n")

    def test_final_line_without_newline_runs_at_eof(self) -> None:
        lsp, out, ended = self.drive(b"bash")
        lsp.dataReceived(b"echo done")
        lsp.eofReceived()
        self.assertEqual(bytes(out), b"done\n")
        self.assertEqual(ended.get("code"), 0)

    def test_exit_reports_status(self) -> None:
        lsp, _out, ended = self.drive(b"bash")
        lsp.dataReceived(b"exit 3\n")
        self.assertEqual(ended.get("code"), 3)

    def test_cr_and_crlf_line_endings(self) -> None:
        lsp, out, _ended = self.drive(b"bash")
        lsp.dataReceived(b"echo one\r\necho two\r")
        self.assertEqual(bytes(out), b"one\ntwo\n")

    def test_prompt_with_pty(self) -> None:
        lsp, out, _ended = self.drive(b"bash", term="xterm")
        self.assertEqual(bytes(out), PROMPT)
        out.clear()
        lsp.dataReceived(b"echo hi\r")
        self.assertEqual(bytes(out), b"hi\n" + PROMPT)

    def test_ctrl_d_on_empty_line_exits(self) -> None:
        lsp, _out, ended = self.drive(b"bash", term="xterm")
        lsp.dataReceived(b"\x04")
        self.assertEqual(ended.get("code"), 0)

    def test_empty_pipe_into_bash_still_exits(self) -> None:
        # `true | bash`: stdin is the (empty) pipe, not the channel, so the
        # shell sees immediate EOF and the session ends.
        _lsp, _out, ended = self.drive(b"true | bash")
        self.assertEqual(ended.get("code"), 0)

    def test_bash_dash_c_still_exits(self) -> None:
        _lsp, out, ended = self.drive(b"bash -c 'echo hi'")
        self.assertEqual(bytes(out), b"hi\n")
        self.assertEqual(ended.get("code"), 0)

    def test_eof_reports_last_command_status(self) -> None:
        # bash exits with the last command's status when stdin hits EOF.
        lsp, _out, ended = self.drive(b"bash")
        lsp.dataReceived(b"false\n")
        lsp.eofReceived()
        self.assertEqual(ended.get("code"), 1)


if __name__ == "__main__":
    unittest.main()
