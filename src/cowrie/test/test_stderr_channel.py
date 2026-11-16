# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that stderr reaches the SSH client on the channel's stderr
# ABOUTME: stream when no pty was requested, and merges with stdout on a pty.

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace

from twisted.conch.ssh import connection
from twisted.conch.ssh.session import SSHSessionProcessProtocol
from twisted.internet.protocol import connectionDone

from cowrie.insults import insults
from cowrie.shell.session import SSHSessionForCowrieUser
from cowrie.test.eventcapture import CaptureSink, _capture_pipeline
from cowrie.test.fake_server import FakeServer

_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_stderr_")
os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = _DOWNLOAD_DIR
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

insults.LoggingServerProtocol.downloadPath = _DOWNLOAD_DIR


class FakeChannel:
    """The SSH session channel: records what the server sends on the
    channel's data stream, on its stderr (extended data) stream, and as
    channel requests (exit-status)."""

    def __init__(self) -> None:
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.requests: list[tuple[bytes, bytes]] = []
        self.id = "chan0"
        self.buf = None
        events = _capture_pipeline(
            CaptureSink(), session="teststderr", protocol="ssh", src_ip="1.1.1.1"
        )
        peer = SimpleNamespace(host="1.1.1.1", port=2222)
        conn_transport = SimpleNamespace(
            transportId="teststderr",
            factory=SimpleNamespace(starttime=0),
            transport=SimpleNamespace(sessionno=1, getPeer=lambda: peer),
            events=events,
            getPeer=lambda: peer,
        )
        self.conn = SimpleNamespace(
            transport=conn_transport,
            sendRequest=lambda session, name, data: self.requests.append((name, data)),
            sendEOF=lambda session: None,
        )

    def write(self, data: bytes) -> None:
        self.stdout += data

    def writeExtended(self, dataType: int, data: bytes) -> None:
        assert dataType == connection.EXTENDED_DATA_STDERR
        self.stderr += data

    def loseConnection(self) -> None:
        pass


def open_ssh_session(pty: bool) -> tuple[SSHSessionForCowrieUser, FakeChannel]:
    """An SSH session for root on a fake channel, with a pty if ``pty``."""
    channel = FakeChannel()
    avatar = SimpleNamespace(
        server=FakeServer(),
        uid=0,
        gid=0,
        username="root",
        home="/root",
        temporary=False,
        conn=channel.conn,
    )
    session = SSHSessionForCowrieUser(avatar)
    if pty:
        session.getPty(b"xterm", (25, 80, 0, 0), b"")
    return session, channel


class StderrChannelTests(unittest.TestCase):
    """An SSH session sends stderr on its own stream unless a pty merges it."""

    def open_session(self, pty: bool) -> tuple[SSHSessionForCowrieUser, FakeChannel]:
        session, channel = open_ssh_session(pty)
        self.channel = channel
        self.session = session
        return session, channel

    def tearDown(self) -> None:
        if self.session.protocol is not None:
            self.session.protocol.connectionLost(connectionDone)

    def run_exec(self, cmd: bytes, pty: bool = False) -> FakeChannel:
        session, channel = self.open_session(pty)
        session.execCommand(SSHSessionProcessProtocol(channel), cmd)
        return channel

    def test_stdout_and_stderr_use_separate_streams(self) -> None:
        channel = self.run_exec(b"echo out; echo err >&2")
        self.assertEqual(bytes(channel.stdout), b"out\n")
        self.assertEqual(bytes(channel.stderr), b"err\n")

    def test_command_error_goes_to_stderr(self) -> None:
        channel = self.run_exec(b"ls /nonexistent")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(
            bytes(channel.stderr),
            b"ls: cannot access '/nonexistent': No such file or directory\n",
        )

    def test_shell_error_goes_to_stderr(self) -> None:
        channel = self.run_exec(b"nosuchcommand")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertIn(b"nosuchcommand: command not found", bytes(channel.stderr))

    def test_stderr_to_stdout(self) -> None:
        channel = self.run_exec(b"ls /nonexistent 2>&1")
        self.assertEqual(
            bytes(channel.stdout),
            b"ls: cannot access '/nonexistent': No such file or directory\n",
        )
        self.assertEqual(bytes(channel.stderr), b"")

    def test_stdout_to_stderr(self) -> None:
        channel = self.run_exec(b"echo hi 1>&2")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(bytes(channel.stderr), b"hi\n")

    def test_swap_stdout_and_stderr_through_fd_3(self) -> None:
        channel = self.run_exec(
            b"echo hi 3>&1 1>&2 2>&3; ls /nonexistent 3>&1 1>&2 2>&3 | tr a-z A-Z"
        )
        # echo's output went to stderr, and ls's error to the pipe, where tr
        # upper-cased it.
        self.assertEqual(bytes(channel.stderr), b"hi\n")
        self.assertEqual(
            bytes(channel.stdout),
            b"LS: CANNOT ACCESS '/NONEXISTENT': NO SUCH FILE OR DIRECTORY\n",
        )

    def test_fd_3_copied_from_stderr_keeps_the_stream(self) -> None:
        channel = self.run_exec(b"{ echo hi >&3; } 3>&2")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(bytes(channel.stderr), b"hi\n")

    def test_stderr_to_devnull(self) -> None:
        channel = self.run_exec(b"ls /nonexistent 2>/dev/null")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(bytes(channel.stderr), b"")

    def test_pipeline_stage_stderr(self) -> None:
        channel = self.run_exec(b"ls /nonexistent | cat")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertIn(b"No such file or directory", bytes(channel.stderr))

    def test_command_substitution_stderr(self) -> None:
        channel = self.run_exec(b"x=$(ls /nonexistent); echo done")
        self.assertEqual(bytes(channel.stdout), b"done\n")
        self.assertIn(b"No such file or directory", bytes(channel.stderr))

    def test_child_shell_stderr(self) -> None:
        channel = self.run_exec(b"bash -c 'echo err >&2'")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(bytes(channel.stderr), b"err\n")

    def test_redirection_error_goes_to_stderr(self) -> None:
        channel = self.run_exec(b"echo hi > /nonexistent/x")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(
            bytes(channel.stderr),
            b"bash: line 1: /nonexistent/x: No such file or directory\n",
        )

    def test_redirection_error_after_stderr_to_devnull(self) -> None:
        """bash reports a failed redirection on fd 2 as the redirections
        before it left it (checked against bash 5.3)."""
        channel = self.run_exec(b"echo hi 2>/dev/null > /nonexistent/x")
        self.assertEqual(bytes(channel.stdout), b"")
        self.assertEqual(bytes(channel.stderr), b"")

    def test_redirection_error_after_stderr_to_stdout(self) -> None:
        channel = self.run_exec(b"echo hi 2>&1 > /nonexistent/x")
        self.assertEqual(
            bytes(channel.stdout),
            b"bash: line 1: /nonexistent/x: No such file or directory\n",
        )
        self.assertEqual(bytes(channel.stderr), b"")

    def test_pty_merges_stderr_into_stdout(self) -> None:
        channel = self.run_exec(b"echo out; echo err >&2", pty=True)
        self.assertEqual(bytes(channel.stdout), b"out\r\nerr\r\n")
        self.assertEqual(bytes(channel.stderr), b"")

    def test_exec_with_pty_ends_lines_with_crlf(self) -> None:
        """`ssh -t host cmd`: the pty turns each \\n into \\r\\n, as a real
        pty does with onlcr set."""
        channel = self.run_exec(b"printf 'a\\nb\\n'", pty=True)
        self.assertEqual(bytes(channel.stdout), b"a\r\nb\r\n")

    def test_exec_without_pty_keeps_bare_newlines(self) -> None:
        channel = self.run_exec(b"printf 'a\\nb\\n'")
        self.assertEqual(bytes(channel.stdout), b"a\nb\n")

    def test_shell_without_pty_separates_stderr(self) -> None:
        """`ssh -T host` opens a shell with no pty: stderr has its own stream
        there too, as with real sshd."""
        session, channel = self.open_session(pty=False)
        session.openShell(SSHSessionProcessProtocol(channel))
        channel.stderr.clear()
        assert session.protocol is not None
        session.protocol.dataReceived(b"ls /nonexistent\n")
        self.assertEqual(
            bytes(channel.stderr),
            b"ls: cannot access '/nonexistent': No such file or directory\n",
        )
        self.assertNotIn(b"No such file", bytes(channel.stdout))


if __name__ == "__main__":
    unittest.main()
