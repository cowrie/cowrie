# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests an SSH shell session opened without a pty (`ssh -T host`):
# ABOUTME: a non-interactive login shell reading commands from the channel.

from __future__ import annotations

import struct
import unittest

from twisted.conch.ssh.session import SSHSessionProcessProtocol
from twisted.internet.protocol import connectionDone

from cowrie.test.test_stderr_channel import FakeChannel, open_ssh_session


class ShellWithoutPtyTests(unittest.TestCase):
    """Without a pty, real sshd runs the login shell with the channel as its
    stdin: no prompt, no echo of the input, no terminal escape codes and
    bare newlines (checked against bash 5.3 run as `-bash` on a pipe)."""

    def setUp(self) -> None:
        self.session, self.channel = open_ssh_session(pty=False)
        self.session.openShell(SSHSessionProcessProtocol(self.channel))

    def tearDown(self) -> None:
        if self.session.protocol is not None:
            self.session.protocol.connectionLost(connectionDone)

    def send(self, data: bytes) -> None:
        assert self.session.protocol is not None
        self.session.protocol.dataReceived(data)

    def exit_status(self, channel: FakeChannel) -> int | None:
        for name, data in channel.requests:
            if name == b"exit-status":
                code: int = struct.unpack(">L", data)[0]
                return code
        return None

    def test_no_prompt_or_motd(self) -> None:
        self.assertEqual(bytes(self.channel.stdout), b"")
        self.assertEqual(bytes(self.channel.stderr), b"")

    def test_commands_run_without_echo(self) -> None:
        self.send(b"echo a\n")
        self.assertEqual(bytes(self.channel.stdout), b"a\n")

    def test_crlf_input(self) -> None:
        self.send(b"echo a\r\necho b\r\n")
        self.assertEqual(bytes(self.channel.stdout), b"a\nb\n")

    def test_errors_go_to_stderr_with_line_numbers(self) -> None:
        self.send(b"echo a\nls /nope\nnosuch\n")
        self.assertEqual(bytes(self.channel.stdout), b"a\n")
        self.assertEqual(
            bytes(self.channel.stderr),
            b"ls: cannot access '/nope': No such file or directory\n"
            b"-bash: line 3: nosuch: command not found\n",
        )

    def test_exit_ends_the_session_with_its_status(self) -> None:
        self.send(b"exit 3\necho after\n")
        self.assertEqual(bytes(self.channel.stdout), b"")
        self.assertEqual(self.exit_status(self.channel), 3)

    def test_eof_ends_the_session_with_the_last_status(self) -> None:
        self.send(b"echo x\nfalse\n")
        assert self.session.protocol is not None
        self.session.protocol.eofReceived()
        self.assertEqual(bytes(self.channel.stdout), b"x\n")
        self.assertEqual(self.exit_status(self.channel), 1)


class ShellWithPtyTests(unittest.TestCase):
    """With a pty the shell stays interactive: prompt, echo and \\r\\n."""

    def test_prompt_echo_and_crlf(self) -> None:
        session, channel = open_ssh_session(pty=True)
        session.openShell(SSHSessionProcessProtocol(channel))
        terminal = session.protocol
        assert terminal is not None
        self.addCleanup(terminal.connectionLost, connectionDone)
        self.assertIn(b"root@unitTest:~# ", bytes(channel.stdout))
        channel.stdout.clear()
        terminal.dataReceived(b"echo a\r")
        self.assertIn(b"echo a", bytes(channel.stdout))
        self.assertIn(b"a\r\n", bytes(channel.stdout))


if __name__ == "__main__":
    unittest.main()
