# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests how SSH channel input reaches commands: unchanged bytes
# ABOUTME: without a pty, and echoed as a terminal would with one.

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from twisted.conch.ssh.session import SSHSessionProcessProtocol
from twisted.internet.protocol import connectionDone

from cowrie.test.test_stderr_channel import FakeChannel, open_ssh_session

if TYPE_CHECKING:
    from cowrie.shell.session import SSHSessionForCowrieUser

# Bytes a terminal's escape parser would eat: a colour code, an SS3
# sequence (ESC O x) and an ESC before an ordinary character.
ESCAPES = b"a\x1b[31mb\x1bOc\x1bxd"


class InputWithoutPtyTests(unittest.TestCase):
    """Without a pty the channel is a plain pipe: commands read exactly the
    bytes the client sent, escape sequences included."""

    def start(self, cmd: bytes | None) -> tuple[SSHSessionForCowrieUser, FakeChannel]:
        session, channel = open_ssh_session(pty=False)
        process = SSHSessionProcessProtocol(channel)
        if cmd is None:
            session.openShell(process)
        else:
            session.execCommand(process, cmd)
        assert session.protocol is not None
        self.addCleanup(session.protocol.connectionLost, connectionDone)
        return session, channel

    def test_exec_command_reads_escape_bytes(self) -> None:
        session, channel = self.start(b"cat")
        assert session.protocol is not None
        session.protocol.dataReceived(ESCAPES + b"\n")
        session.protocol.eofReceived()
        self.assertEqual(bytes(channel.stdout), ESCAPES + b"\n")

    def test_shell_reads_escape_bytes_in_a_line(self) -> None:
        session, channel = self.start(None)
        assert session.protocol is not None
        session.protocol.dataReceived(b"echo '" + ESCAPES + b"'\n")
        self.assertEqual(bytes(channel.stdout), ESCAPES + b"\n")


if __name__ == "__main__":
    unittest.main()
