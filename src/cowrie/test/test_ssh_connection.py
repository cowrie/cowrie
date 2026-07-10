# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for CowrieSSHConnection channel message handling: stale EOF
# ABOUTME: and CLOSE for an already-closed channel are ignored, not a crash.

from __future__ import annotations

import struct
import unittest

from cowrie.ssh.connection import CowrieSSHConnection


class _StubChannel:
    """Records delivery of channel callbacks; never closes locally."""

    localClosed = False
    remoteClosed = False

    def __init__(self) -> None:
        self.gotEOF = False
        self.gotClose = False

    def eofReceived(self) -> None:
        self.gotEOF = True

    def closeReceived(self) -> None:
        self.gotClose = True

    def logPrefix(self) -> str:
        return "stub"


class StaleChannelMessageTests(unittest.TestCase):
    """A libssh2 client can send CHANNEL_EOF / CHANNEL_CLOSE for a channel
    whose close handshake already completed (issue #40296); the connection
    must ignore them instead of raising KeyError to the reactor."""

    def setUp(self) -> None:
        self.conn = CowrieSSHConnection()

    def test_eof_for_unknown_channel_is_ignored(self) -> None:
        self.conn.ssh_CHANNEL_EOF(struct.pack(">L", 0))

    def test_close_for_unknown_channel_is_ignored(self) -> None:
        self.conn.ssh_CHANNEL_CLOSE(struct.pack(">L", 0))

    def test_eof_for_known_channel_is_delivered(self) -> None:
        channel = _StubChannel()
        self.conn.channels[0] = channel
        self.conn.ssh_CHANNEL_EOF(struct.pack(">L", 0))
        self.assertTrue(channel.gotEOF)

    def test_close_for_known_channel_is_delivered(self) -> None:
        channel = _StubChannel()
        self.conn.channels[0] = channel
        self.conn.ssh_CHANNEL_CLOSE(struct.pack(">L", 0))
        self.assertTrue(channel.gotClose)
