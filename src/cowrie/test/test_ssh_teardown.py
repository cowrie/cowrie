# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that SSH session teardown calls the protocol's connectionLost once.
# ABOUTME: Guards against the historic double/quadruple connectionLost on close.

from __future__ import annotations

import unittest

from twisted.conch.ssh.session import SSHSessionProcessProtocol

from cowrie.shell.session import ProtocolTransport, SSHSessionForCowrieUser
from cowrie.ssh.session import HoneyPotSSHSession


class CountingProtocol:
    """Stand-in for LoggingServerProtocol that counts connectionLost calls."""

    def __init__(self) -> None:
        self.lost = 0

    def connectionLost(self, reason) -> None:  # type: ignore[no-untyped-def]
        self.lost += 1

    def dataReceived(self, data) -> None:  # type: ignore[no-untyped-def]
        pass


class ProtocolTransportTestCase(unittest.TestCase):
    """ProtocolTransport must fire connectionLost at most once."""

    def test_lose_connection_is_idempotent(self) -> None:
        proto = CountingProtocol()
        transport = ProtocolTransport(proto)
        transport.loseConnection()
        transport.loseConnection()
        self.assertEqual(proto.lost, 1)


class SessionTeardownTestCase(unittest.TestCase):
    """A full channel close must reach the protocol's connectionLost exactly once."""

    def _wire(self, proto: CountingProtocol) -> HoneyPotSSHSession:
        """Replicate the wiring SSHSessionForCowrieUser.openShell sets up."""
        adapter = SSHSessionForCowrieUser.__new__(SSHSessionForCowrieUser)
        adapter.protocol = proto

        channel = HoneyPotSSHSession.__new__(HoneyPotSSHSession)
        channel.session = adapter
        channel.client = SSHSessionProcessProtocol(channel)
        channel.client.transport = ProtocolTransport(proto)
        return channel

    def test_channel_close_tears_down_protocol_once(self) -> None:
        proto = CountingProtocol()
        channel = self._wire(proto)
        channel.closed()
        self.assertEqual(proto.lost, 1)


if __name__ == "__main__":
    unittest.main()
