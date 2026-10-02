# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: An out-of-sequence keyboard-interactive INFO_RESPONSE must be
# ABOUTME: refused with a protocol-error disconnect, not raise.

from __future__ import annotations

import os
import struct
import unittest
from unittest.mock import MagicMock

from twisted.conch.ssh.common import NS
from twisted.conch.ssh.transport import DISCONNECT_PROTOCOL_ERROR

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer


def _response_packet(*responses: bytes) -> bytes:
    return struct.pack(">L", len(responses)) + b"".join(NS(r) for r in responses)


class InfoResponseOutOfSequenceTests(unittest.TestCase):
    def _server(self) -> HoneyPotSSHUserAuthServer:
        server = HoneyPotSSHUserAuthServer()
        # Kept as an attribute so assertions do not go through the
        # protocol's typed transport.
        self.transport = MagicMock()
        server.transport = self.transport
        # No keyboard-interactive round is in progress.
        server._pamDeferred = None
        return server

    def test_unsolicited_response_disconnects_cleanly(self) -> None:
        """A client can send message 61 at any time during userauth; with no
        INFO_REQUEST outstanding this must not raise."""
        server = self._server()

        server.ssh_USERAUTH_INFO_RESPONSE(_response_packet(b"secret"))

        self.transport.sendDisconnect.assert_called_once()
        self.assertEqual(
            self.transport.sendDisconnect.call_args[0][0], DISCONNECT_PROTOCOL_ERROR
        )

    def test_second_response_to_one_request_disconnects_cleanly(self) -> None:
        """The deferred is cleared once consumed, so a repeat response is the
        same out-of-sequence case."""
        from twisted.internet import defer

        server = self._server()
        server._pamDeferred = defer.Deferred()
        server._pamDeferred.addCallback(lambda _: None)

        server.ssh_USERAUTH_INFO_RESPONSE(_response_packet(b"first"))
        self.transport.sendDisconnect.assert_not_called()

        server.ssh_USERAUTH_INFO_RESPONSE(_response_packet(b"second"))

        self.transport.sendDisconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
