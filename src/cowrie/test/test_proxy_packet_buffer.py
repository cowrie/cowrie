# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The SSH proxy holds traffic for a side that is not ready yet and
# ABOUTME: sends it, in order, as soon as that side is (issue #1788).

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from cowrie.ssh_proxy.client_transport import BackendSSHFactory, BackendSSHTransport
from cowrie.ssh_proxy.server_transport import FrontendSSHTransport
from cowrie.ssh_proxy.userauth import ProxySSHAuthServer


class _PacketRecorder:
    """Stands in for the proxy's SSH packet parser, which forwards each packet
    to the other side; records what would be forwarded, and to whom."""

    def __init__(self) -> None:
        self.client = None
        self.forwarded: list[tuple[str, int, bytes]] = []

    def parse_num_packet(self, parent: str, message_num: int, payload: bytes) -> None:
        self.forwarded.append((parent, message_num, payload))


class ProxyPacketHoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.frontend = FrontendSSHTransport()
        self.frontend.sshParse = self.parser = _PacketRecorder()
        self.frontend.sendPacket = MagicMock()  # type: ignore[method-assign]
        factory = BackendSSHFactory()
        factory.server = self.frontend
        self.backend = BackendSSHTransport(factory)
        self.backend.sendPacket = MagicMock()  # type: ignore[method-assign]

    def _frontend_logs_in(self) -> None:
        auth = ProxySSHAuthServer()
        auth.transport = self.frontend
        auth._cbFinishedAuth(None)

    def _backend_logs_in(self) -> None:
        self.backend.canAuth = True
        with patch("cowrie.ssh_proxy.client_transport.CowrieConfig") as config:
            config.get.return_value = "root"
            self.backend.authenticateBackend()

    def test_frontend_packets_wait_for_backend_login(self) -> None:
        self.frontend.packet_buffer(90, b"open")
        self.frontend.packet_buffer(98, b"exec")
        self.assertEqual(self.parser.forwarded, [])

        self._frontend_logs_in()
        self._backend_logs_in()

        self.assertEqual(
            self.parser.forwarded,
            [("[SERVER]", 90, b"open"), ("[SERVER]", 98, b"exec")],
        )

    def test_frontend_packets_pass_straight_through_after_backend_login(self) -> None:
        self._frontend_logs_in()
        self._backend_logs_in()

        self.frontend.packet_buffer(90, b"open")

        self.assertEqual(self.parser.forwarded, [("[SERVER]", 90, b"open")])

    def test_backend_packets_wait_for_frontend_login(self) -> None:
        self.backend.packet_buffer(7, b"ext-info")
        self.assertEqual(self.parser.forwarded, [])

        self._frontend_logs_in()

        self.assertEqual(self.parser.forwarded, [("[CLIENT]", 7, b"ext-info")])

    def test_backend_packets_pass_straight_through_after_frontend_login(self) -> None:
        self._frontend_logs_in()

        self.backend.packet_buffer(94, b"data")

        self.assertEqual(self.parser.forwarded, [("[CLIENT]", 94, b"data")])


if __name__ == "__main__":
    unittest.main()
