# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The proxy frontend must flush buffered frontend->backend packets once
# ABOUTME: the backend is connected, not strand them (issue #1788).

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

from cowrie.ssh_proxy.server_transport import FrontendSSHTransport


def _make(backend_connected: bool, queued: list[list[Any]]) -> Any:
    """A minimal stand-in exposing just what packet_buffer touches."""
    parsed: list[tuple[str, int, bytes]] = []
    sshParse = Mock()
    sshParse.parse_num_packet = lambda ctx, num, payload: parsed.append(
        (ctx, num, payload)
    )
    return SimpleNamespace(
        backendConnected=backend_connected,
        delayedPackets=queued,
        sshParse=sshParse,
        parsed=parsed,
        _log=Mock(),
    )


class ProxyFrontendPacketBufferTests(unittest.TestCase):
    def test_buffers_while_backend_not_connected(self) -> None:
        s = _make(backend_connected=False, queued=[])
        FrontendSSHTransport.packet_buffer(s, 90, b"open")
        self.assertEqual(s.delayedPackets, [[90, b"open"]])
        self.assertEqual(s.parsed, [])

    def test_parses_immediately_when_connected_and_queue_empty(self) -> None:
        s = _make(backend_connected=True, queued=[])
        FrontendSSHTransport.packet_buffer(s, 90, b"open")
        self.assertEqual(s.parsed, [("[SERVER]", 90, b"open")])
        self.assertEqual(s.delayedPackets, [])

    def test_flushes_queue_when_connected(self) -> None:
        # The bug (#1788): with the backend connected but packets still queued,
        # a new packet must flush the whole queue in order, not strand it.
        s = _make(backend_connected=True, queued=[[80, b"a"], [81, b"b"]])
        FrontendSSHTransport.packet_buffer(s, 90, b"open")
        self.assertEqual(
            s.parsed,
            [("[SERVER]", 80, b"a"), ("[SERVER]", 81, b"b"), ("[SERVER]", 90, b"open")],
        )
        self.assertEqual(s.delayedPackets, [])


if __name__ == "__main__":
    unittest.main()
