# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the telnet auth protocol's initial option negotiation,
# ABOUTME: ensuring DO NAWS is negotiated before the login banner is sent.

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from twisted.conch.telnet import NAWS

from cowrie.telnet.userauth import HoneyPotTelnetAuthProtocol


class TestInitialNegotiation(unittest.TestCase):
    """connectionMade must proactively negotiate NAWS for Mirai-family clients."""

    def setUp(self) -> None:
        self.protocol = HoneyPotTelnetAuthProtocol(MagicMock())
        self.transport = MagicMock()
        self.transport.negotiationMap = {}
        self.protocol.transport = self.transport
        self.protocol.factory = MagicMock()
        self.protocol.factory.banner = b"banner\n"

    def test_naws_negotiated_on_connect(self) -> None:
        self.protocol.connectionMade()
        self.transport.doChain.assert_called_once_with(NAWS)

    def test_naws_handler_registered(self) -> None:
        self.protocol.connectionMade()
        self.assertEqual(self.transport.negotiationMap[NAWS], self.protocol.telnet_NAWS)

    def test_naws_negotiated_before_banner(self) -> None:
        self.protocol.connectionMade()
        call_names = [c[0] for c in self.transport.mock_calls]
        self.assertIn("doChain", call_names)
        self.assertIn("write", call_names)
        self.assertLess(call_names.index("doChain"), call_names.index("write"))


if __name__ == "__main__":
    unittest.main()
