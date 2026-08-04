# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Telnet session setup must survive attacker-controlled input:
# ABOUTME: a non-UTF-8 username and transport queries after teardown.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock

from cowrie.telnet.session import HoneyPotTelnetSession, TelnetSessionProcessProtocol
from cowrie.test.fake_server import FakeServer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class TelnetSessionUsernameTests(unittest.TestCase):
    def test_non_utf8_username_does_not_crash(self) -> None:
        """The username comes raw from the login prompt and need not be valid
        UTF-8; session construction must not raise UnicodeDecodeError."""
        session = HoneyPotTelnetSession(b"admin\xff", FakeServer())

        self.assertEqual(session.username, "admin�")


class TelnetSessionProcessProtocolTests(unittest.TestCase):
    def test_getpeer_gethost_after_connection_lost(self) -> None:
        """connectionLost() clears the session; getPeer()/getHost() must then
        return None instead of raising AttributeError."""
        pp = TelnetSessionProcessProtocol(MagicMock())
        pp.connectionLost(None)

        self.assertIsNone(pp.getPeer())
        self.assertIsNone(pp.getHost())


if __name__ == "__main__":
    unittest.main()
