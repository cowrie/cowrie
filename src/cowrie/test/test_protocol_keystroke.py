# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
# ABOUTME: Tests for keystroke handling in the interactive shell protocol,
# ABOUTME: covering control bytes that should not produce log warnings.
from __future__ import annotations

import os
import unittest

from twisted.logger import ILogObserver, globalLogPublisher
from zope.interface import provider

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class KeystrokeTests(unittest.TestCase):
    """Tests for HoneyPotInteractiveProtocol.keystrokeReceived."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

        self.events: list[dict[str, object]] = []

        @provider(ILogObserver)
        def record(event: dict[str, object]) -> None:
            self.events.append(event)

        globalLogPublisher.addObserver(record)
        self.addCleanup(globalLogPublisher.removeObserver, record)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_nul_byte_logs_no_warning(self) -> None:
        """A NUL byte is routine NVT traffic and must not be logged."""
        self.proto.keystrokeReceived(b"\x00", None)

        unhandled = [
            e
            for e in self.events
            if "Received unhandled keyID" in str(e.get("log_format", ""))
        ]
        self.assertEqual(unhandled, [])

    def test_nul_byte_does_not_reach_line_buffer(self) -> None:
        """The NUL handler is a no-op: it leaves no character in the buffer."""
        self.proto.keystrokeReceived(b"\x00", None)
        self.assertEqual(self.proto.lineBuffer, [])


if __name__ == "__main__":
    unittest.main()
