# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that tab-completion does not crash for a client that never
# ABOUTME: sent a window size, falling back to a default column width.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class ShellTabCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        avatar = FakeAvatar(FakeServer())
        # A client that never sent a window-change request has no windowSize.
        del avatar.windowSize
        self.proto = HoneyPotInteractiveProtocol(avatar)
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.terminal = mock.MagicMock()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_tab_completion_without_window_size(self) -> None:
        shell = self.proto.cmdstack[-1]
        line = b"ls /bin/l"
        self.proto.lineBuffer = [bytes([c]) for c in line]
        self.proto.lineBufferIndex = len(self.proto.lineBuffer)
        # The first TAB expands to the common prefix, the second lists the
        # ambiguous matches, which is where the window width is read.
        shell.handle_TAB()
        shell.handle_TAB()
