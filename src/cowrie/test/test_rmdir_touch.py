# SPDX-FileCopyrightText: 2026 nkbeast
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellRmdirCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/fs.py rmdir."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"mkdir /tmp/AAA /tmp/BBB")
        self.proto.lineReceived(b"touch /tmp/afile")
        self.tr.clear()

    def test_rmdir_processes_all_arguments(self) -> None:
        """A failing argument does not stop the remaining ones."""
        self.proto.lineReceived(b"rmdir /tmp/afile /tmp/AAA")
        self.assertIn(b"rmdir: failed to remove '/tmp/afile': Not a directory\n", self.tr.value())
        self.tr.clear()
        self.proto.lineReceived(b"ls -d /tmp/AAA")
        self.assertIn(b"cannot access", self.tr.value())

    def test_rmdir_keeps_remaining_argument(self) -> None:
        self.proto.lineReceived(b"rmdir /tmp/afile /tmp/BBB")
        self.tr.clear()
        self.proto.lineReceived(b"ls -d /tmp/AAA")
        self.assertIn(b"/tmp/AAA", self.tr.value())


class ShellTouchCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/fs.py touch."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_touch_processes_all_arguments_after_failure(self) -> None:
        """touch /nonexistent/f1 f2 still creates f2."""
        self.proto.lineReceived(b"touch /nonexistent/f1 f2")
        self.assertIn(
            b"touch: cannot touch `/nonexistent/f1`: No such file or directory\n",
            self.tr.value(),
        )
        self.tr.clear()
        self.proto.lineReceived(b"ls -d f2")
        self.assertIn(b"f2", self.tr.value())

    def test_touch_processes_all_arguments_after_permission_denied(self) -> None:
        """touch /proc/x /tmp/ok1 still creates /tmp/ok1."""
        self.proto.lineReceived(b"touch /proc/x /tmp/ok1")
        self.assertIn(b"touch: cannot touch `/proc/x`: Permission denied\n", self.tr.value())
        self.tr.clear()
        self.proto.lineReceived(b"ls -d /tmp/ok1")
        self.assertIn(b"/tmp/ok1", self.tr.value())


if __name__ == "__main__":
    unittest.main()
