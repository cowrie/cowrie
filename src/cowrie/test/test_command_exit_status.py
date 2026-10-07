# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Each command reports failure through its exit status as the GNU tool does;
# ABOUTME: expected statuses were taken from GNU coreutils running the same lines.

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


class CommandExitStatusTestCase(unittest.TestCase):
    def status(self, line: str) -> str:
        """Run ``line`` in a fresh shell, discarding its output; return $?."""
        proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        tr.clear()
        try:
            proto.lineReceived(f"{line} >/dev/null 2>&1; echo $?".encode())
            out: bytes = tr.value()
        finally:
            proto.connectionLost()
        # The last line is the prompt (its directory varies); $? is before it.
        return out.split(b"\n")[-2].decode()

    def check(self, cases: list[tuple[str, int]]) -> None:
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.status(line), str(expected))


class FileCommandExitStatusTests(CommandExitStatusTestCase):
    def test_cd(self) -> None:
        self.check(
            [
                ("cd /tmp", 0),
                ("cd /nonexistent", 1),
                ("cd /etc/passwd", 1),
                ("cd -", 1),
            ]
        )

    def test_rm(self) -> None:
        self.check(
            [
                ("touch /tmp/f; rm /tmp/f", 0),
                ("rm /nonexistent", 1),
                ("rm -f /nonexistent", 0),
                ("rm /tmp", 1),
                ("rm", 1),
                ("rm -Z", 1),
            ]
        )

    def test_rmdir(self) -> None:
        self.check(
            [
                ("mkdir /tmp/d; rmdir /tmp/d", 0),
                ("rmdir /nonexistent", 1),
                ("rmdir", 1),
                ("rmdir /etc", 1),
                ("rmdir /etc/passwd", 1),
            ]
        )

    def test_mkdir(self) -> None:
        self.check(
            [
                ("mkdir /tmp/new", 0),
                ("mkdir /tmp", 1),
                ("mkdir /nonexistent/x", 1),
                ("mkdir", 1),
            ]
        )

    def test_touch(self) -> None:
        self.check(
            [
                ("touch /tmp/f", 0),
                ("touch /nonexistent/x", 1),
                ("touch", 1),
            ]
        )

    def test_cp(self) -> None:
        self.check(
            [
                ("cp /etc/passwd /tmp/x", 0),
                ("cp /nonexistent /tmp/x", 1),
                ("cp", 1),
                ("cp /etc/passwd", 1),
            ]
        )

    def test_mv(self) -> None:
        self.check(
            [
                ("touch /tmp/f; mv /tmp/f /tmp/g", 0),
                ("mv /nonexistent /tmp/x", 1),
                ("mv /tmp", 1),
                ("mv", 1),
            ]
        )


if __name__ == "__main__":
    unittest.main()
