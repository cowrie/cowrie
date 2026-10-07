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


class ChmodExitStatusTests(CommandExitStatusTestCase):
    def test_chmod(self) -> None:
        self.check(
            [
                ("chmod 644 /etc/passwd", 0),
                ("chmod --help", 0),
                ("chmod 755 /nonexistent", 1),
                ("chmod", 1),
                ("chmod 644", 1),
                ("chmod abc /etc/passwd", 1),
                ("chmod -Z /etc/passwd", 1),
            ]
        )


class TextToolExitStatusTests(CommandExitStatusTestCase):
    def test_cut(self) -> None:
        self.check(
            [
                ("cut -d: -f1 /etc/passwd", 0),
                ("cut -f1 /nonexistent", 1),
                ("cut /etc/passwd", 1),
                ("cut -Z", 1),
                ("cut -f abc /etc/passwd", 1),
            ]
        )

    def test_base64(self) -> None:
        self.check(
            [
                ("base64 /etc/passwd", 0),
                ("echo aGk= | base64 -d", 0),
                ("base64 /nonexistent", 1),
                ("base64 /tmp", 1),
                ("base64 -Z", 1),
                ("base64 /etc/passwd /etc/group", 1),
                ("echo '!!!' | base64 -d", 1),
            ]
        )

    def test_tee(self) -> None:
        self.check(
            [
                ("echo a | tee /dev/null", 0),
                ("echo a | tee /nonexistent/x", 1),
                ("echo a | tee /tmp", 1),
                ("echo a | tee -Z", 1),
            ]
        )

    def test_grep(self) -> None:
        self.check(
            [
                ("grep root /etc/passwd", 0),
                ("grep zzzzqqq /etc/passwd", 1),
                ("grep x /nonexistent", 2),
                ("grep root /nonexistent /etc/passwd", 2),
                ("grep", 2),
            ]
        )


class MiscCommandExitStatusTests(CommandExitStatusTestCase):
    def test_sleep(self) -> None:
        self.check([("sleep", 1), ("sleep abc", 1), ("sleep --bogus", 1)])

    def test_uname(self) -> None:
        self.check(
            [
                ("uname -a", 0),
                ("uname -Z", 1),
                ("uname extra", 1),
                ("uname --bogus", 1),
            ]
        )

    def test_which(self) -> None:
        self.check(
            [
                ("which ls", 0),
                ("which nosuchcmd", 1),
                ("which ls nosuchcmd", 1),
            ]
        )

    def test_groups(self) -> None:
        self.check([("groups root", 0), ("groups nosuchuser", 1), ("groups -Z", 1)])

    def test_nohup(self) -> None:
        self.check([("nohup", 125)])

    def test_tar(self) -> None:
        self.check([("tar xf /nonexistent", 2), ("tar", 2), ("tar xf /etc/passwd", 2)])


if __name__ == "__main__":
    unittest.main()
