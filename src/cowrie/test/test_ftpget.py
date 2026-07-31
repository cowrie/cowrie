# SPDX-FileCopyrightText: 2018-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
import socket
import tempfile
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest import mock

from twisted.cred.checkers import (
    AllowAnonymousAccess,
    InMemoryUsernamePasswordDatabaseDontUse,
)
from twisted.cred.portal import Portal
from twisted.internet import defer
from twisted.internet import reactor as _reactor
from twisted.protocols.ftp import FTPFactory, FTPRealm

from cowrie.commands import ftpget as ftpget_module
from cowrie.commands.ftpget import FTPFileReceiver, ftpget_rate_limiter
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport
from cowrie.test.reactorpump import pump

if TYPE_CHECKING:
    from twisted.internet.address import IPv4Address
    from twisted.internet.interfaces import (
        IReactorTCP,
        IReactorTime,
    )

    from cowrie.core.artifact import Artifact

    class _Reactor(IReactorTime, IReactorTCP):
        pass


reactor = cast("_Reactor", _reactor)

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


def closed_loopback_port() -> int:
    """Return a loopback port with nothing listening on it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return cast("tuple[str, int]", probe.getsockname())[1]


class ShellFtpGetCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/ftpget.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        # The limiter is a module-level singleton; keep tests isolated.
        ftpget_rate_limiter.reset()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_help_command(self) -> None:
        usage = (
            b"BusyBox v1.20.2 (2016-06-22 15:12:53 EDT) multi-call binary.\n"
            b"\n"
            b"Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n"
            b"\n"
            b"Download a file via FTP\n"
            b"\n"
            b"    -c Continue previous transfer\n"
            b"    -v Verbose\n"
            b"    -u USER     Username\n"
            b"    -p PASS     Password\n"
            b"    -P NUM      Port\n\n"
        )
        self.proto.lineReceived(b"ftpget\n")
        self.assertEqual(self.tr.value(), usage + PROMPT)

    def test_insufficient_args(self) -> None:
        """ftpget with only one argument shows help"""
        self.proto.lineReceived(b"ftpget host.com\n")
        self.assertIn(b"Usage: ftpget", self.tr.value())

    def test_invalid_directory(self) -> None:
        """ftpget with an invalid local directory reports the open failure"""
        self.proto.lineReceived(
            b"ftpget host.com /nonexistent/dir/file.txt remote.txt\n"
        )
        self.assertIn(b"No such file or directory", self.tr.value())

    def test_connection_refused(self) -> None:
        """ftpget reports a connection error when nothing listens on the port"""
        port = closed_loopback_port()
        with mock.patch.object(
            ftpget_module, "communication_allowed", lambda _address: defer.succeed(True)
        ):
            self.proto.lineReceived(
                f"ftpget -P {port} 127.0.0.1 /tmp/test.txt remote.txt\n".encode()
            )
            self.assertTrue(
                pump(lambda: b"ftpget:" in self.tr.value()), "no error output"
            )
        self.assertIn(b"ftpget: Connection failed", self.tr.value())


class FTPFileReceiverSizeLimitTests(unittest.TestCase):
    """The receiver must stop writing and abort the data connection once the
    download exceeds download_limit_size, so a rogue server can't write
    unbounded data to disk."""

    def _make(self, limit: int) -> tuple[FTPFileReceiver, list[bytes]]:
        written: list[bytes] = []
        artifact = SimpleNamespace(write=written.append)
        receiver = FTPFileReceiver(cast("Artifact", artifact), limit_size=limit)
        receiver.makeConnection(mock.Mock())
        return receiver, written

    def test_aborts_and_stops_writing_past_the_limit(self) -> None:
        receiver, written = self._make(10)
        receiver.dataReceived(b"12345")
        self.assertFalse(receiver.limit_exceeded)
        receiver.dataReceived(b"67890AB")  # total 12 > 10
        self.assertTrue(receiver.limit_exceeded)
        cast("mock.Mock", receiver.transport).loseConnection.assert_called_once()
        receiver.dataReceived(b"dropped")  # ignored once over the limit
        self.assertEqual(b"".join(written), b"1234567890AB")

    def test_no_limit_writes_everything(self) -> None:
        receiver, written = self._make(0)
        receiver.dataReceived(b"x" * 5000)
        self.assertFalse(receiver.limit_exceeded)
        self.assertEqual(len(b"".join(written)), 5000)


class ShellFtpGetAsyncTests(unittest.TestCase):
    """Tests for ftpget against a local FTP server.

    The server listens on loopback, which the outbound blocklist refuses, so
    these tests permit loopback for the duration. Without that the command
    exits at the address check and no FTP traffic ever flows.
    """

    def setUp(self) -> None:
        # Per-test protocol and server: these tests turn the reactor, so a
        # shared protocol would let one test's in-flight transfer land in
        # another test's output and events.
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.events = capture_events(self.proto)

        # Serve test.txt to both the anonymous root and testuser's home.
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        os.mkdir(os.path.join(self.tmpdir.name, "testuser"))
        for path in ("test.txt", os.path.join("testuser", "test.txt")):
            with open(os.path.join(self.tmpdir.name, path), "w") as f:
                f.write("Test file content\n")

        portal = Portal(
            FTPRealm(anonymousRoot=self.tmpdir.name, userHome=self.tmpdir.name)
        )
        portal.registerChecker(AllowAnonymousAccess())
        checker = InMemoryUsernamePasswordDatabaseDontUse()
        checker.addUser("testuser", "testpass")
        portal.registerChecker(checker)
        server = reactor.listenTCP(0, FTPFactory(portal), interface="127.0.0.1")
        self.addCleanup(server.stopListening)
        self.ftp_port = cast("IPv4Address", server.getHost()).port

        # The limiter is a module-level singleton; keep tests isolated.
        ftpget_rate_limiter.reset()
        allow_loopback = mock.patch.object(
            ftpget_module, "communication_allowed", lambda _address: defer.succeed(True)
        )
        allow_loopback.start()
        self.addCleanup(allow_loopback.stop)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def downloaded(self) -> list[dict[str, Any]]:
        return [
            e for e in self.events if e["eventid"] == "cowrie.session.file_download"
        ]

    def failed(self) -> list[dict[str, Any]]:
        return [
            e
            for e in self.events
            if e["eventid"] == "cowrie.session.file_download.failed"
        ]

    def test_successful_download_anonymous(self) -> None:
        """ftpget without credentials downloads via anonymous login"""
        cmd = f"ftpget -P {self.ftp_port} 127.0.0.1 /tmp/downloaded.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        self.assertEqual(
            self.downloaded()[0]["url"], f"ftp://127.0.0.1:{self.ftp_port}/test.txt"
        )
        output = self.tr.value()
        self.assertNotIn(b"ftpget:", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_successful_download_with_auth(self) -> None:
        """ftpget -u/-p downloads via a username/password login"""
        cmd = (
            f"ftpget -u testuser -p testpass -P {self.ftp_port} "
            "127.0.0.1 /tmp/downloaded2.txt test.txt\n"
        )
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        self.assertEqual(
            self.downloaded()[0]["url"],
            f"ftp://testuser:testpass@127.0.0.1:{self.ftp_port}/test.txt",
        )
        self.assertNotIn(b"ftpget:", self.tr.value())

    def test_verbose_output(self) -> None:
        """ftpget -v prints the FTP conversation"""
        cmd = f"ftpget -v -P {self.ftp_port} 127.0.0.1 /tmp/downloaded3.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        output = self.tr.value()
        self.assertIn(b"Connecting to 127.0.0.1", output)
        self.assertIn(b"ftpget: cmd RETR test.txt", output)

    def test_file_not_found(self) -> None:
        """A missing remote file dispatches a failed-download event"""
        cmd = f"ftpget -P {self.ftp_port} 127.0.0.1 /tmp/notfound.txt nonexistent.txt\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.failed()), "no file_download.failed event dispatched"
        )
        self.assertIn(b"ftpget: FTP error", self.tr.value())

    def test_non_blocking_behavior(self) -> None:
        """A line typed during the transfer runs after ftpget completes"""
        cmd = f"ftpget -P {self.ftp_port} 127.0.0.1 /tmp/nonblock.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())
        self.proto.lineReceived(b"echo queued_after_download\n")

        self.assertTrue(
            pump(lambda: b"queued_after_download\n" in self.tr.value()),
            "queued command did not run",
        )
        self.assertEqual(len(self.downloaded()), 1)


if __name__ == "__main__":
    unittest.main()
