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
from twisted.internet.error import ConnectionDone
from twisted.protocols.ftp import FTPFactory, FTPRealm
from twisted.python.failure import Failure

from cowrie.commands import ftpget as ftpget_module
from cowrie.commands.ftpget import (
    Command_ftpget,
    FTPFileReceiver,
    ftpget_rate_limiter,
)
from cowrie.core.artifact import Artifact
from cowrie.shell.command import HoneyPotCommand
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

    class _Reactor(IReactorTime, IReactorTCP):
        pass


reactor = cast("_Reactor", _reactor)

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
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
            ftpget_module,
            "resolve_allowed",
            lambda address: defer.succeed(address),
        ):
            self.proto.lineReceived(
                f"ftpget -P {port} 127.0.0.1 /tmp/test.txt remote.txt\n".encode()
            )
            self.assertTrue(
                pump(lambda: b"ftpget:" in self.tr.value()), "no error output"
            )
        self.assertIn(b"ftpget: Connection failed", self.tr.value())


class FtpGetPinnedAddressTests(unittest.TestCase):
    """The transfer connects to the address that was validated."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        ftpget_rate_limiter.reset()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_connects_to_the_resolved_address(self) -> None:
        # Resolving the hostname a second time at connect time lets a
        # malicious DNS server answer the check and the connection
        # differently.
        captured: dict[str, Any] = {}

        class FakeCreator:
            def __init__(self, *a: Any, **k: Any) -> None:
                pass

            def connectTCP(self, host: str, port: int, **kwargs: Any) -> Any:
                captured["host"] = host
                return defer.Deferred()

        with (
            mock.patch.object(
                ftpget_module,
                "resolve_allowed",
                lambda _address: defer.succeed("198.51.100.7"),
            ),
            mock.patch.object(ftpget_module, "ClientCreator", FakeCreator),
        ):
            self.proto.lineReceived(b"ftpget host.invalid /tmp/f.txt remote.txt\n")

        self.assertEqual(captured.get("host"), "198.51.100.7")


class FtpGetArtifactCleanupTests(unittest.TestCase):
    """An interrupted transfer must not leave its temp file behind."""

    def test_ctrl_c_removes_the_empty_artifact(self) -> None:
        cmd = Command_ftpget.__new__(Command_ftpget)
        cmd.artifactFile = Artifact("ftpget-test")
        temp_name = cmd.artifactFile.fp.name
        self.assertTrue(os.path.exists(temp_name))

        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd.exit()

        self.assertFalse(
            os.path.exists(temp_name), "aborted transfer left its temp file behind"
        )


class FtpGetCtrlCKeepsDownloadingTests(unittest.TestCase):
    """CTRL-C returns the attacker to their prompt but must not cost us the
    sample: the transfer keeps running and is still captured and logged."""

    def _mid_transfer(self) -> Command_ftpget:
        """A command whose data transfer is under way."""
        cmd = Command_ftpget.__new__(Command_ftpget)
        cmd.exited = False
        cmd.exit_code = 0
        cmd.protocol = mock.Mock()
        cmd.fs = mock.Mock()
        cmd.user = {"uid": 0, "gid": 0}
        cmd.write = mock.Mock()  # type: ignore[method-assign]
        cmd.errorWrite = mock.Mock()  # type: ignore[method-assign]
        cmd.url_log = "ftp://evil.example/payload"
        cmd.local_file = "payload"
        cmd.fakeoutfile = "/root/payload"
        cmd.artifactFile = Artifact("ftpget-test")
        self.addCleanup(cmd.artifactFile.close)
        cmd.receiver = FTPFileReceiver(cmd.artifactFile)
        cmd.receiver.makeConnection(mock.Mock())
        cmd.transfer_running = True
        return cmd

    def _ctrl_c(self, cmd: Command_ftpget) -> None:
        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd.handle_CTRL_C()
        cmd.exited = True

    def test_data_connection_is_left_open(self) -> None:
        cmd = self._mid_transfer()

        self._ctrl_c(cmd)

        cast("mock.Mock", cmd.receiver.transport).loseConnection.assert_not_called()

    def test_the_rest_of_the_sample_is_still_written(self) -> None:
        """exit() must not close the artifact out from under the transfer, or
        the capture is truncated to whatever had arrived by then."""
        cmd = self._mid_transfer()
        cmd.receiver.dataReceived(b"first half ")

        self._ctrl_c(cmd)
        cmd.receiver.dataReceived(b"second half")

        cmd.artifactFile.fp.flush()
        with open(cmd.artifactFile.fp.name, "rb") as f:
            self.assertEqual(f.read(), b"first half second half")

    def test_completion_after_ctrl_c_still_reports_the_download(self) -> None:
        cmd = self._mid_transfer()
        cmd.receiver.dataReceived(b"malware")
        self._ctrl_c(cmd)

        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd._download_success(None)

        eventids = [
            call.args[0] for call in cmd.protocol.events.dispatch.call_args_list
        ]
        self.assertIn("cowrie.session.file_download", eventids)
        cmd.fs.mkfile.assert_called_once()

    def test_no_terminal_output_after_ctrl_c(self) -> None:
        """The attacker has their prompt back; a late error must not inject
        text into whatever they are doing now."""
        cmd = self._mid_transfer()
        self._ctrl_c(cmd)

        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd._download_error(Failure(ConnectionDone()))

        cmd.errorWrite.assert_not_called()

    def test_error_is_reported_while_the_command_is_still_running(self) -> None:
        cmd = self._mid_transfer()

        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd._download_error(Failure(ConnectionDone()))

        cmd.errorWrite.assert_called_once()


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
        # The stub wants bytes, but twisted's FTP server logs users in with
        # str credentials, and the checker compares them by equality.
        checker.addUser("testuser", "testpass")  # type: ignore[arg-type]
        portal.registerChecker(checker)
        server = reactor.listenTCP(0, FTPFactory(portal), interface="127.0.0.1")
        self.addCleanup(server.stopListening)
        self.ftp_port = cast("IPv4Address", server.getHost()).port

        # The limiter is a module-level singleton; keep tests isolated.
        ftpget_rate_limiter.reset()
        allow_loopback = mock.patch.object(
            ftpget_module,
            "resolve_allowed",
            lambda address: defer.succeed(address),
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
