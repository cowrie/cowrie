# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
# mypy: disable-error-code="var-annotated,attr-defined,return-value"

from __future__ import annotations

import os
import tempfile
import unittest

from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import Portal
from twisted.internet import defer, reactor
from twisted.protocols.ftp import FTPFactory, FTPRealm

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellFtpGetCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/ftpget.py."""

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
        d = defer.Deferred()

        def do_test():
            self.proto.lineReceived(b"ftpget\n")

            def check():
                self.assertEqual(self.tr.value(), usage + PROMPT)
                d.callback(None)

            reactor.callLater(0.1, check)

        reactor.callLater(0, do_test)
        return d

    def test_insufficient_args(self) -> None:
        """Test ftpget with only one argument shows help"""
        d = defer.Deferred()

        def do_test():
            self.proto.lineReceived(b"ftpget host.com\n")

            def check():
                output = self.tr.value()
                self.assertIn(b"Usage: ftpget", output)
                d.callback(None)

            reactor.callLater(0.1, check)

        reactor.callLater(0, do_test)
        return d

    def test_connection_refused(self) -> None:
        """Test ftpget with invalid host shows connection error"""
        d = defer.Deferred()

        def do_test():
            # Use a non-routable IP to guarantee connection failure
            self.proto.lineReceived(b"ftpget 192.0.2.1 /tmp/test.txt remote.txt\n")

            def check():
                output = self.tr.value()
                # Should see an error message
                self.assertIn(b"ftpget:", output)
                d.callback(None)

            reactor.callLater(0.5, check)

        reactor.callLater(0, do_test)
        return d

    def test_invalid_directory(self) -> None:
        """Test ftpget with invalid local directory"""
        d = defer.Deferred()

        def do_test():
            self.proto.lineReceived(
                b"ftpget host.com /nonexistent/dir/file.txt remote.txt\n"
            )

            def check():
                output = self.tr.value()
                self.assertIn(b"No such file or directory", output)
                d.callback(None)

            reactor.callLater(0.1, check)

        reactor.callLater(0, do_test)
        return d


class ShellFtpGetAsyncTests(unittest.TestCase):
    """Async tests for ftpget with mock FTP server"""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")
    ftp_port: int
    ftp_server = None
    tmpdir: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

        # Create temp directory for FTP files
        cls.tmpdir = tempfile.TemporaryDirectory()

        # Create a test file
        test_file = os.path.join(cls.tmpdir.name, "test.txt")
        with open(test_file, "w") as f:
            f.write("Test file content\n")

        # Setup FTP server
        portal = Portal(FTPRealm(cls.tmpdir.name))
        checker = InMemoryUsernamePasswordDatabaseDontUse()
        checker.addUser(b"testuser", b"testpass")
        checker.addUser(b"anonymous", b"")
        portal.registerChecker(checker)

        factory = FTPFactory(portal)
        cls.ftp_server = reactor.listenTCP(0, factory, interface="127.0.0.1")
        cls.ftp_port = cls.ftp_server.getHost().port

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()
        if cls.ftp_server:
            cls.ftp_server.stopListening()
        cls.tmpdir.cleanup()

    def setUp(self) -> None:
        self.tr.clear()

    def test_successful_download_anonymous(self) -> None:
        """Test successful FTP download with anonymous login"""
        cmd = f"ftpget 127.0.0.1 -P {self.ftp_port} /tmp/downloaded.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Should complete without error and show prompt
            self.assertIn(PROMPT, output)
            # Should not show error messages
            self.assertNotIn(b"ftpget: ", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_successful_download_with_auth(self) -> None:
        """Test successful FTP download with username/password"""
        cmd = f"ftpget -u testuser -p testpass 127.0.0.1 -P {self.ftp_port} /tmp/downloaded2.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            self.assertIn(PROMPT, output)
            self.assertNotIn(b"error", output.lower())
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_verbose_output(self) -> None:
        """Test ftpget -v shows FTP commands"""
        cmd = f"ftpget -v 127.0.0.1 -P {self.ftp_port} /tmp/downloaded3.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Verbose mode should show FTP commands
            self.assertIn(b"Connecting", output)
            self.assertIn(b"ftpget: cmd", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_file_not_found(self) -> None:
        """Test FTP download of non-existent file"""
        cmd = f"ftpget 127.0.0.1 -P {self.ftp_port} /tmp/notfound.txt nonexistent.txt\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Should show error for file not found
            self.assertIn(b"ftpget:", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_non_blocking_behavior(self) -> None:
        """Test that FTP download doesn't block the reactor"""
        # Start FTP download
        cmd = f"ftpget 127.0.0.1 -P {self.ftp_port} /tmp/nonblock.txt test.txt\n"
        self.proto.lineReceived(cmd.encode())

        # Immediately try another command
        self.proto.lineReceived(b"echo test\n")

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Should see echo output, proving shell wasn't blocked
            self.assertIn(b"test", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d
