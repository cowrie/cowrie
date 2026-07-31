# SPDX-FileCopyrightText: 2018-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

from twisted.internet import defer
from twisted.internet import reactor as _reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.python.failure import Failure

from cowrie.commands import tftp as tftp_module
from cowrie.commands.tftp import (
    OPCODE_ACK,
    OPCODE_DATA,
    OPCODE_ERROR,
    OPCODE_RRQ,
    TFTP_BLOCK_SIZE,
    Command_tftp,
    tftp_rate_limiter,
)
from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.rate_limiter import RateLimiter
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport
from cowrie.test.reactorpump import pump

if TYPE_CHECKING:
    from twisted.internet.address import IPv4Address
    from twisted.internet.interfaces import (
        IReactorTime,
        IReactorUDP,
    )

    class _Reactor(IReactorTime, IReactorUDP):
        pass


reactor = cast("_Reactor", _reactor)

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class MockTFTPServer(DatagramProtocol):
    """Mock TFTP server for testing"""

    def __init__(self, test_file_content: bytes = b"Test file content\n"):
        self.test_file_content = test_file_content
        self.client_addr: tuple[str, int] | None = None

    def datagramReceived(self, datagram: bytes, addr: Any) -> None:
        """Handle TFTP packets"""
        if len(datagram) < 2:
            return

        opcode = struct.unpack("!H", datagram[:2])[0]

        if opcode == OPCODE_RRQ:
            # Read request - send data back
            self.client_addr = addr
            self.sendFile()
        elif opcode == OPCODE_ACK:
            # ACK received - if not final ACK, send next block
            block_num = struct.unpack("!H", datagram[2:4])[0]
            self.sendNextBlock(block_num)

    def sendFile(self) -> None:
        """Send file in 512-byte blocks"""
        # Send first block
        self.sendBlock(1, self.test_file_content[:TFTP_BLOCK_SIZE])

    def sendNextBlock(self, acked_block: int) -> None:
        """Send next block after receiving ACK"""
        start = acked_block * TFTP_BLOCK_SIZE
        end = start + TFTP_BLOCK_SIZE

        if start < len(self.test_file_content):
            data = self.test_file_content[start:end]
            self.sendBlock(acked_block + 1, data)

    def sendBlock(self, block_num: int, data: bytes) -> None:
        """Send a DATA packet"""
        packet = struct.pack("!HH", OPCODE_DATA, block_num) + data
        if self.client_addr:
            self.transport.write(packet, self.client_addr)  # type: ignore[union-attr]

    def sendError(self, error_code: int, error_msg: str) -> None:
        """Send an ERROR packet"""
        packet = struct.pack("!HH", OPCODE_ERROR, error_code)
        packet += error_msg.encode() + b"\x00"
        if self.client_addr:
            self.transport.write(packet, self.client_addr)  # type: ignore[union-attr]


class ShellTftpCommandTests(unittest.TestCase):
    """Basic tests for TFTP command parsing"""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        # The limiter is a module-level singleton; keep tests isolated.
        tftp_rate_limiter.reset()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_tftp_no_args(self) -> None:
        """Test tftp command without arguments shows usage"""
        self.proto.lineReceived(b"tftp\n")
        self.assertEqual(
            self.tr.value(),
            b"usage: tftp [-h] [-c C C] [-l L] [-g G] [-p P] [-r R] [hostname]\n"
            + PROMPT,
        )

    def test_tftp_insufficient_args(self) -> None:
        """Test tftp with only hostname shows usage"""
        self.proto.lineReceived(b"tftp hostname.com\n")
        pump(lambda: b"usage: tftp" in self.tr.value())
        self.assertIn(b"usage: tftp", self.tr.value())

    def test_tftp_invalid_directory(self) -> None:
        """Test tftp with invalid local directory"""
        with patch.object(
            tftp_module, "communication_allowed", lambda _address: defer.succeed(True)
        ):
            self.proto.lineReceived(b"tftp -c get /nonexistent/file.txt 8.8.8.8\n")
            pump(lambda: b"No such file or directory" in self.tr.value())
        self.assertIn(b"No such file or directory", self.tr.value())


class ShellTftpAsyncTests(unittest.TestCase):
    """Async tests for TFTP with mock server.

    The mock server listens on loopback, which the outbound blocklist refuses,
    so these tests permit loopback for the duration. Without that the command
    exits at the address check and every assertion below passes without a
    single byte being transferred.
    """

    test_content = b"Test file from TFTP server\n"

    def setUp(self) -> None:
        # Per-test protocol and server: these tests turn the reactor, so a
        # shared protocol would let one test's in-flight transfer land in
        # another test's output and events.
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.events = capture_events(self.proto)

        self.tftp_port = self.serve(self.test_content)

        # The limiter is a module-level singleton; keep tests isolated.
        tftp_rate_limiter.reset()
        allow_loopback = patch.object(
            tftp_module, "communication_allowed", lambda _address: defer.succeed(True)
        )
        allow_loopback.start()
        self.addCleanup(allow_loopback.stop)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def serve(self, content: bytes) -> int:
        """Start a mock TFTP server on loopback and return its port."""
        server = reactor.listenUDP(
            0, MockTFTPServer(content), interface="127.0.0.1", maxPacketSize=8192
        )
        self.addCleanup(server.stopListening)
        return cast("IPv4Address", server.getHost()).port

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

    def test_successful_download(self) -> None:
        """Test successful TFTP download"""
        cmd = f"tftp -c get /tmp/tftp_test.txt 127.0.0.1:{self.tftp_port}\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        output = self.tr.value()
        self.assertIn(PROMPT, output)
        self.assertNotIn(b"tftp: TFTP Error", output)
        # The file really arrived, with the content the server served.
        with open(self.downloaded()[0]["outfile"], "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_download_with_r_flag(self) -> None:
        """Test TFTP download with -r flag"""
        cmd = f"tftp -r /tmp/tftp_test2.txt -g 127.0.0.1:{self.tftp_port}\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        self.assertNotIn(b"tftp: TFTP Error", self.tr.value())

    def test_unreachable_host_reports_timeout(self) -> None:
        """An unreachable target fails the transfer instead of hanging."""
        # Shorten the retransmission schedule so the failure lands promptly.
        with (
            patch.object(tftp_module, "TFTP_TIMEOUT", 0.05),
            patch.object(tftp_module, "TFTP_MAX_RETRIES", 2),
        ):
            # 192.0.2.1 is TEST-NET-1: routers drop it, nothing answers.
            self.proto.lineReceived(b"tftp -c get /tmp/test.txt 192.0.2.1\n")
            self.assertTrue(
                pump(lambda: self.failed()), "unreachable transfer never failed"
            )

        self.assertIn("timed out", self.failed()[0]["error"].lower())
        self.assertEqual(self.downloaded(), [])
        self.assertIn(PROMPT, self.tr.value())

    def test_non_blocking_behavior(self) -> None:
        """A transfer must not wedge the reactor or the shell.

        The download runs on the reactor rather than blocking it, so other
        scheduled work still fires while it is in flight, and input queued
        behind the command runs once it finishes.
        """
        ticked: list[bool] = []
        reactor.callLater(0, lambda: ticked.append(True))

        cmd = f"tftp -c get /tmp/nonblock.txt 127.0.0.1:{self.tftp_port}\n"
        self.proto.lineReceived(cmd.encode())
        # Queued behind the running command.
        self.proto.lineReceived(b"echo test\n")

        self.assertTrue(pump(lambda: self.downloaded()), "transfer never completed")
        self.assertEqual(ticked, [True], "reactor did not run during the transfer")
        self.assertTrue(
            pump(lambda: b"test" in self.tr.value()),
            "queued command never ran after the transfer",
        )

    def test_large_file_download(self) -> None:
        """Test TFTP download of file larger than one block"""
        # Two full blocks plus a short final one
        large_content = b"X" * (TFTP_BLOCK_SIZE * 2 + 100)
        large_port = self.serve(large_content)

        cmd = f"tftp -c get /tmp/large.txt 127.0.0.1:{large_port}\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.downloaded()), "no file_download event dispatched"
        )
        self.assertNotIn(b"tftp: TFTP Error", self.tr.value())
        # All three blocks were reassembled, not just the first.
        with open(self.downloaded()[0]["outfile"], "rb") as f:
            self.assertEqual(f.read(), large_content)

    def test_download_over_limit_is_refused(self) -> None:
        """A transfer past download_limit_size must abort, end to end."""
        limited_port = self.serve(b"Y" * (TFTP_BLOCK_SIZE * 3))

        orig_limit = Command_tftp.limit_size
        Command_tftp.limit_size = TFTP_BLOCK_SIZE  # one block
        self.addCleanup(setattr, Command_tftp, "limit_size", orig_limit)

        cmd = f"tftp -c get /tmp/limited.txt 127.0.0.1:{limited_port}\n"
        self.proto.lineReceived(cmd.encode())

        self.assertTrue(
            pump(lambda: self.failed()), "transfer over the limit was not refused"
        )
        self.assertIn("limit", self.failed()[0]["error"].lower())
        self.assertEqual(self.downloaded(), [])


class TFTPArtifactCloseTests(unittest.TestCase):
    """Tests for the artifact close sequence used by the download callbacks"""

    def test_close_safety_net_hashes_artifact(self) -> None:
        """The download close safety-net must hash and store the artifact.

        The success/error callbacks read ``artifactFile.shasum`` and
        ``shasumFilename`` to log the download and dispatch the
        ``file_download`` event. If the close sequence fails to hash the
        artifact, those fields stay empty and downstream consumers (e.g. the
        VirusTotal output) receive an empty path.
        """
        import hashlib

        from cowrie.commands.tftp import Command_tftp
        from cowrie.core.artifact import Artifact

        content = b"tftp artifact hashing regression\n"
        expected_sha = hashlib.sha256(content).hexdigest()

        cmd = Command_tftp.__new__(Command_tftp)
        cmd.artifactFile = Artifact("tftp-download")
        cmd.artifactFile.write(content)

        cmd._ensure_artifact_closed(None)

        self.assertEqual(cmd.artifactFile.shasum, expected_sha)
        self.assertTrue(cmd.artifactFile.shasumFilename)
        self.assertTrue(
            os.path.exists(cmd.artifactFile.shasumFilename),
            f"artifact not stored at {cmd.artifactFile.shasumFilename}",
        )
        with open(cmd.artifactFile.shasumFilename, "rb") as f:
            self.assertEqual(f.read(), content)
        os.remove(cmd.artifactFile.shasumFilename)


class TFTPHostnameResolutionTests(unittest.TestCase):
    """The TFTP client must feed a numeric IP to the UDP transport.

    Twisted's UDP transport raises InvalidAddressError synchronously when
    handed a hostname, and that raise happens inside listenUDP() -> startProtocol()
    before start() has wired the download callbacks, orphaning the artifact and
    producing an unhandled Deferred error (issue #40297).
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self._orig_artifact_dir = Artifact.artifactDir
        Artifact.artifactDir = self.tmpdir

    def tearDown(self) -> None:
        Artifact.artifactDir = self._orig_artifact_dir
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _make_command(self, host_ip: str) -> Command_tftp:
        cmd = Command_tftp.__new__(Command_tftp)
        cmd.hostname = "hostname.example.com"
        cmd.host_ip = host_ip
        cmd.port = 69
        cmd.file_to_get = "test.sh"
        cmd.artifactFile = Artifact("tftp-download")
        return cmd

    def test_transport_address_error_fails_cleanly(self) -> None:
        # A non-numeric address reaching transport.write must not raise out of
        # tftp_download_async(); it must surface as a failed transfer Deferred
        # and leave no orphaned temp file.
        cmd = self._make_command(host_ip="hostname.example.com")
        temp = cmd.artifactFile.tempFilename
        self.assertTrue(os.path.exists(temp))

        d = cmd.tftp_download_async()  # must NOT raise
        results: list[Any] = []
        d.addBoth(results.append)
        d.addBoth(cmd._ensure_artifact_closed)

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Failure)
        self.assertFalse(
            os.path.exists(temp), "artifact orphaned on transport address error"
        )

    def test_download_uses_resolved_numeric_ip(self) -> None:
        # When a numeric IP is supplied (as hostname resolution produces), the
        # client contacts that IP and startProtocol does not raise.
        cmd = self._make_command(host_ip="127.0.0.1")

        d = cmd.tftp_download_async()  # must NOT raise
        client = cmd.tftp_client
        try:
            assert client is not None
            self.assertEqual(client.host, "127.0.0.1")
        finally:
            if client and client.timeout_call and client.timeout_call.active():
                client.timeout_call.cancel()
            if cmd.udp_port:
                cmd.udp_port.stopListening()
            d.addErrback(lambda _f: None)
            d.cancel()
            cmd.artifactFile.close()

    def _bound_host(self, cmd: Command_tftp) -> str:
        d = cmd.tftp_download_async()
        try:
            assert cmd.udp_port is not None
            host: str = cmd.udp_port.getHost().host
            return host
        finally:
            client = cmd.tftp_client
            if client and client.timeout_call and client.timeout_call.active():
                client.timeout_call.cancel()
            if cmd.udp_port:
                cmd.udp_port.stopListening()
            d.addErrback(lambda _f: None)
            d.cancel()
            cmd.artifactFile.close()

    def test_download_binds_to_out_addr(self) -> None:
        # The UDP socket must bind to the configured out_addr so the transfer
        # does not leak the honeypot's real interface IP (issue #752).
        self.addCleanup(CowrieConfig.remove_option, "honeypot", "out_addr")
        CowrieConfig.set("honeypot", "out_addr", "127.0.0.1")
        cmd = self._make_command(host_ip="127.0.0.1")
        self.assertEqual(self._bound_host(cmd), "127.0.0.1")

    def test_download_defaults_to_wildcard_bind(self) -> None:
        # With no out_addr configured, the OS chooses the source address.
        CowrieConfig.remove_option("honeypot", "out_addr")
        cmd = self._make_command(host_ip="127.0.0.1")
        self.assertEqual(self._bound_host(cmd), "0.0.0.0")


class TFTPHostPortParseTests(unittest.TestCase):
    """The target argument accepts host, host:port, bare IPv6, and
    [IPv6]:port forms; any IPv6 literal used to crash the two-way split."""

    def parse(self, target: str) -> tuple[str, int] | None:
        from cowrie.commands.tftp import parse_host_port

        return parse_host_port(target, 69)

    def test_plain_host(self) -> None:
        self.assertEqual(self.parse("host.example.com"), ("host.example.com", 69))

    def test_host_with_port(self) -> None:
        self.assertEqual(
            self.parse("host.example.com:1069"), ("host.example.com", 1069)
        )

    def test_ipv4_with_port(self) -> None:
        self.assertEqual(self.parse("192.0.2.1:1069"), ("192.0.2.1", 1069))

    def test_bare_ipv6_loopback(self) -> None:
        self.assertEqual(self.parse("::1"), ("::1", 69))

    def test_bare_ipv6(self) -> None:
        self.assertEqual(self.parse("2001:db8::1"), ("2001:db8::1", 69))

    def test_bracketed_ipv6_with_port(self) -> None:
        self.assertEqual(self.parse("[2001:db8::1]:1069"), ("2001:db8::1", 1069))

    def test_bracketed_ipv6_without_port(self) -> None:
        self.assertEqual(self.parse("[2001:db8::1]"), ("2001:db8::1", 69))

    def test_non_numeric_port_rejected(self) -> None:
        self.assertIsNone(self.parse("host.example.com:abc"))

    def test_out_of_range_port_rejected(self) -> None:
        self.assertIsNone(self.parse("host.example.com:99999"))

    def test_zero_port_rejected(self) -> None:
        self.assertIsNone(self.parse("host.example.com:0"))

    def test_bracketed_bad_port_rejected(self) -> None:
        self.assertIsNone(self.parse("[2001:db8::1]:abc"))

    def test_empty_host_rejected(self) -> None:
        self.assertIsNone(self.parse(":69"))


class TFTPTargetHandlingTests(unittest.TestCase):
    """Shell-level target handling: IPv6 must not crash the command."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        # The limiter is a module-level singleton; keep tests isolated.
        tftp_rate_limiter.reset()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_ipv6_target_does_not_crash(self) -> None:
        # ::1 is an IP literal: no DNS is involved, the blocklist check runs
        # synchronously, and the command must come back to a prompt instead of
        # dying in host:port parsing with ValueError.
        self.proto.lineReceived(b"tftp -c get /tmp/tftp_v6.txt ::1\n")
        self.assertIn(PROMPT, self.tr.value())

    def test_bracketed_ipv6_target_does_not_crash(self) -> None:
        self.proto.lineReceived(b"tftp -c get /tmp/tftp_v6.txt [::1]:1069\n")
        self.assertIn(PROMPT, self.tr.value())

    def test_invalid_port_reports_error(self) -> None:
        self.proto.lineReceived(b"tftp -c get /tmp/tftp_bad.txt host.example.com:abc\n")
        output = self.tr.value()
        self.assertIn(b"bad port", output)
        self.assertIn(PROMPT, output)


class TFTPResolutionPinningTests(unittest.TestCase):
    """The address validated must be the address contacted.

    The command used to validate one resolution of the target and then resolve
    it again independently for the UDP transport, so a DNS answer that changed
    between the two lookups let a private address through (issue #40394).
    """

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        tftp_rate_limiter.reset()
        self.addCleanup(tftp_rate_limiter.reset)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _reactor_resolving_to(self, address: str) -> Any:
        """The tftp module's reactor, with resolution pinned to one answer."""
        return SimpleNamespace(
            resolve=lambda _host: defer.succeed(address),
            listenUDP=reactor.listenUDP,
            callLater=reactor.callLater,
        )

    def test_validates_the_address_it_will_contact(self) -> None:
        validated: list[str] = []

        def fake_allowed(address: str) -> defer.Deferred[bool]:
            validated.append(address)
            return defer.succeed(False)  # stop before any transfer

        with (
            patch.object(
                tftp_module, "reactor", self._reactor_resolving_to("192.0.2.7")
            ),
            patch.object(tftp_module, "communication_allowed", fake_allowed),
        ):
            self.proto.lineReceived(b"tftp -c get /tmp/pin.txt host.example.com\n")

        self.assertEqual(
            validated,
            ["192.0.2.7"],
            "the resolved address must be what gets validated, not the hostname",
        )

    def test_address_resolving_to_private_is_refused(self) -> None:
        # The rebinding case: the hostname would pass validation, but it
        # resolves to loopback. The transfer must never start.
        started: list[bool] = []

        def fake_download(_self: Any) -> defer.Deferred[None]:
            started.append(True)
            return defer.succeed(None)

        def only_blocks_the_private_ip(address: str) -> defer.Deferred[bool]:
            """Stands in for a DNS answer that differs between lookups: the
            hostname validates, the address it resolves to does not."""
            return defer.succeed(address != "127.0.0.1")

        with (
            patch.object(
                tftp_module, "reactor", self._reactor_resolving_to("127.0.0.1")
            ),
            patch.object(
                tftp_module, "communication_allowed", only_blocks_the_private_ip
            ),
            patch.object(
                tftp_module.Command_tftp, "tftp_download_async", fake_download
            ),
        ):
            self.proto.lineReceived(b"tftp -c get /tmp/pin.txt rebind.example.com\n")

        self.assertEqual(started, [], "contacted an address that resolves to loopback")

    def test_public_address_still_downloads(self) -> None:
        started: list[bool] = []

        def fake_download(_self: Any) -> defer.Deferred[None]:
            started.append(True)
            return defer.succeed(None)

        # 8.8.8.8 is globally routable, so the real blocklist permits it.
        with (
            patch.object(tftp_module, "reactor", self._reactor_resolving_to("8.8.8.8")),
            patch.object(
                tftp_module.Command_tftp, "tftp_download_async", fake_download
            ),
        ):
            self.proto.lineReceived(b"tftp -c get /tmp/pin.txt host.example.com\n")

        self.assertEqual(started, [True])


class TFTPRateLimitTests(unittest.TestCase):
    """tftp must bound how many outbound transfers a session can trigger,
    the way wget, curl and ftpget do (issue #40394)."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        capture_events(self.proto)
        tftp_rate_limiter.reset()
        self.addCleanup(tftp_rate_limiter.reset)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_transfers_over_limit_are_refused(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        with patch.object(tftp_module, "tftp_rate_limiter", limiter):
            # 192.0.2.0/24 is TEST-NET-1: globally routable per the blocklist,
            # so the limiter is what stops the third attempt, and no packet
            # reaches a real host.
            for _ in range(3):
                self.proto.lineReceived(b"tftp -c get /tmp/rl.txt 192.0.2.1\n")

        self.assertEqual(limiter.check("192.0.2.1"), False)
        self.assertIn(b"timed out", self.tr.value())

    def test_limit_is_per_host(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        with patch.object(tftp_module, "tftp_rate_limiter", limiter):
            self.proto.lineReceived(b"tftp -c get /tmp/rl1.txt 192.0.2.1\n")
            self.proto.lineReceived(b"tftp -c get /tmp/rl2.txt 192.0.2.2\n")

        # Each host consumed its own single allowance.
        self.assertFalse(limiter.check("192.0.2.1"))
        self.assertFalse(limiter.check("192.0.2.2"))
        self.assertNotIn(b"timed out", self.tr.value())


class TFTPDownloadLimitTests(unittest.TestCase):
    """download_limit_size must actually stop a transfer.

    The limit was declared on the command but never reached the client that
    receives the data, so transfers were unbounded in practice (issue #40394).
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self._orig_artifact_dir = Artifact.artifactDir
        Artifact.artifactDir = self.tmpdir
        self._artifacts: list[Artifact] = []

    def tearDown(self) -> None:
        # Close artifacts while artifactDir still points at the scratch dir,
        # so close() renames into it rather than the configured download path.
        for artifact in self._artifacts:
            artifact.close()
        Artifact.artifactDir = self._orig_artifact_dir
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _client(self, limit_size: int) -> Any:
        from cowrie.commands.tftp import TFTPClient

        artifact = Artifact("tftp-limit")
        self._artifacts.append(artifact)
        client = TFTPClient("127.0.0.1", 69, "f", artifact, limit_size=limit_size)
        # A real transport is only needed for ACKs; record writes instead.
        client.transport = cast("Any", _FakeUDPTransport())
        return client

    def _data_packet(self, block: int, payload: bytes) -> bytes:
        return struct.pack("!HH", OPCODE_DATA, block) + payload

    def test_transfer_over_limit_fails(self) -> None:
        client = self._client(limit_size=600)
        results: list[Any] = []
        client.deferred.addBoth(results.append)

        # Two full blocks: 1024 bytes received against a 600-byte limit.
        client.datagramReceived(
            self._data_packet(1, b"A" * TFTP_BLOCK_SIZE), ("127.0.0.1", 69)
        )
        client.datagramReceived(
            self._data_packet(2, b"B" * TFTP_BLOCK_SIZE), ("127.0.0.1", 69)
        )

        self.assertEqual(len(results), 1, "transfer over the limit did not stop")
        self.assertIsInstance(results[0], Failure)
        self.assertIn("limit", results[0].getErrorMessage().lower())

    def test_transfer_under_limit_completes(self) -> None:
        client = self._client(limit_size=10000)
        results: list[Any] = []
        client.deferred.addBoth(results.append)

        # A short final block completes the transfer.
        client.datagramReceived(self._data_packet(1, b"A" * 10), ("127.0.0.1", 69))

        self.assertEqual(results, [None])

    def test_zero_limit_means_unlimited(self) -> None:
        client = self._client(limit_size=0)
        results: list[Any] = []
        client.deferred.addBoth(results.append)

        client.datagramReceived(
            self._data_packet(1, b"A" * TFTP_BLOCK_SIZE), ("127.0.0.1", 69)
        )
        # Still running: no result yet, and the block was kept.
        self.assertEqual(results, [])
        self.assertEqual(client.bytes_received, TFTP_BLOCK_SIZE)
        if client.timeout_call and client.timeout_call.active():
            client.timeout_call.cancel()

    def test_command_threads_limit_to_client(self) -> None:
        # The command must hand its configured limit to the client, otherwise
        # the enforcement above never runs in production.
        cmd = Command_tftp.__new__(Command_tftp)
        cmd.hostname = "127.0.0.1"
        cmd.host_ip = "127.0.0.1"
        cmd.port = 69
        cmd.file_to_get = "test.sh"
        cmd.limit_size = 1234
        cmd.artifactFile = Artifact("tftp-download")

        d = cmd.tftp_download_async()
        client = cmd.tftp_client
        try:
            assert client is not None
            self.assertEqual(client.limit_size, 1234)
        finally:
            if client and client.timeout_call and client.timeout_call.active():
                client.timeout_call.cancel()
            if cmd.udp_port:
                cmd.udp_port.stopListening()
            d.addErrback(lambda _f: None)
            d.cancel()
            cmd.artifactFile.close()


class _FakeUDPTransport:
    """Records datagrams instead of sending them."""

    def __init__(self) -> None:
        self.written: list[tuple[bytes, Any]] = []

    def write(self, data: bytes, addr: Any = None) -> None:
        self.written.append((data, addr))
