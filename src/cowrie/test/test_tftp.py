# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
# mypy: disable-error-code="var-annotated,attr-defined,return-value"

from __future__ import annotations

import os
import struct
import unittest

from twisted.internet import defer, reactor
from twisted.internet.protocol import DatagramProtocol

from cowrie.commands.tftp import (
    OPCODE_ACK,
    OPCODE_DATA,
    OPCODE_ERROR,
    OPCODE_RRQ,
    TFTP_BLOCK_SIZE,
)
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class MockTFTPServer(DatagramProtocol):
    """Mock TFTP server for testing"""

    def __init__(self, test_file_content: bytes = b"Test file content\n"):
        self.test_file_content = test_file_content
        self.client_addr: tuple[str, int] | None = None

    def datagramReceived(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle TFTP packets"""
        if len(data) < 2:
            return

        opcode = struct.unpack("!H", data[:2])[0]

        if opcode == OPCODE_RRQ:
            # Read request - send data back
            self.client_addr = addr
            self.sendFile()
        elif opcode == OPCODE_ACK:
            # ACK received - if not final ACK, send next block
            block_num = struct.unpack("!H", data[2:4])[0]
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
        d = defer.Deferred()

        def do_test():
            self.proto.lineReceived(b"tftp hostname.com\n")

            def check():
                output = self.tr.value()
                self.assertIn(b"usage: tftp", output)
                d.callback(None)

            reactor.callLater(0.1, check)

        reactor.callLater(0, do_test)
        return d

    def test_tftp_invalid_directory(self) -> None:
        """Test tftp with invalid local directory"""
        d = defer.Deferred()

        def do_test():
            self.proto.lineReceived(b"tftp -c get /nonexistent/file.txt host.com\n")

            def check():
                output = self.tr.value()
                self.assertIn(b"No such file or directory", output)
                d.callback(None)

            reactor.callLater(0.1, check)

        reactor.callLater(0, do_test)
        return d


class ShellTftpAsyncTests(unittest.TestCase):
    """Async tests for TFTP with mock server"""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")
    tftp_port: int
    tftp_server = None
    test_content = b"Test file from TFTP server\n"

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

        # Setup mock TFTP server
        server_protocol = MockTFTPServer(cls.test_content)
        cls.tftp_server = reactor.listenUDP(0, server_protocol, interface="127.0.0.1")
        cls.tftp_port = cls.tftp_server.getHost().port

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()
        if cls.tftp_server:
            cls.tftp_server.stopListening()

    def setUp(self) -> None:
        self.tr.clear()

    def test_successful_download(self) -> None:
        """Test successful TFTP download"""
        cmd = f"tftp -c get /tmp/tftp_test.txt 127.0.0.1:{self.tftp_port}\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Should complete and show prompt
            self.assertIn(PROMPT, output)
            # Should not show error
            self.assertNotIn(b"tftp: TFTP Error", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_download_with_r_flag(self) -> None:
        """Test TFTP download with -r flag"""
        cmd = f"tftp -r /tmp/tftp_test2.txt -g 127.0.0.1:{self.tftp_port}\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            self.assertIn(PROMPT, output)
            self.assertNotIn(b"tftp: TFTP Error", output)
            d.callback(None)

        reactor.callLater(1.0, check)
        return d

    def test_connection_refused(self) -> None:
        """Test TFTP with unreachable host"""
        # Use non-routable IP
        cmd = b"tftp -c get /tmp/test.txt 192.0.2.1\n"
        self.proto.lineReceived(cmd)

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            # Should show error or timeout
            self.assertIn(PROMPT, output)
            d.callback(None)

        # Give it time to timeout
        reactor.callLater(6.0, check)
        return d

    def test_non_blocking_behavior(self) -> None:
        """Test that TFTP download doesn't block the reactor"""
        # Start TFTP download
        cmd = f"tftp -c get /tmp/nonblock.txt 127.0.0.1:{self.tftp_port}\n"
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

    def test_large_file_download(self) -> None:
        """Test TFTP download of file larger than one block"""
        # Create a larger test file (2 blocks)
        large_content = b"X" * (TFTP_BLOCK_SIZE * 2 + 100)

        # Create new server with large content
        server_protocol = MockTFTPServer(large_content)
        large_server = reactor.listenUDP(0, server_protocol, interface="127.0.0.1")
        large_port = large_server.getHost().port

        cmd = f"tftp -c get /tmp/large.txt 127.0.0.1:{large_port}\n"
        self.proto.lineReceived(cmd.encode())

        d = defer.Deferred()

        def check():
            output = self.tr.value()
            self.assertIn(PROMPT, output)
            self.assertNotIn(b"tftp: TFTP Error", output)
            large_server.stopListening()
            d.callback(None)

        reactor.callLater(1.5, check)
        return d


class TFTPProtocolTests(unittest.TestCase):
    """Tests for TFTP protocol implementation"""

    def test_rrq_packet_format(self) -> None:
        """Test that RRQ packets are correctly formatted"""
        from cowrie.commands.tftp import MODE_OCTET, OPCODE_RRQ

        filename = "test.txt"
        packet = struct.pack("!H", OPCODE_RRQ)
        packet += filename.encode() + b"\x00"
        packet += MODE_OCTET + b"\x00"

        # Verify packet structure
        opcode = struct.unpack("!H", packet[:2])[0]
        self.assertEqual(opcode, OPCODE_RRQ)
        self.assertIn(b"test.txt", packet)
        self.assertIn(b"octet", packet)

    def test_ack_packet_format(self) -> None:
        """Test that ACK packets are correctly formatted"""
        block_num = 5
        packet = struct.pack("!HH", OPCODE_ACK, block_num)

        # Verify packet structure
        opcode, block = struct.unpack("!HH", packet)
        self.assertEqual(opcode, OPCODE_ACK)
        self.assertEqual(block, 5)

    def test_data_packet_parsing(self) -> None:
        """Test parsing of DATA packets"""
        block_num = 3
        data = b"Hello, TFTP!"
        packet = struct.pack("!HH", OPCODE_DATA, block_num) + data

        # Parse packet
        opcode = struct.unpack("!H", packet[:2])[0]
        block = struct.unpack("!H", packet[2:4])[0]
        content = packet[4:]

        self.assertEqual(opcode, OPCODE_DATA)
        self.assertEqual(block, 3)
        self.assertEqual(content, b"Hello, TFTP!")

    def test_error_packet_parsing(self) -> None:
        """Test parsing of ERROR packets"""
        error_code = 1
        error_msg = "File not found"
        packet = struct.pack("!HH", OPCODE_ERROR, error_code)
        packet += error_msg.encode() + b"\x00"

        # Parse packet
        opcode = struct.unpack("!H", packet[:2])[0]
        code = struct.unpack("!H", packet[2:4])[0]
        msg = packet[4:].rstrip(b"\x00").decode()

        self.assertEqual(opcode, OPCODE_ERROR)
        self.assertEqual(code, 1)
        self.assertEqual(msg, "File not found")
