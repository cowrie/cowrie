from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from twisted.internet import defer, reactor
from twisted.internet.defer import CancelledError
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.network import communication_allowed
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.customparser import CustomParser, OptionNotFound

if TYPE_CHECKING:
    from twisted.internet.interfaces import IDelayedCall
    from twisted.python.failure import Failure

commands = {}

# TFTP Opcodes (RFC 1350)
OPCODE_RRQ = 1  # Read request
OPCODE_WRQ = 2  # Write request
OPCODE_DATA = 3  # Data packet
OPCODE_ACK = 4  # Acknowledgment
OPCODE_ERROR = 5  # Error packet

# TFTP Error Codes
ERROR_NOT_DEFINED = 0
ERROR_FILE_NOT_FOUND = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_OPERATION = 4
ERROR_UNKNOWN_TID = 5
ERROR_FILE_EXISTS = 6
ERROR_NO_SUCH_USER = 7

# TFTP Transfer modes
MODE_OCTET = b"octet"
MODE_NETASCII = b"netascii"

# Protocol constants
TFTP_BLOCK_SIZE = 512
TFTP_TIMEOUT = 5  # seconds
TFTP_MAX_RETRIES = 3


class TFTPClient(DatagramProtocol):
    """
    Async TFTP client using Twisted's DatagramProtocol
    Implements RFC 1350 TFTP protocol
    """

    def __init__(self, host: str, port: int, filename: str, artifact: Artifact):
        self.host = host
        self.port = port
        self.filename = filename
        self.artifact = artifact
        self.deferred: defer.Deferred[None] = defer.Deferred()
        self.current_block = 0
        self.last_packet = b""
        self.retry_count = 0
        self.timeout_call: IDelayedCall | None = None
        self.bytes_received = 0
        self.server_tid: tuple[str, int] | None = None  # Server's transfer ID (port)

    def startProtocol(self) -> None:
        """Called when protocol starts - send initial RRQ"""
        self.sendRRQ()

    def stopProtocol(self) -> None:
        """Called when protocol stops"""
        if self.timeout_call is not None and self.timeout_call.active():
            self.timeout_call.cancel()

    def sendRRQ(self) -> None:
        """Send Read ReQuest packet"""
        # RRQ format: opcode(2) filename(string) 0 mode(string) 0
        packet = struct.pack("!H", OPCODE_RRQ)
        packet += self.filename.encode() + b"\x00"
        packet += MODE_OCTET + b"\x00"

        self.transport.write(packet, (self.host, self.port))  # type: ignore[union-attr]
        self.scheduleTimeout()

    def sendACK(self, block_num: int) -> None:
        """Send ACKnowledgment packet"""
        # ACK format: opcode(2) block#(2)
        packet = struct.pack("!HH", OPCODE_ACK, block_num)

        # Send to server's TID (not the original port)
        if self.server_tid:
            self.transport.write(packet, self.server_tid)  # type: ignore[union-attr]
        else:
            self.transport.write(packet, (self.host, self.port))  # type: ignore[union-attr]

        self.last_packet = packet
        self.scheduleTimeout()

    def datagramReceived(self, datagram: bytes, addr: tuple[str, int]) -> None:
        """Handle received TFTP packet"""
        if len(datagram) < 4:
            log.msg("TFTP: Received malformed packet (too short)")
            return

        # Extract opcode
        opcode = struct.unpack("!H", datagram[:2])[0]

        # Save server's TID (port) from first response
        if self.server_tid is None:
            self.server_tid = addr

        # Cancel timeout since we got a response
        if self.timeout_call is not None and self.timeout_call.active():
            self.timeout_call.cancel()
        self.retry_count = 0

        if opcode == OPCODE_DATA:
            self.handleDATA(datagram)
        elif opcode == OPCODE_ERROR:
            self.handleERROR(datagram)
        else:
            log.msg(f"TFTP: Unexpected opcode {opcode}")

    def handleDATA(self, packet: bytes) -> None:
        """Handle DATA packet"""
        # DATA format: opcode(2) block#(2) data(0-512 bytes)
        if len(packet) < 4:
            log.msg("TFTP: Malformed DATA packet")
            return

        block_num = struct.unpack("!H", packet[2:4])[0]
        data = packet[4:]

        # Check if this is the expected block
        if block_num == self.current_block + 1:
            self.current_block = block_num
            self.bytes_received += len(data)

            # Write data to artifact
            self.artifact.write(data)

            # Send ACK
            self.sendACK(block_num)

            # Check if this is the last packet (< 512 bytes of data)
            if len(data) < TFTP_BLOCK_SIZE:
                # Transfer complete
                if self.timeout_call is not None and self.timeout_call.active():
                    self.timeout_call.cancel()
                self.deferred.callback(None)
        elif block_num == self.current_block:
            # Duplicate packet, re-send ACK
            self.sendACK(block_num)
        else:
            log.msg(f"TFTP: Out of order block {block_num}, expected {self.current_block + 1}")

    def handleERROR(self, packet: bytes) -> None:
        """Handle ERROR packet"""
        # ERROR format: opcode(2) errorcode(2) errmsg(string) 0
        if len(packet) < 5:
            log.msg("TFTP: Malformed ERROR packet")
            return

        error_code = struct.unpack("!H", packet[2:4])[0]
        error_msg = packet[4:].rstrip(b"\x00").decode("utf-8", errors="replace")

        if self.timeout_call is not None and self.timeout_call.active():
            self.timeout_call.cancel()

        error_text = f"TFTP Error {error_code}: {error_msg}"
        self.deferred.errback(Exception(error_text))

    def scheduleTimeout(self) -> None:
        """Schedule timeout for retransmission"""
        if self.timeout_call is not None and self.timeout_call.active():
            self.timeout_call.cancel()

        self.timeout_call = reactor.callLater(TFTP_TIMEOUT, self.handleTimeout)  # type: ignore[attr-defined]

    def handleTimeout(self) -> None:
        """Handle timeout - retry or fail"""
        self.retry_count += 1

        if self.retry_count >= TFTP_MAX_RETRIES:
            self.deferred.errback(Exception("TFTP: Transfer timed out"))
            return

        # Retransmit last packet
        if self.current_block == 0:
            # Haven't received any data yet, resend RRQ
            self.sendRRQ()
        else:
            # Resend last ACK
            self.sendACK(self.current_block)


class Command_tftp(HoneyPotCommand):
    """
    TFTP command - async implementation using Twisted
    """

    port: int = 69
    hostname: str | None = None
    file_to_get: str
    limit_size = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    artifactFile: Artifact
    tftp_client: TFTPClient | None = None
    fakeoutfile: str
    udp_port: Any | None = None

    def start(self) -> None:
        parser = CustomParser(self)
        parser.prog = "tftp"
        parser.add_argument("hostname", nargs="?", default=None)
        parser.add_argument("-c", nargs=2)
        parser.add_argument("-l", metavar="FILE")  # Local file
        parser.add_argument("-g", action="store_true")  # Get mode (flag)
        parser.add_argument("-p", action="store_true")  # Put mode (flag)
        parser.add_argument("-r", metavar="FILE")  # Remote file

        try:
            args = parser.parse_args(self.args)
        except (OptionNotFound, TypeError):
            # CustomParser.error() raises OptionNotFound incorrectly (missing value arg)
            # Catch both OptionNotFound and TypeError to handle the bug
            self.exit()
            return

        if args.c:
            if len(args.c) > 1:
                self.file_to_get = args.c[1]
                if args.hostname is None:
                    self.exit()
                    return
                self.hostname = args.hostname
        elif args.r:
            self.file_to_get = args.r
            # Hostname is positional argument, not from -g flag
            self.hostname = args.hostname
        else:
            self.write(
                "usage: tftp [-h] [-c C C] [-l L] [-g G] [-p P] [-r R] [hostname]\n"
            )
            self.exit()
            return

        if self.hostname is None:
            self.exit()
            return

        # Parse port from hostname if provided
        if self.hostname.find(":") != -1:
            host, port_str = self.hostname.split(":")
            self.hostname = host
            self.port = int(port_str)

        # Check if communication is allowed
        if not communication_allowed(self.hostname):
            self.exit()
            return

        # Resolve local file path
        self.fakeoutfile = self.fs.resolve_path(self.file_to_get, self.protocol.cwd)
        path = self.fakeoutfile.rsplit("/", 1)[0] if "/" in self.fakeoutfile else "/"

        if not self.fs.exists(path) or not self.fs.isdir(path):
            self.write(
                f"tftp: {self.file_to_get}: No such file or directory\n"
            )
            self.exit()
            return

        # Initialize artifact
        self.artifactFile = Artifact(self.file_to_get)

        # Start async download
        d = self.tftp_download_async()
        # Ensure artifact is always closed, even on error
        d.addBoth(self._ensure_artifact_closed)
        d.addCallback(self._download_success)
        d.addErrback(self._download_error)

    def tftp_download_async(self) -> defer.Deferred[None]:
        """
        Start async TFTP download
        """
        assert self.hostname is not None  # Checked in start()

        # Create TFTP client
        self.tftp_client = TFTPClient(
            self.hostname, self.port, self.file_to_get, self.artifactFile
        )

        # Listen on random UDP port
        self.udp_port = reactor.listenUDP(0, self.tftp_client)  # type: ignore[attr-defined]

        # Clean up port when done
        def cleanup(result: Any) -> Any:
            if self.udp_port:
                self.udp_port.stopListening()
            return result

        self.tftp_client.deferred.addBoth(cleanup)
        return self.tftp_client.deferred

    def _ensure_artifact_closed(self, result: Any) -> Any:
        """Ensure artifact file handle is closed - called via addBoth"""
        # Close the underlying file handle if still open
        if hasattr(self.artifactFile, "fp") and not self.artifactFile.fp.closed:
            try:
                self.artifactFile.fp.close()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        return result

    def _download_success(self, _result: None) -> None:
        """Called when download completes successfully"""
        # Artifact.close() processes the file (hashing, renaming)
        # The file handle is already closed by _ensure_artifact_closed
        try:
            self.artifactFile.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # Already closed or empty file

        url = f"tftp://{self.hostname}:{self.port}/{self.file_to_get.lstrip('/')}"

        # Log to cowrie.log
        log.msg(
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=url,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
        )

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download",
            format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=url,
            outfile=self.artifactFile.shasumFilename,
            shasum=self.artifactFile.shasum,
            destfile=self.file_to_get,
        )

        # Update honeyfs
        size = self.tftp_client.bytes_received if self.tftp_client else 0
        self.fs.mkfile(
            self.fakeoutfile,
            self.protocol.user.uid,
            self.protocol.user.gid,
            size,
            33188,
        )

        # Update the honeyfs to point to downloaded file
        self.fs.update_realfile(
            self.fs.getfile(self.fakeoutfile), self.artifactFile.shasumFilename
        )
        self.fs.chown(
            self.fakeoutfile, self.protocol.user.uid, self.protocol.user.gid
        )

        self._safe_exit()

    def _download_error(self, failure: Failure) -> None:
        """Called when download fails"""
        # File handle already closed by _ensure_artifact_closed
        # Just clean up the temp file if it exists
        try:
            self.artifactFile.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # Already closed or empty file

        # Check if this is a cancellation (from CTRL-C)
        if failure.check(CancelledError):
            # User cancelled with CTRL-C, exit silently (^C already printed)
            return

        error_msg = failure.getErrorMessage()
        url = f"tftp://{self.hostname}:{self.port}/{self.file_to_get.lstrip('/')}"

        log.msg(
            format="Attempt to download file(s) from URL (%(url)s) failed: %(error)s",
            url=url,
            error=error_msg,
        )

        self.protocol.logDispatch(
            eventid="cowrie.session.file_download.failed",
            format="Attempt to download file(s) from URL (%(url)s) failed",
            url=url,
        )

        self.write(f"tftp: {error_msg}\n")
        self._safe_exit()

    def _safe_exit(self) -> None:
        """Safely exit command, handling case where already removed from cmdstack"""
        try:
            self.exit()
        except ValueError:
            # Already removed from cmdstack
            pass

    def handle_CTRL_C(self) -> None:
        """Handle CTRL-C interruption - cancel TFTP transfer"""
        log.msg("TFTP: Received CTRL-C, canceling transfer")

        # Cancel timeout if active
        if self.tftp_client and self.tftp_client.timeout_call:
            if self.tftp_client.timeout_call.active():
                self.tftp_client.timeout_call.cancel()

        # Close artifact file
        if hasattr(self, "artifactFile"):
            try:
                if hasattr(self.artifactFile, "fp") and not self.artifactFile.fp.closed:
                    self.artifactFile.fp.close()
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        # Cancel the deferred - this will trigger cleanup callback which stops UDP port
        if self.tftp_client:
            if self.tftp_client.deferred and not self.tftp_client.deferred.called:
                self.tftp_client.deferred.cancel()

        self.write("^C")
        self.exit()


commands["/usr/bin/tftp"] = Command_tftp
commands["tftp"] = Command_tftp
