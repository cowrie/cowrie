# SPDX-FileCopyrightText: 2017 fe7ch
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import socket
import struct
from typing import TYPE_CHECKING

from twisted.internet import error, reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.protocol import ClientFactory, Protocol, connectionDone
from twisted.logger import Logger

from cowrie.core.config import CowrieConfig
from cowrie.core.network import (
    is_valid_port,
    outbound_bind_address,
    resolve_allowed,
)
from cowrie.core.rate_limiter import RateLimiter
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from twisted.internet.interfaces import IAddress, IConnector, ITransport
    from twisted.python import failure

long = int

commands = {}

# Initialize rate limiter
nc_rate_limiter = RateLimiter(
    enabled=CowrieConfig.getboolean("shell", "nc_rate_limit_enabled", fallback=True),
    max_requests=CowrieConfig.getint("shell", "nc_rate_limit_requests", fallback=5),
    window_seconds=CowrieConfig.getint("shell", "nc_rate_limit_window", fallback=60),
    max_keys=CowrieConfig.getint("shell", "nc_rate_limit_max_hosts", fallback=1000),
)


def makeMask(n: int) -> int:
    """
    return a mask of n bits as a long integer
    """
    return (long(2) << n - 1) - 1


def dottedQuadToNum(ip: str) -> int:
    """
    convert decimal dotted quad string to long integer
    this will throw builtins.OSError on failure
    """
    ip32bit: bytes = socket.inet_aton(ip)
    num: int = struct.unpack("I", ip32bit)[0]
    return num


def networkMask(ip: str, bits: int) -> int:
    """
    Convert a network address to a long integer
    """
    return dottedQuadToNum(ip) & makeMask(bits)


def addressInNetwork(ip: int, net: int) -> int:
    """
    Is an address in a network
    """
    return ip & net == net


class NcClientProtocol(Protocol):
    """
    The outbound TCP connection of an nc session. It runs on the reactor's
    asynchronous event loop, so a slow, silent, or malicious remote peer only
    stalls the one session that connected to it, never the whole honeypot.
    """

    def __init__(self, command: Command_nc) -> None:
        self.command = command

    def connectionMade(self) -> None:
        self.command.connectionEstablished(self)

    def dataReceived(self, data: bytes) -> None:
        self.command.remoteDataReceived(data)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        self.command.remoteConnectionLost()


class NcClientFactory(ClientFactory):
    def __init__(self, command: Command_nc) -> None:
        self.command = command

    def buildProtocol(self, addr: IAddress | None) -> NcClientProtocol:
        return NcClientProtocol(self.command)

    def clientConnectionFailed(
        self, connector: IConnector, reason: failure.Failure
    ) -> None:
        self.command.connectionFailed(reason)


class Command_nc(HoneyPotCommand):
    """
    netcat
    """

    _log = Logger()

    CONNECT_TIMEOUT: float = 10.0  # seconds
    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)

    nc_transport: ITransport | None = None
    received_size: int = 0
    verbose: bool = False
    zero_io: bool = False
    host: str = ""
    port: int = 0

    def print_usage_error(self, error_msg: str = "") -> None:
        """Print usage error message"""
        if error_msg:
            self.errorWrite(f"nc: {error_msg}\n")

        self.errorWrite(
            "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n"
        )
        self.errorWrite(
            "\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n"
        )
        self.errorWrite(
            "\t  [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]\n"
        )
        self.errorWrite(
            "\t  [-X proxy_protocol] [-x proxy_address[:port]]\t\t  [destination] [port]\n"
        )

    def print_help_message(self) -> None:
        self.errorWrite("OpenBSD netcat\n")
        self.print_usage_error()
        self.errorWrite("\tCommand Summary:\n")
        self.errorWrite("\t\t-4\t\tUse IPv4\n")
        self.errorWrite("\t\t-6\t\tUse IPv6\n")
        self.errorWrite("\t\t-b\t\tAllow broadcast\n")
        self.errorWrite("\t\t-C\t\tSend CRLF as line-ending\n")
        self.errorWrite("\t\t-D\t\tEnable the debug socket option\n")
        self.errorWrite("\t\t-d\t\tDetach from stdin\n")
        self.errorWrite("\t\t-F\t\tPass socket fd\n")
        self.errorWrite("\t\t-h\t\tThis help text\n")
        self.errorWrite("\t\t-I length\tTCP receive buffer length\n")
        self.errorWrite(
            "\t\t-i interval\tDelay interval for lines sent, ports scanned\n"
        )
        self.errorWrite("\t\t-k\t\tKeep inbound sockets open for multiple connects\n")
        self.errorWrite("\t\t-l\t\tListen mode, for inbound connects\n")
        self.errorWrite("\t\t-M ttl\t\tOutgoing TTL / Hop Limit\n")
        self.errorWrite("\t\t-m minttl\tMinimum incoming TTL / Hop Limit\n")
        self.errorWrite("\t\t-N\t\tShutdown the network socket after EOF on stdin\n")
        self.errorWrite("\t\t-n\t\tSuppress name/port resolutions\n")
        self.errorWrite("\t\t-O length\tTCP send buffer length\n")
        self.errorWrite("\t\t-P proxyuser\tUsername for proxy authentication\n")
        self.errorWrite("\t\t-p port\t\tSpecify local port for remote connects\n")
        self.errorWrite("\t\t-q secs\t\tquit after EOF on stdin and delay of secs\n")
        self.errorWrite("\t\t-r\t\tRandomize remote ports\n")
        self.errorWrite("\t\t-S\t\tEnable the TCP MD5 signature option\n")
        self.errorWrite("\t\t-s source\tLocal source address\n")
        self.errorWrite("\t\t-T keyword\tTOS value\n")
        self.errorWrite("\t\t-t\t\tAnswer TELNET negotiation\n")
        self.errorWrite("\t\t-U\t\tUse UNIX domain socket\n")
        self.errorWrite("\t\t-u\t\tUDP mode\n")
        self.errorWrite("\t\t-V rtable\tSpecify alternate routing table\n")
        self.errorWrite("\t\t-v\t\tVerbose\n")
        self.errorWrite(
            "\t\t-W recvlimit\tTerminate after receiving a number of packets\n"
        )
        self.errorWrite("\t\t-w timeout\tTimeout for connects and final net reads\n")
        self.errorWrite('\t\t-X proto\tProxy protocol: "4", "5" (SOCKS) or "connect"\n')
        self.errorWrite("\t\t-x addr[:port]\tSpecify proxy address and port\n")
        self.errorWrite("\t\t-Z\t\tDCCP mode\n")
        self.errorWrite("\t\t-z\t\tZero-I/O mode [used for scanning]\n")
        self.errorWrite(
            "\tPort numbers can be individual or ranges: lo-hi [inclusive]\n"
        )

    @inlineCallbacks
    def start(self):
        try:
            _optlist, args = getopt.getopt(
                self.args, "46CDdFhklNnrStUuvZzI:i:M:m:O:P:p:q:s:T:V:W:w:X:x:"
            )
        except getopt.GetoptError as err:
            if "requires argument" in err.msg:
                message = "option requires an argument"
            else:
                message = "invalid option"

            self.print_usage_error(f"{message} -- '{err.opt}'")
            self.exit()
            return

        # Handle help option first - print help and exit immediately
        if "-h" in [o[0] for o in _optlist]:
            self.print_help_message()
            self.exit()
            return

        # Parse relevant options
        listen_mode = False
        source_port = None
        use_udp = False
        use_ipv6 = False
        verbose = False
        zero_io = False

        for o, a in _optlist:
            if o == "-6":
                use_ipv6 = True
            elif o == "-l":
                listen_mode = True
            elif o == "-p":
                source_port = a
            elif o == "-u":
                use_udp = True
            elif o == "-v":
                verbose = True
            elif o == "-z":
                zero_io = True

        # No arguments provided
        if not args:
            if listen_mode:
                if not source_port:
                    # Listen mode requires -p to specify port
                    self.errorWrite("nc: missing port number\n")
                elif not is_valid_port(source_port):
                    # Port specified but invalid
                    self.errorWrite(f"nc: port number invalid: {source_port}\n")
                else:
                    # Valid listen mode request, but not implemented - fake permission denied
                    self.errorWrite("nc: Permission denied\n")
            else:
                # Client mode without any arguments
                self.print_usage_error()
            self.exit()
            return

        # Mixing listen mode with client mode is invalid
        if listen_mode:
            self.print_usage_error()
            self.exit()
            return

        # UDP mode not implemented - fake permission denied
        if use_udp:
            self.errorWrite("nc: Permission denied\n")
            self.exit()
            return

        # IPv6 not supported - simulate unreachable network
        if use_ipv6:
            self.errorWrite("nc: Network is unreachable\n")
            self.exit()
            return

        # Client mode requires host and port
        if len(args) < 2:
            self.errorWrite("nc: missing port number\n")
            self.exit()
            return

        host = args[0]
        port = args[1]

        if not is_valid_port(port):
            self.errorWrite(f"nc: port number invalid: {port}\n")
            self.exit()
            return

        # Check rate limit before proceeding
        if not nc_rate_limiter.check(host):
            self._log.info(
                "nc: rate limit exceeded for host: {host}. Simulating operation timeout",
                host=host,
            )
            if verbose:
                self.errorWrite(
                    f"nc: connect to {host} port {port} (tcp) failed: Operation timed out\n"
                )
            self.exit()
            return

        resolved_ip = yield resolve_allowed(host)
        if resolved_ip is None:
            self._log.info(
                "nc: blocked connection attempt to {host} (unresolvable or private/reserved address)",
                host=host,
            )
            self.exit()
            return

        self.host = host
        self.port = int(port)
        self.verbose = verbose
        self.zero_io = zero_io

        # Connect to the IP resolve_allowed() validated, not to the hostname:
        # re-resolving the hostname here would reopen the DNS-rebinding window
        # that resolve_allowed() closed.
        reactor.connectTCP(
            resolved_ip,
            self.port,
            NcClientFactory(self),
            timeout=self.CONNECT_TIMEOUT,
            bindAddress=(outbound_bind_address(), 0),
        )

    def connectionEstablished(self, protocol: NcClientProtocol) -> None:
        if self.exited:
            # The connection completed after the command was already
            # interrupted (^C or EOF while still connecting): tear it down.
            if protocol.transport is not None:
                protocol.transport.loseConnection()
            return
        self.nc_transport = protocol.transport
        if self.verbose:
            self.errorWrite(
                f"Connection to {self.host} {self.port} port [tcp/*] succeeded!\n"
            )
        # Zero I/O mode: test connection only, no data transfer
        if self.zero_io:
            if self.nc_transport is not None:
                self.nc_transport.loseConnection()
            self.exit()

    def remoteDataReceived(self, data: bytes) -> None:
        if self.exited:
            return
        self.received_size += len(data)
        if self.limit_size > 0 and self.received_size > self.limit_size:
            self._log.info(
                "nc: connection to {host}:{port} closed: exceeded download_limit_size",
                host=self.host,
                port=self.port,
            )
            if self.nc_transport is not None:
                self.nc_transport.loseConnection()
            self.exit()
            return
        self.writeBytes(data)

    def remoteConnectionLost(self) -> None:
        self.nc_transport = None
        self.exit()

    def connectionFailed(self, reason: failure.Failure) -> None:
        if self.verbose:
            if reason.check(error.TimeoutError):
                self.errorWrite(
                    f"nc: connect to {self.host} port {self.port} (tcp) failed: Operation timed out\n"
                )
            else:
                self.errorWrite(
                    f"nc: connect to {self.host} port {self.port} (tcp) failed: Connection refused\n"
                )
        self.exit()

    def lineReceived(self, line: str) -> None:
        if self.nc_transport is not None:
            self.nc_transport.write(line.encode("utf8", errors="replace"))

    def handle_CTRL_C(self) -> None:
        self.write("^C\n")
        if self.nc_transport is not None:
            self.nc_transport.loseConnection()
        self.exit()

    def eofReceived(self) -> None:
        if self.nc_transport is not None:
            self.nc_transport.loseConnection()
        self.exit()


commands["/bin/nc"] = Command_nc
commands["nc"] = Command_nc
commands["/usr/bin/nc"] = Command_nc
commands["netcat"] = Command_nc
commands["/bin/netcat"] = Command_nc
