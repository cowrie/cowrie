from __future__ import annotations
import getopt
import re
import socket
import struct


from cowrie.core.config import CowrieConfig
from cowrie.core.network import communication_allowed
from cowrie.shell.command import HoneyPotCommand

long = int

commands = {}


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


class Command_nc(HoneyPotCommand):
    """
    netcat
    """

    s: socket.socket

    def print_usage_error(self, error_msg: str = "") -> None:
        """Print usage error message"""
        if error_msg:
            self.errorWrite(f"nc: {error_msg}\n")

        self.errorWrite("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n")
        self.errorWrite("\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n")
        self.errorWrite("\t  [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]\n")
        self.errorWrite("\t  [-X proxy_protocol] [-x proxy_address[:port]]\t\t  [destination] [port]\n")

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
        self.errorWrite("\t\t-i interval\tDelay interval for lines sent, ports scanned\n")
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
        self.errorWrite("\t\t-W recvlimit\tTerminate after receiving a number of packets\n")
        self.errorWrite("\t\t-w timeout\tTimeout for connects and final net reads\n")
        self.errorWrite("\t\t" '-X proto\tProxy protocol: "4", "5" (SOCKS) or "connect"' "\n")
        self.errorWrite("\t\t-x addr[:port]\tSpecify proxy address and port\n")
        self.errorWrite("\t\t-Z\t\tDCCP mode\n")
        self.errorWrite("\t\t-z\t\tZero-I/O mode [used for scanning]\n")
        self.errorWrite("\tPort numbers can be individual or ranges: lo-hi [inclusive]\n")

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

        if not args or len(args) < 2:
            self.print_usage_error()
            self.exit()
            return

        host = args[0]
        port = args[1]

        if not re.match(r"^\d+$", port):
            self.errorWrite(f"nc: port number invalid: {port}\n")
            self.exit()
            return

        allowed = communication_allowed(host)
        if not allowed:
            self.exit()
            return

        out_addr = None
        try:
            out_addr = (CowrieConfig.get("honeypot", "out_addr"), 0)
        except Exception:
            out_addr = ("0.0.0.0", 0)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(out_addr)
        try:
            self.s.connect((host, int(port)))
            self.recv_data()
        except Exception:
            self.exit()

    def recv_data(self) -> None:
        data = b""
        while 1:
            packet = self.s.recv(1024)
            if packet == b"":
                break
            else:
                data += packet

        self.writeBytes(data)
        self.s.close()
        self.exit()

    def lineReceived(self, line: str) -> None:
        if hasattr(self, "s"):
            self.s.send(line.encode("utf8"))

    def handle_CTRL_C(self) -> None:
        self.write("^C\n")
        if hasattr(self, "s"):
            self.s.close()

    def handle_CTRL_D(self) -> None:
        if hasattr(self, "s"):
            self.s.close()


commands["/bin/nc"] = Command_nc
commands["nc"] = Command_nc
