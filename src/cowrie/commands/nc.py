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

    def help(self) -> None:
        self.write(
            """This is nc from the netcat-openbsd package. An alternative nc is available
in the netcat-traditional package.
usage: nc [-46bCDdhjklnrStUuvZz] [-I length] [-i interval] [-O length]
          [-P proxy_username] [-p source_port] [-q seconds] [-s source]
          [-T toskeyword] [-V rtable] [-w timeout] [-X proxy_protocol]
          [-x proxy_address[:port]] [destination] [port]\n"""
        )

    def start(self):
        try:
            optlist, args = getopt.getopt(
                self.args, "46bCDdhklnrStUuvZzI:i:O:P:p:q:s:T:V:w:X:x:"
            )
        except getopt.GetoptError:
            self.help()
            self.exit()
            return

        if not args or len(args) < 2:
            self.help()
            self.exit()
            return

        host = args[0]
        port = args[1]

        if not re.match(r"^\d+$", port):
            self.errorWrite(f"nc: port number invalid: {port}\n")
            self.exit()
            return

        allowed = yield communication_allowed(host)
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
