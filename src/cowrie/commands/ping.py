# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getopt
import hashlib
import random
import re
import socket
from typing import Any

from twisted.internet import reactor

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_ping(HoneyPotCommand):
    """
    ping command
    """

    host: str
    ip: str
    count: int
    max: int
    running: bool
    scheduled: Any

    def valid_ip(self, address: str) -> bool:
        try:
            socket.inet_aton(address)
            return True
        except Exception:
            return False

    def start(self) -> None:
        self.host = ""
        self.max = 0
        self.running = False

        try:
            optlist, args = getopt.gnu_getopt(self.args, "c:")
        except getopt.GetoptError as err:
            self.write(f"ping: {err}\n")
            self.exit()
            return

        for opt in optlist:
            if opt[0] == "-c":
                try:
                    self.max = int(opt[1])
                except Exception:
                    self.max = 0
                if self.max <= 0:
                    self.write("ping: bad number of packets to transmit.\n")
                    self.exit()
                    return

        if len(args) == 0:
            for line in (
                "Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]",
                "            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]",
                "            [-M mtu discovery hint] [-S sndbuf]",
                "            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination",
            ):
                self.write(f"{line}\n")
            self.exit()
            return
        self.host = args[0].strip()

        if re.match("^[0-9.]+$", self.host):
            if self.valid_ip(self.host):
                self.ip = self.host
            else:
                self.write(f"ping: unknown host {self.host}\n")
                self.exit()
        else:
            s = hashlib.md5((self.host).encode("utf-8")).hexdigest()
            self.ip = ".".join(
                [str(int(x, 16)) for x in (s[0:2], s[2:4], s[4:6], s[6:8])]
            )

        self.running = True
        self.write(f"PING {self.host} ({self.ip}) 56(84) bytes of data.\n")
        self.scheduled = reactor.callLater(0.2, self.showreply)  # type: ignore[attr-defined]
        self.count = 0

    def showreply(self) -> None:
        ms = 40 + random.random() * 10
        self.write(
            "64 bytes from {} ({}): icmp_seq={} ttl=50 time={:.1f} ms\n".format(
                self.host, self.ip, self.count + 1, ms
            )
        )
        self.count += 1
        if self.count == self.max:
            self.running = False
            self.write("\n")
            self.printstatistics()
            self.exit()
        else:
            self.scheduled = reactor.callLater(1, self.showreply)  # type: ignore[attr-defined]

    def printstatistics(self) -> None:
        self.write(f"--- {self.host} ping statistics ---\n")
        self.write(
            "%d packets transmitted, %d received, 0%% packet loss, time 907ms\n"
            % (self.count, self.count)
        )
        self.write("rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms\n")

    def handle_CTRL_C(self) -> None:
        if self.running is False:
            return HoneyPotCommand.handle_CTRL_C(self)
        else:
            self.write("^C\n")
            self.scheduled.cancel()
            self.printstatistics()
            self.exit()


commands["/bin/ping"] = Command_ping
commands["ping"] = Command_ping
