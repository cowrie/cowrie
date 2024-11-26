# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import getopt
import hashlib
import re
import socket
import time

from twisted.internet import reactor
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

commands = {}


OUTPUT = [
    "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]",
    "           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]",
    "           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]",
    "           [-i identity_file] [-J [user@]host[:port]] [-L address]",
    "           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]",
    "           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]",
    "           [-w local_tun[:remote_tun]] destination [command]",
]


class Command_ssh(HoneyPotCommand):
    """
    ssh
    """

    host: str
    callbacks: list[Callable]

    def valid_ip(self, address: str) -> bool:
        try:
            socket.inet_aton(address)
        except Exception:
            return False
        else:
            return True

    def start(self) -> None:
        try:
            options = "-1246AaCfgKkMNnqsTtVvXxYb:c:D:e:F:i:L:l:m:O:o:p:R:S:w:"
            optlist, args = getopt.getopt(self.args, options)
        except getopt.GetoptError:
            self.write("Unrecognized option\n")
            self.exit()
            return

        for opt in optlist:
            if opt[0] == "-V":
                self.write(
                    CowrieConfig.get(
                        "shell",
                        "ssh_version",
                        fallback="OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018",
                    )
                    + "\n"
                )
                self.exit()
                return
        if not len(args):
            for line in OUTPUT:
                self.write(f"{line}\n")
            self.exit()
            return
        user, host = "root", args[0]
        for opt in optlist:
            if opt[0] == "-l":
                user = opt[1]
        if args[0].count("@"):
            user, host = args[0].split("@", 1)

        if re.match("^[0-9.]+$", host):
            if self.valid_ip(host):
                self.ip = host
            else:
                self.write(
                    f"ssh: Could not resolve hostname {host}: \
                    Name or service not known\n"
                )
                self.exit()
        else:
            s = hashlib.md5(host.encode()).hexdigest()
            self.ip = ".".join(
                [str(int(x, 16)) for x in (s[0:2], s[2:4], s[4:6], s[6:8])]
            )

        self.host = host
        self.user = user

        self.write(
            f"The authenticity of host '{self.host} ({self.ip})' \
            can't be established.\n"
        )
        self.write(
            "RSA key fingerprint is \
            9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.\n"
        )
        self.write("Are you sure you want to continue connecting (yes/no)? ")
        self.callbacks = [self.yesno, self.wait]

    def yesno(self, line: str) -> None:
        self.write(
            f"Warning: Permanently added '{self.host}' (RSA) to the \
            list of known hosts.\n"
        )
        self.write(f"{self.user}@{self.host}'s password: ")
        self.protocol.password_input = True

    def wait(self, line: str) -> None:
        reactor.callLater(2, self.finish, line)  # type: ignore[attr-defined]

    def finish(self, line: str) -> None:
        self.pause = False
        rests = self.host.strip().split(".")
        if len(rests) and rests[0].isalpha():
            host = rests[0]
        else:
            host = "localhost"
        self.protocol.hostname = host
        self.protocol.cwd = "/root"
        if not self.fs.exists(self.protocol.cwd):
            self.protocol.cwd = "/"
        self.protocol.password_input = False
        self.write(
            f"Linux {self.protocol.hostname} 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 \
            UTC 2009 i686\n"
        )
        self.write(f"Last login: {time.ctime(time.time() - 123123)} from 192.168.9.4\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg("INPUT (ssh):", line)
        if len(self.callbacks):
            self.callbacks.pop(0)(line)


commands["/usr/bin/ssh"] = Command_ssh
commands["ssh"] = Command_ssh
