# Copyright (c) 2019 Nuno Novais <nuno@noais.me>
# All rights reserved.
# All rights given to Cowrie project

"""
This module contains the chpasswd commnad
"""

from __future__ import annotations

import getopt

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_chpasswd(HoneyPotCommand):
    def help(self) -> None:
        output = (
            "Usage: chpasswd [options]",
            "",
            "Options:",
            "  -c, --crypt-method METHOD     the crypt method (one of NONE DES MD5 SHA256 SHA512)",
            "  -e, --encrypted               supplied passwords are encrypted",
            "  -h, --help                    display this help message and exit",
            "  -m, --md5                     encrypt the clear text password using",
            "                                the MD5 algorithm"
            "  -R, --root CHROOT_DIR         directory to chroot into"
            "  -s, --sha-rounds              number of SHA rounds for the SHA*"
            "                                crypt algorithms",
        )
        for line in output:
            self.write(line + "\n")

    def chpasswd_application(self, contents: bytes) -> None:
        c = 1
        try:
            for line in contents.split(b"\n"):
                if len(line):
                    u, p = line.split(b":")
                    if not len(p):
                        self.write(f"chpasswd: line {c}: missing new password\n")
                    else:
                        pass
                        """
                        TODO:
                            - update shadow file
                            - update userDB.txt (???)
                            - updte auth_random.json (if in use)
                        """
                c += 1
        except Exception:
            self.write(f"chpasswd: line {c}: missing new password\n")

    def start(self) -> None:
        try:
            opts, args = getopt.getopt(
                self.args,
                "c:ehmr:s:",
                ["crypt-method", "encrypted", "help", "md5", "root", "sha-rounds"],
            )
        except getopt.GetoptError:
            self.help()
            self.exit()
            return

        # Parse options
        for o, a in opts:
            if o in "-h":
                self.help()
                self.exit()
                return
            elif o in "-c":
                if a not in ["NONE", "DES", "MD5", "SHA256", "SHA512"]:
                    self.errorWrite(f"chpasswd: unsupported crypt method: {a}\n")
                    self.help()
                    self.exit()

        if not self.input_data:
            pass
        else:
            self.chpasswd_application(self.input_data)
            self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="chpasswd",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        self.chpasswd_application(line.encode())

    def handle_CTRL_D(self) -> None:
        self.exit()


commands["/usr/sbin/chpasswd"] = Command_chpasswd
commands["chpasswd"] = Command_chpasswd
