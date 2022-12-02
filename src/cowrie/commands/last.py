# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import time

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_last(HoneyPotCommand):
    def call(self) -> None:
        line = list(self.args)
        while len(line):
            arg = line.pop(0)
            if not arg.startswith("-"):
                continue
            elif arg == "-n" and len(line) and line[0].isdigit():
                line.pop(0)

        self.write(
            "%-8s %-12s %-16s %s   still logged in\n"
            % (
                self.protocol.user.username,
                "pts/0",
                self.protocol.clientIP,
                time.strftime(
                    "%a %b %d %H:%M", time.localtime(self.protocol.logintime)
                ),
            )
        )

        self.write("\n")
        self.write(
            "wtmp begins {}\n".format(
                time.strftime(
                    "%a %b %d %H:%M:%S %Y",
                    time.localtime(
                        self.protocol.logintime // (3600 * 24) * (3600 * 24) + 63
                    ),
                )
            )
        )


commands["/usr/bin/last"] = Command_last
commands["last"] = Command_last
