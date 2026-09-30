# SPDX-FileCopyrightText: 2009-2010 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import time

from cowrie.shell.command import HoneyPotCommand

commands = {}


def last_date(stamp: float, *, seconds: bool) -> str:
    """A date as util-linux last prints it: the day padded with a space, and
    with seconds and year for the wtmp start."""
    t = time.localtime(stamp)
    text = time.strftime("%a %b ", t) + f"{t.tm_mday:2d}" + time.strftime(" %H:%M", t)
    if seconds:
        text += time.strftime(":%S %Y", t)
    return text


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
            "{:8s} {:12s} {:16s} {}   still logged in\n".format(
                self.user["username"],
                "pts/0",
                self.protocol.clientIP,
                last_date(self.protocol.logintime, seconds=False),
            )
        )

        # wtmp starts at the emulated boot, the same clock uptime reports.
        boot = self.protocol.boot_time()
        self.write("\n")
        self.write(f"wtmp begins {last_date(boot, seconds=True)}\n")


commands["/usr/bin/last"] = Command_last
commands["last"] = Command_last
