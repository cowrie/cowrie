# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class SystemGoingDown(HoneyPotCommand):
    """A command that announces the system is going down and, a moment
    later, ends the session."""

    def finish(self) -> None:
        self.protocol.end_process(0)

    def handle_CTRL_C(self) -> None:
        # The shutdown is under way; Ctrl-C does not stop it.
        pass


class Command_shutdown(SystemGoingDown):
    def start(self) -> None:
        if self.args and self.args[0].strip().count("--help"):
            output = [
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. ",
                "-r:      reboot after shutdown. ",
                "-h:      halt after shutdown. ",
                "-P:      halt action is to turn off power. ",
                "-H:      halt action is to just halt. ",
                "-f:      do a 'fast' reboot (skip fsck). ",
                "-F:      Force fsck on reboot. ",
                '-n:      do not go through "init" but go down real fast. ',
                "-c:      cancel a running shutdown. ",
                "-t secs: delay between warning and kill signal. ",
                '** the "time" argument is mandatory! (try "now") **',
            ]
            for line in output:
                self.write(f"{line}\n")
            self.exit()
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-h")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for maintenance NOW!\n")
            self.callLater(3, self.finish)
        elif (
            len(self.args) > 1
            and self.args[0].strip().count("-r")
            and self.args[1].strip().count("now")
        ):
            self.write("\n")
            self.write(
                f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n"
            )
            self.write("\n")
            self.write("The system is going down for reboot NOW!\n")
            self.callLater(3, self.finish)
        else:
            self.write("Try `shutdown --help' for more information.\n")
            self.exit()


commands["/sbin/shutdown"] = Command_shutdown
commands["shutdown"] = Command_shutdown
commands["/sbin/poweroff"] = Command_shutdown
commands["poweroff"] = Command_shutdown
commands["/sbin/halt"] = Command_shutdown
commands["halt"] = Command_shutdown


class Command_reboot(SystemGoingDown):
    def start(self) -> None:
        self.write("\n")
        self.write(
            f"Broadcast message from root@{self.protocol.hostname} (pts/0) ({time.ctime()}):\n\n"
        )
        self.write("The system is going down for reboot NOW!\n")
        self.callLater(3, self.finish)


commands["/sbin/reboot"] = Command_reboot
commands["reboot"] = Command_reboot
