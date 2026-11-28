# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_passwd(HoneyPotCommand):
    callbacks: list[Callable]
    passwd: str | None

    def start(self) -> None:
        self.write("Enter new UNIX password: ")
        self.protocol.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None

    def ask_again(self, line: str) -> None:
        self.passwd = line
        self.write("Retype new UNIX password: ")

    def finish(self, line: str) -> None:
        self.protocol.password_input = False

        if line != self.passwd or self.passwd == "*":
            self.write("Sorry, passwords do not match\n")
        else:
            self.write("passwd: password updated successfully\n")
        self.exit()

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.success",
            "INPUT (%(realm)s): %(input)s",
            realm="passwd",
            input=line,
        )
        self.password = line.strip()
        self.callbacks.pop(0)(line)


commands["/usr/bin/passwd"] = Command_passwd
commands["passwd"] = Command_passwd
