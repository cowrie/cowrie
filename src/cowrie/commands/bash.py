# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# coding=utf-8

from __future__ import annotations

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import HoneyPotShell
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_sh(HoneyPotCommand):
    def call(self) -> None:
        if self.args and self.args[0].strip() == "-c":
            line = " ".join(self.args[1:])

            # it might be sh -c 'echo "sometext"', so don't use line.strip('\'\"')
            if (line[0] == "'" and line[-1] == "'") or (
                line[0] == '"' and line[-1] == '"'
            ):
                line = line[1:-1]

            self.execute_commands(line)

        elif self.input_data:
            self.execute_commands(self.input_data.decode("utf8"))

        else:
            self.interactive_shell()

        # TODO: handle spawning multiple shells, support other sh flags

    def execute_commands(self, cmds: str) -> None:
        # self.input_data holds commands passed via PIPE
        # create new HoneyPotShell for our a new 'sh' shell
        self.protocol.cmdstack.append(HoneyPotShell(self.protocol, interactive=False))

        # call lineReceived method that indicates that we have some commands to parse
        self.protocol.cmdstack[-1].lineReceived(cmds)

        # remove the shell
        self.protocol.cmdstack.pop()

    def interactive_shell(self) -> None:
        log.msg("starting new shell")
        shell = HoneyPotShell(self.protocol, interactive=True)
        shell.environ["SHLVL"] = shell.environ["SHLVL"] + 1
        self.protocol.cmdstack.append(shell)
        self.exit()


commands["/bin/bash"] = Command_sh
commands["bash"] = Command_sh
commands["/bin/sh"] = Command_sh
commands["sh"] = Command_sh
