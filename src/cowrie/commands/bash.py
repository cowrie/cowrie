# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Implements bash/sh shell command for cowrie honeypot.
# ABOUTME: Handles -c flags, piped input, script file execution, and interactive shells.

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand, process_status
from cowrie.shell.honeypot import HoneyPotShell
from cowrie.shell.script import run_script_file

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_sh(HoneyPotCommand):
    def start(self) -> None:
        if self.args and self.args[0].strip() == "-c":
            line = " ".join(self.args[1:])

            # it might be sh -c 'echo "sometext"', so don't use line.strip('\'\"')
            if (line[0] == "'" and line[-1] == "'") or (
                line[0] == '"' and line[-1] == '"'
            ):
                line = line[1:-1]

            self.execute_commands(line)
            self.exit()

        elif self.input_data:
            self.execute_commands(self.input_data.decode("utf8"))
            self.exit()

        elif self.args and not self.args[0].startswith("-"):
            self.execute_script_file(self.args[0])
            self.exit()

        else:
            self.interactive_shell()

    def execute_script_file(self, filename: str) -> None:
        # bash refuses to run a binary file and reports it the same way for a
        # missing one; the script contents otherwise go straight to the parser.
        path = self.fs.resolve_path(filename, self.protocol.cwd)
        run_script_file(
            self,
            path,
            not_found_message=f"bash: {filename}: No such file or directory\n",
            binary_message=(
                f"bash: {filename}: cannot execute binary file: Exec format error\n"
            ),
        )

    def execute_commands(self, cmds: str) -> None:
        # self.input_data holds commands passed via PIPE
        # create new HoneyPotShell for our a new 'sh' shell
        shell = HoneyPotShell(self.protocol, interactive=False)
        self.protocol.cmdstack.append(shell)

        # call lineReceived method that indicates that we have some commands to parse
        shell.lineReceived(cmds)

        # `bash -c '...'` exits with the status of the last command it ran.
        self.exit_code = shell.last_exit_code

        # The shell removes itself from cmdstack in _finish() once its queue is
        # drained. A pop() here would remove whatever is on top instead, which
        # for a `-c` command that launched an async wget/curl is the in-flight
        # command, not this shell.

    def interactive_shell(self) -> None:
        parentshell = self.protocol.cmdstack[-2]
        # A sub-shell launched from a non-interactive parent (pipe, redirect, or
        # command substitution) will never have a terminal feeding its stdin, so
        # spawning an interactive shell would leak it on the cmdstack and write a
        # prompt into captured output via showPrompt(). Behave like EOF instead.
        if not getattr(parentshell, "interactive", True):
            self.exit()
            return
        shell = HoneyPotShell(self.protocol, interactive=True)
        # TODO: copy more variables, but only exported variables
        try:
            shell.environ["SHLVL"] = str(int(parentshell.environ["SHLVL"]) + 1)
        except KeyError:
            shell.environ["SHLVL"] = "1"
        self.protocol.cmdstack.append(shell)
        self.protocol.cmdstack.remove(self)
        shell.showPrompt()


commands["/bin/bash"] = Command_sh
commands["bash"] = Command_sh
commands["/bin/sh"] = Command_sh
commands["sh"] = Command_sh


class Command_exit(HoneyPotCommand):
    def call(self) -> None:
        # `exit [N]` exits with N, or the last command's status ($?) by default.
        code = getattr(self.protocol.cmdstack[-2], "last_exit_code", 0)
        if self.args:
            try:
                code = int(self.args[0]) & 0xFF
            except ValueError:
                self.errorWrite(
                    f"-bash: exit: {self.args[0]}: numeric argument required\n"
                )
                code = 2
        # this removes the second last command, which is the shell
        self.protocol.cmdstack.pop(-2)
        if len(self.protocol.cmdstack) < 2:
            self.protocol.terminal.transport.processEnded(process_status(code))


commands["exit"] = Command_exit
commands["logout"] = Command_exit
