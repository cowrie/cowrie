# SPDX-FileCopyrightText: 2009 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Implements bash/sh shell command for cowrie honeypot.
# ABOUTME: Handles -c flags, piped input, script file execution, and interactive shells.

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand
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
        from cowrie.shell.protocol import HoneyPotExecProtocol

        parentshell = self.protocol.cmdstack[-2]
        if (
            isinstance(self.protocol, HoneyPotExecProtocol)
            and len(self.protocol.cmdstack) == 2
            and self.input_data is None
            and not getattr(self.protocol.pp, "stdin_from_pipe", False)
        ):
            # The shell was exec'd as the SSH command (`ssh host bash`): its
            # stdin is the live channel, so keep reading command lines from it
            # until EOF. A pty request (TERM set by getPty) makes the shell
            # interactive, with a prompt.
            interactive = "TERM" in self.protocol.environ
            reads_stdin = True
            self.protocol.stdin_line_mode = True
        elif not getattr(parentshell, "interactive", True):
            # A sub-shell launched from a non-interactive parent (pipe,
            # redirect, or command substitution) will never have a terminal
            # feeding its stdin, so spawning an interactive shell would leak it
            # on the cmdstack and write a prompt into captured output via
            # showPrompt(). Behave like EOF instead.
            self.exit()
            return
        else:
            interactive = True
            reads_stdin = False
        shell = HoneyPotShell(
            self.protocol, interactive=interactive, reads_stdin=reads_stdin
        )
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
        shell = self.protocol.cmdstack[-2]
        code = getattr(shell, "last_exit_code", 0)
        if self.args:
            try:
                code = int(self.args[0]) & 0xFF
            except ValueError:
                self.errorWrite(
                    f"-bash: exit: {self.args[0]}: numeric argument required\n"
                )
                code = 2
        # The code is the dying shell's final status: whoever launched the
        # shell (sh -c, su -c, a substitution) reads it from last_exit_code.
        shell.last_exit_code = code
        self.exit_code = code
        self.protocol.cmdstack.remove(shell)
        # start() follows with exit(); with the shell gone that either resumes
        # the command that launched it (nested shell) or, on an empty cmdstack
        # (top-level shell), ends the session with this exit_code.


commands["exit"] = Command_exit
commands["logout"] = Command_exit
