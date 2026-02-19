# ABOUTME: Implements bash/sh shell command for cowrie honeypot.
# ABOUTME: Handles -c flags, piped input, script file execution, and interactive shells.

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from twisted.internet import error
from twisted.python import failure

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound
from cowrie.shell.honeypot import HoneyPotShell

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}

MAX_SCRIPT_DEPTH = 5
_SHEBANG_RE = re.compile(r"^#!\s*/bin/(ba)?sh")


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
        depth = getattr(self.protocol, "_script_depth", 0)
        if depth >= MAX_SCRIPT_DEPTH:
            self.errorWrite(f"-bash: {filename}: too many levels of recursion\n")
            return

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        try:
            contents = self.fs.file_contents(path)
        except (FileNotFound, FileNotFoundError):
            self.errorWrite(f"bash: {filename}: No such file or directory\n")
            return

        lines = contents.decode("utf-8", errors="replace").splitlines()
        # Strip shebang line
        if lines and _SHEBANG_RE.match(lines[0]):
            lines = lines[1:]
        # Strip comment-only lines and blank lines
        lines = [line for line in lines if line.strip() and not line.strip().startswith("#")]

        if not lines:
            return

        self.protocol._script_depth = depth + 1
        try:
            self.execute_commands("; ".join(lines))
        finally:
            self.protocol._script_depth = depth

    def execute_commands(self, cmds: str) -> None:
        # self.input_data holds commands passed via PIPE
        # create new HoneyPotShell for our a new 'sh' shell
        self.protocol.cmdstack.append(HoneyPotShell(self.protocol, interactive=False))

        # call lineReceived method that indicates that we have some commands to parse
        self.protocol.cmdstack[-1].lineReceived(cmds)

        # remove the shell
        self.protocol.cmdstack.pop()

    def interactive_shell(self) -> None:
        shell = HoneyPotShell(self.protocol, interactive=True)
        parentshell = self.protocol.cmdstack[-2]
        # TODO: copy more variables, but only exported variables
        try:
            shell.environ["SHLVL"] = str(int(parentshell.environ["SHLVL"]) + 1)
        except KeyError:
            shell.environ["SHLVL"] = "1"
        self.protocol.cmdstack.append(shell)
        self.protocol.cmdstack.remove(self)


commands["/bin/bash"] = Command_sh
commands["bash"] = Command_sh
commands["/bin/sh"] = Command_sh
commands["sh"] = Command_sh


class Command_exit(HoneyPotCommand):
    def call(self) -> None:
        # this removes the second last command, which is the shell
        self.protocol.cmdstack.pop(-2)
        if len(self.protocol.cmdstack) < 2:
            stat = failure.Failure(error.ProcessDone(status=""))
            self.protocol.terminal.transport.processEnded(stat)


commands["exit"] = Command_exit
commands["logout"] = Command_exit
