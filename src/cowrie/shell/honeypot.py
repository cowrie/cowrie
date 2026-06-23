# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import copy
import os
from typing import Any

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.bashparse import (
    BashParser,
    Command,
    Statement,
    Subshell,
    SyntaxError_,
)
from cowrie.shell.parser import CommandParser
from cowrie.shell.pipe import PipeProtocol


class HoneyPotShell:
    def __init__(
        self, protocol: Any, interactive: bool = True, redirect: bool = False
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        self.cmdpending: list[list[str]] = []
        # A nested shell (e.g. a command substitution) inherits the live
        # environment of whichever shell is currently running; the very first
        # shell of a session falls back to the login environment, all of which
        # is exported.
        if protocol.cmdstack:
            parent = protocol.cmdstack[-1]
            self.environ: dict[str, str] = copy.copy(parent.environ)
            self.exported: set[str] = copy.copy(parent.exported)
        else:
            self.environ = copy.copy(protocol.environ)
            self.exported = set(protocol.environ.keys())
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])
        self.parser = CommandParser()
        self.bashparser = BashParser(self)

    # -- bashparse.ShellContext interface -----------------------------------

    def get_variable(self, name: str) -> str | None:
        """Look up a shell variable for the Lark word evaluator."""
        return self.environ.get(name)

    def command_substitution(self, source: str) -> str:
        """Run ``source`` as a command substitution and return its captured
        stdout with trailing newlines stripped.

        The inner source is parsed with the same Lark grammar as a top-level
        line; each command runs in its own output-capturing subshell and a
        nested ``(...)`` group recurses.
        """
        return self._capture_statements(self.bashparser.parse(source)).rstrip("\n")

    def _capture_statements(self, statements: list[Statement]) -> str:
        """Run statements in capture mode, concatenating their stdout."""
        output = ""
        for statement in statements:
            if isinstance(statement, Command):
                output += self._capture_command(statement.tokens)
            elif isinstance(statement, Subshell):
                output += self._capture_statements(statement.statements)
        return output

    def lineReceived(self, line: str) -> None:
        """Parse a command line with the Lark grammar and run the result."""
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
        self._queue_statements(self.bashparser.parse(line))

        if self.cmdpending:
            # Coalesce fd redirection tokens so we don't treat `2` as a command.
            self.cmdpending = [
                self.parser.merge_redirection_tokens(tokens)
                for tokens in self.cmdpending
            ]
            self.runCommand()
        else:
            self.showPrompt()

    def _queue_statements(self, statements: list[Statement]) -> bool:
        """Append parsed statements to ``cmdpending`` for sequential execution.

        A subshell's inner statements are flattened into the queue in place so
        they run in order with the surrounding commands. Cowrie does not
        emulate a subshell's isolated environment (``cwd`` and friends live on
        the protocol, not the shell), so flattening matches bash's output
        ordering without a separate captured-output pass.

        Returns False to stop queueing after a syntax error: commands already
        queued before the error still run, as in bash.
        """
        for statement in statements:
            if isinstance(statement, Command):
                self.cmdpending.append(statement.tokens)
            elif isinstance(statement, Subshell):
                if not self._queue_statements(statement.statements):
                    return False
            elif isinstance(statement, SyntaxError_):
                if statement.token:
                    self.protocol.terminal.write(
                        f"-bash: syntax error near unexpected token `{statement.token}'\n".encode()
                    )
                else:
                    self.protocol.terminal.write(
                        b"-bash: syntax error: unexpected end of file\n"
                    )
                return False
        return True

    def _capture_command(self, tokens: list[str]) -> str:
        """Run one parsed command in an output-capturing subshell and return
        its stdout.

        Used for command substitution, where the output becomes a word instead
        of reaching the terminal. The already-parsed tokens run directly, so no
        quoting or expansion is repeated.
        """
        shell = HoneyPotShell(self.protocol, interactive=False, redirect=True)
        self.protocol.cmdstack.append(shell)
        shell.cmdpending.append(self.parser.merge_redirection_tokens(tokens))
        shell.runCommand()
        res = self.protocol.cmdstack.pop()

        try:
            output: str = res.protocol.pp.redirected_data.decode()
        except AttributeError:
            return ""
        else:
            return output

    def runCommand(self):
        pp = None

        def runOrPrompt() -> None:
            if self.cmdpending:
                self.runCommand()
            else:
                self.showPrompt()

        if not self.cmdpending:
            if self.protocol.pp.next_command is None:  # command dont have pipe(s)
                if self.interactive:
                    self.showPrompt()
                else:
                    # when commands passed to a shell via PIPE, we spawn a HoneyPotShell in none interactive mode
                    # if there are another shells on stack (cmdstack), let's just exit our new shell
                    # else close connection
                    if len(self.protocol.cmdstack) == 1:
                        ret = failure.Failure(error.ProcessDone(status=""))
                        self.protocol.terminal.transport.processEnded(ret)
                    else:
                        return
            else:
                pass  # command with pipes
            return

        cmdAndArgs = self.cmdpending.pop(0)

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_tokens: list[str] = []
        cmd_array: list[dict[str, Any]] = []
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count("="):
                key, val = piece.split("=", 1)
                environ[key] = val
                continue
            cmd_tokens = [piece, *cmdAndArgs]
            break

        if not cmd_tokens:
            # A statement of only assignments (no command) persists those
            # variables for the rest of the session. They are shell variables,
            # not exported, so self.exported is left untouched.
            self.environ = environ
            runOrPrompt()
            return

        pipe_indices = [i for i, x in enumerate(cmd_tokens) if x == "|"]
        multipleCmdArgs: list[list[str]] = []
        pipe_indices.append(len(cmd_tokens))
        start = 0

        # Gather all arguments with pipes

        for _index, pipe_indice in enumerate(pipe_indices):
            multipleCmdArgs.append(cmd_tokens[start:pipe_indice])
            start = pipe_indice + 1

        first_args, first_ops = self.parser.parse_redirections(multipleCmdArgs.pop(0))
        if not first_args:
            if first_ops:
                # Handle redirection without command (e.g. > file)
                pp = PipeProtocol(
                    self.protocol,
                    None,
                    [],
                    None,
                    None,
                    self.redirect,
                    first_ops,
                )
                # This triggers _setup_redirections which creates files
            runOrPrompt()
            return

        cmd_array.append(
            {
                "command": first_args.pop(0),
                "rargs": first_args,
                "redirects": first_ops,
            }
        )

        for cmd_args in multipleCmdArgs:
            args, ops = self.parser.parse_redirections(cmd_args)
            if not args:
                continue
            cmd_array.append(
                {
                    "command": args.pop(0),
                    "rargs": args,
                    "redirects": ops,
                }
            )

        lastpp = None
        cmdclass = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            cmdclass = self.protocol.getCommand(
                cmd["command"], environ.get("PATH", "").split(":")
            )
            if cmdclass:
                log.msg(
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command found: %(input)s",
                )
                if index == len(cmd_array) - 1:
                    lastpp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        None,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    pp = lastpp
                else:
                    pp = PipeProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        lastpp,
                        self.redirect,
                        cmd.get("redirects", []),
                    )
                    lastpp = pp
            else:
                log.msg(
                    eventid="cowrie.command.failed",
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command not found: %(input)s",
                )
                message = self.command_not_found_message(cmd["command"]).encode("utf8")
                redirects = cmd.get("redirects", [])
                if redirects:
                    temp_pp = PipeProtocol(
                        self.protocol,
                        None,
                        [],
                        None,
                        None,
                        self.redirect,
                        redirects,
                    )
                    temp_pp.errReceived(message)
                    for real_path, virtual_path in temp_pp.redirect_real_files:
                        self.protocol.terminal.redirFiles.add((real_path, virtual_path))
                else:
                    self.protocol.terminal.write(message)

                # Import here to avoid circular dependency with protocol module
                from cowrie.shell import protocol

                if (
                    isinstance(self.protocol, protocol.HoneyPotExecProtocol)
                    and not self.cmdpending
                ):
                    exit_status = failure.Failure(error.ProcessDone(status=""))
                    self.protocol.terminal.transport.processEnded(exit_status)

                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            runOrPrompt()
            return

        if pp:
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

    def command_not_found_message(self, cmd: str) -> str:
        """
        Build the error a real shell prints when a command cannot be run.
        For a path-like command (one starting with "." or "/") match bash's
        errno-based messages: an existing directory yields "Is a directory"
        (EISDIR) and a path that does not exist yields "No such file or
        directory" (ENOENT). Anything else yields "command not found".
        """
        if cmd[:1] in (".", "/"):
            path = self.protocol.fs.resolve_path(cmd, self.protocol.cwd)
            if self.protocol.fs.isdir(path):
                return f"-bash: {cmd}: Is a directory\n"
            if not self.protocol.fs.exists(path):
                return f"-bash: {cmd}: No such file or directory\n"
        return f"-bash: {cmd}: command not found\n"

    def resume(self) -> None:
        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()

    def showPrompt(self) -> None:
        if not self.interactive:
            return

        prompt = ""
        if CowrieConfig.has_option("honeypot", "prompt"):
            prompt = CowrieConfig.get("honeypot", "prompt")
            prompt += " "
        else:
            cwd = self.protocol.cwd
            homelen = len(self.protocol.user.avatar.home)
            if cwd == self.protocol.user.avatar.home:
                cwd = "~"
            elif (
                len(cwd) > (homelen + 1)
                and cwd[: (homelen + 1)] == self.protocol.user.avatar.home + "/"
            ):
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{self.protocol.user.username}@{self.protocol.hostname}:{cwd}"
            if not self.protocol.user.uid:
                prompt += "# "  # "Root" user
            else:
                prompt += "$ "  # "Non-Root" user

        self.protocol.terminal.write(prompt.encode("ascii"))
        self.protocol.ps = (prompt.encode("ascii"), b"> ")

    def eofReceived(self) -> None:
        """
        EOF with the shell as the active reader (no command running) logs out.
        """
        log.msg("received eof, logging out")
        status = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(status)

    def handle_CTRL_C(self) -> None:
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_TAB(self) -> None:
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            return

        line: bytes = b"".join(self.protocol.lineBuffer)
        if line[-1:] == b" ":
            clue = ""
        else:
            clue = line.split()[-1].decode("utf8")

        # clue now contains the string to complete or is empty.
        # line contains the buffer as bytes
        basedir = os.path.dirname(clue)
        if basedir and basedir[-1] != "/":
            basedir += "/"

        if not basedir:
            tmppath = self.protocol.cwd
        else:
            tmppath = basedir

        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except Exception:
            return

        if not self.protocol.fs.exists(r):
            return

        files = []
        for x in self.protocol.fs.get_path(r):
            if clue == "":
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if not files:
            return

        # Clear early so we can call showPrompt if needed
        for _i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ""
        if len(files) == 1:
            newbuf = " ".join(
                [*line.decode("utf8").split()[:-1], f"{basedir}{files[0][fs.A_NAME]}"]
            )
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += "/"
            else:
                newbuf += " "
            newbyt = newbuf.encode("utf8")
        else:
            if os.path.basename(clue):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ""
            first = line.decode("utf8").split(" ")[:-1]
            newbuf = " ".join([*first, f"{basedir}{prefix}"])
            newbyt = newbuf.encode("utf8")
            if newbyt == b"".join(self.protocol.lineBuffer):
                self.protocol.terminal.write(b"\n")
                maxlen = max(len(x[fs.A_NAME]) for x in files) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b"\n")
                    self.protocol.terminal.write(
                        file[fs.A_NAME].ljust(maxlen).encode("utf8")
                    )
                    count += 1
                self.protocol.terminal.write(b"\n")
                self.showPrompt()

        self.protocol.lineBuffer = list(iterbytes(newbyt))
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)
