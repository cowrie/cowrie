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
from cowrie.shell.command import process_status
from cowrie.shell.parser import CommandParser
from cowrie.shell.pipe import PipeProtocol


class HoneyPotShell:
    def __init__(
        self,
        protocol: Any,
        interactive: bool = True,
        redirect: bool = False,
        effective_user: dict[str, Any] | None = None,
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        self.effective_user = effective_user  # For su: {uid, gid, username, home}
        # Parsed-but-not-yet-evaluated statements; each is expanded against the
        # live environment only when it is about to run (see runCommand). A
        # subshell stays a single unit here so its &&/|| gate covers the whole
        # group; runCommand splices its statements in only when it runs.
        self.cmdpending: list[Command | Subshell] = []
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
        # Exit status of the most recent command in this shell, for $? and the
        # && / || short-circuit logic.
        self.last_exit_code: int = 0

    # -- bashparse.ShellContext interface -----------------------------------

    def get_variable(self, name: str) -> str | None:
        """Look up a shell variable for the Lark word evaluator."""
        return self.environ.get(name)

    def get_status(self) -> str:
        """Return $? -- the last command's exit status as a string."""
        return str(self.last_exit_code)

    def command_substitution(self, source: str) -> str:
        """Run ``source`` as a command substitution and return its captured
        stdout with trailing newlines stripped.

        The inner source runs in a single capture subshell with the same
        sequencing as a top-level line: a same-line assignment is visible to
        later statements, ``$?`` carries across them, and ``&&`` / ``||``
        short-circuit. A nested ``(...)`` group recurses. Output is captured
        instead of reaching the terminal.
        """
        shell = HoneyPotShell(self.protocol, interactive=False, redirect=True)
        self.protocol.cmdstack.append(shell)
        try:
            return shell._capture_statements(
                self.bashparser.parse(source)
            ).rstrip("\n")
        finally:
            self.protocol.cmdstack.pop()

    def _capture_statements(self, statements: list[Statement]) -> str:
        """Run statements in this capture shell, concatenating their stdout and
        honoring &&/|| short-circuit between them (a subshell's gate covers the
        whole group)."""
        output = ""
        for statement in statements:
            if not isinstance(statement, (Command, Subshell)):
                continue  # ignore a syntax error inside a substitution
            if self._short_circuit(statement.op):
                continue
            if isinstance(statement, Subshell):
                output += self._capture_statements(statement.statements)
            else:
                output += self._capture_command(statement)
        return output

    def lineReceived(self, line: str) -> None:
        """Parse a command line with the Lark grammar and run the result."""
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
        self._queue_statements(self.bashparser.parse(line))
        self._advance()

    def _queue_statements(self, statements: list[Statement]) -> bool:
        """Append parsed statements to ``cmdpending`` for sequential execution.

        A subshell is queued as one unit so its join operator (e.g. the || in
        `x || (a; b)`) gates the whole group; runCommand splices the inner
        statements in only when the group actually runs. Cowrie does not
        emulate a subshell's isolated environment (``cwd`` and friends live on
        the protocol, not the shell), so the inner statements then run in the
        parent shell.

        Returns False to stop queueing after a syntax error: commands already
        queued before the error still run, as in bash.
        """
        for statement in statements:
            if isinstance(statement, SyntaxError_):
                self._report_syntax_error(statement)
                return False
            if isinstance(statement, Subshell) and not self._reject_inner_error(
                statement.statements
            ):
                return False
            self.cmdpending.append(statement)
        return True

    def _reject_inner_error(self, statements: list[Statement]) -> bool:
        """Report a syntax error nested anywhere inside a subshell, since the
        whole line is rejected at parse time. Returns False once reported."""
        for statement in statements:
            if isinstance(statement, SyntaxError_):
                self._report_syntax_error(statement)
                return False
            if isinstance(statement, Subshell) and not self._reject_inner_error(
                statement.statements
            ):
                return False
        return True

    def _report_syntax_error(self, statement: SyntaxError_) -> None:
        """Write the message bash prints for a syntax error and set $? to 2."""
        if statement.token:
            self.protocol.terminal.write(
                f"-bash: syntax error near unexpected token `{statement.token}'\n".encode()
            )
        else:
            self.protocol.terminal.write(
                b"-bash: syntax error: unexpected end of file\n"
            )
        self.last_exit_code = 2  # bash uses 2 for a syntax error

    def _capture_command(self, command: Command) -> str:
        """Run one command in this capture shell and return its captured stdout.

        The command's words are expanded against the capture shell's live
        environment, so it sees inherited and same-substitution variables.
        ``protocol.pp`` is cleared first so a statement that builds no pipe
        (a bare assignment, or a command-not-found) reads as empty output
        rather than re-reading the previous statement's capture.
        """
        self.protocol.pp = None
        self.cmdpending.append(command)
        self.runCommand()
        pp = self.protocol.pp
        return pp.redirected_data.decode() if pp is not None else ""

    def _finish(self) -> None:
        """The command queue is drained: do the shell's idle action.

        An interactive shell shows the next prompt. A top-level non-interactive
        shell (an exec session) ends the process. A nested non-interactive shell
        (a pipe stage or a command-substitution capture) just returns so its
        parent can carry on.
        """
        if self.interactive:
            self.showPrompt()
        elif len(self.protocol.cmdstack) == 1:
            # Top-level non-interactive shell (an exec session): end the process
            # with the last command's status so the SSH channel reports a real
            # exit-status to the client.
            self.protocol.terminal.transport.processEnded(
                process_status(self.last_exit_code)
            )

    def _short_circuit(self, op: str | None) -> bool:
        """Whether a statement joined by ``op`` should be skipped given the last
        command's exit status: ``&&`` after a failure, ``||`` after a success.
        """
        return (op == "&&" and self.last_exit_code != 0) or (
            op == "||" and self.last_exit_code == 0
        )

    def _advance(self) -> None:
        """Run the next queued command, or finish when the queue is drained."""
        if self.cmdpending:
            self.runCommand()
        else:
            self._finish()

    def runCommand(self):
        pp = None

        # Mid-pipeline: an earlier stage just finished but a downstream command
        # has not run yet. Let the pipe machinery drive the rest before touching
        # the next statement -- otherwise `a | b; c` would run c before b and
        # drop b's output.
        if self.protocol.pp is not None and self.protocol.pp.next_command is not None:
            return

        if not self.cmdpending:
            # The queue is drained.
            self._finish()
            return

        command = self.cmdpending.pop(0)

        # && / || short-circuit: skip this statement (or whole group) based on
        # the previous command's exit status, leaving $? unchanged.
        if self._short_circuit(command.op):
            self._advance()
            return

        if isinstance(command, Subshell):
            # The group runs: splice its statements to the front so they run in
            # order. The group's own gate was checked above; each inner
            # statement keeps its own &&/|| relative to its siblings.
            self.cmdpending[0:0] = command.statements
            self._advance()
            return

        # Expand the statement's words against the *current* environment, just
        # before it runs, so a same-line `x=hi; echo $x` sees the value.
        cmdAndArgs = self.bashparser.evaluate(command)

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
            # not exported, so self.exported is left untouched. A bare
            # assignment succeeds, so $? is 0.
            self.environ = environ
            self.last_exit_code = 0
            self._advance()
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
            self._advance()
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

                self.last_exit_code = 127  # command not found
                self._advance()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            self._advance()
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
            # Use effective_user if set (from su), otherwise use session user
            if self.effective_user:
                username = self.effective_user["username"]
                uid = self.effective_user["uid"]
                home = self.effective_user["home"]
            else:
                username = self.protocol.user.username
                uid = self.protocol.user.uid
                home = self.protocol.user.avatar.home

            cwd = self.protocol.cwd
            homelen = len(home)
            if cwd == home:
                cwd = "~"
            elif len(cwd) > (homelen + 1) and cwd[: (homelen + 1)] == home + "/":
                cwd = "~" + cwd[homelen:]

            # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
            # Example: root@svr03:~#     (More of a "Debian" feel)
            prompt = f"{username}@{self.protocol.hostname}:{cwd}"
            if not uid:
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
