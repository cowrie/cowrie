# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

import copy
import os
import re
import shlex
import stat
import time
from typing import Any

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs


class HoneyPotShell:
    def __init__(
        self, protocol: Any, interactive: bool = True, redirect: bool = False
    ) -> None:
        self.protocol = protocol
        self.interactive: bool = interactive
        self.redirect: bool = redirect  # to support output redirection
        self.cmdpending: list[list[str]] = []
        self.environ: dict[str, str] = copy.copy(protocol.environ)
        if hasattr(protocol.user, "windowSize"):
            self.environ["COLUMNS"] = str(protocol.user.windowSize[1])
            self.environ["LINES"] = str(protocol.user.windowSize[0])
        self.lexer: shlex.shlex | None = None

        # this is the first prompt after starting
        self.showPrompt()

    def lineReceived(self, line: str) -> None:
        log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")
        self.lexer = shlex.shlex(instream=line, punctuation_chars=True, posix=True)
        # Add these special characters that are not in the default lexer
        self.lexer.wordchars += "@%{}=$:+^,()`"

        tokens: list[str] = []

        while True:
            try:
                tokkie: str | None = self.lexer.get_token()
                # log.msg("tok: %s" % (repr(tok)))

                if tokkie is None:  # self.lexer.eof put None for mypy
                    if tokens:
                        self.cmdpending.append(tokens)
                    break
                else:
                    tok: str = tokkie

                # For now, treat && and || same as ;, just execute without checking return code
                if tok == "&&" or tok == "||":
                    if tokens:
                        self.cmdpending.append(tokens)
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            f"-bash: syntax error near unexpected token `{tok}'\n".encode()
                        )
                        break
                elif tok == ";":
                    if tokens:
                        self.cmdpending.append(tokens)
                        tokens = []
                    continue
                elif tok == "$?":
                    tok = "0"
                elif tok == "(" or (tok.startswith("(") and not tok.startswith("$(")):
                    # Parentheses can only appear at the start of a command, not in the middle
                    if tokens:
                        # Parentheses in the middle of a command line is a syntax error
                        self.protocol.terminal.write(
                            f"-bash: syntax error near unexpected token `{tok}'\\n".encode()
                        )
                        break
                    if tok == "(":
                        self.do_subshell_execution_from_lexer()
                    else:
                        self.do_subshell_execution(tok)
                    continue
                elif "$(" in tok or "`" in tok:
                    tok = self.do_command_substitution(tok)
                elif tok.startswith("${"):
                    envRex = re.compile(r"^\${([_a-zA-Z0-9]+)}$")
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue
                elif tok.startswith("$"):
                    envRex = re.compile(r"^\$([_a-zA-Z0-9]+)$")
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue

                tokens.append(tok)
            except Exception as e:
                self.protocol.terminal.write(
                    b"-bash: syntax error: unexpected end of file\n"
                )
                # Could run runCommand here, but i'll just clear the list instead
                log.msg(f"exception: {e}")
                self.cmdpending = []
                self.showPrompt()
                return

        if self.cmdpending:
            # Coalesce fd redirection tokens so we don't treat `2` as a command
            self.cmdpending = [
                self._merge_redirection_tokens(tokens) for tokens in self.cmdpending
            ]
            # if we have a complete command, go and run it
            self.runCommand()
        else:
            # if there's no command, display a prompt again
            self.showPrompt()

    def _merge_redirection_tokens(self, tokens: list[str]) -> list[str]:
        """
        Combine shlex-split redirection tokens back together.
        Example: ['2', '>', '/dev/null'] -> ['2>', '/dev/null']
        """
        merged: list[str] = []
        i = 0
        while i < len(tokens):
            combined, consumed = self._combine_redir_sequence(tokens, i)
            if combined:
                merged.append(combined)
                i += consumed
                continue
            merged.append(tokens[i])
            i += 1
        return merged

    def _combine_redir_sequence(
        self, tokens: list[str], index: int
    ) -> tuple[str | None, int]:
        """Glue together fd + operator (+ optional ampersand/target) tokens."""
        tok = tokens[index]
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        nxt2 = tokens[index + 2] if index + 2 < len(tokens) else None
        nxt3 = tokens[index + 3] if index + 3 < len(tokens) else None

        if tok.isdigit() and nxt in (">", ">>", ">&"):
            combined = f"{tok}{nxt}"
            if nxt == ">&" and nxt2 not in (None, "|", ";", "&&", "||"):
                return combined + str(nxt2), 3
            if nxt in (">", ">>") and nxt2 == "&":
                if nxt3 not in (None, "|", ";", "&&", "||"):
                    return combined + "&" + str(nxt3), 4
                return combined + "&", 3
            return combined, 2

        if tok in (">", ">>") and nxt == "&":
            return f"{tok}&", 2

        return None, 1

    def _extract_redir_op(
        self, token: str
    ) -> tuple[str | None, int | None, str]:
        """Parse a combined redirection token into (op, fd, inline target)."""
        match = re.match(r"^(\d*)(>>|>&|>|<)(.*)$", token)
        if not match:
            return None, None, ""
        fd_text, op, inline_target = match.groups()
        fd = int(fd_text) if fd_text else None
        return op, fd, inline_target

    def _apply_redirection(
        self,
        op: str,
        fd: int | None,
        inline_target: str,
        next_token: str | None,
        redirects: dict[str, Any],
        cleaned: list[str],
        raw_token: str,
    ) -> int:
        """Handle one redirection token and record it in the redirects dict."""
        if op in (">", ">>"):
            target_fd = 1 if fd is None else fd
            append_flag = op == ">>"
            target = inline_target or next_token
            if target is None:
                cleaned.append(raw_token)
                return 1
            return self._record_file_redir(
                redirects, target_fd, target, append_flag, inline_target
            )

        if op == "<":
            source_fd = 0 if fd is None else fd
            target = inline_target or next_token
            if target is None:
                cleaned.append(raw_token)
                return 1
            if not inline_target:
                return self._set_stdin_redirect(redirects, source_fd, target)
            redirects["stdin"] = {"fd": source_fd, "target": target}
            return 1

        if op == ">&":
            target = inline_target or next_token
            if target is None or not target.isdigit():
                cleaned.append(raw_token)
                return 1
            consume = 1 if inline_target else 2
            source_fd = 1 if fd is None else fd
            redirects["fd_mappings"][source_fd] = int(target)
            return consume

        return 0

    def _record_file_redir(
        self,
        redirects: dict[str, Any],
        target_fd: int,
        target: str,
        append_flag: bool,
        inline_target: str,
    ) -> int:
        """Add a stdout/stderr file redirection entry."""
        redirects["files"].append(
            {"fd": target_fd, "target": target, "append": append_flag}
        )
        return 1 if inline_target else 2

    def _set_stdin_redirect(
        self, redirects: dict[str, Any], source_fd: int, target: str
    ) -> int:
        """Record stdin redirection target."""
        redirects["stdin"] = {"fd": source_fd, "target": target}
        return 2

    def do_command_substitution(self, start_tok: str) -> str:
        """
        this performs command substitution, like replace $(ls) `ls`
        """
        result = ""
        if start_tok[0] == "(":
            # start parsing the (...) expression
            cmd_expr = start_tok
            pos = 1
        elif "$(" in start_tok:
            # split the first token to prefix and $(... part
            dollar_pos = start_tok.index("$(")
            result = start_tok[:dollar_pos]
            cmd_expr = start_tok[dollar_pos:]
            pos = 2
        elif "`" in start_tok:
            # split the first token to prefix and `... part
            backtick_pos = start_tok.index("`")
            result = start_tok[:backtick_pos]
            cmd_expr = start_tok[backtick_pos:]
            pos = 1
        else:
            log.msg(f"failed command substitution: {start_tok}")
            return start_tok

        opening_count = 1
        closing_count = 0

        # parse the remaining tokens and execute subshells
        while opening_count > closing_count:
            if cmd_expr[pos] in (")", "`"):
                # found an end of $(...) or `...`
                closing_count += 1
                if opening_count == closing_count:
                    if cmd_expr[0] == "(":
                        # execute the command in () and print to user
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                    else:
                        # execute the command in $() or `` and return the output
                        result += self.run_subshell_command(cmd_expr[: pos + 1])

                    # check whether there are more command substitutions remaining
                    if pos < len(cmd_expr) - 1:
                        remainder = cmd_expr[pos + 1 :]
                        if "$(" in remainder or "`" in remainder:
                            result = self.do_command_substitution(result + remainder)
                        else:
                            result += remainder
                else:
                    pos += 1
            elif cmd_expr[pos : pos + 2] == "$(":
                # found a new $(...) expression
                opening_count += 1
                pos += 2
            else:
                if opening_count > closing_count and pos == len(cmd_expr) - 1:
                    if self.lexer:
                        tokkie = self.lexer.get_token()
                        if tokkie is None:  # self.lexer.eof put None for mypy
                            break
                        else:
                            cmd_expr = cmd_expr + " " + tokkie
                elif opening_count == closing_count:
                    result += cmd_expr[pos]
                pos += 1

        return result

    def do_subshell_execution_from_lexer(self) -> None:
        """
        Execute a subshell command reading tokens from the lexer until matching closing parenthesis.
        Output goes directly to the terminal.
        """
        cmd_tokens = []
        opening_count = 1
        closing_count = 0

        while opening_count > closing_count:
            if self.lexer is None:
                break
            tok = self.lexer.get_token()
            if tok is None:
                break

            if tok == ")":
                closing_count += 1
                if opening_count == closing_count:
                    break
                else:
                    cmd_tokens.append(tok)
            elif tok == "(":
                opening_count += 1
                cmd_tokens.append(tok)
            else:
                cmd_tokens.append(tok)

        # execute the command and print to terminal
        cmd_str = " ".join(cmd_tokens)
        self.protocol.terminal.write(self.run_subshell_command(f"({cmd_str})").encode())

    def do_subshell_execution(self, start_tok: str) -> None:
        """
        Execute a subshell command (command) without output substitution.
        Output goes directly to the terminal.
        """
        if start_tok[0] == "(":
            cmd_expr = start_tok
            pos = 1
            opening_count = 1
            closing_count = 0

            # parse the remaining tokens to find the matching closing parenthesis
            while opening_count > closing_count:
                if cmd_expr[pos] == ")":
                    closing_count += 1
                    if opening_count == closing_count:
                        # execute the command in () and print to terminal
                        self.protocol.terminal.write(
                            self.run_subshell_command(cmd_expr[: pos + 1]).encode()
                        )
                        break
                    else:
                        pos += 1
                elif cmd_expr[pos] == "(":
                    opening_count += 1
                    pos += 1
                else:
                    if opening_count > closing_count and pos == len(cmd_expr) - 1:
                        if self.lexer:
                            tokkie = self.lexer.get_token()
                            if tokkie is None:  # self.lexer.eof put None for mypy
                                break
                            else:
                                cmd_expr = cmd_expr + " " + tokkie
                    pos += 1

    def run_subshell_command(self, cmd_expr: str) -> str:
        # extract the command from $(...) or `...` or (...) expression
        if cmd_expr.startswith("$("):
            cmd = cmd_expr[2:-1]
        else:
            cmd = cmd_expr[1:-1]

        # For subshells with multiple commands, we need to capture all output
        # Create a custom output accumulator
        if cmd_expr.startswith("("):
            return self._execute_subshell_with_full_output(cmd)
        else:
            # Command substitution - use existing method
            return self._execute_command_substitution(cmd)

    def _execute_subshell_with_full_output(self, cmd: str) -> str:
        """Execute subshell commands and capture ALL output, not just the last command."""
        # Split commands by separators and execute each one
        lexer = shlex.shlex(instream=cmd, punctuation_chars=True, posix=True)
        lexer.wordchars += "@%{}=$:+^,()`"

        accumulated_output = ""
        current_cmd_tokens: list[str] = []

        while True:
            tok = lexer.get_token()
            if tok is None:
                # Process final command
                if current_cmd_tokens:
                    cmd_str = " ".join(current_cmd_tokens)
                    output = self._execute_single_command_with_redirect(cmd_str)
                    accumulated_output += output
                break
            elif tok in (";", "&&", "||"):
                # Process current command and start new one
                if current_cmd_tokens:
                    cmd_str = " ".join(current_cmd_tokens)
                    output = self._execute_single_command_with_redirect(cmd_str)
                    accumulated_output += output
                    current_cmd_tokens = []
                # Note: We're ignoring && and || conditional logic for now
            else:
                current_cmd_tokens.append(tok)

        return accumulated_output

    def _execute_command_substitution(self, cmd: str) -> str:
        """Execute command substitution - should capture all output."""
        # Command substitution should also capture all output from multiple commands
        output = self._execute_subshell_with_full_output(cmd)
        # trailing newlines are stripped for command substitution
        return output.rstrip("\n")

    def _execute_single_command_with_redirect(self, cmd: str) -> str:
        """Execute a single command and return its output."""
        # instantiate new shell with redirect output
        self.protocol.cmdstack.append(
            HoneyPotShell(self.protocol, interactive=False, redirect=True)
        )
        # call lineReceived method that indicates that we have some commands to parse
        self.protocol.cmdstack[-1].lineReceived(cmd)
        # and remove the shell
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

        def parse_arguments(arguments: list[str]) -> list[str]:
            parsed_arguments = []
            for arg in arguments:
                parsed_arguments.append(arg)

            return parsed_arguments

        def parse_file_arguments(arguments: str) -> list[str]:
            """
            Look up arguments in the file system
            """
            parsed_arguments = []
            for arg in arguments:
                matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
                if matches:
                    parsed_arguments.extend(matches)
                else:
                    parsed_arguments.append(arg)

            return parsed_arguments

        def parse_redirections(
            arguments: list[str],
        ) -> tuple[list[str], dict[str, Any]]:
            cleaned: list[str] = []
            redirects: dict[str, Any] = {
                "files": [],
                "fd_mappings": {},
                "stdin": None,
                "has_redirections": False,
            }

            i = 0
            while i < len(arguments):
                tok = arguments[i]
                op, fd, inline_target = self._extract_redir_op(tok)
                consume = 1

                if not op and tok in (">", ">>", "<", ">&"):
                    op = tok

                if op:
                    next_token = arguments[i + 1] if (i + 1) < len(arguments) else None
                    consumed = self._apply_redirection(
                        op,
                        fd,
                        inline_target,
                        next_token,
                        redirects,
                        cleaned,
                        tok,
                    )
                    if consumed:
                        i += consumed
                        continue

                cleaned.append(tok)
                i += consume

            redirects["has_redirections"] = bool(
                redirects["files"] or redirects["fd_mappings"] or redirects["stdin"]
            )
            return cleaned, redirects

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
        cmd2 = copy.copy(cmdAndArgs)

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_tokens: list[str] = []
        cmd_array = []
        cmd: dict[str, Any] = {}
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count("="):
                key, val = piece.split("=", 1)
                environ[key] = val
                continue
            cmd_tokens = [piece, *cmdAndArgs]
            break

        if not cmd_tokens:
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

        first_args, first_redirects = parse_redirections(multipleCmdArgs.pop(0))
        if not first_args:
            runOrPrompt()
            return

        cmd_array.append(
            {
                "command": first_args.pop(0),
                "rargs": parse_arguments(first_args),
                "redirects": first_redirects,
            }
        )

        for value in multipleCmdArgs:
            if not value:  # Skip empty command lists
                continue
            cleaned_args, redirects = parse_redirections(value)
            if not cleaned_args:
                continue
            cmd["command"] = cleaned_args.pop(0)
            cmd["rargs"] = parse_arguments(cleaned_args)
            cmd["redirects"] = redirects
            cmd_array.append(cmd)
            cmd = {}

        lastpp = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            cmdclass = self.protocol.getCommand(
                cmd["command"], environ["PATH"].split(":")
            )
            if cmdclass:
                log.msg(
                    input=cmd["command"] + " " + " ".join(cmd["rargs"]),
                    format="Command found: %(input)s",
                )
                if index == len(cmd_array) - 1:
                    lastpp = StdOutStdErrEmulationProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        None,
                        self.redirect,
                        cmd.get("redirects", {}),
                    )
                    pp = lastpp
                else:
                    pp = StdOutStdErrEmulationProtocol(
                        self.protocol,
                        cmdclass,
                        cmd["rargs"],
                        None,
                        lastpp,
                        self.redirect,
                        cmd.get("redirects", {}),
                    )
                    lastpp = pp
            else:
                log.msg(
                    eventid="cowrie.command.failed",
                    input=" ".join(cmd2),
                    format="Command not found: %(input)s",
                )
                message = "-bash: {}: command not found\n".format(cmd["command"]).encode(
                    "utf8"
                )
                redirects = cmd.get("redirects", {})
                if redirects.get("has_redirections"):
                    temp_pp = StdOutStdErrEmulationProtocol(
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
                    stat = failure.Failure(error.ProcessDone(status=""))
                    self.protocol.terminal.transport.processEnded(stat)

                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp and getattr(pp, "has_redirection_error", False):
            runOrPrompt()
            return

        if pp:
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]["rargs"])

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
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        log.msg("received eof, sending ctrl-d to command")
        if self.protocol.cmdstack:
            self.protocol.cmdstack[-1].handle_CTRL_D()

    def handle_CTRL_C(self) -> None:
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"\n")
        self.showPrompt()

    def handle_CTRL_D(self) -> None:
        log.msg("Received CTRL-D, exiting..")
        stat = failure.Failure(error.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)

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

        self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(newbyt))]
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbyt)


class StdOutStdErrEmulationProtocol:
    """
    Pipe support written by Dave Germiquet
    Support for commands chaining added by Ivan Korolev (@fe7ch)
    """

    __author__ = "davegermiquet"

    def __init__(
        self,
        protocol: Any,
        cmd: Any,
        cmdargs: list[str],
        input_data: bytes | None,
        next_command: Any,
        redirect: bool = False,
        redirections: dict[str, Any] | None = None,
    ) -> None:
        self.cmd = cmd
        self.cmdargs = cmdargs
        self.input_data: bytes | None = input_data
        self.next_command = next_command
        self.data: bytes = b""
        self.redirected_data: bytes = b""
        self.err_data: bytes = b""
        self.protocol = protocol
        self.redirect = redirect  # dont send to terminal if enabled
        self.redirections = redirections or {
            "files": [],
            "fd_mappings": {},
            "stdin": None,
            "has_redirections": False,
        }
        self.stdout_file: dict[str, Any] | None = None
        self.stderr_file: dict[str, Any] | None = None
        self.stdout_to_stderr = False
        self.stderr_to_stdout = False
        self.redirection_error = False
        self.redirect_real_files: list[tuple[str, str]] = []
        self._stdout_written = 0
        self._stderr_written = 0
        self._setup_redirections()
        self.has_redirection_error = self.redirection_error or (
            getattr(self.next_command, "has_redirection_error", False)
            if self.next_command
            else False
        )
        self.has_redirections = bool(self.redirections.get("has_redirections"))
        self.write_stdout = self._write_stdout
        self.write_stderr = self._write_stderr

    def _setup_redirections(self) -> None:
        """Prepare stdin/stdout/stderr file handles and fd mappings."""
        fd_mappings = self.redirections.get("fd_mappings", {})
        self.stderr_to_stdout = fd_mappings.get(2) == 1
        self.stdout_to_stderr = fd_mappings.get(1) == 2

        stdin_info = self.redirections.get("stdin")
        if stdin_info:
            self._prepare_stdin(stdin_info)

        for entry in self.redirections.get("files", []):
            fd = entry.get("fd")
            target = entry.get("target")
            append = entry.get("append", False)
            if fd is None or target is None:
                continue
            if fd == 1:
                self.stdout_file = self._prepare_output_file(target, append)
                if self.stdout_file:
                    self._stdout_written = self.stdout_file.get("start_size", 0)
            elif fd == 2:
                self.stderr_file = self._prepare_output_file(target, append)
                if self.stderr_file:
                    self._stderr_written = self.stderr_file.get("start_size", 0)

    def _prepare_stdin(self, stdin_info: dict[str, Any]) -> None:
        """Load stdin from a redirected file path into input_data."""
        target = stdin_info.get("target")
        if target is None:
            return

        try:
            path = self.protocol.fs.resolve_path(target, self.protocol.cwd)
            data = self.protocol.fs.file_contents(path)
        except fs.FileNotFound:
            self._emit_redirection_error(
                f"-bash: {target}: No such file or directory\n"
            )
            return
        except fs.PermissionDenied:
            self._emit_redirection_error(f"-bash: {target}: Permission denied\n")
            return
        else:
            self.input_data = data

    def _prepare_output_file(
        self, target: str, append: bool
    ) -> dict[str, Any] | None:
        """Resolve and ready an output file, returning metadata for writing."""
        outfile = self.protocol.fs.resolve_path(target, self.protocol.cwd)
        p = self.protocol.fs.getfile(outfile)
        if outfile == "/dev/null":
            return {
                "virtual": outfile,
                "real": None,
                "append": append,
                "start_size": 0,
                "devnull": True,
            }
        start_size = p[fs.A_SIZE] if p and append else 0

        if self._needs_new_backing(p):
            safeoutfile = self._create_redirect_target(outfile)
            if safeoutfile is None:
                return None
        else:
            reuse = self._reuse_existing_backing(outfile, p, append)
            if reuse is None:
                return None
            safeoutfile, start_size = reuse

        self.redirect_real_files.append((safeoutfile, outfile))
        return {
            "virtual": outfile,
            "real": safeoutfile,
            "append": append,
            "start_size": start_size,
        }

    def _needs_new_backing(self, p: Any) -> bool:
        """Decide whether to create a fresh real file for redirection target."""
        return not p or not p[fs.A_REALFILE] or p[fs.A_REALFILE].startswith("honeyfs")

    def _create_redirect_target(self, outfile: str) -> str | None:
        """Create a new backing file for a redirected output target."""
        tmp_fname = "{}-{}-{}-redir_{}".format(
            time.strftime("%Y%m%d-%H%M%S"),
            self.protocol.getProtoTransport().transportId,
            self.protocol.terminal.transport.session.id,
            re.sub("[^A-Za-z0-9]", "_", outfile),
        )
        safeoutfile = os.path.join(
            CowrieConfig.get("honeypot", "download_path"), tmp_fname
        )
        perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        try:
            self.protocol.fs.mkfile(
                outfile,
                self.protocol.user.uid,
                self.protocol.user.gid,
                0,
                stat.S_IFREG | perm,
            )
        except fs.FileNotFound:
            self._emit_redirection_error(
                f"-bash: {outfile}: No such file or directory\n"
            )
            return None
        except fs.PermissionDenied:
            self._emit_redirection_error(f"-bash: {outfile}: Permission denied\n")
            return None

        with open(safeoutfile, "ab"):
            self.protocol.fs.update_realfile(
                self.protocol.fs.getfile(outfile), safeoutfile
            )
        return safeoutfile

    def _reuse_existing_backing(
        self, outfile: str, p: Any, append: bool
    ) -> tuple[str, int] | None:
        """Reuse an existing backing file, truncating if needed."""
        safeoutfile = p[fs.A_REALFILE]
        start_size = p[fs.A_SIZE] if append else 0
        if not append:
            try:
                open(safeoutfile, "wb").close()
                self.protocol.fs.update_size(outfile, 0)
                start_size = 0
            except OSError as e:
                log.msg(f"Failed to truncate redirect target {safeoutfile}: {e}")
                return None
        return safeoutfile, start_size

    def _emit_redirection_error(self, message: str) -> None:
        """Send a redirection-related error to the terminal and flag failure."""
        self.redirection_error = True
        try:
            self.protocol.terminal.write(message.encode("utf8"))
        except Exception:
            log.msg(message)

    def connectionMade(self) -> None:
        if self.input_data is None:
            self.input_data = b""

    def outReceived(self, data: bytes) -> None:
        """
        Invoked when a command in the chain called 'write' method
        """
        self._write_stdout(data)

    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        command.next_command = self.next_command
        self.next_command = command

    def errReceived(self, data: bytes) -> None:
        self._write_stderr(data)

    def inConnectionLost(self) -> None:
        pass

    def outConnectionLost(self) -> None:
        """
        Called from HoneyPotBaseProtocol.call_command() to run a next command in the chain
        """

        if self.next_command:
            # self.next_command.input_data = self.data
            npcmd = self.next_command.cmd
            npcmdargs = self.next_command.cmdargs
            self.protocol.call_command(self.next_command, npcmd, *npcmdargs)

    def errConnectionLost(self) -> None:
        pass

    def processExited(self, reason: failure.Failure) -> None:
        log.msg(f"processExited for {self.cmd}, status {reason.value.exitCode}")

    def processEnded(self, reason: failure.Failure) -> None:
        log.msg(f"processEnded for {self.cmd}, status {reason.value.exitCode}")

    def _pipe_to_next(self, data: bytes) -> bool:
        """
        Pass data to the next command in the pipeline if present.
        """
        if not self.next_command:
            return False
        if self.next_command.input_data is None:
            self.next_command.input_data = data
        else:
            self.next_command.input_data += data
        return True

    def _write_to_terminal(self, data: bytes) -> None:
        if self.protocol is not None and self.protocol.terminal is not None:
            self.protocol.terminal.write(data)
        else:
            log.msg("Connection was probably lost. Could not write to terminal")

    def _write_stdout(self, data: bytes, from_stderr: bool = False) -> None:
        self.data = data

        if self.stdout_to_stderr and not from_stderr:
            self._write_stderr(data, redirected=True)
            return

        if self.stdout_file:
            self._write_to_file(self.stdout_file, data, is_stdout=True)
            return

        if self._pipe_to_next(data):
            return

        if self.redirect:
            # Used for command substitutions
            self.redirected_data += data
            return

        self._write_to_terminal(data)

    def _write_stderr(self, data: bytes, redirected: bool = False) -> None:
        self.err_data = self.err_data + data

        if self.stderr_to_stdout and not redirected:
            # Duplicate stderr to stdout destinations (e.g., 2>&1)
            if self.stdout_file:
                self._write_to_file(self.stdout_file, data, is_stdout=True)
                return
            if self._pipe_to_next(data):
                return
            if self.redirect:
                self.redirected_data += data
                return
            if self.protocol and self.protocol.terminal:
                self.protocol.terminal.write(data)
            return

        if self.stderr_file:
            self._write_to_file(self.stderr_file, data, is_stdout=False)
            return

        if self.protocol and self.protocol.terminal:
            self.protocol.terminal.write(data)

    def _write_to_file(
        self, file_info: dict[str, Any], data: bytes, is_stdout: bool
    ) -> None:
        if file_info.get("devnull"):
            return

        real_path = file_info["real"]
        try:
            with open(real_path, "ab") as f:
                f.write(data)
        except OSError as e:
            log.msg(f"Failed to write redirected output: {e}")
            return

        if is_stdout:
            self._stdout_written += len(data)
            written = self._stdout_written
        else:
            self._stderr_written += len(data)
            written = self._stderr_written

        self.protocol.fs.update_size(file_info["virtual"], written)
