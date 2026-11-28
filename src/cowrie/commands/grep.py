# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import os.path
import re
from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_grep(HoneyPotCommand):
    """
    grep command
    """

    consumes_stdin = True

    interactive: bool = False
    matched: bool = False
    # A file could not be read: grep then exits 2, unless -q and a match.
    errored: bool = False
    quiet: bool = False
    max_count: int | None = None
    match_count: int = 0
    ignore_case: bool = False
    # -c: print the number of matching lines instead of the lines.
    count_only: bool = False
    # Counts are prefixed with the file name when grep reads several files.
    show_names: bool = False
    # Matches seen so far on interactive stdin, for -c at end of input.
    stdin_count: int = 0

    def grep_get_contents(self, path: str, name: str, match: str) -> None:
        """Search the file at path; name is how the user wrote it, for
        messages and -c prefixes."""
        try:
            contents = self.fs.file_contents(path)
        except Exception:
            self.errorWrite(f"grep: {name}: No such file or directory\n")
            self.errored = True
            return
        count = self.grep_application(contents, match)
        self.report_count(count, name)

    def report_count(self, count: int, filename: str | None = None) -> None:
        if not self.count_only or self.quiet:
            return
        if self.show_names and filename is not None:
            self.write(f"{filename}:{count}\n")
        else:
            self.write(f"{count}\n")

    def compile_match(self, match: str) -> re.Pattern[bytes]:
        bmatch = os.path.basename(match).replace('"', "").encode("utf8")
        flags = re.NOFLAG
        if self.ignore_case:
            flags = re.IGNORECASE
        return re.compile(bmatch, flags)

    def grep_application(self, contents: bytes, match: str) -> int:
        """Print the lines of contents that match; return how many matched."""
        count = 0
        matcher = self.compile_match(match)
        lines = contents.split(b"\n")
        if contents.endswith(b"\n"):
            # The final newline ends the last line; it does not start a new one.
            lines.pop()
        for line in lines:
            if self.max_count is not None and self.match_count >= self.max_count:
                break
            if matcher.search(line):
                self.matched = True
                self.match_count += 1
                count += 1
                if not self.quiet and not self.count_only:
                    self.writeBytes(line + b"\n")
        return count

    def help(self) -> None:
        self.writeBytes(
            b"usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num] [-B num] [-C[num]]\n"
        )
        self.writeBytes(
            b"\t[-e pattern] [-f file] [--binary-files=value] [--color=when]\n"
        )
        self.writeBytes(
            b"\t[--context[=num]] [--directories=action] [--label] [--line-buffered]\n"
        )
        self.writeBytes(b"\t[--null] [pattern] [file ...]\n")

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit(2)
            return

        try:
            optlist, args = getopt.getopt(
                self.args,
                "abcDEFGHhIiJLlnOoPqRSsUVvwxZA:B:C:e:f:m:",
                [
                    "binary-files=",
                    "color=",
                    "color",
                    "context=",
                    "directories=",
                    "label",
                    "line-buffered",
                    "quiet",
                    "silent",
                ],
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"grep: invalid option -- {err.opt}\n")
            self.help()
            self.exit(2)
            return

        for opt, arg in optlist:
            if opt == "-h":
                self.help()
            elif opt in ("-q", "--quiet", "--silent"):
                self.quiet = True
            elif opt == "-c":
                self.count_only = True
            elif opt == "-m":
                try:
                    n = int(arg)
                except ValueError:
                    n = -1
                if n < 0:
                    self.errorWrite("grep: invalid max count\n")
                    self.exit(2)
                    return
                self.max_count = n
            elif opt == "-i":
                self.ignore_case = True

        if not args:
            # Options only, no pattern (e.g. `grep -h`).
            self.exit()
            return

        self.match = args[0]

        # grep validates the pattern before it reads any input, so a malformed
        # one is reported once rather than per file or per line of stdin.
        try:
            self.compile_match(self.match)
        except re.error:
            self.errorWrite("grep: Invalid regular expression\n")
            self.exit(2)
            return

        files = args[1:]

        if self.input_data is not None:
            self.report_count(self.grep_application(self.input_data, self.match))
        elif files:
            self.show_names = len(files) > 1
            for name in files:
                for path in self.check_arguments("grep", [name]):
                    self.grep_get_contents(path, name, self.match)
        else:
            # No file and no pipe: read stdin until EOF.
            self.interactive = True
            return

        self.exit(self._status())

    def _status(self) -> int:
        """grep's exit status: 0 on a match, 1 on none, 2 if a file could not
        be read -- except that with -q any match is success."""
        if self.matched and self.quiet:
            return 0
        if self.errored:
            return 2
        return 0 if self.matched else 1

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="grep",
            input=line,
        )
        if self.interactive:
            self.stdin_count += self.grep_application(line.encode("utf8"), self.match)

    def eofReceived(self) -> None:
        if self.interactive:
            terminal = self.protocol.terminal
            if (
                getattr(terminal, "stdinlogOpen", False)
                and getattr(terminal, "stdinlogFile", "")
                and os.path.exists(terminal.stdinlogFile)
            ):
                # Live exec-channel stdin (e.g. `grep foo < file` over an ssh
                # exec): the bytes were streamed to the stdin log rather than
                # arriving via lineReceived, so match against them now.
                with open(terminal.stdinlogFile, "rb") as f:
                    self.stdin_count += self.grep_application(f.read(), self.match)
            self.report_count(self.stdin_count)
        self.exit(self._status())


commands["/bin/grep"] = Command_grep
commands["grep"] = Command_grep
commands["/bin/egrep"] = Command_grep
commands["/bin/fgrep"] = Command_grep
