# SPDX-FileCopyrightText: 2019 NunoNovais <nuno@novais.me>
# SPDX-FileCopyrightText: 2018 Free Software Foundation, Inc.\n")
# SPDX-FileCopyrightText: 2019 Nuno Novais <nuno@noais.me>
# SPDX-FileCopyrightText: 2020-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The wc command: counts lines, words, bytes and line length the way
# ABOUTME: GNU coreutils 9.1 does in the C locale, with its column layout.

"""
This module contains the wc command
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_SIZE, FileNotFound
from cowrie.shell.pipe import FD_FILE_INPUT

commands = {}

# In the C locale a word is a run of printable characters other than space.
# These bytes end a word; all other bytes (control characters and bytes over
# 0x7e) neither start nor end one.
WORD_SEPARATORS = b" \t\n\v\f\r"
NEUTRAL_BYTES = bytes(
    c for c in range(256) if not 0x21 <= c <= 0x7E and c not in WORD_SEPARATORS
)

# The count fields, in the order wc always prints them.
FIELDS = ("lines", "words", "chars", "bytes", "max_line_length")
OPTION_FIELDS = {
    "-l": "lines",
    "--lines": "lines",
    "-w": "words",
    "--words": "words",
    "-m": "chars",
    "--chars": "chars",
    "-c": "bytes",
    "--bytes": "bytes",
    "-L": "max_line_length",
    "--max-line-length": "max_line_length",
}


def count(data: bytes) -> dict[str, int]:
    """Count data as GNU wc does in the C locale, where a character is a byte."""
    return {
        "lines": data.count(b"\n"),
        "words": len(data.translate(None, NEUTRAL_BYTES).split()),
        "chars": len(data),
        "bytes": len(data),
        "max_line_length": max_line_length(data),
    }


def max_line_length(data: bytes) -> int:
    """The widest line in display columns: tabs stop every 8 columns, and
    newline, carriage return and form feed each start a new line."""
    widest = column = 0
    for c in data:
        if c in b"\n\r\f":
            widest = max(widest, column)
            column = 0
        elif c == 0x09:
            column += 8 - column % 8
        elif 0x20 <= c <= 0x7E:
            column += 1
    return max(widest, column)


class Command_wc(HoneyPotCommand):
    """
    wc command
    """

    consumes_stdin = True

    def __init__(self, protocol, *args):
        super().__init__(protocol, *args)
        # Standard input typed at the terminal, counted at end of file.
        self.typed = bytearray()

    def version(self) -> None:
        self.write(
            "wc (GNU coreutils) 9.1\n"
            "Copyright (C) 2022 Free Software Foundation, Inc.\n"
            "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
            "This is free software: you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n"
            "\n"
            "Written by Paul Rubin and David MacKenzie.\n"
        )

    def help(self) -> None:
        self.write(
            """Usage: wc [OPTION]... [FILE]...
  or:  wc [OPTION]... --files0-from=F
Print newline, word, and byte counts for each FILE, and a total line if
more than one FILE is specified.  A word is a non-zero-length sequence of
printable characters delimited by white space.

With no FILE, or when FILE is -, read standard input.

The options below may be used to select which counts are printed, always in
the following order: newline, word, character, byte, maximum line length.
  -c, --bytes            print the byte counts
  -m, --chars            print the character counts
  -l, --lines            print the newline counts
      --files0-from=F    read input from the files specified by
                           NUL-terminated names in file F;
                           If F is - then read names from standard input
  -L, --max-line-length  print the maximum display width
  -w, --words            print the word counts
      --help        display this help and exit
      --version     output version information and exit

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report any translation bugs to <https://translationproject.org/team/>
Full documentation <https://www.gnu.org/software/coreutils/wc>
or available locally via: info '(coreutils) wc invocation'
"""
        )

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args,
                "clLmw",
                [
                    "bytes",
                    "chars",
                    "lines",
                    "max-line-length",
                    "words",
                    "help",
                    "version",
                ],
            )
        except getopt.GetoptError as err:
            if err.msg.startswith("option --"):
                self.errorWrite(f"wc: unrecognized option '--{err.opt}'\n")
            else:
                self.errorWrite(f"wc: invalid option -- '{err.opt}'\n")
            self.errorWrite("Try 'wc --help' for more information.\n")
            self.exit(1)
            return

        selected = set()
        for opt, _arg in optlist:
            if opt == "--help":
                self.help()
                self.exit()
                return
            if opt == "--version":
                self.version()
                self.exit()
                return
            selected.add(OPTION_FIELDS[opt])
        self.fields = [f for f in FIELDS if f in selected] or [
            "lines",
            "words",
            "bytes",
        ]

        # None stands for standard input named by no operand at all.
        self.pending: list[str | None] = list(args) if args else [None]
        self.show_total = len(self.pending) > 1
        self.totals = dict.fromkeys(FIELDS, 0)
        self.stdin_read = False
        self.width = self.number_width()
        self.count_pending()

    def stdin_is_regular_file(self) -> bool:
        """Whether stdin is redirected from a file (`wc < f`), which wc sizes
        like a named file, rather than a pipe or terminal."""
        targets = getattr(self.pp, "targets", None) or {}
        kind, target = targets.get(0, (None, None))
        return bool(kind == FD_FILE_INPUT and target != "<<")

    def number_width(self) -> int:
        """The column width: 1 for a single count of a single input, else the
        digits of the regular files' total size, and at least 7 if any input
        is not a regular file."""
        if len(self.pending) == 1 and len(self.fields) == 1:
            return 1
        minimum = 1
        regular_total = 0
        for name in self.pending:
            if name is None or name == "-":
                if self.stdin_is_regular_file():
                    regular_total += len(self.input_data or b"")
                else:
                    minimum = 7
                continue
            path = self.fs.resolve_path(name, self.cwd)
            if self.fs.isdir(path):
                minimum = 7
                continue
            node = self.fs.getfile(path)
            if node is not None:
                regular_total += node[A_SIZE]
        return max(minimum, len(str(regular_total)))

    def count_pending(self) -> None:
        """Count the operands in order. Typed standard input pauses this until
        end of file; eofReceived resumes it."""
        while self.pending:
            name = self.pending[0]
            if name is None or name == "-":
                if self.input_data is None and not self.stdin_read:
                    return
                data = b"" if self.stdin_read else (self.input_data or b"")
                self.stdin_read = True
                self.pending.pop(0)
                self.report(count(data), name)
                continue
            self.pending.pop(0)
            path = self.fs.resolve_path(name, self.cwd)
            if self.fs.isdir(path):
                self.errorWrite(f"wc: {name}: Is a directory\n")
                self.exit_code = 1
                self.report(count(b""), name)
                continue
            try:
                contents = self.fs.file_contents(path)
            except FileNotFound:
                self.errorWrite(f"wc: {name}: No such file or directory\n")
                self.exit_code = 1
                continue
            self.report(count(contents), name)

        if self.show_total:
            self.write_counts(self.totals, "total")
        self.exit()

    def report(self, counts: dict[str, int], name: str | None) -> None:
        self.write_counts(counts, name)
        for field in FIELDS:
            if field == "max_line_length":
                self.totals[field] = max(self.totals[field], counts[field])
            else:
                self.totals[field] += counts[field]

    def write_counts(self, counts: dict[str, int], name: str | None) -> None:
        line = " ".join(str(counts[f]).rjust(self.width) for f in self.fields)
        if name is not None:
            line += f" {name}"
        self.write(line + "\n")

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="wc",
            input=line,
        )
        self.typed += line.encode("utf8") + b"\n"

    def eofReceived(self) -> None:
        if self.exited:
            return
        live = self.stdin_log_contents()
        self.input_data = live if live is not None else bytes(self.typed)
        self.count_pending()


commands["/usr/bin/wc"] = Command_wc
commands["/bin/wc"] = Command_wc
commands["wc"] = Command_wc
