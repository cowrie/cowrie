# SPDX-FileCopyrightText: 2019 NunoNovais <nuno@novais.me>
# SPDX-FileCopyrightText: 2018 Free Software Foundation, Inc.\n")
# SPDX-FileCopyrightText: 2019 Nuno Novais <nuno@noais.me>
# SPDX-FileCopyrightText: 2020-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains the wc commnad
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_TYPE, T_FILE
from cowrie.shell.pipe import FD_FILE_INPUT

commands = {}

# The counts, in the order wc prints them
LINES, WORDS, CHARS, BYTES, MAXLEN = range(5)


class Command_wc(HoneyPotCommand):
    """
    wc command
    """

    consumes_stdin = True

    # Which counts to print, set by start()
    show: tuple[bool, ...] = ()
    # The files to count; none means standard input
    files: list[str] = []
    # Standard input typed at a terminal, counted at ctrl-d
    typed: bytes = b""
    counted: bool = False

    def version(self) -> None:
        self.writeBytes(b"wc (GNU coreutils) 8.30\n")
        self.writeBytes(b"Copyright (C) 2018 Free Software Foundation, Inc.\n")
        self.writeBytes(
            b"License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
        )
        self.writeBytes(
            b"This is free software: you are free to change and redistribute it.\n"
        )
        self.writeBytes(b"There is NO WARRANTY, to the extent permitted by law.\n")
        self.writeBytes(b"\n")
        self.writeBytes(b"Written by Paul Rubin and David MacKenzie.\n")

    def help(self) -> None:
        self.writeBytes(b"Usage: wc [OPTION]... [FILE]...\n")
        self.writeBytes(
            b"Print newline, word, and byte counts for each FILE, and a total line if\n"
        )
        self.writeBytes(
            b"more than one FILE is specified.  A word is a non-zero-length sequence of\n"
        )
        self.writeBytes(b"characters delimited by white space.\n")
        self.writeBytes(b"\n")
        self.writeBytes(b"With no FILE, or when FILE is -, read standard input.\n")
        self.writeBytes(b"\n")
        self.writeBytes(
            b"The options below may be used to select which counts are printed, always in\n"
        )
        self.writeBytes(
            b"the following order: newline, word, character, byte, maximum line length.\n"
        )
        self.writeBytes(b"\t-c\tprint the byte counts\n")
        self.writeBytes(b"\t-m\tprint the character counts\n")
        self.writeBytes(b"\t-l\tprint the newline counts\n")
        self.writeBytes(b"\t-L\tprint the length of the longest line\n")
        self.writeBytes(b"\t-w\tprint the word counts\n")
        self.writeBytes(b"\t-h\tdisplay this help and exit\n")
        self.writeBytes(b"\t-v\toutput version information and exit\n")

    @staticmethod
    def count(contents: bytes) -> list[int]:
        """Return the lines, words, characters, bytes and longest line length."""
        longest = 0
        for line in contents.split(b"\n"):
            width = 0
            for char in line.decode("utf-8", errors="ignore"):
                if char == "\t":
                    width = (width // 8 + 1) * 8
                elif char in "\r\f":
                    width = 0
                elif char.isprintable():
                    width += 1
            longest = max(longest, width)
        return [
            contents.count(b"\n"),
            len(contents.split()),
            len(contents.decode("utf-8", errors="ignore")),
            len(contents),
            longest,
        ]

    def stdin_contents(self) -> bytes:
        """Standard input, which only the first reader gets."""
        contents = self.typed or self.input_data or b""
        self.typed = b""
        self.input_data = b""
        return contents

    def stdin_is_file(self) -> bool:
        """Whether standard input was redirected from a file with ``< file``."""
        kind, target = getattr(self.pp, "targets", {}).get(0, (None, None))
        return bool(kind == FD_FILE_INPUT and target != "<<")

    def format_counts(self, counts: list[int], width: int, name: str | None) -> str:
        line = " ".join(f"{n:>{width}}" for n, shown in zip(counts, self.show) if shown)
        if name is not None:
            line += f" {name}"
        return line + "\n"

    def run(self) -> None:
        """Count every file, or standard input, and print the result."""
        self.counted = True
        results: list[tuple[str | None, list[int]]] = []
        size = 0
        # A pipe, a directory or a device has no known size
        unknown_size = False
        for name in self.files or [None]:  # type: ignore[list-item]
            if name is None or name == "-":
                contents = self.stdin_contents()
                if self.stdin_is_file():
                    size += len(contents)
                else:
                    unknown_size = True
                results.append((name, self.count(contents)))
                continue
            path = self.fs.resolve_path(name, self.cwd)
            if self.fs.isdir(path):
                self.errorWrite(f"wc: {name}: Is a directory\n")
                self.exit_code = 1
                unknown_size = True
                results.append((name, [0, 0, 0, 0, 0]))
                continue
            try:
                contents = self.fs.file_contents(path)
            except Exception:
                self.errorWrite(f"wc: {name}: No such file or directory\n")
                self.exit_code = 1
                continue
            node = self.fs.getfile(path)
            if node is not None and node[A_TYPE] != T_FILE:
                unknown_size = True
            size += len(contents)
            results.append((name, self.count(contents)))

        # Like GNU wc, a single count for a single input is not padded and
        # an input of unknown size gets a column of 7. Otherwise the columns
        # are as wide as the total size of the files.
        if sum(self.show) == 1 and len(self.files) <= 1:
            width = 1
        elif unknown_size:
            width = 7
        else:
            width = len(str(size))
        for name, counts in results:
            self.write(self.format_counts(counts, width, name))
        if len(self.files) > 1:
            total = [sum(counts[i] for _, counts in results) for i in range(MAXLEN)]
            total.append(max((counts[MAXLEN] for _, counts in results), default=0))
            self.write(self.format_counts(total, width, "total"))
        self.exit()

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args,
                "cmlLwhv",
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
            if len(err.opt) == 1:
                self.errorWrite(f"wc: invalid option -- '{err.opt}'\n")
            else:
                self.errorWrite(f"wc: unrecognized option '--{err.opt}'\n")
            self.errorWrite("Try 'wc --help' for more information.\n")
            self.exit_code = 1
            self.exit()
            return

        options = {opt for opt, _arg in optlist}
        if options & {"-v", "--version"}:
            self.version()
            self.exit()
            return
        if options & {"-h", "--help"}:
            self.help()
            self.exit()
            return

        show = (
            bool(options & {"-l", "--lines"}),
            bool(options & {"-w", "--words"}),
            bool(options & {"-m", "--chars"}),
            bool(options & {"-c", "--bytes"}),
            bool(options & {"-L", "--max-line-length"}),
        )
        # Without options wc prints lines, words and bytes
        self.show = show if any(show) else (True, True, False, True, False)
        self.files = args

        # Input from a terminal ends with ctrl-d, a pipe or a file is complete
        reads_stdin = not args or "-" in args
        if reads_stdin and not getattr(self.pp, "stdin_from_pipe", False):
            return
        self.run()

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="wc",
            input=line,
        )
        self.typed += line.removesuffix("\n").encode("utf-8") + b"\n"

    def eofReceived(self) -> None:
        if self.show and not self.counted:
            self.run()
        else:
            self.exit()


commands["/usr/bin/wc"] = Command_wc
commands["/bin/wc"] = Command_wc
commands["wc"] = Command_wc
