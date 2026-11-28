# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import re
from typing import TYPE_CHECKING

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


# GNU size suffixes accepted by head and tail counts.
_COUNT_SUFFIXES = {
    "": 1,
    "b": 512,
    "kB": 1000,
    "k": 1024,
    "K": 1024,
    "KiB": 1024,
    "MB": 1000**2,
    "M": 1024**2,
    "MiB": 1024**2,
    "GB": 1000**3,
    "G": 1024**3,
    "GiB": 1024**3,
}


def _parse_count(text: str) -> tuple[str, int] | None:
    """Parse a head/tail count: an optional sign ("-" or "+"), digits and a
    GNU size suffix. Returns (sign, value), or None when it is invalid."""
    match = re.fullmatch(r"([-+]?)(\d+)([A-Za-z]*)", text)
    if not match or match.group(3) not in _COUNT_SUFFIXES:
        return None
    return match.group(1), int(match.group(2)) * _COUNT_SUFFIXES[match.group(3)]


def _split_lines(data: bytes) -> list[bytes]:
    """Split into lines that keep their newline; a final line without one
    stays without one."""
    parts = data.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


class _HeadTail(HoneyPotCommand):
    """The shared option handling and file loop of head and tail."""

    consumes_stdin = True
    name: str

    # Count mode ("lines" or "bytes"), its sign as typed and its value.
    mode: str = "lines"
    sign: str = ""
    count: int = 10

    def select(self, data: bytes) -> bytes:
        raise NotImplementedError

    def start(self) -> None:
        args = list(self.args)
        # The obsolete "-NUM" form (and "+NUM" for tail) as the first argument.
        if args and re.fullmatch(r"-\d+", args[0]):
            args[0:1] = ["-n", args[0][1:]]
        try:
            optlist, files = getopt.gnu_getopt(
                args,
                "c:n:qvfF",
                ["bytes=", "lines=", "quiet", "silent", "verbose", "follow"],
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"{self.name}: invalid option -- '{err.opt}'\n"
                f"Try '{self.name} --help' for more information.\n"
            )
            self.exit_code = 1
            self.exit()
            return

        for opt, value in optlist:
            if opt in ("-n", "--lines", "-c", "--bytes"):
                mode = "lines" if opt in ("-n", "--lines") else "bytes"
                parsed = _parse_count(value)
                if parsed is None:
                    self.errorWrite(
                        f"{self.name}: invalid number of {mode}: '{value}'\n"
                    )
                    self.exit_code = 1
                    self.exit()
                    return
                self.mode = mode
                self.sign, self.count = parsed

        if files:
            for index, name in enumerate(files):
                if len(files) > 1:
                    prefix = "\n" if index else ""
                    self.write(f"{prefix}==> {name} <==\n")
                self.write_file(name)
        elif self.input_data is not None:
            self.writeBytes(self.select(self.input_data))
        else:
            # Reading the terminal: wait for its end of input.
            return
        self.exit()

    def write_file(self, name: str) -> None:
        path = self.fs.resolve_path(name, self.cwd)
        if self.fs.isdir(path):
            self.errorWrite(f"{self.name}: error reading '{name}': Is a directory\n")
            self.exit_code = 1
            return
        try:
            contents = self.fs.file_contents(path)
        except fs.FileNotFound:
            self.errorWrite(
                f"{self.name}: cannot open '{name}' for reading: "
                "No such file or directory\n"
            )
            self.exit_code = 1
            return
        self.writeBytes(self.select(contents))

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm=self.name,
            input=line,
        )

    def eofReceived(self) -> None:
        self.exit()


class Command_tail(_HeadTail):
    """
    tail command
    """

    name = "tail"

    def select(self, data: bytes) -> bytes:
        if self.mode == "bytes":
            if self.sign == "+":
                return data[max(self.count - 1, 0) :]
            return data[-self.count :] if self.count else b""
        lines = _split_lines(data)
        if self.sign == "+":
            return b"".join(lines[max(self.count - 1, 0) :])
        return b"".join(lines[-self.count :]) if self.count else b""


commands["/bin/tail"] = Command_tail
commands["/usr/bin/tail"] = Command_tail
commands["tail"] = Command_tail


class Command_head(_HeadTail):
    """
    head command
    """

    name = "head"

    def select(self, data: bytes) -> bytes:
        if self.mode == "bytes":
            if self.sign == "-":
                return data[: max(len(data) - self.count, 0)]
            return data[: self.count]
        lines = _split_lines(data)
        if self.sign == "-":
            return b"".join(lines[: max(len(lines) - self.count, 0)])
        return b"".join(lines[: self.count])


commands["/bin/head"] = Command_head
commands["/usr/bin/head"] = Command_head
commands["head"] = Command_head
