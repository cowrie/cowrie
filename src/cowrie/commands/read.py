# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The read builtin: reads one line of stdin, splits it into fields by
# ABOUTME: IFS as bash does, and assigns the fields to shell variables.

"""
``read [-r] [-p prompt] [name ...]`` reads one line and assigns its fields to
the names, the last name taking the rest of the line; with no names the whole
line goes to ``REPLY``. Without ``-r`` a backslash escapes the next character
and a backslash before the newline joins the next line on.

Buffered stdin (a pipe, a ``< file`` on the loop around it) is read one line
at a time: the rest is handed back to the shell for the next reader, so
``while read`` walks the input and stops at its end. The status is 1 at end
of input, even when a last line without a newline was assigned.

``-s`` and ``-t`` are accepted and ignored; ``-a``, ``-d``, ``-e``, ``-E``,
``-i``, ``-n``, ``-N`` and ``-u`` are accepted but not implemented.
"""

from __future__ import annotations

import getopt
import re

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pipe import FD_FILE_INPUT

commands = {}

USAGE = (
    "read: usage: read [-Eers] [-a array] [-d delim] [-i text] [-n nchars] "
    "[-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]\n"
)

DEFAULT_IFS = " \t\n"

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# A character of the line, and whether a backslash escaped it: an escaped
# character is never a field separator
Char = tuple[str, bool]


def unescape(text: str, raw: bool) -> tuple[list[Char], bool]:
    """Mark the backslash-escaped characters of one line of input; returns
    the characters and whether a final backslash continues the line."""
    chars: list[Char] = []
    i = 0
    while i < len(text):
        if text[i] == "\\" and not raw:
            if i + 1 == len(text):
                return chars, True
            chars.append((text[i + 1], True))
            i += 2
        else:
            chars.append((text[i], False))
            i += 1
    return chars, False


def split_fields(chars: list[Char], count: int, ifs: str) -> list[str]:
    """Split a line into ``count`` fields as bash's read does: IFS whitespace
    is trimmed from both ends and runs of it separate fields, each other IFS
    character separates exactly one field, and the last field is the rest of
    the line."""
    whitespace = {c for c in ifs if c in DEFAULT_IFS}

    def is_space(i: int) -> bool:
        return i < len(chars) and not chars[i][1] and chars[i][0] in whitespace

    def is_separator(i: int) -> bool:
        return i < len(chars) and not chars[i][1] and chars[i][0] in ifs

    def skip_separator(i: int) -> int:
        while is_space(i):
            i += 1
        if is_separator(i):
            i += 1
            while is_space(i):
                i += 1
        return i

    def text(part: list[Char]) -> str:
        return "".join(c for c, _ in part)

    i = 0
    while is_space(i):
        i += 1
    fields = []
    for _ in range(count - 1):
        start = i
        while i < len(chars) and not is_separator(i):
            i += 1
        fields.append(text(chars[start:i]))
        i = skip_separator(i)

    end = len(chars)
    while end > i and is_space(end - 1):
        end -= 1
    chars = chars[:end]
    # A single field followed by a single separator loses the separator
    # ("x:y:" read into two names gives "y")
    j = i
    while j < len(chars) and not is_separator(j):
        j += 1
    if j < len(chars) and skip_separator(j) == len(chars):
        end = j
    fields.append(text(chars[i:end]))
    return fields


class Command_read(HoneyPotCommand):
    consumes_stdin = True

    raw = False
    names: list[str]
    chars: list[Char]

    def start(self) -> None:
        # Whether the input is the shell's own buffer, which read shares with
        # the commands after it, rather than this command's own `< file`
        self.shared_input = self.input_data is not None and (
            self.pp is None or self.pp.targets.get(0, (None,))[0] != FD_FILE_INPUT
        )
        try:
            optlist, self.names = getopt.getopt(self.args, "Eersa:d:i:n:N:p:t:u:")
        except getopt.GetoptError as err:
            if "requires argument" in err.msg:
                message = f"-{err.opt}: option requires an argument"
            else:
                message = f"-{err.opt}: invalid option"
            self.errorWrite(f"{self.shell.error_prefix()}read: {message}\n{USAGE}")
            self.fail(2)
            return

        for name in self.names:
            if not _NAME.match(name):
                self.errorWrite(
                    f"{self.shell.error_prefix()}read: `{name}': not a valid identifier\n"
                )
                self.fail(1)
                return

        prompt = ""
        for opt, arg in optlist:
            if opt == "-r":
                self.raw = True
            elif opt == "-p":
                prompt = arg

        self.chars = []
        if self.input_data is None:
            # Live input: wait for the next line typed at the terminal. As in
            # bash, the prompt is shown only then.
            if prompt:
                self.errorWrite(prompt)
            return

        line, complete, rest = self.take_line(self.input_data)
        if self.shared_input:
            self.shell.stdin = rest
        self.chars = line
        self.finish(0 if complete else 1)

    def fail(self, status: int) -> None:
        """Exit without reading, leaving shared input for the next reader."""
        if self.shared_input:
            self.shell.stdin = self.input_data
        self.exit(status)

    def take_line(self, data: bytes) -> tuple[list[Char], bool, bytes]:
        """Take one logical line from ``data``: the line's characters, whether
        it ended in a newline, and the input after it."""
        chars: list[Char] = []
        while True:
            end = data.find(b"\n")
            if end == -1:
                part, _ = unescape(data.decode("utf-8", errors="replace"), self.raw)
                return chars + part, False, b""
            part, continued = unescape(
                data[:end].decode("utf-8", errors="replace"), self.raw
            )
            chars += part
            data = data[end + 1 :]
            if not continued:
                return chars, True, data

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.session.input",
            "INPUT (%(realm)s): %(input)s",
            realm="read",
            input=line,
        )
        part, continued = unescape(line, self.raw)
        self.chars += part
        if not continued:
            self.finish(0)

    def eofReceived(self) -> None:
        self.finish(1)

    def finish(self, status: int) -> None:
        if not self.names:
            self.environ["REPLY"] = "".join(c for c, _ in self.chars)
        else:
            ifs = self.pp.assignments.get("IFS") if self.pp is not None else None
            if ifs is None:
                ifs = self.environ.get("IFS", DEFAULT_IFS)
            fields = split_fields(self.chars, len(self.names), ifs)
            for name, value in zip(self.names, fields, strict=True):
                self.environ[name] = value
        self.exit(status)


commands["read"] = Command_read
