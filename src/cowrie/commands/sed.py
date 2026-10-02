# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Emulates GNU sed: addresses, s/y/d/p/q/a/i/c/=, hold space, labels
# ABOUTME: and blocks, with POSIX basic and extended regex, -n, -e, -f and -i.

from __future__ import annotations

import getopt
import re
from dataclasses import dataclass, field
from typing import Any, NoReturn

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pipe import PipeProtocol

commands = {}

USAGE = """\
Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...

  -n, --quiet, --silent
                 suppress automatic printing of pattern space
      --debug
                 annotate program execution
  -e script, --expression=script
                 add the script to the commands to be executed
  -f script-file, --file=script-file
                 add the contents of script-file to the commands to be executed
  --follow-symlinks
                 follow symlinks when processing in place
  -i[SUFFIX], --in-place[=SUFFIX]
                 edit files in place (makes backup if SUFFIX supplied)
  -l N, --line-length=N
                 specify the desired line-wrap length for the `l' command
  --posix
                 disable all GNU extensions.
  -E, -r, --regexp-extended
                 use extended regular expressions in the script
                 (for portability use POSIX -E).
  -s, --separate
                 consider files as separate rather than as a single
                 continuous long stream.
      --sandbox
                 operate in sandbox mode (disable e/r/w commands).
  -u, --unbuffered
                 load minimal amounts of data from the input files and flush
                 the output buffers more often
  -z, --null-data
                 separate lines by NUL characters
      --help     display this help and exit
      --version  output version information and exit

If no -e, --expression, -f, or --file option is given, then the first
non-option argument is taken as the sed script to interpret.  All
remaining arguments are names of input files; if no input files are
specified, then the standard input is read.

GNU sed home page: <https://www.gnu.org/software/sed/>.
General help using GNU software: <https://www.gnu.org/gethelp/>.
"""

# POSIX bracket classes as Python character-class contents.
_BRACKET_CLASSES = {
    "alnum": "a-zA-Z0-9",
    "alpha": "a-zA-Z",
    "blank": " \\t",
    "cntrl": "\\x00-\\x1f\\x7f",
    "digit": "0-9",
    "graph": "\\x21-\\x7e",
    "lower": "a-z",
    "print": "\\x20-\\x7e",
    "punct": re.escape("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    "space": " \\t\\n\\r\\f\\v",
    "upper": "A-Z",
    "xdigit": "0-9A-Fa-f",
}

_TEXT_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a"}


class SedError(Exception):
    """A script error, reported as GNU sed reports it."""


def _fail(message: str) -> NoReturn:
    raise SedError(message)


def translate_regex(pattern: str, extended: bool) -> str:
    """Translate a POSIX basic (or, with ``extended``, extended) regular
    expression with GNU extensions into Python ``re`` syntax."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "[":
            end, body = _bracket(pattern, i)
            out.append(body)
            i = end
            continue
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            i += 2
            if not extended and nxt in "(){}+?|":
                out.append(nxt)
            elif nxt in "<>":
                out.append("\\b")
            elif nxt == "`":
                out.append("\\A")
            elif nxt == "'":
                out.append("\\Z")
            elif nxt in _TEXT_ESCAPES:
                out.append(re.escape(_TEXT_ESCAPES[nxt]))
            elif nxt.isdigit() or nxt in "wWsSbB":
                out.append("\\" + nxt)
            else:
                out.append(re.escape(nxt))
            continue
        if not extended and ch in "(){}+?|":
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _bracket(pattern: str, start: int) -> tuple[int, str]:
    """Translate the bracket expression starting at ``start``; returns the
    index after it and its Python form. An unclosed "[" is a literal."""
    i = start + 1
    parts = ["["]
    if i < len(pattern) and pattern[i] == "^":
        parts.append("^")
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        parts.append("\\]")
        i += 1
    while i < len(pattern):
        if pattern.startswith("[:", i):
            end = pattern.find(":]", i + 2)
            if end != -1 and pattern[i + 2 : end] in _BRACKET_CLASSES:
                parts.append(_BRACKET_CLASSES[pattern[i + 2 : end]])
                i = end + 2
                continue
        ch = pattern[i]
        if ch == "]":
            parts.append("]")
            return i + 1, "".join(parts)
        # Inside brackets a backslash is an ordinary character in POSIX.
        parts.append("\\\\" if ch == "\\" else ("\\[" if ch == "[" else ch))
        i += 1
    return start + 1, "\\["


@dataclass
class Address:
    kind: str  # "line", "last" or "regex"
    line: int = 0
    regex: re.Pattern[str] | None = None


@dataclass
class Command:
    name: str
    addr1: Address | None = None
    addr2: Address | None = None
    negate: bool = False
    text: str = ""
    label: str = ""
    regex: re.Pattern[str] | None = None
    replacement: list[tuple[str, Any]] = field(default_factory=list)
    count: int = 1
    global_: bool = False
    print_: bool = False
    source: str = ""
    target: str = ""
    code: int = 0
    block_end: int = 0
    in_range: bool = False


class ScriptParser:
    """Parse one -e expression into Commands, tracking the character
    position GNU sed reports in its errors."""

    def __init__(self, text: str, number: int, extended: bool) -> None:
        self.text = text
        self.number = number
        self.extended = extended
        self.pos = 0

    def fail(self, message: str, pos: int | None = None) -> NoReturn:
        where = self.pos if pos is None else pos
        _fail(f"sed: -e expression #{self.number}, char {where}: {message}")

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def skip_blanks(self) -> None:
        while self.peek() in (" ", "\t"):
            self.pos += 1

    def parse(self) -> list[Command]:
        commands: list[Command] = []
        while True:
            while self.peek() in (" ", "\t", "\n", ";"):
                self.pos += 1
            if self.pos >= len(self.text):
                return commands
            if self.peek() == "#":
                while self.peek() not in ("", "\n"):
                    self.pos += 1
                continue
            commands.append(self.parse_command())

    def parse_address(self) -> Address | None:
        ch = self.peek()
        if ch.isdigit():
            start = self.pos
            while self.peek().isdigit():
                self.pos += 1
            return Address("line", line=int(self.text[start : self.pos]))
        if ch == "$":
            self.pos += 1
            return Address("last")
        if ch in ("/", "\\"):
            if ch == "\\":
                self.pos += 1
            delimiter = self.peek()
            self.pos += 1
            pattern = self.read_until(delimiter, "unterminated address regex")
            flags = 0
            while self.peek() in ("I", "M"):
                flags |= re.IGNORECASE if self.peek() == "I" else re.MULTILINE
                self.pos += 1
            return Address("regex", regex=self.compile(pattern, flags))
        return None

    def read_until(self, delimiter: str, message: str) -> str:
        """Read text up to an unescaped ``delimiter`` and consume it; an
        escaped delimiter becomes the plain character."""
        out: list[str] = []
        while True:
            ch = self.peek()
            if ch == "":
                self.fail(message, len(self.text))
            self.pos += 1
            if ch == "\\" and self.peek() == delimiter:
                out.append(delimiter)
                self.pos += 1
            elif ch == "\\" and self.peek():
                out.append(ch + self.peek())
                self.pos += 1
            elif ch == delimiter:
                return "".join(out)
            else:
                out.append(ch)

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        try:
            return re.compile(translate_regex(pattern, self.extended), flags)
        except re.error as err:
            self.fail(f"Invalid regex: {err}")

    def parse_command(self) -> Command:
        addr1 = self.parse_address()
        addr2 = None
        if addr1 is not None and self.peek() == ",":
            self.pos += 1
            addr2 = self.parse_address()
            if addr2 is None:
                self.fail("unexpected `,'")
        self.skip_blanks()
        negate = False
        while self.peek() == "!":
            negate = True
            self.pos += 1
            self.skip_blanks()
        name = self.peek()
        self.pos += 1
        command = Command(name, addr1=addr1, addr2=addr2, negate=negate)
        if name == "":
            self.fail("missing command", len(self.text))
        if name in "{}=dDgGhHlnNpPxz":
            return command
        if name in "qQ":
            self.skip_blanks()
            start = self.pos
            while self.peek().isdigit():
                self.pos += 1
            command.code = int(self.text[start : self.pos] or 0)
            return command
        if name in "aic":
            command.text = self.read_text()
            return command
        if name in ":btT":
            self.skip_blanks()
            start = self.pos
            while self.peek() not in ("", "\n", ";"):
                self.pos += 1
            command.label = self.text[start : self.pos].strip()
            if name == ":" and not command.label:
                self.fail('":" lacks a label')
            return command
        if name in "rRwW":
            self.skip_blanks()
            start = self.pos
            while self.peek() not in ("", "\n"):
                self.pos += 1
            command.text = self.text[start : self.pos]
            return command
        if name == "s":
            return self.parse_substitute(command)
        if name == "y":
            return self.parse_transliterate(command)
        self.fail(f"unknown command: `{name}'", self.pos)

    def read_text(self) -> str:
        """The text of a/i/c: GNU's one-line form "a text" or "a\\" and the
        next line."""
        if self.peek() == "\\":
            self.pos += 1
            if self.peek() == "\n":
                self.pos += 1
        else:
            self.skip_blanks()
        out: list[str] = []
        while self.peek() not in ("", "\n"):
            ch = self.peek()
            self.pos += 1
            if ch == "\\" and self.peek():
                out.append(self.peek())
                self.pos += 1
            else:
                out.append(ch)
        return "".join(out)

    def parse_substitute(self, command: Command) -> Command:
        delimiter = self.peek()
        if delimiter in ("", "\n", "\\"):
            self.fail("unterminated `s' command", len(self.text))
        self.pos += 1
        pattern = self.read_until(delimiter, "unterminated `s' command")
        replacement = self.read_until(delimiter, "unterminated `s' command")
        flags = 0
        while self.peek() not in ("", "\n", ";", "}", " ", "\t"):
            flag = self.peek()
            self.pos += 1
            if flag == "g":
                command.global_ = True
            elif flag == "p":
                command.print_ = True
            elif flag in ("i", "I"):
                flags |= re.IGNORECASE
            elif flag in ("m", "M"):
                flags |= re.MULTILINE
            elif flag.isdigit():
                start = self.pos - 1
                while self.peek().isdigit():
                    self.pos += 1
                command.count = int(self.text[start : self.pos])
            elif flag == "w":
                self.skip_blanks()
                while self.peek() not in ("", "\n"):
                    self.pos += 1
            else:
                self.fail("unknown option to `s'")
        command.regex = self.compile(pattern, flags) if pattern else None
        command.replacement = parse_replacement(replacement)
        return command

    def parse_transliterate(self, command: Command) -> Command:
        delimiter = self.peek()
        self.pos += 1
        source = self.read_until(delimiter, "unterminated `y' command")
        target = self.read_until(delimiter, "unterminated `y' command")
        source = _unescape_text(source)
        target = _unescape_text(target)
        if len(source) != len(target):
            self.fail("strings for `y' command are different lengths")
        command.source, command.target = source, target
        return command


def _unescape_text(text: str) -> str:
    return re.sub(r"\\(.)", lambda m: _TEXT_ESCAPES.get(m.group(1), m.group(1)), text)


def parse_replacement(text: str) -> list[tuple[str, Any]]:
    """Split an s replacement into literal text, "&" and \\N group parts."""
    parts: list[tuple[str, Any]] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt.isdigit():
                parts.append(("group", int(nxt)))
            else:
                parts.append(("text", _TEXT_ESCAPES.get(nxt, nxt)))
            i += 2
        elif ch == "&":
            parts.append(("group", 0))
            i += 1
        else:
            parts.append(("text", ch))
            i += 1
    return parts


def link_blocks(script: list[Command]) -> None:
    """Point each "{" at the index after its matching "}"."""
    stack: list[int] = []
    for index, command in enumerate(script):
        if command.name == "{":
            stack.append(index)
        elif command.name == "}":
            if not stack:
                _fail("sed: -e expression #1, char 0: unexpected `}'")
            script[stack.pop()].block_end = index + 1
    if stack:
        _fail("sed: -e expression #1, char 0: unmatched `{'")


def split_in_place(args: list[str]) -> tuple[list[str], str | None]:
    """Take GNU sed's -i[SUFFIX] and --in-place[=SUFFIX] out of ``args``. The
    suffix is glued to the option, which getopt only supports from Python
    3.14. Returns the remaining arguments and the backup suffix ("" for
    none), or None when there is no in-place option."""
    out: list[str] = []
    suffix: str | None = None
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            out += args[i - 1 :]
            break
        if arg == "--in-place" or arg.startswith("--in-place="):
            suffix = arg.partition("=")[2]
            continue
        if not arg.startswith("-") or arg.startswith("--") or arg == "-":
            out.append(arg)
            continue
        # A cluster of short options: -i ends it, taking the rest as suffix;
        # -e, -f and -l take the rest, or the next argument, as their value.
        for pos, ch in enumerate(arg[1:], 1):
            if ch == "i":
                suffix = arg[pos + 1 :]
                if pos > 1:
                    out.append(arg[:pos])
                break
            if ch in "efl":
                out.append(arg)
                if pos == len(arg) - 1 and i < len(args):
                    out.append(args[i])
                    i += 1
                break
        else:
            out.append(arg)
    return out, suffix


class Command_sed(HoneyPotCommand):
    """
    sed command
    """

    consumes_stdin = True

    def start(self) -> None:
        try:
            arguments, self.backup_suffix = split_in_place(self.args)
            optlist, args = getopt.gnu_getopt(
                arguments,
                "ne:f:Ersuz",
                [
                    "quiet",
                    "silent",
                    "expression=",
                    "file=",
                    "regexp-extended",
                    "separate",
                    "posix",
                    "debug",
                    "help",
                    "version",
                ],
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"sed: invalid option -- '{err.opt}'\n" + USAGE.split("\n\n")[0] + "\n"
            )
            self.exit_code = 1
            self.exit()
            return

        self.quiet = False
        self.extended = False
        self.in_place = self.backup_suffix is not None
        expressions: list[str] = []
        for opt, value in optlist:
            if opt in ("-n", "--quiet", "--silent"):
                self.quiet = True
            elif opt in ("-e", "--expression"):
                expressions.append(value)
            elif opt in ("-f", "--file"):
                try:
                    expressions.append(
                        self.fs.file_contents(
                            self.fs.resolve_path(value, self.cwd)
                        ).decode("utf-8", errors="replace")
                    )
                except fs.FileNotFound:
                    self.errorWrite(
                        f"sed: couldn't open file {value}: No such file or directory\n"
                    )
                    self.exit_code = 1
                    self.exit()
                    return
            elif opt in ("-E", "-r", "--regexp-extended"):
                self.extended = True
            elif opt == "--help":
                self.write(USAGE)
                self.exit()
                return
            elif opt == "--version":
                self.write("sed (GNU sed) 4.9\n")
                self.exit()
                return

        if not expressions:
            if not args:
                self.errorWrite(USAGE)
                self.exit_code = 1
                self.exit()
                return
            expressions.append(args.pop(0))

        try:
            self.script: list[Command] = []
            for number, text in enumerate(expressions, 1):
                self.script += ScriptParser(text, number, self.extended).parse()
            link_blocks(self.script)
        except SedError as err:
            self.errorWrite(f"{err}\n")
            self.exit_code = 1
            self.exit()
            return

        self.hold = ""
        self.last_regex: re.Pattern[str] | None = None
        if args:
            self.run_files(args)
        elif self.input_data is not None:
            self.writeBytes(self.run_script(self.input_data))
        else:
            # Reading the terminal: collect it until end of input.
            self.typed = b""
            return
        self.exit()

    def run_files(self, names: list[str]) -> None:
        streams: list[tuple[str, bytes]] = []
        for name in names:
            path = self.fs.resolve_path(name, self.cwd)
            if self.fs.isdir(path):
                self.errorWrite(f"sed: couldn't edit {name}: not a regular file\n")
                self.exit_code = 4
                continue
            try:
                streams.append((name, self.fs.file_contents(path)))
            except fs.FileNotFound:
                self.errorWrite(f"sed: can't read {name}: No such file or directory\n")
                self.exit_code = 2
        if self.in_place:
            for name, data in streams:
                if self.backup_suffix:
                    self.write_file(name + self.backup_suffix, data)
                self.write_file(name, self.run_script(data))
        else:
            self.writeBytes(self.run_script(b"".join(data for _, data in streams)))

    def write_file(self, name: str, data: bytes) -> None:
        """Replace a file's contents the way an output redirection does, so
        the new contents are captured like any other written file."""
        pp = PipeProtocol(
            self.protocol,
            None,
            [],
            None,
            None,
            [{"type": "file", "fd": 1, "target": name, "append": False}],
            cwd=self.cwd,
            user=self.user,
        )
        pp.outReceived(data)
        for real_path, virtual_path in pp.redirect_real_files:
            self.protocol.terminal.redirFiles.add((real_path, virtual_path))

    def matches(self, address: Address, pattern: str, number: int, last: bool) -> bool:
        if address.kind == "line":
            return number == address.line
        if address.kind == "last":
            return last
        assert address.regex is not None
        return address.regex.search(pattern) is not None

    def selected(self, command: Command, pattern: str, number: int, last: bool) -> bool:
        if command.addr1 is None:
            result = True
        elif command.addr2 is None:
            result = self.matches(command.addr1, pattern, number, last)
        elif command.in_range:
            end = command.addr2
            if end.kind == "line":
                done = number >= end.line
            else:
                done = self.matches(end, pattern, number, last)
            command.in_range = not done
            result = True
        elif self.matches(command.addr1, pattern, number, last):
            end = command.addr2
            command.in_range = not (end.kind == "line" and end.line <= number)
            result = True
        else:
            result = False
        return result != command.negate

    def substitute(self, command: Command, pattern: str) -> tuple[str, bool]:
        regex = command.regex or self.last_regex
        if regex is None:
            _fail("sed: no previous regular expression")
        self.last_regex = regex

        def expand(match: re.Match[str]) -> str:
            return "".join(
                part if kind == "text" else (match.group(part) or "")
                for kind, part in command.replacement
            )

        occurrence = 0
        replaced = False
        out: list[str] = []
        pos = 0
        for match in regex.finditer(pattern):
            occurrence += 1
            if occurrence < command.count:
                continue
            out.append(pattern[pos : match.start()])
            out.append(expand(match))
            pos = match.end()
            replaced = True
            if not command.global_:
                break
        out.append(pattern[pos:])
        return "".join(out), replaced

    def run_script(self, data: bytes) -> bytes:
        """Run the script over ``data``; a runtime error ends the run as it
        does in sed, keeping the output produced so far."""
        out: list[str] = []
        try:
            self._run(data, out)
        except SedError as err:
            self.errorWrite(f"{err}\n")
            self.exit_code = 1
        return "".join(out).encode("utf-8", errors="surrogateescape")

    def _run(self, data: bytes, out: list[str]) -> None:
        text = data.decode("utf-8", errors="surrogateescape")
        lines = text.split("\n")
        missing_newline = bool(lines[-1])
        if not lines[-1]:
            lines.pop()
        index = 0
        quit_now = False
        # D restarts the cycle on what is left of the pattern space instead of
        # reading the next line.
        restart: str | None = None
        number = 0
        while (restart is not None or index < len(lines)) and not quit_now:
            if restart is not None:
                pattern, restart = restart, None
            else:
                pattern = lines[index]
                index += 1
                number = index
            appended: list[str] = []
            substituted = False
            deleted = False
            pc = 0
            while pc < len(self.script):
                command = self.script[pc]
                last = index == len(lines)
                pc += 1
                if command.name == "}":
                    continue
                if not self.selected(command, pattern, number, last):
                    if command.name == "{":
                        pc = command.block_end
                    continue
                name = command.name
                if name == "s":
                    pattern, done = self.substitute(command, pattern)
                    substituted = substituted or done
                    if done and command.print_:
                        out.append(pattern + "\n")
                elif name == "y":
                    pattern = pattern.translate(
                        str.maketrans(command.source, command.target)
                    )
                elif name == "d" or (name == "D" and "\n" not in pattern):
                    deleted = True
                    break
                elif name == "D":
                    restart = pattern.split("\n", 1)[1]
                    deleted = True
                    break
                elif name == "p":
                    out.append(pattern + "\n")
                elif name == "P":
                    out.append(pattern.split("\n", 1)[0] + "\n")
                elif name == "=":
                    out.append(f"{number}\n")
                elif name == "a":
                    appended.append(command.text + "\n")
                elif name == "i":
                    out.append(command.text + "\n")
                elif name == "c":
                    if command.addr2 is None or not command.in_range:
                        out.append(command.text + "\n")
                    deleted = True
                    break
                elif name == "r":
                    try:
                        path = self.fs.resolve_path(command.text, self.cwd)
                        appended.append(
                            self.fs.file_contents(path).decode(
                                "utf-8", errors="surrogateescape"
                            )
                        )
                    except fs.FileNotFound:
                        pass
                elif name == "h":
                    self.hold = pattern
                elif name == "H":
                    self.hold += "\n" + pattern
                elif name == "g":
                    pattern = self.hold
                elif name == "G":
                    pattern += "\n" + self.hold
                elif name == "x":
                    pattern, self.hold = self.hold, pattern
                elif name == "z":
                    pattern = ""
                elif name == "n":
                    if index >= len(lines):
                        break
                    if not self.quiet:
                        out.append(pattern + "\n")
                    pattern = lines[index]
                    index += 1
                    number = index
                elif name == "N":
                    if index >= len(lines):
                        break
                    pattern += "\n" + lines[index]
                    index += 1
                    number = index
                elif name in ("b", "t", "T"):
                    jump = name == "b" or (name == "t") == substituted
                    if name in "tT":
                        substituted = False
                    if jump:
                        pc = self.label_index(command.label)
                elif name in "qQ":
                    self.exit_code = command.code
                    quit_now = True
                    if name == "Q":
                        deleted = True
                    break
            if not deleted and not self.quiet:
                out.append(pattern + "\n")
            out += appended
        # Like sed, keep a missing newline at the end of the input missing.
        if missing_newline and index >= len(lines) and out and out[-1].endswith("\n"):
            out[-1] = out[-1][:-1]

    def label_index(self, label: str) -> int:
        if not label:
            return len(self.script)
        for index, command in enumerate(self.script):
            if command.name == ":" and command.label == label:
                return index + 1
        return len(self.script)

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="sed",
            input=line,
        )
        self.typed += line.encode("utf-8") + b"\n"

    def eofReceived(self) -> None:
        self.writeBytes(self.run_script(self.typed))
        self.exit()


commands["/bin/sed"] = Command_sed
commands["/usr/bin/sed"] = Command_sed
commands["sed"] = Command_sed
