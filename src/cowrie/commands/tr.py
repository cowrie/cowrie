# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Emulates GNU coreutils tr: translate, delete (-d) and squeeze (-s)
# ABOUTME: bytes, with ranges, escapes, [:class:] names, -c and -t.

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}

TRY_HELP = "Try 'tr --help' for more information.\n"

_CLASSES: dict[str, bytes] = {
    "alnum": bytes(c for c in range(256) if chr(c).isascii() and chr(c).isalnum()),
    "alpha": bytes(c for c in range(256) if chr(c).isascii() and chr(c).isalpha()),
    "blank": b" \t",
    "cntrl": bytes([*range(32), 127]),
    "digit": b"0123456789",
    "graph": bytes(range(33, 127)),
    "lower": b"abcdefghijklmnopqrstuvwxyz",
    "print": bytes(range(32, 127)),
    "punct": bytes(c for c in range(33, 127) if not chr(c).isalnum()),
    "space": b" \t\n\v\f\r",
    "upper": b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "xdigit": b"0123456789ABCDEFabcdef",
}

_ESCAPES = {
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
    "\\": 92,
}


def _unescape(text: str) -> list[int]:
    """The bytes of a set string with its backslash escapes resolved."""
    raw = text.encode("utf-8", errors="surrogateescape")
    out: list[int] = []
    i = 0
    while i < len(raw):
        if raw[i] == 0x5C and i + 1 < len(raw):
            nxt = chr(raw[i + 1])
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            digits = b""
            j = i + 1
            while j < len(raw) and len(digits) < 3 and chr(raw[j]) in "01234567":
                digits += raw[j : j + 1]
                j += 1
            if digits:
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            out.append(raw[i + 1])
            i += 2
            continue
        out.append(raw[i])
        i += 1
    return out


def expand_set(text: str) -> bytes:
    """Expand a tr set: [:class:] names, then a-z ranges over the escaped
    bytes."""
    out = bytearray()
    rest = text
    while rest:
        if rest.startswith("[:"):
            end = rest.find(":]", 2)
            if end != -1 and rest[2:end] in _CLASSES:
                out += _CLASSES[rest[2:end]]
                rest = rest[end + 2 :]
                continue
        # Consume up to the next class name as plain text with ranges.
        nxt = rest.find("[:", 1)
        chunk, rest = (rest, "") if nxt == -1 else (rest[:nxt], rest[nxt:])
        values = _unescape(chunk)
        i = 0
        while i < len(values):
            if i + 2 < len(values) and values[i + 1] == ord("-"):
                low, high = values[i], values[i + 2]
                out += bytes(range(low, high + 1))
                i += 3
            else:
                out.append(values[i])
                i += 1
    return bytes(out)


class Command_tr(HoneyPotCommand):
    """
    tr command
    """

    consumes_stdin = True

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args,
                "cCdst",
                ["complement", "delete", "squeeze-repeats", "truncate-set1"],
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"tr: invalid option -- '{err.opt}'\n" + TRY_HELP)
            self.exit_code = 1
            self.exit()
            return

        opts = {opt for opt, _value in optlist}
        complement = bool(opts & {"-c", "-C", "--complement"})
        self.delete = bool(opts & {"-d", "--delete"})
        self.squeeze = bool(opts & {"-s", "--squeeze-repeats"})
        truncate = bool(opts & {"-t", "--truncate-set1"})

        error = self._operand_error(args)
        if error:
            self.errorWrite(error + TRY_HELP)
            self.exit_code = 1
            self.exit()
            return

        set1 = expand_set(args[0])
        if complement:
            set1 = bytes(c for c in range(256) if c not in set1)
        set2 = expand_set(args[1]) if len(args) > 1 else b""

        self.table: dict[int, int] = {}
        if not self.delete and set2:
            if truncate:
                set1 = set1[: len(set2)]
            padded = set2 + set2[-1:] * max(len(set1) - len(set2), 0)
            for source, target in zip(set1, padded, strict=False):
                self.table[source] = target
        self.deleted = set1 if self.delete else b""
        # Squeezing applies to the last set given: set2 when translating.
        self.squeezed = (set2 if set2 else set1) if self.squeeze else b""

        if self.input_data is not None:
            self.writeBytes(self.translate(self.input_data))
            self.exit()
        # else: wait for stdin via lineReceived / CTRL-D

    def _operand_error(self, args: list[str]) -> str | None:
        """GNU tr's message for a wrong number of set operands, or None."""
        if not args:
            return "tr: missing operand\n"
        if self.delete and not self.squeeze and len(args) > 1:
            return (
                f"tr: extra operand '{args[1]}'\n"
                "Only one string may be given when deleting without "
                "squeezing repeats.\n"
            )
        if not self.delete and not self.squeeze and len(args) == 1:
            return (
                f"tr: missing operand after '{args[0]}'\n"
                "Two strings must be given when translating.\n"
            )
        if len(args) > 2:
            return f"tr: extra operand '{args[2]}'\n"
        return None

    def translate(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            if byte in self.deleted:
                continue
            byte = self.table.get(byte, byte)
            if out and byte == out[-1] and byte in self.squeezed:
                continue
            out.append(byte)
        return bytes(out)

    def lineReceived(self, line: str) -> None:
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="tr",
            input=line,
        )
        self.writeBytes(self.translate(line.encode("utf-8") + b"\n"))

    def eofReceived(self) -> None:
        self.exit()


commands["/bin/tr"] = Command_tr
commands["/usr/bin/tr"] = Command_tr
commands["tr"] = Command_tr
