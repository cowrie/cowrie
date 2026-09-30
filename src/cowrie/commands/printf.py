# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The printf builtin: bash's format conversions, escapes, format reuse
# ABOUTME: over extra arguments, -v assignment and bash's error messages.

from __future__ import annotations

import re

from cowrie.shell.command import HoneyPotCommand

commands = {}

USAGE = "printf: usage: printf [-v var] format [arguments]\n"

# A conversion: flags, width, precision, ignored length modifiers, then the
# conversion character (absent when the format ends right after the "%").
_SPEC = re.compile(r"%([-+ #0']*)(\*|\d+)?(?:\.(\*|\d*))?[hjlLtz]*(.?)", re.DOTALL)

_SIMPLE_ESCAPES = {
    "a": b"\a",
    "b": b"\b",
    "e": b"\x1b",
    "E": b"\x1b",
    "f": b"\f",
    "n": b"\n",
    "r": b"\r",
    "t": b"\t",
    "v": b"\v",
    "\\": b"\\",
    '"': b'"',
    "'": b"'",
    "?": b"?",
}

_OCTAL = "01234567"
_HEX = "0123456789abcdefABCDEF"


class _Stop(Exception):
    """Output ends here: \\c in a %b argument, or a bad conversion."""


def _take(text: str, i: int, digits: str, limit: int) -> str:
    """The run of up to ``limit`` characters from ``digits`` at ``i``."""
    end = i
    while end < len(text) and end - i < limit and text[end] in digits:
        end += 1
    return text[i:end]


def expand_escapes(text: str, *, in_b: bool = False) -> tuple[bytes, bool]:
    """Expand backslash escapes as printf does in its format (``in_b`` False)
    or in a %b argument (``in_b`` True). Returns the bytes and whether a \\c
    in a %b argument ended the output."""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\" or i + 1 >= len(text):
            out += ch.encode("utf-8", errors="surrogateescape")
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _SIMPLE_ESCAPES:
            out += _SIMPLE_ESCAPES[nxt]
            i += 2
        elif in_b and nxt == "c":
            return bytes(out), True
        elif nxt in _OCTAL:
            # The format takes \NNN; %b takes \0NNN (and \NNN without the 0).
            start = i + 2 if in_b and nxt == "0" else i + 1
            digits = _take(text, start, _OCTAL, 3)
            out.append(int(digits or "0", 8) & 0xFF)
            i = start + len(digits)
        elif nxt == "x" and _take(text, i + 2, _HEX, 2):
            digits = _take(text, i + 2, _HEX, 2)
            out.append(int(digits, 16))
            i += 2 + len(digits)
        elif nxt in "uU" and _take(text, i + 2, _HEX, 4 if nxt == "u" else 8):
            digits = _take(text, i + 2, _HEX, 4 if nxt == "u" else 8)
            out += chr(int(digits, 16)).encode("utf-8", errors="surrogatepass")
            i += 2 + len(digits)
        else:
            out += b"\\" + nxt.encode("utf-8", errors="surrogateescape")
            i += 2
    return bytes(out), False


def _shell_quote(text: str) -> str:
    """Quote ``text`` so bash reads it back as one word, as %q does."""
    if text == "":
        return "''"
    return re.sub(r"([^\w@%+=:,./-])", r"\\\1", text)


class Command_printf(HoneyPotCommand):
    def call(self) -> None:
        args = list(self.args)
        var = None
        if args[:1] == ["-v"] and len(args) >= 2:
            var = args[1]
            args = args[2:]
        if args[:1] == ["--"]:
            args = args[1:]
        if not args:
            self.errorWrite(USAGE)
            self.exit_code = 2
            return

        self.status = 0
        out = bytearray()
        try:
            self._format(args[0], args[1:], out)
        except _Stop:
            pass
        if var is not None:
            self.environ[var] = out.decode("utf-8", errors="replace")
        else:
            self.writeBytes(bytes(out))
        self.exit_code = self.status

    def _error(self, message: str) -> None:
        self.errorWrite(f"{self.shell.error_prefix()}printf: {message}\n")
        self.status = 1

    def _format(self, fmt: str, args: list[str], out: bytearray) -> None:
        """Apply ``fmt`` to ``args``, reusing it while arguments remain."""
        while True:
            consumed = self._format_once(fmt, args, out)
            args = args[consumed:]
            if not args or consumed == 0:
                return

    def _format_once(self, fmt: str, args: list[str], out: bytearray) -> int:
        taken = 0

        def next_arg() -> str | None:
            nonlocal taken
            if taken < len(args):
                taken += 1
                return args[taken - 1]
            return None

        pos = 0
        for match in _SPEC.finditer(fmt):
            out += expand_escapes(fmt[pos : match.start()])[0]
            pos = match.end()
            flags, width, precision, conv = match.groups()
            if conv == "":
                self._error("`%': missing format character")
                raise _Stop
            if conv == "%":
                if flags or width or precision is not None:
                    self._error("`%': invalid format character")
                    raise _Stop
                out += b"%"
                continue
            if width == "*":
                width = str(self._integer(next_arg()))
            if precision == "*":
                precision = str(self._integer(next_arg()))
            spec = "%" + flags.replace("'", "") + (width or "")
            if precision is not None:
                spec += "." + (precision or "0")
            self._convert(spec, conv, next_arg(), out)
        out += expand_escapes(fmt[pos:])[0]
        return taken

    def _convert(self, spec: str, conv: str, arg: str | None, out: bytearray) -> None:
        """Append one conversion of ``arg`` to ``out``."""
        if conv in "sbqc":
            text = arg or ""
            stop = False
            if conv == "b":
                expanded, stop = expand_escapes(text, in_b=True)
                text = expanded.decode("utf-8", errors="surrogateescape")
            elif conv == "q":
                text = _shell_quote(text)
            elif conv == "c":
                text = text[:1]
                spec = spec.split(".")[0]
            out += ((spec + "s") % text).encode("utf-8", errors="surrogateescape")
            if stop:
                raise _Stop
            return
        out += self._number(spec, conv, arg)

    def _number(self, spec: str, conv: str, arg: str | None) -> bytes:
        if conv in "diouxX":
            value = self._integer(arg)
            if conv == "u":
                conv = "d"
                value %= 1 << 64
            elif conv in "oxX" and value < 0:
                value %= 1 << 64
            elif conv == "i":
                conv = "d"
            return ((spec + conv) % value).encode()
        if conv in "eEfFgGaA":
            number = self._float(arg)
            if conv in "aA":
                # C prints the shortest mantissa; float.hex() pads it with zeros.
                mantissa, exponent = number.hex().split("p")
                text = mantissa.rstrip("0").rstrip(".") + "p" + exponent
                return ((spec + "s") % (text.upper() if conv == "A" else text)).encode()
            return ((spec + conv) % number).encode()
        self._error(f"`{conv}': invalid format character")
        raise _Stop

    def _integer(self, arg: str | None) -> int:
        """Parse a printf integer argument the way bash does: a leading quote
        gives the next character's code, and a malformed number is reported
        and read up to where it stops being valid."""
        if arg is None:
            return 0
        text = arg.strip()
        if text[:1] in ("'", '"'):
            return ord(text[1]) if len(text) > 1 else 0
        match = re.match(r"[-+]?(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)", text)
        if not match or match.end() != len(text):
            self._error(f"{arg}: invalid number")
        if not match:
            return 0
        number = match.group(0)
        sign = -1 if number.startswith("-") else 1
        digits = number.lstrip("+-")
        if digits[:2].lower() == "0x":
            return sign * int(digits[2:], 16)
        if digits.startswith("0"):
            return sign * int(digits, 8)
        return sign * int(digits)

    def _float(self, arg: str | None) -> float:
        if arg is None:
            return 0.0
        text = arg.strip()
        if text[:1] in ("'", '"'):
            return float(ord(text[1])) if len(text) > 1 else 0.0
        match = re.match(r"[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?", text)
        if not match or match.end() != len(text):
            self._error(f"{arg}: invalid number")
        return float(match.group(0)) if match else 0.0


commands["/usr/bin/printf"] = Command_printf
commands["printf"] = Command_printf
