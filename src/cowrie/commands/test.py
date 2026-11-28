# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import stat
from typing import TYPE_CHECKING, Any, ClassVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_MODE, A_SIZE

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class _TestError(Exception):
    """A malformed test expression; ``test`` reports it and exits 2.

    Message templates live here so the call sites raise with a short tag,
    keeping the human-readable text in one place.
    """

    _MESSAGES: ClassVar[dict[str, str]] = {
        "too_many": "too many arguments",
        "integer": "integer expression expected",
        "unary": "{token}: unary operator expected",
        "binary": "{token}: binary operator expected",
    }

    def __init__(self, kind: str, token: str = "") -> None:
        super().__init__(self._MESSAGES[kind].format(token=token))


class Command_test(HoneyPotCommand):
    """The ``test`` / ``[`` conditional utility.

    Evaluates an expression and exits 0 (true) or 1 (false); a malformed
    expression exits 2. Supports the operators shell scripts rely on for flow
    control: file tests against the emulated filesystem (``-e -f -d -r -w -x
    -s -L -h -b -c -p -S -g -u -k``), string tests (``-z -n``, ``= == != < >``)
    and integer comparisons (``-eq -ne -lt -le -gt -ge``), plus ``!`` negation
    and ``-a`` / ``-o`` combination.

    Invoked as ``[`` the final argument must be ``]``.
    """

    # Set by the ``[`` alias so the closing bracket is required.
    require_bracket: bool = False
    name: str = "test"

    _STRING_OPS = ("=", "==", "!=", "<", ">")
    _INT_OPS = ("-eq", "-ne", "-lt", "-le", "-gt", "-ge")
    _UNARY_FILE_OPS = (
        "-e",
        "-f",
        "-d",
        "-r",
        "-w",
        "-x",
        "-s",
        "-L",
        "-h",
        "-b",
        "-c",
        "-p",
        "-S",
        "-g",
        "-u",
        "-k",
    )

    def call(self) -> None:
        args = list(self.args)
        if self.require_bracket:
            if not args or args[-1] != "]":
                self.errorWrite(f"{self.name}: missing `]'\n")
                self.exit_code = 2
                return
            args = args[:-1]

        try:
            result = self._eval(args)
        except _TestError as exc:
            self.errorWrite(f"{self.name}: {exc}\n")
            self.exit_code = 2
            return
        self.exit_code = 0 if result else 1

    def _eval(self, args: list[str]) -> bool:
        n = len(args)
        if n == 0:
            return False
        if n == 1:
            # A single argument is true when it is a non-empty string.
            return args[0] != ""
        if args[0] == "!":
            # Negation of the remaining expression.
            return not self._eval(args[1:])
        if n == 2:
            return self._unary(args[0], args[1])
        if n == 3:
            # `STR1 -a STR2` / `STR1 -o STR2` combine two single-argument
            # (non-empty) tests; otherwise the middle word is a binary operator.
            if args[1] == "-a":
                return self._eval(args[:1]) and self._eval(args[2:])
            if args[1] == "-o":
                return self._eval(args[:1]) or self._eval(args[2:])
            return self._binary(args[0], args[1], args[2])
        if n == 4 and args[0] == "(" and args[3] == ")":
            return self._eval(args[1:3])
        # `EXPR -a EXPR` / `EXPR -o EXPR`: bash deprecates these, but scripts
        # still use them. Split on the first top-level -a / -o we find.
        for combiner in ("-o", "-a"):
            if combiner in args:
                idx = args.index(combiner)
                left = self._eval(args[:idx])
                right = self._eval(args[idx + 1 :])
                return (left or right) if combiner == "-o" else (left and right)
        raise _TestError("too_many")

    def _unary(self, op: str, operand: str) -> bool:
        if op == "-z":
            return len(operand) == 0
        if op == "-n":
            return len(operand) != 0
        if op in self._UNARY_FILE_OPS:
            return self._file_test(op, operand)
        raise _TestError("unary", op)

    def _binary(self, left: str, op: str, right: str) -> bool:
        if op in self._STRING_OPS:
            if op in ("=", "=="):
                return left == right
            if op == "!=":
                return left != right
            if op == "<":
                return left < right
            return left > right  # ">"
        if op in self._INT_OPS:
            try:
                a, b = int(left), int(right)
            except ValueError:
                raise _TestError("integer", op) from None
            return {
                "-eq": a == b,
                "-ne": a != b,
                "-lt": a < b,
                "-le": a <= b,
                "-gt": a > b,
                "-ge": a >= b,
            }[op]
        raise _TestError("binary", op)

    def _file_test(self, op: str, operand: str) -> bool:
        if not operand:
            # An empty path is not any kind of file: bash reports every file
            # test on "" as false. Short-circuit before resolving it.
            return False
        path = self.fs.resolve_path(operand, self.cwd)
        if op in ("-L", "-h"):
            try:
                return bool(self.fs.islink(path))
            except Exception:
                return False
        if op == "-d":
            return bool(self.fs.isdir(path))
        if op == "-f":
            return bool(self.fs.isfile(path))
        if op == "-e":
            return bool(self.fs.exists(path))
        if op in ("-r", "-w"):
            # No per-user permission model; treat any existing path as readable
            # and writable, which is true for the honeypot's root sessions.
            return bool(self.fs.exists(path))
        if op == "-x":
            return self._has_mode(path, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if op == "-s":
            entry = self._stat(path)
            return entry is not None and entry[A_SIZE] > 0
        if op == "-g":
            return self._has_mode(path, stat.S_ISGID)
        if op == "-u":
            return self._has_mode(path, stat.S_ISUID)
        if op == "-k":
            return self._has_mode(path, stat.S_ISVTX)
        # -b -c -p -S: special file types we do not model; report absent.
        return False

    def _stat(self, path: str) -> list[Any] | None:
        try:
            entry: list[Any] | None = self.fs.getfile(path)
        except Exception:
            return None
        return entry

    def _has_mode(self, path: str, mask: int) -> bool:
        entry = self._stat(path)
        if entry is None:
            return False
        try:
            return bool(entry[A_MODE] & mask)
        except (IndexError, TypeError):
            return False


class Command_lbracket(Command_test):
    """The ``[`` alias of ``test``; requires a closing ``]``."""

    require_bracket = True
    name = "["


commands["test"] = Command_test
commands["/usr/bin/test"] = Command_test
commands["["] = Command_lbracket
commands["/usr/bin/["] = Command_lbracket
