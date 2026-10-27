# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Integer arithmetic for $((...)) as bash evaluates it: 64-bit
# ABOUTME: signed integers, C operator precedence, shell variables by name.

"""
Arithmetic expansion.

:func:`evaluate` computes the text between ``$((`` and ``))`` after the
shell has expanded any ``$name`` and command substitutions in it. The
supported operators are, from lowest to highest precedence::

    ?:   ||   &&   |   ^   &   == !=   < > <= >=   << >>   + -   * / %   **
    unary + - ! ~

with parentheses for grouping. Numbers are decimal, octal (``010``), hex
(``0x1f``) or ``base#digits``. A bare name is a shell variable: unset or
empty is 0, anything else is itself evaluated as an expression. Results wrap
at 64 bits like bash's ``intmax_t``.

Not supported, reported as a syntax error: assignment operators (``=``,
``+=`` ...), increment and decrement (``++`` / ``--``), and the comma
operator.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_INT_BITS = 64
_INT_MOD = 1 << _INT_BITS
_INT_MIN = -(1 << (_INT_BITS - 1))

# Digit values for base#digits up to base 64. Up to base 36 letters of either
# case are 10-35; above it, lowercase is 10-35 and uppercase 36-61.
_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_"

# How deeply a variable's value may refer to further variables before bash
# gives up, which also stops a self-reference such as x=x
_MAX_RECURSION = 32

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<number>[0-9][0-9a-zA-Z@_#]*)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\*\*|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%<>&^|!~?:()])
    """,
    re.VERBOSE,
)

# Binary operators by precedence level, lowest first; ** is handled apart
# because it is right-associative
_BINARY_LEVELS: tuple[frozenset[str], ...] = (
    frozenset({"||"}),
    frozenset({"&&"}),
    frozenset({"|"}),
    frozenset({"^"}),
    frozenset({"&"}),
    frozenset({"==", "!="}),
    frozenset({"<", ">", "<=", ">="}),
    frozenset({"<<", ">>"}),
    frozenset({"+", "-"}),
    frozenset({"*", "/", "%"}),
)


class ArithmeticExpansionError(Exception):
    """An expression bash would reject, with bash's message for it."""

    def __init__(self, expression: str, message: str, token: str) -> None:
        super().__init__(f'{expression}: {message} (error token is "{token}")')


def _wrap(value: int) -> int:
    """Reduce ``value`` to a 64-bit signed integer, as C arithmetic does."""
    value %= _INT_MOD
    return value - _INT_MOD if value >= -_INT_MIN else value


class _Evaluator:
    """Parse and evaluate one expression by precedence climbing.

    ``evaluating`` is False in the branch that ``&&``, ``||`` or ``?:`` skips:
    that branch is still parsed, but cannot fail on a division by zero.
    """

    def __init__(
        self, expression: str, lookup: Callable[[str], str | None], depth: int
    ) -> None:
        self.expression = expression
        self.lookup = lookup
        self.depth = depth
        self.tokens: list[tuple[str, str, int]] = []  # (kind, text, offset)
        pos = 0
        while pos < len(expression):
            match = _TOKEN.match(expression, pos)
            if match is None:
                self.fail("arithmetic syntax error: invalid arithmetic operator", pos)
            assert match is not None and match.lastgroup is not None
            if match.lastgroup != "space":
                self.tokens.append((match.lastgroup, match.group(), pos))
            pos = match.end()
        self.index = 0
        self.evaluating = True

    def fail(self, message: str, offset: int) -> None:
        raise ArithmeticExpansionError(
            self.expression, message, self.expression[offset:].strip()
        )

    def peek(self) -> str | None:
        if self.index < len(self.tokens):
            return self.tokens[self.index][1]
        return None

    def offset(self) -> int:
        """Where the next token starts, or the end of the expression."""
        if self.index < len(self.tokens):
            return self.tokens[self.index][2]
        return len(self.expression)

    def run(self) -> int:
        if not self.tokens:
            return 0
        value = self.ternary()
        if self.index < len(self.tokens):
            self.fail("arithmetic syntax error in expression", self.offset())
        return value

    def ternary(self) -> int:
        condition = self.binary(0)
        if self.peek() != "?":
            return condition
        self.index += 1
        outer = self.evaluating
        self.evaluating = outer and condition != 0
        then = self.ternary()
        if self.peek() != ":":
            self.fail(
                "arithmetic syntax error: `:' expected for conditional expression",
                self.offset(),
            )
        self.index += 1
        self.evaluating = outer and condition == 0
        otherwise = self.ternary()
        self.evaluating = outer
        return then if condition else otherwise

    def binary(self, level: int) -> int:
        if level == len(_BINARY_LEVELS):
            return self.power()
        left = self.binary(level + 1)
        while (op := self.peek()) in _BINARY_LEVELS[level]:
            self.index += 1
            outer = self.evaluating
            if op == "&&":
                self.evaluating = outer and left != 0
            elif op == "||":
                self.evaluating = outer and left == 0
            right_offset = self.offset()
            right = self.binary(level + 1)
            self.evaluating = outer
            left = self.apply(op, left, right, right_offset)
        return left

    def power(self) -> int:
        base = self.unary()
        if self.peek() != "**":
            return base
        self.index += 1
        exponent = self.power()  # right-associative
        if exponent < 0:
            if self.evaluating:
                self.fail("exponent less than 0", self.tokens[self.index - 1][2])
            return 0
        return _wrap(pow(base, exponent, _INT_MOD))

    def unary(self) -> int:
        op = self.peek()
        if op in ("+", "-", "!", "~"):
            self.index += 1
            value = self.unary()
            if op == "-":
                return _wrap(-value)
            if op == "!":
                return int(value == 0)
            if op == "~":
                return _wrap(~value)
            return value
        return self.operand()

    def operand(self) -> int:
        if self.index >= len(self.tokens):
            previous = self.tokens[self.index - 1][2] if self.tokens else 0
            self.fail("arithmetic syntax error: operand expected", previous)
        kind, text, offset = self.tokens[self.index]
        self.index += 1
        if text == "(":
            value = self.ternary()
            if self.peek() != ")":
                self.fail("arithmetic syntax error: `)' expected", self.offset())
            self.index += 1
            return value
        if kind == "number":
            return self.number(text, offset)
        if kind == "name":
            return self.variable(text, offset)
        self.fail("arithmetic syntax error: operand expected", offset)
        return 0  # not reached: fail() raises

    def number(self, text: str, offset: int) -> int:
        base, digits = 10, text
        if "#" in text:
            prefix, digits = text.split("#", 1)
            base = int(prefix) if prefix.isdigit() else 0
            if not 2 <= base <= 64:
                self.fail("invalid arithmetic base", offset)
        elif text[:2] in ("0x", "0X"):
            base, digits = 16, text[2:]
        elif len(text) > 1 and text[0] == "0":
            base = 8
        if base <= 36:
            digits = digits.lower()
        value = 0
        for digit in digits:
            place = _DIGITS.find(digit)
            if not 0 <= place < base:
                self.fail("value too great for base", offset)
            value = value * base + place
        if not digits:
            self.fail("invalid number", offset)
        return _wrap(value)

    def variable(self, name: str, offset: int) -> int:
        value = self.lookup(name)
        if value is None or not value.strip():
            return 0
        if self.depth >= _MAX_RECURSION:
            self.fail("expression recursion level exceeded", offset)
        return _Evaluator(value, self.lookup, self.depth + 1).run()

    def apply(self, op: str, left: int, right: int, right_offset: int) -> int:
        if op in ("/", "%"):
            if right == 0:
                if self.evaluating:
                    self.fail("division by 0", right_offset)
                return 0
            # C division truncates toward zero; the remainder takes the
            # dividend's sign
            quotient = abs(left) // abs(right)
            if (left < 0) != (right < 0):
                quotient = -quotient
            return _wrap(quotient if op == "/" else left - right * quotient)
        match op:
            case "+":
                return _wrap(left + right)
            case "-":
                return _wrap(left - right)
            case "*":
                return _wrap(left * right)
            case "<<":
                return _wrap(left << (right & (_INT_BITS - 1)))
            case ">>":
                return left >> (right & (_INT_BITS - 1))
            case "<":
                return int(left < right)
            case ">":
                return int(left > right)
            case "<=":
                return int(left <= right)
            case ">=":
                return int(left >= right)
            case "==":
                return int(left == right)
            case "!=":
                return int(left != right)
            case "&":
                return left & right
            case "^":
                return left ^ right
            case "|":
                return left | right
            case "&&":
                return int(left != 0 and right != 0)
            case "||":
                return int(left != 0 or right != 0)
            case _:
                raise AssertionError(op)


def evaluate(expression: str, lookup: Callable[[str], str | None]) -> int:
    """Evaluate an arithmetic expression; ``lookup`` returns a shell
    variable's value, or None when it is unset.

    Raises :class:`ArithmeticExpansionError` for an expression bash rejects.
    """
    return _Evaluator(expression, lookup, 0).run()
