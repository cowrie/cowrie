# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the $((...)) evaluator, checked against bash 5.3:
# ABOUTME: values, precedence, 64-bit wrapping, variables and error messages.

from __future__ import annotations

import unittest

from cowrie.shell.arithmetic import ArithmeticExpansionError, evaluate

VARIABLES = {"x": "3", "y": "x+1", "empty": "", "self": "self"}


def calc(expression: str) -> int:
    return evaluate(expression, VARIABLES.get)


class ArithmeticValueTests(unittest.TestCase):
    """Each expression gives the value bash 5.3 prints for it."""

    def test_values(self) -> None:
        for expression, value in (
            ("952*665+17", 633097),
            ("", 0),
            ("  ", 0),
            ("(1+2)*3", 9),
            (" 1 + (2 * (3 + (4))) ", 15),
            ("2**3**2", 512),
            ("-7/2", -3),
            ("-7%3", -1),
            ("1?2:3", 2),
            ("5 > 3 ? 10 : 20", 10),
            ("!5", 0),
            ("~0", -1),
            ("-+-1", 1),
            ("5>3&&2<1", 0),
            ("1 == 1 && 2 != 3", 1),
            ("6 & 3 | 8 ^ 1", 11),
            ("1<<62<<2", 0),
            ("1<<64", 1),
            ("1<<65", 2),
            ("-8>>1", -4),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(calc(expression), value)

    def test_numbers(self) -> None:
        for expression, value in (
            ("0x1f+010", 39),
            ("0X10", 16),
            ("10#08", 8),
            ("36#z", 35),
            ("2#101", 5),
            ("64#@", 62),
            ("64#_", 63),
            ("64#Z", 61),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(calc(expression), value)

    def test_wraps_at_64_bits(self) -> None:
        for expression, value in (
            ("9223372036854775807+1", -9223372036854775808),
            ("2**63", -9223372036854775808),
            ("-9223372036854775808 / -1", -9223372036854775808),
            ("-9223372036854775808 % -1", 0),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(calc(expression), value)

    def test_variables(self) -> None:
        for expression, value in (
            ("x*2", 6),
            ("y+1", 5),  # y's value is itself evaluated
            ("unset+1", 1),
            ("empty+1", 1),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(calc(expression), value)

    def test_skipped_branch_cannot_fail(self) -> None:
        for expression, value in (
            ("0 && 1/0", 0),
            ("1 || 1/0", 1),
            ("1 ? 2 : 1/0", 2),
        ):
            with self.subTest(expression=expression):
                self.assertEqual(calc(expression), value)


class ArithmeticErrorTests(unittest.TestCase):
    """Rejected expressions carry bash's message and error token."""

    def test_errors(self) -> None:
        for expression, message in (
            ("1/0", '1/0: division by 0 (error token is "0")'),
            ("7%0", '7%0: division by 0 (error token is "0")'),
            ("1/(2-2)", '1/(2-2): division by 0 (error token is "(2-2)")'),
            (
                "1+",
                '1+: arithmetic syntax error: operand expected (error token is "+")',
            ),
            (
                "2 3",
                '2 3: arithmetic syntax error in expression (error token is "3")',
            ),
            ("2**-1", '2**-1: exponent less than 0 (error token is "1")'),
            ("08", '08: value too great for base (error token is "08")'),
            (
                "self",
                'self: expression recursion level exceeded (error token is "self")',
            ),
        ):
            with self.subTest(expression=expression):
                with self.assertRaises(ArithmeticExpansionError) as caught:
                    calc(expression)
                self.assertEqual(str(caught.exception), message)

    def test_unsupported_operators_are_errors(self) -> None:
        for expression in ("x = 2", "x += 1", "x++", "1, 2"):
            with self.subTest(expression=expression):
                with self.assertRaises(ArithmeticExpansionError):
                    calc(expression)


if __name__ == "__main__":
    unittest.main()
