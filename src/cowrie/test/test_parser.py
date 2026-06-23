# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Unit tests for the shell command parser.
# ABOUTME: Tests redirection parsing of the tokens the grammar produces.

from __future__ import annotations

import unittest

from cowrie.shell.parser import CommandParser


class ParseRedirectionsTests(unittest.TestCase):
    """Unit tests for CommandParser.parse_redirections()"""

    def setUp(self) -> None:
        self.parser = CommandParser()

    def test_no_redirections(self) -> None:
        args = ["echo", "hello"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["echo", "hello"])
        self.assertEqual(ops, [])

    def test_stdout_to_file(self) -> None:
        args = ["echo", "test", ">", "file"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["echo", "test"])
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["type"], "file")
        self.assertEqual(ops[0]["fd"], 1)
        self.assertEqual(ops[0]["target"], "file")
        self.assertEqual(ops[0]["append"], False)

    def test_stdout_append(self) -> None:
        args = ["echo", "test", ">>", "file"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["echo", "test"])
        self.assertEqual(ops[0]["type"], "file")
        self.assertEqual(ops[0]["append"], True)

    def test_stderr_to_file(self) -> None:
        args = ["cmd", "2>", "errors"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["fd"], 2)
        self.assertEqual(ops[0]["target"], "errors")

    def test_stderr_to_devnull_inline(self) -> None:
        args = ["cmd", "2>/dev/null"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["target"], "/dev/null")

    def test_stdin_redirect(self) -> None:
        args = ["cat", "<", "input"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cat"])
        self.assertEqual(ops[0]["type"], "stdin")
        self.assertEqual(ops[0]["fd"], 0)
        self.assertEqual(ops[0]["target"], "input")

    def test_fd_duplication(self) -> None:
        args = ["cmd", "2>&1"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["type"], "dup")
        self.assertEqual(ops[0]["fd"], 2)
        self.assertEqual(ops[0]["target"], 1)

    def test_multiple_redirections(self) -> None:
        args = ["cmd", ">", "out", "2>", "err"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(len(ops), 2)
        self.assertEqual(ops[0]["target"], "out")
        self.assertEqual(ops[1]["target"], "err")

    def test_redirect_with_args(self) -> None:
        args = ["grep", "pattern", "file", ">", "output"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["grep", "pattern", "file"])
        self.assertEqual(ops[0]["target"], "output")

    def test_redirect_without_target(self) -> None:
        # '>' at end with no target should be kept as argument
        args = ["echo", ">"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["echo", ">"])
        self.assertEqual(ops, [])

    def test_custom_fd_redirect(self) -> None:
        args = ["cmd", "5>", "file"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["fd"], 5)

    def test_inline_target(self) -> None:
        # '>file' without space
        args = ["echo", ">file"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["echo"])
        self.assertEqual(ops[0]["target"], "file")

    def test_fd_close_syntax(self) -> None:
        # 2>&- should be parsed (even if not fully supported)
        args = ["cmd", "2>&-"]
        cleaned, _ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd"])
        # FD close is parsed but results in no operation currently

    def test_non_digit_after_dup(self) -> None:
        # >&file is treated as argument (not bash-style redirect)
        args = ["cmd", ">&file"]
        cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(cleaned, ["cmd", ">&file"])
        self.assertEqual(ops, [])

    def test_redirect_both_stdout_stderr(self) -> None:
        # &>file sends both stdout and stderr to the file (== >file 2>&1)
        cleaned, ops = self.parser.parse_redirections(["cmd", "&>", "file"])
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(
            ops,
            [
                {"type": "file", "fd": 1, "target": "file", "append": False},
                {"type": "dup", "fd": 2, "target": 1},
            ],
        )

    def test_redirect_both_append(self) -> None:
        cleaned, ops = self.parser.parse_redirections(["cmd", "&>>", "file"])
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["append"], True)
        self.assertEqual(ops[1], {"type": "dup", "fd": 2, "target": 1})

    def test_redirect_both_inline_target(self) -> None:
        cleaned, ops = self.parser.parse_redirections(["cmd", "&>file"])
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["target"], "file")

    def test_order_preserved(self) -> None:
        # Redirection order matters for FD duplication
        args = ["cmd", "2>&1", ">", "file"]
        _cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(len(ops), 2)
        self.assertEqual(ops[0]["type"], "dup")
        self.assertEqual(ops[1]["type"], "file")
