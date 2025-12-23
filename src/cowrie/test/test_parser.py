# ABOUTME: Unit tests for the shell command parser.
# ABOUTME: Tests token merging, redirection parsing, and edge cases.

from __future__ import annotations

import unittest

from cowrie.shell.parser import CommandParser


class MergeRedirectionTokensTests(unittest.TestCase):
    """Unit tests for CommandParser.merge_redirection_tokens()"""

    def setUp(self) -> None:
        self.parser = CommandParser()

    def test_no_redirections(self) -> None:
        tokens = ["echo", "hello", "world"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["echo", "hello", "world"])

    def test_simple_stdout_redirect(self) -> None:
        # ['echo', 'test', '>', 'file'] stays as is (no FD prefix)
        tokens = ["echo", "test", ">", "file"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["echo", "test", ">", "file"])

    def test_stderr_redirect_split(self) -> None:
        # ['2', '>', '/dev/null'] -> ['2>', '/dev/null']
        tokens = ["cat", "file", "2", ">", "/dev/null"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cat", "file", "2>", "/dev/null"])

    def test_stderr_append_split(self) -> None:
        # ['2', '>>', 'log'] -> ['2>>', 'log']
        tokens = ["cmd", "2", ">>", "log"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2>>", "log"])

    def test_fd_dup_split(self) -> None:
        # ['2', '>&', '1'] -> ['2>&1']
        tokens = ["cmd", "2", ">&", "1"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2>&1"])

    def test_fd_dup_with_ampersand_split(self) -> None:
        # ['1', '>', '&', '2'] -> ['1>&2']
        tokens = ["cmd", "1", ">", "&", "2"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "1>&2"])

    def test_stdout_stderr_merge(self) -> None:
        # ['>', '&'] -> ['>&']
        tokens = ["cmd", ">", "&", "file"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", ">&", "file"])

    def test_multiple_redirections(self) -> None:
        # Multiple redirections in one command
        tokens = ["cat", "2", ">", "/dev/null", "1", ">", "out"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cat", "2>", "/dev/null", "1>", "out"])

    def test_fd_before_pipe(self) -> None:
        # FD followed by pipe should not merge
        tokens = ["cmd", "2", "|", "other"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2", "|", "other"])

    def test_fd_at_end(self) -> None:
        # FD at end with no operator
        tokens = ["cmd", "2"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2"])

    def test_complex_fd_chain(self) -> None:
        # ['3', '>&', '1', '1', '>&', '2', '2', '>&', '3']
        tokens = ["cmd", "3", ">&", "1", "1", ">&", "2", "2", ">&", "3"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "3>&1", "1>&2", "2>&3"])


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

    def test_order_preserved(self) -> None:
        # Redirection order matters for FD duplication
        args = ["cmd", "2>&1", ">", "file"]
        _cleaned, ops = self.parser.parse_redirections(args)
        self.assertEqual(len(ops), 2)
        self.assertEqual(ops[0]["type"], "dup")
        self.assertEqual(ops[1]["type"], "file")
