# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Unit tests for the Lark-based bashparse parser.
# ABOUTME: Covers tokenisation, quoting, redirection, substitution and subshells.

from __future__ import annotations

import unittest

from cowrie.shell.bashparse import (
    BashParser,
    Command,
    Subshell,
    SyntaxError_,
)


class FakeContext:
    """Minimal ShellContext: fixed variables and a recording substitution."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        self.env = env or {}
        self.substitutions: list[str] = []

    def get_variable(self, name: str) -> str | None:
        return self.env.get(name)

    def command_substitution(self, source: str) -> str:
        self.substitutions.append(source)
        # Echo back a marker so tests can assert the captured source text.
        return f"<{source.strip()}>"


class BashParseTokenTests(unittest.TestCase):
    """Tokenisation and quoting behaviour."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"LOGNAME": "root", "x": "hi"})
        self.parser = BashParser(self.ctx)

    def _tokens(self, line: str) -> list[str]:
        statements = self.parser.parse(line)
        self.assertEqual(len(statements), 1)
        self.assertIsInstance(statements[0], Command)
        return statements[0].tokens  # type: ignore[union-attr]

    def test_simple_words(self) -> None:
        self.assertEqual(self._tokens("echo hello world"), ["echo", "hello", "world"])

    def test_collapses_whitespace(self) -> None:
        self.assertEqual(self._tokens("echo   a    b"), ["echo", "a", "b"])

    def test_double_quotes_stripped(self) -> None:
        self.assertEqual(self._tokens('echo "a b"'), ["echo", "a b"])

    def test_adjacent_quotes_concatenate(self) -> None:
        self.assertEqual(self._tokens('echo "ls""ls"'), ["echo", "lsls"])

    def test_single_quote_inside_double(self) -> None:
        self.assertEqual(self._tokens("echo \"'ls'\""), ["echo", "'ls'"])

    def test_double_quote_inside_single(self) -> None:
        self.assertEqual(self._tokens("echo '\"ls\"'"), ["echo", '"ls"'])

    def test_backslash_n_in_double_quotes_kept(self) -> None:
        # bash does not treat \n specially inside double quotes
        self.assertEqual(self._tokens('echo "\\n"'), ["echo", "\\n"])

    def test_pipe_is_its_own_token(self) -> None:
        self.assertEqual(
            self._tokens("echo a | grep b"), ["echo", "a", "|", "grep", "b"]
        )


class BashParseVariableTests(unittest.TestCase):
    """Variable expansion, including the single-quote correctness fix."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"LOGNAME": "root", "x": "hi"})
        self.parser = BashParser(self.ctx)

    def _tokens(self, line: str) -> list[str]:
        statement = self.parser.parse(line)[0]
        assert isinstance(statement, Command)
        return statement.tokens

    def test_bare_variable_expands(self) -> None:
        self.assertEqual(self._tokens("echo $LOGNAME"), ["echo", "root"])

    def test_braced_variable_expands(self) -> None:
        self.assertEqual(self._tokens("echo ${LOGNAME}"), ["echo", "root"])

    def test_embedded_variable_expands(self) -> None:
        self.assertEqual(self._tokens('echo "X:$x"'), ["echo", "X:hi"])
        self.assertEqual(self._tokens("echo a${x}b"), ["echo", "ahib"])

    def test_bare_unset_variable_drops_word(self) -> None:
        self.assertEqual(self._tokens("echo $nope end"), ["echo", "end"])

    def test_embedded_unset_variable_kept_verbatim(self) -> None:
        # Deliberate compromise (see bashparse._expand_embedded): unset
        # references embedded in a token survive so quoted field references do.
        self.assertEqual(self._tokens('echo "X:$nope"'), ["echo", "X:$nope"])

    def test_single_quotes_never_expand(self) -> None:
        # Correctness improvement over the shlex path, which loses quoting and
        # would expand a set variable inside single quotes.
        self.assertEqual(self._tokens("echo '$LOGNAME'"), ["echo", "$LOGNAME"])

    def test_single_quoted_field_reference_survives(self) -> None:
        self.assertEqual(self._tokens("awk '{print $1}'"), ["awk", "{print $1}"])

    def test_question_mark_status(self) -> None:
        self.assertEqual(self._tokens("echo $?"), ["echo", "0"])


class BashParseRedirectionTests(unittest.TestCase):
    """Redirection operators are emitted as discrete tokens for runCommand."""

    def setUp(self) -> None:
        self.parser = BashParser(FakeContext())

    def _tokens(self, line: str) -> list[str]:
        statement = self.parser.parse(line)[0]
        assert isinstance(statement, Command)
        return statement.tokens

    def test_stdout_redirect(self) -> None:
        self.assertEqual(self._tokens("echo a > f"), ["echo", "a", ">", "f"])

    def test_inline_stderr_redirect(self) -> None:
        self.assertEqual(
            self._tokens("cmd 2>/dev/null"), ["cmd", "2", ">", "/dev/null"]
        )

    def test_fd_dup(self) -> None:
        self.assertEqual(self._tokens("cmd 2>&1"), ["cmd", "2", ">&", "1"])

    def test_append(self) -> None:
        self.assertEqual(self._tokens("cmd >> log"), ["cmd", ">>", "log"])


class BashParseStatementTests(unittest.TestCase):
    """Statement splitting, substitution and subshells."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"x": "hi"})
        self.parser = BashParser(self.ctx)

    def test_semicolon_splits(self) -> None:
        statements = self.parser.parse("echo a; echo b")
        self.assertEqual(
            [s.tokens for s in statements],  # type: ignore[union-attr]
            [["echo", "a"], ["echo", "b"]],
        )

    def test_and_or_split_like_semicolon(self) -> None:
        statements = self.parser.parse("a && b || c")
        self.assertEqual(
            [s.tokens for s in statements],  # type: ignore[union-attr]
            [["a"], ["b"], ["c"]],
        )

    def test_command_substitution_captures_source(self) -> None:
        statements = self.parser.parse("echo $(echo inner)")
        self.assertEqual(statements[0].tokens, ["echo", "<echo inner>"])  # type: ignore[union-attr]
        self.assertEqual(self.ctx.substitutions, ["echo inner"])

    def test_backtick_substitution(self) -> None:
        statements = self.parser.parse("echo `id`")
        self.assertEqual(statements[0].tokens, ["echo", "<id>"])  # type: ignore[union-attr]

    def test_nested_substitution_source(self) -> None:
        # The inner $(...) source is handed to the context verbatim; the nested
        # shell parses it recursively rather than the grammar flattening it.
        statements = self.parser.parse("echo $(echo $(echo deep))")
        self.assertEqual(self.ctx.substitutions, ["echo $(echo deep)"])
        self.assertEqual(statements[0].tokens, ["echo", "<echo $(echo deep)>"])  # type: ignore[union-attr]

    def test_subshell_alone(self) -> None:
        statements = self.parser.parse("(echo one; echo two)")
        self.assertEqual(len(statements), 1)
        self.assertIsInstance(statements[0], Subshell)
        self.assertEqual(statements[0].source, "echo one; echo two")  # type: ignore[union-attr]

    def test_subshell_after_semicolon(self) -> None:
        statements = self.parser.parse("echo first; (echo second)")
        self.assertIsInstance(statements[0], Command)
        self.assertIsInstance(statements[1], Subshell)

    def test_subshell_in_middle_is_syntax_error(self) -> None:
        statements = self.parser.parse("echo before (echo middle) after")
        self.assertIsInstance(statements[0], SyntaxError_)
        self.assertEqual(statements[0].token, "(echo")  # type: ignore[union-attr]

    def test_leading_andor_is_syntax_error(self) -> None:
        statements = self.parser.parse("&& echo a")
        self.assertIsInstance(statements[0], SyntaxError_)
        self.assertEqual(statements[0].token, "&&")  # type: ignore[union-attr]

    def test_commands_before_error_are_kept(self) -> None:
        # A syntax error stops parsing but earlier statements still run.
        statements = self.parser.parse("echo ok ; uname -a (bad) | tr a b")
        self.assertIsInstance(statements[0], Command)
        self.assertEqual(statements[0].tokens, ["echo", "ok"])  # type: ignore[union-attr]
        self.assertIsInstance(statements[1], SyntaxError_)

    def test_empty_line(self) -> None:
        self.assertEqual(self.parser.parse(""), [])

    def test_only_whitespace(self) -> None:
        self.assertEqual(self.parser.parse("   \t  "), [])


class BashParseCommentTests(unittest.TestCase):
    """A "#" starts a comment only at a word boundary, like bash."""

    def setUp(self) -> None:
        self.parser = BashParser(FakeContext())

    def _tokens(self, line: str) -> list[str]:
        statement = self.parser.parse(line)[0]
        assert isinstance(statement, Command)
        return statement.tokens

    def test_trailing_comment_dropped(self) -> None:
        self.assertEqual(self._tokens("echo foo #comment"), ["echo", "foo"])

    def test_hash_inside_word_kept(self) -> None:
        self.assertEqual(self._tokens("echo a#b"), ["echo", "a#b"])

    def test_whole_line_comment_yields_nothing(self) -> None:
        self.assertEqual(self.parser.parse("# just a comment"), [])

    def test_hash_in_quotes_not_a_comment(self) -> None:
        self.assertEqual(self._tokens('echo "a # b"'), ["echo", "a # b"])


if __name__ == "__main__":
    unittest.main()
