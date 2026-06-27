# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Unit tests for the Lark-based bashparse parser.
# ABOUTME: Covers tokenisation, quoting, redirection, substitution and subshells.

from __future__ import annotations

import unittest

from cowrie.shell.bashparse import (
    BashParser,
    BraceGroup,
    CaseClause,
    Command,
    ForClause,
    FunctionDef,
    IfClause,
    Subshell,
    SyntaxError_,
    WhileClause,
)


class FakeContext:
    """Minimal ShellContext: fixed variables and a recording substitution."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        self.env = env or {}
        self.substitutions: list[str] = []
        self.status = "0"

    def get_variable(self, name: str) -> str | None:
        return self.env.get(name)

    def get_status(self) -> str:
        return self.status

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
        statement = self.parser.parse(line)[0]
        assert isinstance(statement, Command)
        return self.parser.evaluate(statement)

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
        return self.parser.evaluate(statement)

    def test_bare_variable_expands(self) -> None:
        self.assertEqual(self._tokens("echo $LOGNAME"), ["echo", "root"])

    def test_braced_variable_expands(self) -> None:
        self.assertEqual(self._tokens("echo ${LOGNAME}"), ["echo", "root"])

    def test_embedded_variable_expands(self) -> None:
        self.assertEqual(self._tokens('echo "X:$x"'), ["echo", "X:hi"])
        self.assertEqual(self._tokens("echo a${x}b"), ["echo", "ahib"])

    def test_unquoted_variable_after_literal_expands(self) -> None:
        # A bare $VAR directly after literal text must still expand, e.g.
        # PATH=$PATH:/x or url=$x/p.
        self.assertEqual(self._tokens("echo got=$x"), ["echo", "got=hi"])
        self.assertEqual(self._tokens("echo $x/p"), ["echo", "hi/p"])

    def test_bare_unset_variable_drops_word(self) -> None:
        self.assertEqual(self._tokens("echo $nope end"), ["echo", "end"])

    def test_embedded_unset_variable_expands_empty(self) -> None:
        # An embedded unset reference expands to empty, like bash. Single-quoted
        # refs stay literal (handled by the grammar), so awk/sed field idioms
        # still survive without a verbatim compromise.
        self.assertEqual(self._tokens('echo "X:$nope"'), ["echo", "X:"])
        self.assertEqual(self._tokens("echo a$nope"), ["echo", "a"])
        self.assertEqual(self._tokens("echo a${nope}b"), ["echo", "ab"])

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
        return self.parser.evaluate(statement)

    def test_stdout_redirect(self) -> None:
        self.assertEqual(self._tokens("echo a > f"), ["echo", "a", ">", "f"])

    def test_inline_stderr_redirect(self) -> None:
        # A file descriptor attached to the operator is one token.
        self.assertEqual(self._tokens("cmd 2>/dev/null"), ["cmd", "2>", "/dev/null"])

    def test_spaced_fd_is_an_argument(self) -> None:
        # Whitespace before ">" makes the digit a plain argument, not an fd
        # (bash: "echo 2 > f" writes "2" to f via stdout). See issue #2917.
        self.assertEqual(self._tokens("echo 2 > f"), ["echo", "2", ">", "f"])

    def test_fd_dup(self) -> None:
        self.assertEqual(self._tokens("cmd 2>&1"), ["cmd", "2>&", "1"])

    def test_append(self) -> None:
        self.assertEqual(self._tokens("cmd >> log"), ["cmd", ">>", "log"])

    def test_redirect_both_stdout_stderr(self) -> None:
        self.assertEqual(self._tokens("cmd &>/dev/null"), ["cmd", "&>", "/dev/null"])
        self.assertEqual(self._tokens("cmd &>> log"), ["cmd", "&>>", "log"])

    def test_missing_redirect_target_is_syntax_error(self) -> None:
        # A redirect with no target is a bash syntax error (issue #2920).
        for line in ("echo test >", "echo test 2>", "cmd >>"):
            statement = self.parser.parse(line)[0]
            self.assertIsInstance(statement, SyntaxError_)
            self.assertEqual(statement.token, "newline")  # type: ignore[union-attr]

    def test_redirect_before_operator_is_syntax_error(self) -> None:
        statement = self.parser.parse("echo x > | cat")[0]
        self.assertIsInstance(statement, SyntaxError_)
        self.assertEqual(statement.token, "|")  # type: ignore[union-attr]


class BashParseStatementTests(unittest.TestCase):
    """Statement splitting, substitution and subshells."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"x": "hi"})
        self.parser = BashParser(self.ctx)

    def _eval(self, statement: object) -> list[str]:
        assert isinstance(statement, Command)
        return self.parser.evaluate(statement)

    def test_semicolon_splits(self) -> None:
        statements = self.parser.parse("echo a; echo b")
        self.assertEqual(
            [self._eval(s) for s in statements],
            [["echo", "a"], ["echo", "b"]],
        )

    def test_and_or_split_like_semicolon(self) -> None:
        statements = self.parser.parse("a && b || c")
        self.assertEqual(
            [self._eval(s) for s in statements],
            [["a"], ["b"], ["c"]],
        )

    def test_command_substitution_captures_source(self) -> None:
        statements = self.parser.parse("echo $(echo inner)")
        self.assertEqual(self._eval(statements[0]), ["echo", "<echo inner>"])
        self.assertEqual(self.ctx.substitutions, ["echo inner"])

    def test_backtick_substitution(self) -> None:
        statements = self.parser.parse("echo `id`")
        self.assertEqual(self._eval(statements[0]), ["echo", "<id>"])

    def test_command_substitution_as_whole_statement(self) -> None:
        # A command substitution that is the entire statement, or an assignment
        # value, parses as one command word -- not a misparsed bare "$" next to
        # a "(...)" subshell (which used to be a syntax error).
        self.assertEqual(self._eval(self.parser.parse("$(id)")[0]), ["<id>"])
        self.assertEqual(self._eval(self.parser.parse("x=$(id)")[0]), ["x=<id>"])
        self.assertEqual(
            self._eval(self.parser.parse("var=$( (echo a; echo b) )")[0]),
            ["var=<(echo a; echo b)>"],
        )

    def test_nested_substitution_source(self) -> None:
        # The inner $(...) source is handed to the context verbatim; the nested
        # shell parses it recursively rather than the grammar flattening it.
        statements = self.parser.parse("echo $(echo $(echo deep))")
        self.assertEqual(self._eval(statements[0]), ["echo", "<echo $(echo deep)>"])
        self.assertEqual(self.ctx.substitutions, ["echo $(echo deep)"])

    def test_subshell_alone(self) -> None:
        statements = self.parser.parse("(echo one; echo two)")
        self.assertEqual(len(statements), 1)
        self.assertIsInstance(statements[0], Subshell)
        inner = statements[0].statements  # type: ignore[union-attr]
        self.assertEqual(
            [self._eval(s) for s in inner],
            [["echo", "one"], ["echo", "two"]],
        )

    def test_subshell_after_semicolon(self) -> None:
        statements = self.parser.parse("echo first; (echo second)")
        self.assertIsInstance(statements[0], Command)
        self.assertIsInstance(statements[1], Subshell)

    def test_substitution_is_lazy(self) -> None:
        # Command substitutions run when a statement is evaluated, not at parse
        # time; evaluating in order hits them in source order.
        statements = self.parser.parse("echo $(a); echo $(b)")
        self.assertEqual(self.ctx.substitutions, [])
        for statement in statements:
            self._eval(statement)
        self.assertEqual(self.ctx.substitutions, ["a", "b"])

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
        self.assertEqual(self._eval(statements[0]), ["echo", "ok"])
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
        return self.parser.evaluate(statement)

    def test_trailing_comment_dropped(self) -> None:
        self.assertEqual(self._tokens("echo foo #comment"), ["echo", "foo"])

    def test_hash_inside_word_kept(self) -> None:
        self.assertEqual(self._tokens("echo a#b"), ["echo", "a#b"])

    def test_whole_line_comment_yields_nothing(self) -> None:
        self.assertEqual(self.parser.parse("# just a comment"), [])

    def test_hash_in_quotes_not_a_comment(self) -> None:
        self.assertEqual(self._tokens('echo "a # b"'), ["echo", "a # b"])


class BashParseCompoundTests(unittest.TestCase):
    """Compound commands parse into their structured AST nodes."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"x": "hi"})
        self.parser = BashParser(self.ctx)

    def _one(self, line: str) -> object:
        statements = self.parser.parse(line)
        self.assertEqual(len(statements), 1)
        return statements[0]

    def _eval(self, command: object) -> list[str]:
        assert isinstance(command, Command)
        return self.parser.evaluate(command)

    def test_for_clause(self) -> None:
        node = self._one("for i in a b c; do echo $i; done")
        assert isinstance(node, ForClause)
        self.assertEqual(node.var, "i")
        self.assertEqual(self._eval(node.items), ["a", "b", "c"])
        self.assertEqual(len(node.body), 1)

    def test_for_multiline(self) -> None:
        node = self._one("for i in a b\ndo\n echo $i\ndone")
        assert isinstance(node, ForClause)
        self.assertEqual(self._eval(node.items), ["a", "b"])

    def test_if_clause(self) -> None:
        node = self._one("if true; then echo a; elif false; then echo b; else echo c; fi")
        assert isinstance(node, IfClause)
        self.assertEqual(len(node.branches), 2)
        self.assertIsNotNone(node.else_body)

    def test_while_clause(self) -> None:
        node = self._one("while true; do echo x; done")
        assert isinstance(node, WhileClause)
        self.assertFalse(node.until)

    def test_until_clause(self) -> None:
        node = self._one("until false; do echo x; done")
        assert isinstance(node, WhileClause)
        self.assertTrue(node.until)

    def test_case_clause(self) -> None:
        node = self._one("case $x in a) echo 1;; b|c) echo 2;; *) echo 3;; esac")
        assert isinstance(node, CaseClause)
        self.assertEqual([pats for pats, _ in node.items], [["a"], ["b", "c"], ["*"]])

    def test_brace_group(self) -> None:
        node = self._one("{ echo a; echo b; }")
        assert isinstance(node, BraceGroup)
        self.assertEqual(len(node.statements), 2)

    def test_function_paren_form(self) -> None:
        node = self._one("f() { echo hi; }")
        assert isinstance(node, FunctionDef)
        self.assertEqual(node.name, "f")

    def test_function_keyword_form(self) -> None:
        node = self._one("function g { echo g; }")
        assert isinstance(node, FunctionDef)
        self.assertEqual(node.name, "g")

    def test_newline_separates_statements(self) -> None:
        statements = self.parser.parse("echo a\necho b\necho c")
        self.assertEqual(len(statements), 3)
        self.assertEqual(self._eval(statements[0]), ["echo", "a"])

    def test_reserved_word_as_argument(self) -> None:
        # "done" outside a loop is an ordinary argument, not a keyword.
        node = self._one("echo done")
        self.assertEqual(self._eval(node), ["echo", "done"])

    def test_compound_join_operator(self) -> None:
        statements = self.parser.parse("true && for i in 1; do echo $i; done")
        self.assertIsInstance(statements[0], Command)
        self.assertIsInstance(statements[1], ForClause)
        self.assertEqual(statements[1].op, "&&")  # type: ignore[union-attr]

    def test_unterminated_for_is_error(self) -> None:
        node = self._one("for i in 1 2 3; do echo $i")
        self.assertIsInstance(node, SyntaxError_)


if __name__ == "__main__":
    unittest.main()
