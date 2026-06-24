# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Lark-based bash-subset parser that turns a command line into a list
# ABOUTME: of statements (token lists, subshells, syntax errors) for the shell.

"""
A small Lark grammar and evaluator that tokenises a command line and resolves
its quoting, redirection, command substitution and subshells for the shell in
``honeypot.py``.

The parser produces a list of :class:`Statement` objects -- simple commands and
the compound commands ``for`` / ``if`` / ``while`` / ``until`` / ``case``, brace
groups, subshells and function definitions -- each carrying the operator that
joins it to the previous one (``;`` / ``&&`` / ``||``) and still-unevaluated word
trees. Words are expanded only when a statement is about to run (see
:meth:`BashParser.evaluate`), so the shell can interleave parsing and execution
like a real shell. The control operators a real shell cares about — ``|`` and
the redirection operators — pass through as their own string tokens so the
existing ``CommandParser`` / ``runCommand`` machinery consumes the result
unchanged.

There is a single tokeniser for the whole language: the Lark grammar lexes a
line (or a whole multi-line script) into word trees and control tokens, and the
recursive descent in :meth:`BashParser._parse_list` recognises reserved words
only at a command position to build the compound structure, exactly as a real
shell parses. Newlines separate statements like ``;`` so a script is parsed
directly rather than line-by-line.

The grammar models the subset of bash that Cowrie emulates: lists separated by
``;`` / newline / ``&&`` / ``||``, pipelines, simple redirections, single/double
quoting, ``$VAR`` / ``${VAR}`` expansion, command substitution (``$(...)`` and
backticks), subshells (``(...)``), the compound commands above, and function
definitions.

Known deviations from standard bash (none are emulated yet):

* A trailing ``&`` is treated as a literal argument, not a background job.
* No word expansions beyond ``$VAR`` / ``${VAR}``: tilde (``~``), brace
  (``{a,b}`` / ``{1..3}``), arithmetic (``$((...))``), the parameter
  expansion operators (``${x:-y}``, ``${#x}``, ``${x/a/b}`` ...), and ANSI-C
  quoting (``$'...'``) are all passed through literally.
* Word splitting is not applied to the result of an expansion, so a ``for``
  list built from ``$(cmd)`` or an unquoted ``$var`` holding spaces iterates
  once over the whole string rather than once per field.
* Pathname expansion (globbing of ``*`` / ``?`` / ``[...]``) is left to the
  individual command implementations, not done by the parser; ``case`` patterns
  are matched with fnmatch.
* Here-documents (``<<EOF``) and here-strings (``<<<``) are not supported; the
  operators are tokenised as plain ``<`` redirections.
* A compound command nested inside ``$(...)`` is not captured (its output is
  empty); command substitution captures simple commands and subshells only.
* ``$@`` / ``$#`` / ``$*`` expand to the positional parameters only while a
  function is running; elsewhere they are kept literally. Other special
  parameters (``$!``, ``$$`` ...) other than ``$?`` are kept literally.

Input the grammar cannot parse at all (e.g. an unterminated quote) surfaces as
a syntax error, exactly as the previous implementation degraded on input it
could not handle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from lark import Lark, Token, Tree
from lark.exceptions import LarkError

# Grammar for the supported bash subset. Whitespace is significant as a word
# separator, so it is matched explicitly rather than ignored: adjacent atoms
# with no whitespace between them form a single word ("a"$x'b' -> one word).
#
# The grammar is a single tokeniser for the whole language: it emits a flat
# stream of word trees and control tokens (separators, pipes, redirections,
# parentheses, ";;", newlines). The structure above a simple command --
# &&/|| lists, pipelines, and the compound commands for/if/while/until/case,
# brace groups and function definitions -- is recognised by the recursive
# descent in :meth:`BashParser._parse_list`, which reads reserved words only at
# a command position, exactly as a real shell does. Keeping one tokeniser means
# the script-level constructs reuse the same quoting, expansion and redirection
# lexing as a single interactive line.
_GRAMMAR = r"""
// A line is whitespace-separated content (words and subshells) broken up by the
// control operators. Whitespace is REQUIRED between two content words, so a run
// of atoms with no spaces is a single word (a"b"$c -> one word) while operators
// stay self-delimiting (echo a|b is three tokens). Requiring the space is also
// what keeps "$(...)" one command-substitution word instead of letting it be
// re-read as a bare "$" next to a "(...)" subshell.
start: _WS? _line? _WS?
_line: _run (_WS? _op _WS? _run)*
_run: (_content (_WS _content)*)?
_content: subshell | word | _COMMENT
_op: SEP | PIPE | AMP | IO_REDIR | REDIR | NEWLINE | LPAR | RPAR | DSEMI

// A balanced "(...)" group is preferred over the bare LPAR/RPAR tokens (rule
// priority), so a command substitution keeps the right extent for "$( (a) )"
// and a real subshell parses as one unit. A lone ")" with no matching "(" --
// the close of a case pattern like "x86*)" -- has no subshell parse available
// and falls back to the RPAR token, which the statement parser consumes.
subshell.10: LPAR start RPAR

word: _atom+
_atom: sq | dq | cmdsub | backtick | dollar_brace | dollar_var | ESC | BARE_DOLLAR | LITERAL

// An explicit, high-priority "$(" terminal so command substitution wins over a
// bare "$" followed by the LPAR token now that "(" is a self-standing operator.
cmdsub: CMDSUB_OPEN start ")"
CMDSUB_OPEN.6: "$("

backtick: "`" _bq_atom* "`"
_bq_atom: dollar_var | dollar_brace | BQ_LITERAL
BQ_LITERAL: /[^`]+/

dq: "\"" _dq_part* "\""
_dq_part: cmdsub | backtick | dollar_brace | dollar_var | DQ_ESC | DQ_TEXT
DQ_TEXT: /[^"$`\\]+/
DQ_ESC: /\\[\\"$`]/ | /\\/

sq: SQ
SQ: /'[^']*'/

dollar_brace: "${" BRACE_NAME "}"
BRACE_NAME: /[_a-zA-Z0-9]+/

// Higher priority than the bare BARE_DOLLAR so a "$" that begins a variable
// reference is lexed as one "$VAR" token even when it directly follows literal
// text in the same word ("got=$x", "$PATH:/x"), rather than splitting into a
// bare "$" plus a "VAR" literal.
dollar_var: DOLLAR_NAME | DOLLAR_SPECIAL
DOLLAR_NAME.2: /\$[_a-zA-Z0-9]+/
DOLLAR_SPECIAL.2: /\$[?@$#!*]/

ESC: /\\./

// ";;" (case item terminator) must win over a single ";".
DSEMI.7: ";;"
// Higher priority than the bare AMP so "&&" and "&>" win maximal munch.
SEP.2: "&&" | "||" | ";"
PIPE: "|"
AMP: "&"
// A redirection with a file descriptor directly attached to it ("2>", "2>&",
// "1>>"): one high-priority token so the digit is a file descriptor, not an
// argument. A digit separated by whitespace ("2 >") stays an ordinary word,
// which is how bash tells the two apart.
IO_REDIR.5: /\d+(?:>>|>&|>|<)/
REDIR.2: />>|>&|&>>|&>|>|</

LPAR: "("
RPAR: ")"
// A newline separates statements like ";" (so a multi-line script is parsed
// directly); a backslash-newline is a line continuation and counts as
// whitespace (see _WS below).
NEWLINE: /\r?\n/

BARE_DOLLAR: "$"
LITERAL: /[^ \t\r\n|&;<>()$`'"\\]+/

// A "#" starts a comment only at a word boundary (higher priority than the
// LITERAL that would otherwise begin a word with "#"); a "#" inside a word
// such as "a#b" stays part of the LITERAL.
_COMMENT.2: /#[^\r\n]*/

// Inline whitespace and line continuations only; a bare newline is NEWLINE.
_WS: /([ \t]|\\\r?\n)+/
"""

_parser = Lark(
    _GRAMMAR,
    start="start",
    parser="earley",
    lexer="dynamic",
    propagate_positions=True,
)


class ShellContext(Protocol):
    """What the evaluator needs from the live shell to evaluate words."""

    def get_variable(self, name: str) -> str | None:
        """Return the value of a shell variable, or None if unset."""

    def get_status(self) -> str:
        """Return ``$?`` -- the last command's exit status, as a string."""

    def command_substitution(self, source: str) -> str:
        """Execute ``source`` and return its captured stdout (newlines stripped)."""


@dataclass
class Command:
    """A simple command / pipeline, structure only.

    ``items`` keeps the ordered word trees (still unevaluated) interleaved with
    the control operator strings (``|``, ``>``, ``2>`` ...). Words are expanded
    against the live shell by :meth:`BashParser.evaluate` only when the command
    is about to run, so a same-line ``x=hi; echo $x`` sees the assignment.
    ``op`` is the operator that joins this statement to the previous one
    (``None`` / ``;`` / ``&&`` / ``||``); ``line`` is the source the word trees
    point into.
    """

    items: list[str | Tree] = field(default_factory=list)
    line: str = ""
    op: str | None = None


@dataclass
class Subshell:
    """A ``(...)`` group, holding its parsed (still unevaluated) inner statements.

    Cowrie does not emulate a subshell's isolated environment, so the caller
    runs these statements in order with the surrounding line. ``op`` joins this
    group to the previous statement.
    """

    statements: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class BraceGroup:
    """A ``{ ...; }`` command group: its statements run in the current shell."""

    statements: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class ForClause:
    """``for VAR in WORDS; do BODY; done``.

    ``items`` is a :class:`Command` whose words are the (unevaluated) ``in``
    list, expanded against the live shell when the loop runs.
    """

    var: str = ""
    items: Command | None = None
    body: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class IfClause:
    """``if COND; then BODY; [elif COND; then BODY;]* [else BODY;] fi``.

    ``branches`` pairs each condition statement-list with its body; ``else_body``
    is the optional trailing ``else`` arm.
    """

    branches: list[tuple[list[Statement], list[Statement]]] = field(
        default_factory=list
    )
    else_body: list[Statement] | None = None
    op: str | None = None


@dataclass
class WhileClause:
    """``while COND; do BODY; done`` (or ``until`` when ``until`` is True)."""

    condition: list[Statement] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    until: bool = False
    op: str | None = None


@dataclass
class CaseClause:
    """``case WORD in PATTERN[|PATTERN]) BODY ;; ... esac``.

    ``word`` is a :class:`Command` carrying the (unevaluated) word to match;
    ``items`` pairs each list of raw glob patterns with its body.
    """

    word: Command | None = None
    items: list[tuple[list[str], list[Statement]]] = field(default_factory=list)
    op: str | None = None


@dataclass
class FunctionDef:
    """``name() { BODY; }`` -- registers ``name`` for later invocation."""

    name: str = ""
    body: list[Statement] = field(default_factory=list)
    op: str | None = None


@dataclass
class SyntaxError_:
    """A bash-style syntax error to report verbatim.

    TODO: the trailing underscore avoids shadowing the builtin SyntaxError.
    Consider renaming to ParseError for clarity (touches honeypot.py and the
    tests).
    """

    token: str


Statement = (
    Command
    | Subshell
    | BraceGroup
    | ForClause
    | IfClause
    | WhileClause
    | CaseClause
    | FunctionDef
    | SyntaxError_
)

# Reserved words recognised only at a command position (the start of a
# statement). Anywhere else they are ordinary arguments, so ``echo done`` still
# prints "done", exactly as in bash.
_RESERVED = frozenset(
    {
        "for",
        "in",
        "do",
        "done",
        "if",
        "then",
        "elif",
        "else",
        "fi",
        "while",
        "until",
        "case",
        "esac",
        "function",
        "{",
        "}",
    }
)

# Tokens that end a simple command / pipeline (a separator or the close of an
# enclosing construct).
_STATEMENT_END = frozenset({"SEP", "NEWLINE", "DSEMI", "RPAR"})

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class _Cursor:
    """A forward cursor over the grammar's flat child stream."""

    def __init__(self, tokens: list[Tree | Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self, ahead: int = 0) -> Tree | Token | None:
        index = self.pos + ahead
        return self.tokens[index] if index < len(self.tokens) else None

    def next(self) -> Tree | Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token


class BashParser:
    """Parse a command line into a list of statements for the shell to run."""

    def __init__(self, context: ShellContext) -> None:
        self.context = context

    # -- public API ---------------------------------------------------------

    def parse(self, line: str) -> list[Statement]:
        """
        Parse ``line`` into ordered statements. Raises nothing for input the
        grammar rejects: it returns a single :class:`SyntaxError_` with an
        empty token so the caller can emit the generic message, matching the
        previous "unexpected end of file" fallback.
        """
        try:
            tree = _parser.parse(line)
        except LarkError:
            return [SyntaxError_(token="")]
        return self._split_statements(line, tree)

    # -- statement splitting ------------------------------------------------

    def _split_statements(self, line: str, tree: Tree) -> list[Statement]:
        """Recursive-descent parse of the flat token stream into statements."""
        cursor = _Cursor(list(tree.children))
        return self._parse_list(line, cursor, stop=frozenset())

    @staticmethod
    def _token_type(node: Tree | Token | None) -> str | None:
        return node.type if isinstance(node, Token) else None

    def _is_separator(self, node: Tree | Token | None) -> bool:
        return self._token_type(node) in ("SEP", "NEWLINE")

    def _separator_op(self, node: Tree | Token) -> str:
        """The join operator a separator implies: && / || keep their meaning;
        ``;``, a newline and ``&`` all sequence without gating."""
        if self._token_type(node) == "SEP":
            assert isinstance(node, Token)
            return node.value
        return ";"  # NEWLINE

    def _word_literal(self, node: Tree | Token | None) -> str | None:
        """Return the text of a word that is a single unquoted literal atom, else
        None. Keywords are recognised only through this, so a quoted or expanded
        word (``'for'``, ``$kw``) is never treated as reserved."""
        if not isinstance(node, Tree) or node.data != "word":
            return None
        if len(node.children) != 1:
            return None
        atom = node.children[0]
        if isinstance(atom, Token) and atom.type == "LITERAL":
            return str(atom.value)
        return None

    def _keyword(self, node: Tree | Token | None) -> str | None:
        text = self._word_literal(node)
        return text if text in _RESERVED else None

    def _parse_list(
        self, line: str, cursor: _Cursor, stop: frozenset[str]
    ) -> list[Statement]:
        """Parse statements separated by ``;`` / newline / ``&&`` / ``||`` until a
        reserved stop word, a ``)`` / ``;;`` token, or the end of input."""
        statements: list[Statement] = []
        pending_op: str | None = None
        seen = False

        while True:
            # Consume the separators between statements, tracking the operator
            # that will join the next statement to the previous one.
            while self._is_separator(cursor.peek()):
                node = cursor.next()
                value = self._separator_op(node)
                if value in ("&&", "||"):
                    if not seen:
                        # A leading && / || is a bash syntax error.
                        statements.append(SyntaxError_(token=value))
                        return statements
                    pending_op = value
                elif pending_op not in ("&&", "||"):
                    pending_op = ";"

            node = cursor.peek()
            if node is None:
                break
            if self._keyword(node) in stop:
                break
            if self._token_type(node) in ("DSEMI", "RPAR"):
                break

            statement = self._parse_statement(
                line, cursor, pending_op if seen else None
            )
            statements.append(statement)
            seen = True
            pending_op = None
            if isinstance(statement, SyntaxError_):
                return statements

        return statements

    def _parse_statement(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        node = cursor.peek()

        # A subshell at command position runs in sequence; anything piped after
        # it is dropped (see the pipeline TODO below).
        if isinstance(node, Tree) and node.data == "subshell":
            cursor.next()
            self._skip_to_statement_end(cursor)
            return Subshell(statements=self._subshell_statements(line, node), op=op)

        keyword = self._keyword(node)
        if keyword == "for":
            return self._parse_for(line, cursor, op)
        if keyword == "if":
            return self._parse_if(line, cursor, op)
        if keyword in ("while", "until"):
            return self._parse_while(line, cursor, op, until=keyword == "until")
        if keyword == "case":
            return self._parse_case(line, cursor, op)
        if keyword == "{":
            return self._parse_brace_group(line, cursor, op)
        if keyword == "function":
            return self._parse_function_keyword(line, cursor, op)
        if self._looks_like_funcdef(cursor):
            return self._parse_function(line, cursor, op)

        return self._parse_simple(line, cursor, op)

    def _parse_simple(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        """Gather one simple command / pipeline up to the next statement end."""
        units: list[Tree | Token] = []
        while True:
            node = cursor.peek()
            if node is None or self._token_type(node) in _STATEMENT_END:
                break
            # A "(...)" that survived as a unit here is a subshell in the middle
            # of a command -- a bash syntax error reported on the "(" token.
            if isinstance(node, Tree) and node.data == "subshell":
                return SyntaxError_(token=self._error_token(line, node))
            if self._token_type(node) == "LPAR":
                return SyntaxError_(token=self._error_token_at(line, node))
            units.append(cursor.next())
        return self._make_command(line, units, op)

    def _make_command(
        self, line: str, units: list[Tree | Token], op: str | None
    ) -> Statement:
        # A redirection operator must be followed by a target word. A redirect at
        # the end of a statement, or directly before another operator, is a bash
        # syntax error (e.g. `echo >` reports the unexpected token `newline').
        for i, unit in enumerate(units):
            if isinstance(unit, Token) and unit.type in ("REDIR", "IO_REDIR"):
                target = units[i + 1] if i + 1 < len(units) else None
                if target is None:
                    return SyntaxError_(token="newline")
                if isinstance(target, Token):
                    return SyntaxError_(token=target.value)

        # Keep the structure; words are evaluated later by evaluate(). An
        # operator token (PIPE / AMP / REDIR / IO_REDIR) is a fixed string.
        items: list[str | Tree] = [
            unit.value if isinstance(unit, Token) else unit for unit in units
        ]
        return Command(items=items, line=line, op=op)

    # -- compound commands --------------------------------------------------

    def _parse_for(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        cursor.next()  # "for"
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # NAME

        words: list[Tree] = []
        if self._keyword(cursor.peek()) == "in":
            cursor.next()  # "in"
            while True:
                node = cursor.peek()
                if node is None or self._is_separator(node):
                    break
                if self._keyword(node) == "do":
                    break
                if isinstance(node, Tree) and node.data == "word":
                    words.append(cursor.next())  # type: ignore[arg-type]
                    continue
                break

        self._skip_separators(cursor)
        if self._keyword(cursor.peek()) != "do":
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # "do"
        body = self._parse_list(line, cursor, stop=frozenset({"done"}))
        error = self._expect(cursor, "done")
        if error is not None:
            return error
        items = Command(items=list(words), line=line)
        return ForClause(var=name, items=items, body=body, op=op)

    def _parse_if(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        cursor.next()  # "if"
        branches: list[tuple[list[Statement], list[Statement]]] = []
        while True:
            condition = self._parse_list(line, cursor, stop=frozenset({"then"}))
            error = self._expect(cursor, "then")
            if error is not None:
                return error
            body = self._parse_list(
                line, cursor, stop=frozenset({"elif", "else", "fi"})
            )
            branches.append((condition, body))
            if self._keyword(cursor.peek()) == "elif":
                cursor.next()
                continue
            break

        else_body: list[Statement] | None = None
        if self._keyword(cursor.peek()) == "else":
            cursor.next()
            else_body = self._parse_list(line, cursor, stop=frozenset({"fi"}))

        error = self._expect(cursor, "fi")
        if error is not None:
            return error
        return IfClause(branches=branches, else_body=else_body, op=op)

    def _parse_while(
        self, line: str, cursor: _Cursor, op: str | None, until: bool
    ) -> Statement:
        cursor.next()  # "while" / "until"
        condition = self._parse_list(line, cursor, stop=frozenset({"do"}))
        error = self._expect(cursor, "do")
        if error is not None:
            return error
        body = self._parse_list(line, cursor, stop=frozenset({"done"}))
        error = self._expect(cursor, "done")
        if error is not None:
            return error
        return WhileClause(condition=condition, body=body, until=until, op=op)

    def _parse_case(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        cursor.next()  # "case"
        word_trees: list[Tree] = []
        while True:
            node = cursor.peek()
            if node is None or self._keyword(node) == "in" or self._is_separator(node):
                break
            if isinstance(node, Tree) and node.data == "word":
                word_trees.append(cursor.next())  # type: ignore[arg-type]
                continue
            break
        if self._keyword(cursor.peek()) != "in":
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # "in"
        self._skip_separators(cursor)

        items: list[tuple[list[str], list[Statement]]] = []
        while True:
            node = cursor.peek()
            if node is None or self._keyword(node) == "esac":
                break
            patterns, error = self._parse_case_patterns(line, cursor)
            if error is not None:
                return error
            body = self._parse_list(line, cursor, stop=frozenset({"esac"}))
            if self._token_type(cursor.peek()) == "DSEMI":
                cursor.next()
            self._skip_separators(cursor)
            items.append((patterns, body))

        error = self._expect(cursor, "esac")
        if error is not None:
            return error
        return CaseClause(word=Command(items=list(word_trees), line=line), items=items, op=op)

    def _parse_case_patterns(
        self, line: str, cursor: _Cursor
    ) -> tuple[list[str], Statement | None]:
        """Read ``pat[|pat]*)`` and return the raw pattern strings."""
        patterns: list[str] = []
        while True:
            node = cursor.peek()
            if node is None:
                return patterns, SyntaxError_(token="newline")
            if self._token_type(node) == "RPAR":
                cursor.next()
                return patterns, None
            if self._token_type(node) == "PIPE":
                cursor.next()
                continue
            if isinstance(node, Tree) and node.data == "word":
                patterns.append(self._word_source(line, node))
                cursor.next()
                continue
            return patterns, SyntaxError_(token=self._unexpected(line, cursor))

    def _parse_brace_group(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        cursor.next()  # "{"
        body = self._parse_list(line, cursor, stop=frozenset({"}"}))
        error = self._expect(cursor, "}")
        if error is not None:
            return error
        return BraceGroup(statements=body, op=op)

    def _looks_like_funcdef(self, cursor: _Cursor) -> bool:
        """Detect ``name ()`` at command position (the "()" lexes as LPAR RPAR,
        or as an empty subshell when separated by a space)."""
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return False
        after = cursor.peek(1)
        if isinstance(after, Tree) and after.data == "subshell":
            return not self._subshell_statements("", after)
        return (
            self._token_type(after) == "LPAR"
            and self._token_type(cursor.peek(2)) == "RPAR"
        )

    def _parse_function(self, line: str, cursor: _Cursor, op: str | None) -> Statement:
        name = self._word_literal(cursor.next())
        assert name is not None
        self._consume_empty_parens(cursor)
        return self._finish_function(line, cursor, name, op)

    def _parse_function_keyword(
        self, line: str, cursor: _Cursor, op: str | None
    ) -> Statement:
        cursor.next()  # "function"
        name = self._word_literal(cursor.peek())
        if name is None or not _NAME_RE.match(name):
            return SyntaxError_(token=self._unexpected(line, cursor))
        cursor.next()  # NAME
        self._consume_empty_parens(cursor)
        return self._finish_function(line, cursor, name, op)

    def _consume_empty_parens(self, cursor: _Cursor) -> None:
        node = cursor.peek()
        if isinstance(node, Tree) and node.data == "subshell":
            cursor.next()
        elif self._token_type(node) == "LPAR":
            cursor.next()
            if self._token_type(cursor.peek()) == "RPAR":
                cursor.next()

    def _finish_function(
        self, line: str, cursor: _Cursor, name: str, op: str | None
    ) -> Statement:
        self._skip_separators(cursor)
        if self._keyword(cursor.peek()) != "{":
            return SyntaxError_(token=self._unexpected(line, cursor))
        group = self._parse_brace_group(line, cursor, None)
        if isinstance(group, SyntaxError_):
            return group
        assert isinstance(group, BraceGroup)
        return FunctionDef(name=name, body=group.statements, op=op)

    # -- parser helpers -----------------------------------------------------

    def _skip_separators(self, cursor: _Cursor) -> None:
        while self._is_separator(cursor.peek()):
            cursor.next()

    def _skip_to_statement_end(self, cursor: _Cursor) -> None:
        """Drop tokens up to (not including) the next statement separator."""
        while True:
            node = cursor.peek()
            if node is None or self._token_type(node) in _STATEMENT_END:
                return
            cursor.next()

    def _expect(self, cursor: _Cursor, keyword: str) -> Statement | None:
        if self._keyword(cursor.peek()) != keyword:
            return SyntaxError_(token=self._unexpected("", cursor))
        cursor.next()
        return None

    def _unexpected(self, line: str, cursor: _Cursor) -> str:
        node = cursor.peek()
        if node is None:
            return "newline"
        if isinstance(node, Token):
            return str(node.value)
        if node.data == "word":
            return self._word_source(line, node) or "newline"
        return "newline"

    def _word_source(self, line: str, word: Tree) -> str:
        """The raw source text of a word, for keywords and case patterns."""
        if not line or word.meta.empty:
            literal = self._word_literal(word)
            return literal if literal is not None else ""
        return line[word.meta.start_pos : word.meta.end_pos]

    def _error_token_at(self, line: str, token: Token) -> str:
        start = getattr(token, "start_pos", None)
        if start is None:
            return "("
        end = start + 1
        while end < len(line) and not line[end].isspace() and line[end] != ")":
            end += 1
        return line[start:end]

    # -- word evaluation ----------------------------------------------------

    def evaluate(self, command: Command) -> list[str]:
        """Expand a command's words against the live context, now.

        Operator strings pass through; each word tree is evaluated against the
        current shell (variables, command substitution), and a word that
        resolves to nothing (an unquoted unset reference) is dropped.
        """
        tokens: list[str] = []
        for item in command.items:
            if isinstance(item, str):
                tokens.append(item)
                continue
            value = self._eval_word(command.line, item)
            if value is not None:
                tokens.append(value)
        return tokens

    def _eval_word(self, line: str, word: Tree) -> str | None:
        """Evaluate a word to its final string, or None if it should be dropped.

        A word is dropped when it is exactly an unquoted reference to an unset
        or empty variable, like ``echo $unset`` which yields no argument at all
        in a real shell.
        """
        atoms = word.children

        # Whole-word bare reference: ``$x`` / ``${x}`` as the entire,
        # unquoted word. An unset or empty value drops the word; a special
        # parameter like ``$?`` expands via _special_param.
        if len(atoms) == 1 and isinstance(atoms[0], Tree):
            only = atoms[0]
            if only.data in ("dollar_var", "dollar_brace"):
                special = self._special_param(only)
                if special is not None:
                    return special
                value = self.context.get_variable(self._var_name(only)[0])
                if not value:
                    return None
                return value

        parts: list[str] = []
        for atom in atoms:
            parts.append(self._eval_atom(line, atom))
        return "".join(parts)

    def _eval_atom(self, line: str, atom: Tree | Token) -> str:
        if isinstance(atom, Token):
            if atom.type == "ESC":
                # Unquoted backslash escape: the backslash is removed.
                return str(atom.value)[1:]
            return str(atom.value)

        if atom.data == "sq":
            return self._leaf_value(atom)[1:-1]  # strip surrounding quotes
        if atom.data == "dq":
            return self._eval_dquoted(line, atom)
        if atom.data == "dollar_var" or atom.data == "dollar_brace":
            return self._expand_embedded(atom)
        if atom.data == "cmdsub":
            return self.context.command_substitution(self._group_source(line, atom))
        if atom.data == "backtick":
            return self.context.command_substitution(self._backtick_source(line, atom))
        return ""

    def _eval_dquoted(self, line: str, dq: Tree) -> str:
        parts: list[str] = []
        for part in dq.children:
            if isinstance(part, Token):
                if part.type == "DQ_TEXT":
                    parts.append(part.value)
                elif part.type == "DQ_ESC":
                    parts.append(self._unescape_dq(part.value))
                continue
            if part.data == "dollar_var" or part.data == "dollar_brace":
                parts.append(self._expand_embedded(part))
            elif part.data == "cmdsub":
                parts.append(
                    self.context.command_substitution(self._group_source(line, part))
                )
            elif part.data == "backtick":
                parts.append(
                    self.context.command_substitution(self._backtick_source(line, part))
                )
        return "".join(parts)

    def _unescape_dq(self, text: str) -> str:
        # Inside double quotes a backslash is literal unless it precedes one of
        # \ " $ ` ; only then is it removed.
        if len(text) == 2 and text[1] in '\\"$`':
            return text[1]
        return text

    def _expand_embedded(self, node: Tree) -> str:
        """Expand a ``$VAR`` reference that is embedded in a larger word.

        A set variable expands to its value (empty included); an unset
        reference expands to the empty string, as bash does for an unquoted or
        double-quoted reference. A single-quoted reference is kept literal by
        the grammar (it never reaches here), so quoted awk/sed field references
        still survive.
        """
        special = self._special_param(node)
        if special is not None:
            return special
        value = self.context.get_variable(self._var_name(node)[0])
        if value is None:
            return ""
        return value

    def _special_param(self, node: Tree) -> str | None:
        """Expand a special parameter ($?, $@, $#, ...) to its string value, or
        None for an ordinary ``$name`` reference the caller should look up.

        ``$?`` is the last exit status. ``$@`` / ``$#`` / ``$*`` resolve to the
        positional parameters the shell sets while running a function; outside a
        function they are unset and kept verbatim. Other specials are kept
        verbatim.
        """
        _, special = self._var_name(node)
        if special is None:
            return None
        if special == "?":
            return self.context.get_status()
        if special in ("@", "#", "*"):
            value = self.context.get_variable(special)
            return value if value is not None else self._leaf_value(node)
        return self._leaf_value(node)

    def _leaf_value(self, node: Tree) -> str:
        """Return the string value of a node's single leaf token."""
        token = node.children[0]
        assert isinstance(token, Token)
        return str(token)

    def _var_name(self, node: Tree) -> tuple[str, str | None]:
        """Return (name, special) for a dollar_var/dollar_brace node."""
        if node.data == "dollar_brace":
            return self._leaf_value(node), None
        tok = node.children[0]
        assert isinstance(tok, Token)
        text = str(tok)
        if tok.type == "DOLLAR_SPECIAL":
            return text, text[1:]
        return text[1:], None  # DOLLAR_NAME: strip leading $

    # -- source slicing for substitution / subshells ------------------------

    def _subshell_statements(self, line: str, subshell: Tree) -> list[Statement]:
        """Parse the inner ``start`` tree of a ``(...)`` group into statements."""
        for child in subshell.children:
            if isinstance(child, Tree) and child.data == "start":
                return self._split_statements(line, child)
        return []

    def _group_source(self, line: str, node: Tree) -> str:
        """Raw source of the inner ``start`` tree of a ``$(...)`` or ``(...)``."""
        for child in node.children:
            if isinstance(child, Tree) and child.data == "start":
                if child.meta.empty:
                    return ""
                return line[child.meta.start_pos : child.meta.end_pos]
        return ""

    def _backtick_source(self, line: str, node: Tree) -> str:
        if node.meta.empty:
            return ""
        # Drop the surrounding backtick delimiters from the matched span.
        return line[node.meta.start_pos + 1 : node.meta.end_pos - 1]

    def _error_token(self, line: str, subshell: Tree) -> str:
        """Reconstruct bash's reported token for a misplaced ``(``.

        bash points at the ``(`` together with the run of non-space characters
        that follow it, e.g. ``(echo`` for ``( echo middle )`` written as
        ``(echo middle)``.
        """
        start = subshell.meta.start_pos
        end = start + 1
        while end < len(line) and not line[end].isspace() and line[end] != ")":
            end += 1
        return line[start:end]
