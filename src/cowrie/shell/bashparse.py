# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Lark-based bash-subset parser that turns a command line into a list
# ABOUTME: of statements (token lists, subshells, syntax errors) for the shell.

"""
A small Lark grammar and evaluator that tokenises a command line and resolves
its quoting, redirection, command substitution and subshells for the shell in
``honeypot.py``.

The parser produces a flat list of :class:`Statement` objects carrying the
joining operator (``;`` / ``&&`` / ``||``) and the still-unevaluated word trees.
Words are expanded only when a statement is about to run (see
:meth:`BashParser.evaluate`), so the shell can interleave parsing and execution
like a real shell. The control operators a real shell cares about — ``|`` and
the redirection operators — pass through as their own string tokens so the
existing ``CommandParser`` / ``runCommand`` machinery consumes the result
unchanged.

The grammar deliberately models only the subset of bash that Cowrie already
emulates: lists separated by ``;`` / ``&&`` / ``||``, pipelines, simple
redirections, single/double quoting, ``$VAR`` / ``${VAR}`` expansion, command
substitution (``$(...)`` and backticks) and subshells (``(...)``).

Known deviations from standard bash (none are emulated yet):

* A trailing ``&`` is treated as a literal argument, not a background job.
* No word expansions beyond ``$VAR`` / ``${VAR}``: tilde (``~``), brace
  (``{a,b}`` / ``{1..3}``), arithmetic (``$((...))``), the parameter
  expansion operators (``${x:-y}``, ``${#x}``, ``${x/a/b}`` ...), and ANSI-C
  quoting (``$'...'``) are all passed through literally.
* Pathname expansion (globbing of ``*`` / ``?`` / ``[...]``) is left to the
  individual command implementations, not done by the parser.
* Here-documents (``<<EOF``) and here-strings (``<<<``) are not supported; the
  operators are tokenised as plain ``<`` redirections.
* ``{ ...; }`` command grouping and reserved words (``for``/``if``/``while``
  ...) are parsed as ordinary commands, so the shell does not run loops or
  conditionals.
* The special parameters ``$@`` / ``$#`` / ``$*`` (and friends other than
  ``$?``) are passed through literally rather than expanded.

Input the grammar cannot parse at all (e.g. an unterminated quote) surfaces as
a syntax error, exactly as the previous implementation degraded on input it
could not handle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from lark import Lark, Token, Tree
from lark.exceptions import LarkError

# Grammar for the supported bash subset. Whitespace is significant as a word
# separator, so it is matched explicitly rather than ignored: adjacent atoms
# with no whitespace between them form a single word ("a"$x'b' -> one word).
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
_op: SEP | PIPE | AMP | IO_REDIR | REDIR

subshell: LPAR start RPAR

word: _atom+
_atom: sq | dq | cmdsub | backtick | dollar_brace | dollar_var | ESC | BARE_DOLLAR | LITERAL

cmdsub: "$(" start ")"

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

BARE_DOLLAR: "$"
LITERAL: /[^ \t\r\n|&;<>()$`'"\\]+/

// A "#" starts a comment only at a word boundary (higher priority than the
// LITERAL that would otherwise begin a word with "#"); a "#" inside a word
// such as "a#b" stays part of the LITERAL.
_COMMENT.2: /#[^\r\n]*/

_WS: /[ \t\r\n]+/
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
class SyntaxError_:
    """A bash-style syntax error to report verbatim.

    TODO: the trailing underscore avoids shadowing the builtin SyntaxError.
    Consider renaming to ParseError for clarity (touches honeypot.py and the
    tests).
    """

    token: str


Statement = Command | Subshell | SyntaxError_


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
        statements: list[Statement] = []
        units: list[Tree | Token] = []
        # The operator joining the statement currently being accumulated to the
        # previous one: None for the first, then ; / && / || as seen.
        current_op: str | None = None

        def flush() -> bool:
            """Turn the accumulated units into a statement. Return False to stop."""
            if not units:
                return True
            stmt = self._build_statement(line, units, current_op)
            units.clear()
            statements.append(stmt)
            return not isinstance(stmt, SyntaxError_)

        for child in tree.children:
            if isinstance(child, Token) and child.type == "SEP":
                if not units and child.value in ("&&", "||"):
                    statements.append(SyntaxError_(token=child.value))
                    return statements
                if not flush():
                    return statements
                current_op = child.value
                continue
            units.append(child)
        flush()
        return statements

    def _build_statement(
        self, line: str, units: list[Tree | Token], op: str | None
    ) -> Statement:
        # A subshell is valid only at the start of a statement. There it runs
        # in sequence with the surrounding line; anything piped after it is
        # ignored. A subshell anywhere else is a syntax error reported on the
        # "(" token, as bash does.
        # TODO: support a subshell as a real pipeline stage, e.g.
        # `(echo a) | wc -c`. We currently run the subshell and discard the
        # rest of the pipeline instead of feeding its output into the pipe.
        # bash also allows a subshell in the middle or end of a pipeline
        # (`x | (cmd)`), which we reject as a syntax error.
        subshell_idx = next(
            (
                i
                for i, u in enumerate(units)
                if isinstance(u, Tree) and u.data == "subshell"
            ),
            None,
        )
        if subshell_idx is not None:
            subshell = units[subshell_idx]
            assert isinstance(subshell, Tree)
            if subshell_idx == 0:
                return Subshell(
                    statements=self._subshell_statements(line, subshell), op=op
                )
            return SyntaxError_(token=self._error_token(line, subshell))

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
        # operator token (PIPE / AMP / REDIR / IO_REDIR) is a fixed string;
        # SEP never reaches here.
        items: list[str | Tree] = [
            unit.value if isinstance(unit, Token) else unit for unit in units
        ]
        return Command(items=items, line=line, op=op)

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
        # unquoted word. An unset or empty value drops the word; ``$?`` is 0.
        if len(atoms) == 1 and isinstance(atoms[0], Tree):
            only = atoms[0]
            if only.data in ("dollar_var", "dollar_brace"):
                name, special = self._var_name(only)
                if special == "?":
                    return self.context.get_status()
                if special is not None:
                    return self._leaf_value(only)  # verbatim, e.g. $@
                value = self.context.get_variable(name)
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
        name, special = self._var_name(node)
        if special == "?":
            return self.context.get_status()
        if special is not None:
            return self._leaf_value(node)
        value = self.context.get_variable(name)
        if value is None:
            return ""
        return value

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
