# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Lark-based bash-subset parser that turns a command line into a list
# ABOUTME: of statements (token lists, subshells, syntax errors) for the shell.

"""
A small Lark grammar and evaluator that replaces the ``shlex`` based
tokenisation and the hand-rolled command-substitution / subshell scanning in
``honeypot.py``.

The parser produces a flat list of :class:`Statement` objects. Words are fully
evaluated (variable expansion and command substitution applied), while the
control operators a real shell cares about — ``|`` and the redirection
operators — are emitted as their own string tokens so the existing
``CommandParser`` / ``runCommand`` machinery can consume the result unchanged.

The grammar deliberately models only the subset of bash that Cowrie already
emulates: lists separated by ``;`` / ``&&`` / ``||``, pipelines, simple
redirections, single/double quoting, ``$VAR`` / ``${VAR}`` expansion, command
substitution (``$(...)`` and backticks) and subshells (``(...)``). Constructs
outside that subset (here-docs, arithmetic expansion, process substitution)
are intentionally unsupported and surface as a syntax error, exactly as the
previous implementation degraded on input it could not handle.
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
start: _WS? (_unit (_WS? _unit)*)? _WS?

_unit: SEP | PIPE | AMP | REDIR | subshell | word

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

dollar_var: DOLLAR_NAME | DOLLAR_SPECIAL
DOLLAR_NAME: /\$[_a-zA-Z0-9]+/
DOLLAR_SPECIAL: /\$[?@$#!*]/

ESC: /\\./

// Higher priority than the bare AMP so "&&" and "&>" win maximal munch.
SEP.2: "&&" | "||" | ";"
PIPE: "|"
AMP: "&"
REDIR.2: />>|>&|&>|>|</

LPAR: "("
RPAR: ")"

BARE_DOLLAR: "$"
LITERAL: /[^ \t\r\n|&;<>()$`'"\\]+/

_WS: /[ \t\r\n]+/
"""

_parser = Lark(
    _GRAMMAR,
    start="start",
    parser="earley",
    lexer="dynamic",
    propagate_positions=True,
)

# Sentinel returned by word evaluation when an unquoted bare reference to an
# unset/empty variable should drop the whole word (like ``echo $unset`` which
# yields no argument at all in a real shell).
_DROP = object()


class ShellContext(Protocol):
    """What the evaluator needs from the live shell to evaluate words."""

    def get_variable(self, name: str) -> str | None:
        """Return the value of a shell variable, or None if unset."""

    def command_substitution(self, source: str) -> str:
        """Execute ``source`` and return its captured stdout (newlines stripped)."""


@dataclass
class Command:
    """A simple command / pipeline: a flat token list with operators kept."""

    tokens: list[str] = field(default_factory=list)


@dataclass
class Subshell:
    """A ``(...)`` group whose raw inner source is run as its own shell."""

    source: str


@dataclass
class SyntaxError_:
    """A bash-style syntax error to report verbatim."""

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

        def flush() -> bool:
            """Turn the accumulated units into a statement. Return False to stop."""
            if not units:
                return True
            stmt = self._build_statement(line, units)
            units.clear()
            if stmt is None:
                return True
            statements.append(stmt)
            return not isinstance(stmt, SyntaxError_)

        for child in tree.children:
            if isinstance(child, Token) and child.type == "SEP":
                if not units and child.value in ("&&", "||"):
                    statements.append(SyntaxError_(token=child.value))
                    return statements
                if not flush():
                    return statements
                continue
            units.append(child)
        flush()
        return statements

    def _build_statement(
        self, line: str, units: list[Tree | Token]
    ) -> Statement | None:
        # A subshell is valid only at the start of a statement. There it runs
        # and writes straight to the terminal; anything piped after it is
        # ignored, matching the shlex path. A subshell anywhere else is a
        # syntax error reported on the "(" token, as bash does.
        subshell_idx = next(
            (
                i
                for i, u in enumerate(units)
                if isinstance(u, Tree) and u.data == "subshell"
            ),
            None,
        )
        if subshell_idx is not None:
            if subshell_idx == 0:
                return Subshell(source=self._subshell_source(line, units[0]))
            return SyntaxError_(token=self._error_token(line, units[subshell_idx]))

        tokens: list[str] = []
        for unit in units:
            if isinstance(unit, Token):
                # SEP never reaches here; PIPE / AMP / REDIR pass through.
                tokens.append(unit.value)
                continue
            value = self._eval_word(line, unit)
            if value is not _DROP:
                tokens.append(value)  # type: ignore[arg-type]
        if not tokens:
            return None
        return Command(tokens=tokens)

    # -- word evaluation ----------------------------------------------------

    def _eval_word(self, line: str, word: Tree) -> str | object:
        atoms = word.children

        # Whole-word bare reference: ``$x`` / ``${x}`` as the entire,
        # unquoted word. An unset or empty value drops the word; ``$?`` is 0.
        if len(atoms) == 1 and isinstance(atoms[0], Tree):
            only = atoms[0]
            if only.data in ("dollar_var", "dollar_brace"):
                name, special = self._var_name(only)
                if special == "?":
                    return "0"
                if special is not None:
                    return only.children[0].value  # verbatim, e.g. $@
                value = self.context.get_variable(name)
                if not value:
                    return _DROP
                return value

        parts: list[str] = []
        for atom in atoms:
            parts.append(self._eval_atom(line, atom))
        return "".join(parts)

    def _eval_atom(self, line: str, atom: Tree | Token) -> str:
        if isinstance(atom, Token):
            if atom.type == "LITERAL" or atom.type == "BARE_DOLLAR":
                return atom.value
            if atom.type == "ESC":
                # Unquoted backslash escape: the backslash is removed.
                return atom.value[1:]
            return atom.value

        if atom.data == "sq":
            return atom.children[0].value[1:-1]  # strip surrounding quotes
        if atom.data == "dq":
            return self._eval_dquoted(line, atom)
        if atom.data == "dollar_var" or atom.data == "dollar_brace":
            return self._expand_embedded(atom)
        if atom.data == "cmdsub":
            return self.context.command_substitution(self._inner_source(line, atom))
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
                    self.context.command_substitution(self._inner_source(line, part))
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
        reference is left verbatim so quoted awk/sed field references survive,
        matching the previous implementation's deliberate compromise.
        """
        name, special = self._var_name(node)
        if special == "?":
            return "0"
        if special is not None:
            return node.children[0].value
        value = self.context.get_variable(name)
        if value is None:
            return node.children[0].value  # verbatim, e.g. "$nope"
        return value

    def _var_name(self, node: Tree) -> tuple[str, str | None]:
        """Return (name, special) for a dollar_var/dollar_brace node."""
        if node.data == "dollar_brace":
            return node.children[0].value, None
        tok = node.children[0]
        if tok.type == "DOLLAR_SPECIAL":
            return tok.value, tok.value[1:]
        return tok.value[1:], None  # DOLLAR_NAME: strip leading $

    # -- source slicing for substitution / subshells ------------------------

    def _inner_source(self, line: str, node: Tree) -> str:
        """Raw source inside ``$(...)`` (the inner ``start`` tree)."""
        for child in node.children:
            if isinstance(child, Tree) and child.data == "start":
                if child.meta.empty:
                    return ""
                return line[child.meta.start_pos : child.meta.end_pos]
        return ""

    def _backtick_source(self, line: str, node: Tree) -> str:
        if node.meta.empty:
            return ""
        # Strip the surrounding backticks from the matched span.
        raw = line[node.meta.start_pos : node.meta.end_pos]
        return raw.strip("`")

    def _subshell_source(self, line: str, node: Tree) -> str:
        for child in node.children:
            if isinstance(child, Tree) and child.data == "start":
                if child.meta.empty:
                    return ""
                return line[child.meta.start_pos : child.meta.end_pos]
        return ""

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
