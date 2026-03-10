# ABOUTME: Parses shell commands including tokenization, redirection operators, and variable expansion.
# ABOUTME: Handles FD redirections like 2>/dev/null, stdin redirects, and command substitution.

from __future__ import annotations

import re
from typing import Any

# Pre-compiled regex for extracting redirection operators
_REDIR_OP_RE = re.compile(r"^(\d*)(>>|>&|>|<)(.*)$")

# Sentinel byte used to mark adjacent digit-redirect pairs (e.g., 2>/dev/null)
# so that shlex tokenization preserves the adjacency information.
REDIRECT_SENTINEL = "\x01"

# Regex to match a single digit immediately followed by a redirect operator
_ADJACENT_REDIR_RE = re.compile(r"(\d)([<>])")


def _find_closing_quote(cmd_string: str, start: int, quote: str) -> int:
    """Return the index past the closing *quote* character.

    *start* is the index of the opening quote.  Backslash escapes are
    honoured inside double-quoted strings.  If the closing quote is
    missing the end of the string is returned.
    """
    j = start + 1
    length = len(cmd_string)
    while j < length and cmd_string[j] != quote:
        if cmd_string[j] == "\\" and quote == '"' and j + 1 < length:
            j += 1  # skip escaped char in double quotes
        j += 1
    return j + 1 if j < length else length


def inject_redirect_sentinels(cmd_string: str) -> str:
    """
    Mark adjacent digit-redirect pairs for the tokenizer.

    Inserts a sentinel byte between a digit [0-9] and an adjacent
    redirect operator [<>] so that shlex tokenization preserves the
    adjacency information. Spaced versions (e.g., ``2 >/dev/null``)
    are not modified.

    Content inside single or double quotes is left untouched so that
    quoted strings like ``"2>/dev/null"`` are not mistakenly marked
    as redirections.

    The sentinel must be stripped after tokenization via
    merge_redirection_tokens().

    Examples:
        "echo test 2>/dev/null"  -> "echo test 2\\x01>/dev/null"
        "echo test 2 >/dev/null" -> "echo test 2 >/dev/null"  (unchanged)
        "cmd 2>&1"               -> "cmd 2\\x01>&1"
        "cmd 2>>log"             -> "cmd 2\\x01>>log"
    """
    # NOTE: The sentinel is an internal tokenization detail. The original
    # command string (before sentinel injection) must be used for all
    # logging and event dispatch. See merge_redirection_tokens().

    # Split the string into quoted and unquoted segments, applying the
    # sentinel substitution only to unquoted portions.
    result: list[str] = []
    i = 0
    length = len(cmd_string)
    while i < length:
        ch = cmd_string[i]
        if ch in ('"', "'"):
            end = _find_closing_quote(cmd_string, i, ch)
            result.append(cmd_string[i:end])
            i = end
        else:
            # Collect unquoted text until the next quote
            j = i
            while j < length and cmd_string[j] not in ('"', "'"):
                j += 1
            result.append(
                _ADJACENT_REDIR_RE.sub(
                    r"\1" + REDIRECT_SENTINEL + r"\2", cmd_string[i:j]
                )
            )
            i = j
    return "".join(result)


class CommandParser:
    """
    Handles parsing of shell commands, including tokenization, redirection,
    and variable expansion.
    """

    def merge_redirection_tokens(self, tokens: list[str]) -> list[str]:
        """
        Combine sentinel-marked fd redirect tokens that shlex split apart.

        Only merges a digit token with a following redirect operator when the
        digit token ends with the sentinel (meaning they were adjacent in the
        original input). Tokens without the sentinel (the spaced case) are
        left as-is: the digit remains a regular command argument.

        All sentinel bytes are stripped from the returned tokens.
        """
        merged: list[str] = []
        i = 0
        while i < len(tokens):
            combined, consumed = self._combine_redir_sequence(tokens, i)
            if combined:
                merged.append(combined)
                i += consumed
                continue
            merged.append(tokens[i])
            i += 1
        # Defensively strip any remaining sentinel bytes
        return [t.replace(REDIRECT_SENTINEL, "") for t in merged]

    def _combine_redir_sequence(
        self, tokens: list[str], index: int
    ) -> tuple[str | None, int]:
        """Glue together sentinel-marked fd + operator (+ optional ampersand/target) tokens."""
        tok = tokens[index]
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        nxt2 = tokens[index + 2] if index + 2 < len(tokens) else None
        nxt3 = tokens[index + 3] if index + 3 < len(tokens) else None

        # Only merge digit + redirect when the sentinel is present,
        # meaning they were adjacent in the original input.
        if tok.endswith(REDIRECT_SENTINEL) and nxt in (">", ">>", ">&", "<", "<<"):
            fd = tok.rstrip(REDIRECT_SENTINEL)
            if fd.isdigit():
                combined = f"{fd}{nxt}"
                if nxt == ">&" and nxt2 not in (None, "|", ";", "&&", "||"):
                    return combined + str(nxt2), 3
                if nxt in (">", ">>") and nxt2 == "&":
                    if nxt3 not in (None, "|", ";", "&&", "||"):
                        return combined + "&" + str(nxt3), 4
                    return combined + "&", 3
                if nxt in ("<", "<<"):
                    return combined, 2
                return combined, 2

        if tok in (">", ">>") and nxt == "&":
            return f"{tok}&", 2

        return None, 1

    def parse_redirections(
        self, arguments: list[str]
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """
        Parse arguments for redirections and return cleaned args and ordered redirection operations.
        """
        cleaned: list[str] = []
        ops: list[dict[str, Any]] = []

        i = 0
        while i < len(arguments):
            tok = arguments[i]
            op, fd, inline_target = self._extract_redir_op(tok)
            consume = 1

            if not op and tok in (">", ">>", "<", ">&"):
                op = tok

            if op:
                next_token = arguments[i + 1] if (i + 1) < len(arguments) else None
                consumed = self._apply_redirection(
                    op,
                    fd,
                    inline_target,
                    next_token,
                    ops,
                    cleaned,
                    tok,
                )
                if consumed:
                    i += consumed
                    continue

            cleaned.append(tok)
            i += consume

        return cleaned, ops

    def _extract_redir_op(self, token: str) -> tuple[str | None, int | None, str]:
        """Parse a combined redirection token into (op, fd, inline target).

        For file-redirect operators (``>``, ``>>``, ``<``), an embedded
        target means the token came from a quoted string — shlex with
        ``punctuation_chars=True`` always splits unquoted redirect
        operators into separate tokens.  Return no-match so the token
        is kept as a plain argument.

        The ``>&`` operator legitimately carries an inline fd number
        (e.g. ``2>&1``) after the merge step, so it is not rejected.
        """
        match = _REDIR_OP_RE.match(token)
        if not match:
            return None, None, ""
        fd_text, op, inline_target = match.groups()
        if inline_target and op in (">", ">>", "<"):
            return None, None, ""
        fd = int(fd_text) if fd_text else None
        return op, fd, inline_target

    def _apply_redirection(
        self,
        op: str,
        fd: int | None,
        inline_target: str,
        next_token: str | None,
        ops: list[dict[str, Any]],
        cleaned: list[str],
        raw_token: str,
    ) -> int:
        """Handle one redirection token and append it to the ops list."""
        if op in (">", ">>"):
            target_fd = 1 if fd is None else fd
            append_flag = op == ">>"
            target = inline_target or next_token
            if target is None:
                cleaned.append(raw_token)
                return 1

            ops.append(
                {
                    "type": "file",
                    "fd": target_fd,
                    "target": target,
                    "append": append_flag,
                }
            )
            return 1 if inline_target else 2

        if op == "<":
            source_fd = 0 if fd is None else fd
            target = inline_target or next_token
            if target is None:
                cleaned.append(raw_token)
                return 1
            ops.append({"type": "stdin", "fd": source_fd, "target": target})
            return 1 if inline_target else 2

        if op == ">&":
            target = inline_target or next_token
            if target is None:
                cleaned.append(raw_token)
                return 1

            consume = 1 if inline_target else 2
            source_fd = 1 if fd is None else fd

            if target == "-":
                # Close FD
                # Not fully supported yet, but we can parse it
                pass
            elif target.isdigit():
                # FD duplication: source_fd = target_fd
                ops.append({"type": "dup", "fd": source_fd, "target": int(target)})
            else:
                # Handle `>&`. Standard `sh` expects a digit or `-` after `>&` for file descriptor duplication.
                # Bash allows `>&file` or `&>file` to redirect both stdout and stderr to a file.
                # However, Cowrie's previous implementation strictly required a digit for `>&`.
                # If the target is not a digit, we treat it as a normal argument rather than a redirection
                # to maintain backward compatibility and avoid ambiguous parsing.
                cleaned.append(raw_token)
                return 1

            return consume

        return 0
