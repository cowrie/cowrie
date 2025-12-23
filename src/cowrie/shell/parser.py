# ABOUTME: Parses shell commands including tokenization, redirection operators, and variable expansion.
# ABOUTME: Handles FD redirections like 2>/dev/null, stdin redirects, and command substitution.

from __future__ import annotations

import re

from typing import Any

# Pre-compiled regex for extracting redirection operators
_REDIR_OP_RE = re.compile(r"^(\d*)(>>|>&|>|<)(.*)$")


class CommandParser:
    """
    Handles parsing of shell commands, including tokenization, redirection,
    and variable expansion.
    """

    def merge_redirection_tokens(self, tokens: list[str]) -> list[str]:
        """
        Combine shlex-split redirection tokens back together.
        Example: ['2', '>', '/dev/null'] -> ['2>', '/dev/null']
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
        return merged

    def _combine_redir_sequence(
        self, tokens: list[str], index: int
    ) -> tuple[str | None, int]:
        """Glue together fd + operator (+ optional ampersand/target) tokens."""
        tok = tokens[index]
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        nxt2 = tokens[index + 2] if index + 2 < len(tokens) else None
        nxt3 = tokens[index + 3] if index + 3 < len(tokens) else None

        if tok.isdigit() and nxt in (">", ">>", ">&"):
            combined = f"{tok}{nxt}"
            if nxt == ">&" and nxt2 not in (None, "|", ";", "&&", "||"):
                return combined + str(nxt2), 3
            if nxt in (">", ">>") and nxt2 == "&":
                if nxt3 not in (None, "|", ";", "&&", "||"):
                    return combined + "&" + str(nxt3), 4
                return combined + "&", 3
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
        """Parse a combined redirection token into (op, fd, inline target)."""
        match = _REDIR_OP_RE.match(token)
        if not match:
            return None, None, ""
        fd_text, op, inline_target = match.groups()
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
