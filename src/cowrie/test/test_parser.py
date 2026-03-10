# ABOUTME: Unit tests for the shell command parser.
# ABOUTME: Tests sentinel injection, token merging, redirection parsing, and edge cases.

from __future__ import annotations

import shlex
import unittest

from cowrie.shell.parser import (
    REDIRECT_SENTINEL,
    CommandParser,
    inject_redirect_sentinels,
)

S = REDIRECT_SENTINEL


class InjectRedirectSentinelsTests(unittest.TestCase):
    """Unit tests for inject_redirect_sentinels()"""

    def test_adjacent_stderr_redirect(self) -> None:
        self.assertEqual(
            inject_redirect_sentinels("echo test 2>/dev/null"),
            f"echo test 2{S}>/dev/null",
        )

    def test_spaced_stderr_redirect_unchanged(self) -> None:
        self.assertEqual(
            inject_redirect_sentinels("echo test 2 >/dev/null"),
            "echo test 2 >/dev/null",
        )

    def test_adjacent_append(self) -> None:
        self.assertEqual(
            inject_redirect_sentinels("echo test 2>>/var/log/x"),
            f"echo test 2{S}>>/var/log/x",
        )

    def test_adjacent_fd_dup(self) -> None:
        self.assertEqual(
            inject_redirect_sentinels("cmd 2>&1"),
            f"cmd 2{S}>&1",
        )

    def test_adjacent_stdin(self) -> None:
        self.assertEqual(
            inject_redirect_sentinels("cmd 0</dev/null"),
            f"cmd 0{S}</dev/null",
        )

    def test_no_redirect_operator(self) -> None:
        self.assertEqual(inject_redirect_sentinels("echo 2 hello"), "echo 2 hello")

    def test_empty_string(self) -> None:
        self.assertEqual(inject_redirect_sentinels(""), "")

    def test_bare_redirect(self) -> None:
        self.assertEqual(inject_redirect_sentinels(">"), ">")

    def test_bare_fd_redirect(self) -> None:
        self.assertEqual(inject_redirect_sentinels("2>"), f"2{S}>")

    def test_multidigit_not_fd(self) -> None:
        result = inject_redirect_sentinels("echo 123 > file")
        self.assertEqual(result, "echo 123 > file")

    def test_adjacent_multidigit_number(self) -> None:
        # 123>file: the regex matches the last digit ('3') adjacent to '>'.
        # Real bash treats multi-digit numbers as fd numbers too
        # (e.g., `echo 123>/dev/null` produces no output), so injecting
        # the sentinel here is correct behavior.
        result = inject_redirect_sentinels("echo 123>file")
        self.assertEqual(result, f"echo 123{S}>file")

    def test_leading_zeros_fd(self) -> None:
        # 02>/dev/null: bash treats this as fd redirect (fd 2 with leading zero)
        result = inject_redirect_sentinels("echo test 02>/dev/null")
        self.assertEqual(result, f"echo test 02{S}>/dev/null")

    def test_large_fd_number(self) -> None:
        # 9999>/dev/null: bash still treats as fd redirect (fails with
        # "Bad file descriptor" but 9999 is never passed as an argument)
        result = inject_redirect_sentinels("echo test 9999>/dev/null")
        self.assertEqual(result, f"echo test 9999{S}>/dev/null")

    def test_multiple_adjacent_redirects(self) -> None:
        result = inject_redirect_sentinels("echo test 2>/dev/null 1>/dev/null")
        self.assertEqual(
            result,
            f"echo test 2{S}>/dev/null 1{S}>/dev/null",
        )


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

    def test_sentinel_stderr_redirect(self) -> None:
        # With sentinel: ['2\x01', '>', '/dev/null'] -> ['2>', '/dev/null']
        tokens = ["cat", "file", f"2{S}", ">", "/dev/null"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cat", "file", "2>", "/dev/null"])

    def test_spaced_stderr_no_merge(self) -> None:
        # Without sentinel: ['2', '>', '/dev/null'] stays separate
        tokens = ["cat", "file", "2", ">", "/dev/null"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cat", "file", "2", ">", "/dev/null"])

    def test_sentinel_stderr_append(self) -> None:
        tokens = ["cmd", f"2{S}", ">>", "log"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2>>", "log"])

    def test_sentinel_fd_dup(self) -> None:
        tokens = ["cmd", f"2{S}", ">&", "1"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2>&1"])

    def test_sentinel_fd_dup_with_ampersand(self) -> None:
        tokens = ["cmd", f"1{S}", ">", "&", "2"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "1>&2"])

    def test_stdout_stderr_merge(self) -> None:
        # ['>', '&'] -> ['>&'] (no digit involved, no sentinel needed)
        tokens = ["cmd", ">", "&", "file"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", ">&", "file"])

    def test_sentinel_multiple_redirections(self) -> None:
        tokens = ["cat", f"2{S}", ">", "/dev/null", f"1{S}", ">", "out"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cat", "2>", "/dev/null", "1>", "out"])

    def test_fd_before_pipe(self) -> None:
        tokens = ["cmd", "2", "|", "other"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2", "|", "other"])

    def test_fd_at_end(self) -> None:
        tokens = ["cmd", "2"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "2"])

    def test_sentinel_complex_fd_chain(self) -> None:
        tokens = ["cmd", f"3{S}", ">&", "1", f"1{S}", ">&", "2", f"2{S}", ">&", "3"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["cmd", "3>&1", "1>&2", "2>&3"])

    def test_sentinel_stdin_redirect(self) -> None:
        tokens = ["echo", f"0{S}", "<", "/dev/null"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["echo", "0<", "/dev/null"])

    def test_empty_list(self) -> None:
        self.assertEqual(self.parser.merge_redirection_tokens([]), [])

    def test_sentinel_only_at_start(self) -> None:
        tokens = [f"2{S}", ">", "/dev/null"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["2>", "/dev/null"])

    def test_sentinel_stripped_from_non_redirect(self) -> None:
        # If a sentinel somehow ends up in a non-redirect token, it gets stripped
        tokens = [f"foo{S}bar"]
        result = self.parser.merge_redirection_tokens(tokens)
        self.assertEqual(result, ["foobar"])


class NoSentinelLeakageTests(unittest.TestCase):
    """Verify sentinel bytes never survive the full pipeline."""

    def setUp(self) -> None:
        self.parser = CommandParser()

    def _full_pipeline(self, cmd: str) -> list[str]:
        """Run inject -> shlex -> merge and return tokens."""
        sentinel_cmd = inject_redirect_sentinels(cmd)
        lexer = shlex.shlex(instream=sentinel_cmd, punctuation_chars=True, posix=True)
        lexer.wordchars += f"@%{{}}=$:+^,()`{REDIRECT_SENTINEL}"
        tokens = list(lexer)
        return self.parser.merge_redirection_tokens(tokens)

    def test_no_sentinel_in_adjacent_redirect(self) -> None:
        tokens = self._full_pipeline("echo test 2>/dev/null")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_spaced_redirect(self) -> None:
        tokens = self._full_pipeline("echo test 2 >/dev/null")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_quoted_string(self) -> None:
        tokens = self._full_pipeline('echo "2>/dev/null"')
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_single_quoted(self) -> None:
        tokens = self._full_pipeline("echo '2>/dev/null'")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_large_fd(self) -> None:
        tokens = self._full_pipeline("echo test 9999>/dev/null")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_leading_zero_fd(self) -> None:
        tokens = self._full_pipeline("echo test 02>/dev/null")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")

    def test_no_sentinel_in_escaped_redirect(self) -> None:
        # Backslash-escaped > should not be treated as redirect by shlex
        # shlex posix mode handles \> as literal >
        tokens = self._full_pipeline("echo test 2\\>/dev/null")
        for tok in tokens:
            self.assertNotIn(S, tok, f"Sentinel leaked in token: {tok!r}")


class EndToEndRedirectParsingTests(unittest.TestCase):
    """
    End-to-end tests: inject -> shlex -> merge -> parse_redirections.

    The critical distinction: adjacent 2> = fd redirect (2 NOT an arg),
    spaced 2 > = arg + stdout redirect (2 IS an arg).
    """

    def setUp(self) -> None:
        self.parser = CommandParser()

    def _parse(self, cmd: str) -> tuple[list[str], list[dict]]:
        """Full pipeline from raw command to cleaned args and redirect ops."""
        sentinel_cmd = inject_redirect_sentinels(cmd)
        lexer = shlex.shlex(instream=sentinel_cmd, punctuation_chars=True, posix=True)
        lexer.wordchars += f"@%{{}}=$:+^,()`{REDIRECT_SENTINEL}"
        tokens = list(lexer)
        merged = self.parser.merge_redirection_tokens(tokens)
        return self.parser.parse_redirections(merged)

    def test_adjacent_fd_redirect(self) -> None:
        """2>/dev/null: fd redirect, 2 is NOT an arg."""
        cleaned, ops = self._parse("uname -a 2>/dev/null")
        self.assertEqual(cleaned, ["uname", "-a"])
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["fd"], 2)

    def test_spaced_arg_plus_redirect(self) -> None:
        """2 >/dev/null: 2 IS an arg, stdout redirect."""
        cleaned, ops = self._parse("uname -a 2 >/dev/null")
        self.assertEqual(cleaned, ["uname", "-a", "2"])
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["fd"], 1)

    def test_echo_adjacent(self) -> None:
        cleaned, _ops = self._parse("echo test 2>/dev/null")
        self.assertEqual(cleaned, ["echo", "test"])

    def test_echo_spaced(self) -> None:
        cleaned, _ops = self._parse("echo test 2 >/dev/null")
        self.assertEqual(cleaned, ["echo", "test", "2"])

    def test_cat_adjacent(self) -> None:
        cleaned, _ops = self._parse("cat /proc/uptime 2>/dev/null")
        self.assertEqual(cleaned, ["cat", "/proc/uptime"])

    def test_cat_spaced(self) -> None:
        cleaned, _ops = self._parse("cat /proc/uptime 2 >/dev/null")
        self.assertEqual(cleaned, ["cat", "/proc/uptime", "2"])

    def test_fd_dup_adjacent(self) -> None:
        cleaned, ops = self._parse("echo test 2>&1 >/dev/null")
        self.assertEqual(cleaned, ["echo", "test"])
        self.assertEqual(len(ops), 2)

    def test_no_redirects(self) -> None:
        cleaned, ops = self._parse("echo hello")
        self.assertEqual(cleaned, ["echo", "hello"])
        self.assertEqual(ops, [])

    def test_echo_spaced_to_file(self) -> None:
        """echo 2 > /tmp/file: 2 is arg, stdout redirect."""
        cleaned, ops = self._parse("echo 2 > /tmp/file")
        self.assertEqual(cleaned, ["echo", "2"])
        self.assertEqual(ops[0]["fd"], 1)

    def test_echo_adjacent_to_file(self) -> None:
        """echo 2>/tmp/file: fd 2 redirect, no args besides echo."""
        cleaned, ops = self._parse("echo 2>/tmp/file")
        self.assertEqual(cleaned, ["echo"])
        self.assertEqual(ops[0]["fd"], 2)

    def test_quoted_redirect_no_sentinel_leak(self) -> None:
        """Quoted '2>/dev/null' must not contain sentinel bytes after pipeline."""
        cleaned, _ops = self._parse('echo "2>/dev/null"')
        for tok in cleaned:
            self.assertNotIn(S, tok)

    def test_single_quoted_redirect_no_sentinel_leak(self) -> None:
        cleaned, _ops = self._parse("echo '2>/dev/null'")
        for tok in cleaned:
            self.assertNotIn(S, tok)

    def test_stdin_redirect(self) -> None:
        cleaned, ops = self._parse("cat < /etc/passwd")
        self.assertEqual(cleaned, ["cat"])
        self.assertEqual(ops[0]["type"], "stdin")

    def test_adjacent_stdin_redirect(self) -> None:
        cleaned, ops = self._parse("cmd 0</dev/null")
        self.assertEqual(cleaned, ["cmd"])
        self.assertEqual(ops[0]["type"], "stdin")
        self.assertEqual(ops[0]["fd"], 0)

    def test_leading_zero_fd(self) -> None:
        """02>/dev/null: leading zero, still fd redirect."""
        cleaned, _ops = self._parse("echo test 02>/dev/null")
        self.assertEqual(cleaned, ["echo", "test"])

    def test_multiple_adjacent_redirects(self) -> None:
        """2>/dev/null 1>/dev/null: both are fd redirects."""
        cleaned, ops = self._parse("echo test 2>/dev/null 1>/dev/null")
        self.assertEqual(cleaned, ["echo", "test"])
        self.assertEqual(len(ops), 2)

    def test_append_adjacent(self) -> None:
        """2>>/dev/null: fd 2 append redirect."""
        cleaned, _ops = self._parse("echo test 2>>/dev/null")
        self.assertEqual(cleaned, ["echo", "test"])

    def test_append_spaced(self) -> None:
        """2 >>/dev/null: 2 is arg, stdout append redirect."""
        cleaned, _ops = self._parse("echo test 2 >>/dev/null")
        self.assertEqual(cleaned, ["echo", "test", "2"])

    def test_quoted_double_not_redirect(self) -> None:
        """Double-quoted "2>/dev/null" is a literal string, not a redirect."""
        cleaned, ops = self._parse('echo "2>/dev/null"')
        self.assertEqual(cleaned, ["echo", "2>/dev/null"])
        self.assertEqual(ops, [])

    def test_quoted_single_not_redirect(self) -> None:
        """Single-quoted '2>/dev/null' is a literal string, not a redirect."""
        cleaned, ops = self._parse("echo '2>/dev/null'")
        self.assertEqual(cleaned, ["echo", "2>/dev/null"])
        self.assertEqual(ops, [])

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
        # After the merge pipeline, fd redirects are always split:
        # "2>" is one token, "/dev/null" is the next.
        args = ["cmd", "2>", "/dev/null"]
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
        # After shlex with punctuation_chars=True, '>' is always a
        # separate token, so the split form is what the pipeline produces.
        args = ["echo", ">", "file"]
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
