# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests here-documents (<<EOF, <<-EOF, quoted delimiters) and
# ABOUTME: here-strings, from the parser's body handling to the shell's stdin.

from __future__ import annotations

import os
import tempfile
import unittest

from twisted.internet.protocol import connectionDone

from cowrie.shell.bashparse import BashParser, Command, Pipeline, SyntaxError_
from cowrie.shell.parser import CommandParser, HereDocBody
from cowrie.shell.prescan import HereDoc
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.configoverride import override_option
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport
from cowrie.test.test_bashparse import FakeContext, evaluate_now
from cowrie.test.test_exec_shell_stdin import start_exec_session

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "
PS2 = b"> "


class HereDocParserTests(unittest.TestCase):
    """The parser lifts the body out and expands it with the command."""

    def setUp(self) -> None:
        self.ctx = FakeContext({"x": "hi", "HOME": "/root"})
        self.parser = BashParser(self.ctx)

    def _tokens(self, text: str) -> list[str]:
        statement = self.parser.parse(text)[0]
        assert isinstance(statement, Command), statement
        return evaluate_now(self.parser, statement)

    def _body(self, text: str) -> HereDocBody:
        tokens = self._tokens(text)
        bodies = [t for t in tokens if isinstance(t, HereDocBody)]
        self.assertEqual(len(bodies), 1, tokens)
        return bodies[0]

    def test_unquoted_delimiter_expands_the_body(self) -> None:
        self.assertEqual(
            self._tokens("cat <<EOF\nhello $x ${x} $(id) `uname`\nEOF\n"),
            ["cat", "hello hi hi <id> <uname>\n"],
        )
        self.assertEqual(self.ctx.substitutions, ["id", "uname"])

    def test_quoted_delimiters_keep_the_body_literal(self) -> None:
        for opener in ("<<'EOF'", '<<"EOF"', "<<\\EOF", '<<E"O"F', "<< 'EOF'"):
            with self.subTest(opener=opener):
                self.assertEqual(
                    self._tokens(f"cat {opener}\n$x $(id) \\$x\nEOF\n"),
                    ["cat", "$x $(id) \\$x\n"],
                )
        self.assertEqual(self.ctx.substitutions, [])

    def test_backslash_rules_in_an_expanded_body(self) -> None:
        # \$ \` \\ lose the backslash, \<newline> joins lines, others stay.
        self.assertEqual(
            self._body("cat <<EOF\n\\$x \\`a\\` \\\\ \\a \\\ncont\nEOF\n"),
            "$x `a` \\ \\a cont\n",
        )

    def test_dash_strips_leading_tabs(self) -> None:
        self.assertEqual(
            self._body("cat <<-EOF\n\t\tone\n\t  two\n\tEOF\n"), "one\n  two\n"
        )

    def test_several_heredocs_each_get_their_body(self) -> None:
        self.assertEqual(
            self._tokens("cat <<A <<B\nfirst\nA\nsecond\nB\n"),
            ["cat", "first\n", "second\n"],
        )
        _, ops = CommandParser().parse_redirections(
            self._tokens("cat <<A <<B\nfirst\nA\nsecond\nB\n")
        )
        self.assertEqual([op["data"] for op in ops], [b"first\n", b"second\n"])

    def test_fd_on_the_operator(self) -> None:
        body = self._body("cat 3<<EOF\nx\nEOF\n")
        self.assertEqual(body.fd, 3)
        self.assertEqual(self._body("cat <<EOF\nx\nEOF\n").fd, 0)
        _, ops = CommandParser().parse_redirections([body])
        self.assertEqual(ops, [{"type": "heredoc", "fd": 3, "data": b"x\n"}])

    def test_operator_without_a_word_is_a_syntax_error(self) -> None:
        self.assertEqual(
            self.parser.parse("echo 1 <<\n"),
            [SyntaxError_(token="newline", lineno=1)],
        )
        self.assertEqual(
            self.parser.parse("echo 1 << ; echo 2"),
            [SyntaxError_(token=";", lineno=1)],
        )

    def test_line_numbers_count_the_body(self) -> None:
        statements = self.parser.parse("cat <<EOF\none\ntwo\nEOF\necho after\n")
        self.assertEqual(
            [s.lineno for s in statements if isinstance(s, Command)], [1, 5]
        )

    def test_body_inside_command_substitution(self) -> None:
        self.assertEqual(
            self._tokens("echo $(cat <<EOF\ninner\nEOF\n) after"),
            ["echo", "<cat", "<<EOF", "inner", "EOF>", "after"],
        )
        self.assertEqual(self.ctx.substitutions, ["cat <<EOF\ninner\nEOF\n"])

    def test_heredoc_on_a_pipeline_stage(self) -> None:
        statement = self.parser.parse("cat <<EOF | tr a-z A-Z\nhi\nEOF\n")[0]
        assert isinstance(statement, Pipeline)
        first = statement.stages[0]
        assert isinstance(first, Command)
        self.assertEqual(evaluate_now(self.parser, first), ["cat", "hi\n"])

    def test_unterminated_body_is_an_incomplete_marker(self) -> None:
        for text in ("cat <<EOF", "cat <<EOF\n", "cat <<EOF\npartial\n"):
            with self.subTest(text=text):
                statements = self.parser.parse(text)
                marker = statements[-1]
                assert isinstance(marker, SyntaxError_)
                self.assertTrue(marker.incomplete)
                self.assertEqual(marker.opener, "heredoc")
                self.assertEqual(
                    [(h.delimiter, h.lineno, h.terminated) for h in marker.heredocs],
                    [("EOF", 1, False)],
                )
        command = self.parser.parse("cat <<EOF\npartial\n")[0]
        assert isinstance(command, Command)
        self.assertEqual(evaluate_now(self.parser, command), ["cat", "partial\n"])

    def test_here_string(self) -> None:
        self.assertEqual(self._tokens('cat <<< "a $x"'), ["cat", "a hi\n"])
        self.assertEqual(self._body("cat 3<<<word").fd, 3)
        self.assertEqual(self._tokens("cat <<<$unset"), ["cat", "\n"])

    def test_heredoc_item_is_in_the_command(self) -> None:
        command = self.parser.parse("cat <<EOF\nx\nEOF\n")[0]
        assert isinstance(command, Command)
        self.assertEqual(
            [item for item in command.items if isinstance(item, HereDoc)],
            [HereDoc(body="x\n", expand=True, delimiter="EOF", lineno=1)],
        )


class HereDocShellTests(unittest.TestCase):
    """The body reaches the command's stdin, line by line at the prompt."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line)
        output: bytes = self.tr.value()
        return output

    def feed(self, *lines: bytes) -> bytes:
        """Feed lines, asserting the `> ` prompt after each but the last, and
        return the output of the last."""
        for line in lines[:-1]:
            self.assertEqual(self.line(line), PS2, line)
        return self.line(lines[-1])

    def test_cat_reads_the_body(self) -> None:
        self.assertEqual(
            self.feed(b"cat <<EOF", b"hello $HOME", b"EOF"), b"hello /root\n" + PROMPT
        )

    def test_quoted_delimiter_is_literal(self) -> None:
        self.assertEqual(
            self.feed(b"cat <<'EOF'", b"hello $HOME", b"EOF"), b"hello $HOME\n" + PROMPT
        )

    def test_delimiter_must_match_exactly(self) -> None:
        self.assertEqual(
            self.feed(b"cat <<EOF", b"EOF ", b" EOF", b"eof", b"EOF"),
            b"EOF \n EOF\neof\n" + PROMPT,
        )

    def test_body_to_a_file(self) -> None:
        self.assertEqual(self.feed(b"cat > hd.txt <<EOF", b"filed", b"EOF"), PROMPT)
        self.assertEqual(self.line(b"cat hd.txt"), b"filed\n" + PROMPT)

    def test_body_through_a_pipe(self) -> None:
        self.assertEqual(
            self.feed(b"cat <<EOF | tr a-z A-Z", b"hi", b"EOF"), b"HI\n" + PROMPT
        )

    def test_inside_compound_commands(self) -> None:
        self.assertEqual(
            self.feed(b"if true; then cat <<EOF", b"in if", b"EOF", b"fi"),
            b"in if\n" + PROMPT,
        )
        self.assertEqual(
            self.feed(b"for i in 1 2; do cat <<EOF", b"n=$i", b"EOF", b"done"),
            b"n=1\nn=2\n" + PROMPT,
        )

    def test_on_a_group(self) -> None:
        self.assertEqual(
            self.feed(b"{ cat; } <<EOF", b"grouped", b"EOF"), b"grouped\n" + PROMPT
        )
        self.assertEqual(self.feed(b"( cat ) <<EOF", b"sub", b"EOF"), b"sub\n" + PROMPT)

    def test_in_a_substitution(self) -> None:
        self.assertEqual(
            self.feed(b"x=$(cat <<EOF", b"inner", b"EOF", b"); echo [$x]"),
            b"[inner]\n" + PROMPT,
        )

    def test_here_string(self) -> None:
        self.assertEqual(self.line(b"cat <<< 'here string'"), b"here string\n" + PROMPT)

    def test_bash_reads_a_script_from_a_heredoc(self) -> None:
        self.assertEqual(
            self.feed(b"bash <<EOF", b"echo from inner \\$HOME", b"EOF"),
            b"from inner /root\n" + PROMPT,
        )

    def test_ctrl_d_in_the_body_warns_and_runs(self) -> None:
        self.feed(b"cat <<EOF", b"partial", b"")
        self.tr.clear()
        self.proto.handle_CTRL_D()
        self.assertEqual(
            self.tr.value(),
            b"-bash: warning: here-document at line 1 delimited by end-of-file "
            b"(wanted `EOF')\npartial\n\n" + PROMPT,
        )
        self.assertEqual(self.line(b"echo rc=$?"), b"rc=0\n" + PROMPT)

    def test_body_beyond_max_heredoc_size_is_truncated(self) -> None:
        override_option(self, "shell", "max_heredoc_size", "10")
        self.assertEqual(
            self.feed(b"cat <<EOF", b"aaaa", b"bbbb", b"cccc", b"EOF"),
            b"aaaa\nbbbb\n" + PROMPT,
        )
        self.assertEqual(self.line(b"echo next"), b"next\n" + PROMPT)

    def test_whole_text_warns_with_the_last_line(self) -> None:
        self.assertEqual(
            self.line(b"bash -c 'cat <<EOF\nhi'"),
            b"bash: line 2: warning: here-document at line 1 delimited by "
            b"end-of-file (wanted `EOF')\nhi\n" + PROMPT,
        )
        self.line(b"printf 'echo s\\ncat <<EOF\\nin script\\n' > hd.sh")
        self.assertEqual(
            self.line(b"bash hd.sh"),
            b"s\nhd.sh: line 3: warning: here-document at line 2 delimited by "
            b"end-of-file (wanted `EOF')\nin script\n" + PROMPT,
        )


class HereDocExecTests(unittest.TestCase):
    """`ssh host bash` fed a heredoc over the channel."""

    def test_body_over_the_channel(self) -> None:
        lsp, out, ended = start_exec_session(b"bash")
        self.addCleanup(lsp.connectionLost, connectionDone)
        lsp.dataReceived(b"cat <<EOF\nline one\nEOF\necho rc=$?\n")
        self.assertEqual(bytes(out), b"line one\nrc=0\n")
        self.assertEqual(ended, {})
        lsp.eofReceived()
        self.assertEqual(ended.get("code"), 0)

    def test_eof_in_the_body_warns_and_runs(self) -> None:
        lsp, out, ended = start_exec_session(b"bash")
        self.addCleanup(lsp.connectionLost, connectionDone)
        lsp.dataReceived(b"cat <<EOF\nhi\n")
        lsp.eofReceived()
        self.assertEqual(
            bytes(out),
            b"bash: line 2: warning: here-document at line 1 delimited by "
            b"end-of-file (wanted `EOF')\nhi\n",
        )
        self.assertEqual(ended.get("code"), 0)


if __name__ == "__main__":
    unittest.main()
