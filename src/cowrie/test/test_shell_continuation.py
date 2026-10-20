# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests the interactive shell's line continuation: an unfinished
# ABOUTME: construct waits at the `> ` prompt, CTRL-C discards it, CTRL-D ends it.

from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.configoverride import override_option
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "
PS2 = b"> "


class ShellContinuationTests(unittest.TestCase):
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

    def assert_continues(self, *lines: bytes) -> None:
        for line in lines:
            self.assertEqual(self.line(line), PS2, line)

    def test_open_compound_commands_wait_for_more(self) -> None:
        self.assert_continues(b"if true", b"then echo yes")
        self.assertEqual(self.line(b"fi"), b"yes\n" + PROMPT)
        self.assert_continues(b"for i in 1 2", b"do echo $i")
        self.assertEqual(self.line(b"done"), b"1\n2\n" + PROMPT)
        self.assert_continues(b"while false", b"do :")
        self.assertEqual(self.line(b"done"), PROMPT)
        self.assert_continues(b"until true; do", b"echo never")
        self.assertEqual(self.line(b"done"), PROMPT)
        self.assert_continues(b"case x in", b"x) echo matched ;;")
        self.assertEqual(self.line(b"esac"), b"matched\n" + PROMPT)
        self.assert_continues(b"{ echo group")
        self.assertEqual(self.line(b"}"), b"group\n" + PROMPT)
        self.assert_continues(b"( echo sub")
        self.assertEqual(self.line(b")"), b"sub\n" + PROMPT)
        self.assert_continues(b"f() {", b"echo in f")
        self.assertEqual(self.line(b"}; f"), b"in f\n" + PROMPT)

    def test_open_quotes_and_substitutions_wait_for_more(self) -> None:
        self.assert_continues(b"echo 'a")
        self.assertEqual(self.line(b"b'"), b"a\nb\n" + PROMPT)
        self.assert_continues(b'echo "a')
        self.assertEqual(self.line(b'b"'), b"a\nb\n" + PROMPT)
        self.assert_continues(b"echo `echo a")
        self.assertEqual(self.line(b"`"), b"a\n" + PROMPT)
        self.assert_continues(b"echo $(echo a")
        self.assertEqual(self.line(b")"), b"a\n" + PROMPT)
        # An open ${ waits too; closing it on the next line is then an error
        # (a bad substitution in bash).
        self.assert_continues(b"echo ${x")
        self.assertEqual(
            self.line(b"}"), b"-bash: syntax error: unexpected end of file\n" + PROMPT
        )

    def test_trailing_operators_wait_for_more(self) -> None:
        self.assert_continues(b"echo a \\")
        self.assertEqual(self.line(b"b"), b"a b\n" + PROMPT)
        self.assert_continues(b"echo ab\\")
        self.assertEqual(self.line(b""), b"ab\n" + PROMPT)
        self.assert_continues(b"echo abc |")
        self.assertEqual(self.line(b"tr a-z A-Z"), b"ABC\n" + PROMPT)
        self.assert_continues(b"true &&")
        self.assertEqual(self.line(b"echo and"), b"and\n" + PROMPT)
        self.assert_continues(b"false ||")
        self.assertEqual(self.line(b"echo or"), b"or\n" + PROMPT)

    def test_missing_redirection_target_is_an_error_not_a_continuation(self) -> None:
        self.assertEqual(
            self.line(b"echo >"),
            b"-bash: syntax error near unexpected token `newline'\n" + PROMPT,
        )

    def test_keywords_as_arguments_are_complete(self) -> None:
        self.assertEqual(self.line(b"echo if"), b"if\n" + PROMPT)
        self.assertEqual(self.line(b"echo done"), b"done\n" + PROMPT)
        self.assertEqual(self.line(b"echo esac"), b"esac\n" + PROMPT)

    def test_closing_keyword_alone_is_still_an_error(self) -> None:
        self.assertEqual(
            self.line(b"fi"),
            b"-bash: syntax error near unexpected token `fi'\n" + PROMPT,
        )

    def test_quote_opened_before_a_hash_continues(self) -> None:
        # The "#" is inside the quote, not a comment.
        self.assert_continues(b"echo 'a # b")
        self.assertEqual(self.line(b"c'"), b"a # b\nc\n" + PROMPT)
        # Whereas a quote inside a comment is nothing.
        self.assertEqual(self.line(b'echo a # "b'), b"a\n" + PROMPT)

    def test_ctrl_c_discards_the_buffer(self) -> None:
        self.assert_continues(b"if true", b"then echo dropped")
        self.tr.clear()
        self.proto.handle_CTRL_C()
        self.assertEqual(self.tr.value(), b"\n" + PROMPT)
        self.assertEqual(self.line(b"echo after"), b"after\n" + PROMPT)

    def test_ctrl_d_reports_unexpected_eof_and_keeps_the_session(self) -> None:
        self.assert_continues(b"if true")
        self.tr.clear()
        self.proto.handle_CTRL_D()
        self.assertEqual(
            self.tr.value(),
            b"-bash: syntax error: unexpected end of file\n" + PROMPT,
        )
        self.assertEqual(self.line(b"echo rc=$?"), b"rc=2\n" + PROMPT)
        self.assertFalse(self.tr.disconnecting)

    def test_ctrl_d_after_a_backslash_drops_the_continuation(self) -> None:
        self.assert_continues(b"echo a \\")
        self.tr.clear()
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"a\n" + PROMPT)

    def test_ctrl_d_in_a_quote_names_the_quote(self) -> None:
        self.assert_continues(b'echo "abc')
        self.tr.clear()
        self.proto.handle_CTRL_D()
        self.assertEqual(
            self.tr.value(),
            b"-bash: unexpected EOF while looking for matching `\"'\n"
            b"-bash: syntax error: unexpected end of file\n" + PROMPT,
        )
        self.assertEqual(self.line(b"echo alive"), b"alive\n" + PROMPT)

    def test_one_input_event_per_physical_line(self) -> None:
        self.proto.lineReceived(b"if true")
        self.proto.lineReceived(b"then echo yes")
        self.proto.lineReceived(b"fi")
        inputs = [
            e["input"]
            for e in self.tr.dispatchedEvents
            if e["eventid"] == "cowrie.command.input"
        ]
        self.assertEqual(inputs, ["if true", "then echo yes", "fi"])

    def test_buffer_over_max_input_size_is_discarded(self) -> None:
        override_option(self, "shell", "max_input_size", "64")
        self.assert_continues(b"if true")
        self.assertEqual(
            self.line(b"then echo " + b"x" * 70),
            b"-bash: syntax error: unexpected end of file\n" + PROMPT,
        )
        # The buffer is gone: the next line starts afresh.
        self.assertEqual(self.line(b"echo fresh"), b"fresh\n" + PROMPT)

    def test_nested_shell_continues_too(self) -> None:
        self.assertEqual(self.line(b"bash"), PROMPT)
        self.assert_continues(b"if false")
        self.assertEqual(
            self.line(b"then echo no; else echo yes; fi"), b"yes\n" + PROMPT
        )


if __name__ == "__main__":
    unittest.main()
