# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that wc counts and lays out its output as GNU coreutils 9.1
# ABOUTME: does in the C locale, for files, pipes, redirects and typed input.

from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellWcCommandTests(unittest.TestCase):
    """Expected output was taken from GNU wc on Linux."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        # a: 2 lines, 5 words, 24 bytes, longest line 15 columns (tab).
        # b: 2 newlines, 5 words, 18 bytes, last line has no newline.
        self.proto.lineReceived(
            b"cd /tmp; printf 'hello world\\nfoo\\tbar baz\\n' > a; "
            b"printf 'x\\n\\nlast line no nl' > b; mkdir d\n"
        )
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def assert_output(self, line: bytes, expected: bytes) -> None:
        self.tr.clear()
        self.proto.lineReceived(line)
        self.assertEqual(self.tr.value(), expected + PROMPT.replace(b"~", b"/tmp"))

    def test_default_counts_one_file(self) -> None:
        self.assert_output(b"wc a", b" 2  5 24 a\n")

    def test_several_files_add_a_total(self) -> None:
        self.assert_output(b"wc a b", b" 2  5 24 a\n 2  5 18 b\n 4 10 42 total\n")

    def test_width_comes_from_the_total_file_size(self) -> None:
        self.assert_output(b"wc -l a b", b" 2 a\n 2 b\n 4 total\n")

    def test_one_count_for_one_file_is_not_padded(self) -> None:
        self.assert_output(b"wc -c a", b"24 a\n")
        self.assert_output(b"wc -w b", b"5 b\n")

    def test_counts_keep_their_order_whatever_the_option_order(self) -> None:
        self.assert_output(b"wc -cl a", b" 2 24 a\n")

    def test_max_line_length_expands_tabs(self) -> None:
        self.assert_output(b"wc -L a b", b"15 a\n15 b\n15 total\n")

    def test_chars_are_bytes_in_the_c_locale(self) -> None:
        self.assert_output(b"wc -m a", b"24 a\n")

    def test_missing_file_is_reported_and_the_rest_counted(self) -> None:
        self.assert_output(
            b"wc a nofile b; echo rc=$?",
            b" 2  5 24 a\n"
            b"wc: nofile: No such file or directory\n"
            b" 2  5 18 b\n"
            b" 4 10 42 total\n"
            b"rc=1\n",
        )

    def test_directory_counts_zero_after_the_error(self) -> None:
        self.assert_output(
            b"wc d; echo rc=$?",
            b"wc: d: Is a directory\n      0       0       0 d\nrc=1\n",
        )

    def test_unknown_option(self) -> None:
        for option in (b"-h", b"-x"):
            with self.subTest(option=option):
                self.assert_output(
                    b"wc " + option + b" a; echo rc=$?",
                    b"wc: invalid option -- '" + option[1:] + b"'\n"
                    b"Try 'wc --help' for more information.\nrc=1\n",
                )

    def test_version(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"wc --version")
        self.assertTrue(self.tr.value().startswith(b"wc (GNU coreutils) 9.1\n"))

    def test_stdin_redirected_from_a_file(self) -> None:
        self.assert_output(b"wc < a", b" 2  5 24\n")
        self.assert_output(b"wc -l < a", b"2\n")
        self.assert_output(b"wc - < a", b" 2  5 24 -\n")
        self.assert_output(b"wc a - < b", b" 2  5 24 a\n 2  5 18 -\n 4 10 42 total\n")

    def test_pipe(self) -> None:
        self.assert_output(b"echo a b | wc", b"      1       2       4\n")
        self.assert_output(b"echo a b | wc -l", b"1\n")
        self.assert_output(b"printf 'a\\nb' | wc -l", b"1\n")
        self.assert_output(b"printf '  lead  trail  ' | wc -w", b"2\n")

    def test_empty_pipe_still_prints_counts(self) -> None:
        self.assert_output(b"printf '' | wc", b"      0       0       0\n")
        self.assert_output(b"printf '' | wc -c", b"0\n")

    def test_unprintable_bytes_neither_make_nor_split_words(self) -> None:
        self.assert_output(b"printf 'a\\001b \\001 \\300' | wc -w", b"1\n")

    def test_typed_input_is_counted_at_end_of_file(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"wc")
        self.proto.lineReceived(b"hello world")
        self.proto.lineReceived(b"x")
        self.proto.handle_CTRL_D()
        self.assertEqual(
            self.tr.value(),
            b"      2       3      14\n" + PROMPT.replace(b"~", b"/tmp"),
        )


if __name__ == "__main__":
    unittest.main()
