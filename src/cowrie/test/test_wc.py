# SPDX-FileCopyrightText: 2026 Aryamann Srivastava
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: wc prints the counts, the columns, the file names and the total line
# ABOUTME: the way GNU coreutils 9.7 does, for files, pipes and typed input.

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

# f has 6 lines, 7 words and 40 bytes, g has 4 bytes and no line break
SETUP = (
    b"echo alpha > f; echo beta gamma >> f; echo alpha >> f; "
    b"echo '  Delta:x:y' >> f; echo 3 >> f; echo 10 >> f; echo -n last > g"
)


class ShellWcCommandTests(unittest.TestCase):
    """Expected output is what GNU coreutils 9.7 prints for the same line."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.run_line(SETUP)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line + b"\n")
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_wc_file_prints_lines_words_and_bytes(self) -> None:
        self.assertEqual(self.run_line(b"wc f"), b" 6  7 40 f\n")

    def test_wc_single_count_is_not_padded(self) -> None:
        self.assertEqual(self.run_line(b"wc -l f"), b"6 f\n")
        self.assertEqual(self.run_line(b"wc -w f"), b"7 f\n")
        self.assertEqual(self.run_line(b"wc -c f"), b"40 f\n")
        self.assertEqual(self.run_line(b"wc -m f"), b"40 f\n")

    def test_wc_longest_line(self) -> None:
        self.assertEqual(self.run_line(b"wc -L f"), b"11 f\n")

    def test_wc_counts_keep_their_order_whatever_the_options(self) -> None:
        self.assertEqual(self.run_line(b"wc -cl f"), b" 6 40 f\n")
        self.assertEqual(self.run_line(b"wc -wl f"), b" 6  7 f\n")
        self.assertEqual(self.run_line(b"wc -l -w f"), b" 6  7 f\n")
        self.assertEqual(self.run_line(b"wc -lwmcL f"), b" 6  7 40 40 11 f\n")

    def test_wc_long_options(self) -> None:
        self.assertEqual(self.run_line(b"wc --lines f"), b"6 f\n")
        self.assertEqual(self.run_line(b"wc --words --bytes f"), b" 7 40 f\n")
        self.assertEqual(self.run_line(b"wc --max-line-length f"), b"11 f\n")

    def test_wc_several_files_get_a_total(self) -> None:
        self.assertEqual(
            self.run_line(b"wc f g"),
            b" 6  7 40 f\n 0  1  4 g\n 6  8 44 total\n",
        )
        self.assertEqual(self.run_line(b"wc -l f g"), b" 6 f\n 0 g\n 6 total\n")

    def test_wc_missing_file_is_reported_and_the_rest_counted(self) -> None:
        output = self.run_line(b"wc -l f nope g")
        self.assertIn(b"wc: nope: No such file or directory\n", output)
        self.assertIn(b" 6 f\n 0 g\n 6 total\n", output)
        self.assertEqual(self.run_line(b"wc nope; echo $?")[-2:], b"1\n")

    def test_wc_directory(self) -> None:
        output = self.run_line(b"mkdir d; wc d f")
        self.assertIn(b"wc: d: Is a directory\n", output)
        self.assertIn(
            b"      0       0       0 d\n      6       7      40 f\n"
            b"      6       7      40 total\n",
            output,
        )

    def test_wc_pipe_uses_a_wide_column(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hi there | wc"), b"      1       2       9\n"
        )
        self.assertEqual(self.run_line(b"echo hi there | wc -lw"), b"      1       2\n")

    def test_wc_pipe_single_count(self) -> None:
        self.assertEqual(self.run_line(b"echo hi there | wc -w"), b"2\n")
        self.assertEqual(self.run_line(b"echo hi there | wc -c"), b"9\n")
        self.assertEqual(self.run_line(b"echo -n last | wc -l"), b"0\n")

    def test_wc_empty_pipe(self) -> None:
        self.assertEqual(self.run_line(b"echo -n | wc -c"), b"0\n")
        self.assertEqual(self.run_line(b"echo -n | wc"), b"      0       0       0\n")

    def test_wc_stdin_redirected_from_a_file_has_a_known_size(self) -> None:
        self.assertEqual(self.run_line(b"wc < f"), b" 6  7 40\n")
        self.assertEqual(self.run_line(b"wc -l < f"), b"6\n")
        self.assertEqual(
            self.run_line(b"wc f - < g"),
            b" 6  7 40 f\n 0  1  4 -\n 6  8 44 total\n",
        )

    def test_wc_last_line_without_line_break_is_not_a_line(self) -> None:
        self.assertEqual(self.run_line(b"wc g"), b"0 1 4 g\n")

    def test_wc_tab_in_longest_line(self) -> None:
        self.run_line(b"echo -e 'a\\tb' > t")
        self.assertEqual(self.run_line(b"wc -L t"), b"9 t\n")

    def test_wc_invalid_option(self) -> None:
        output = self.run_line(b"wc -x f; echo $?")
        self.assertIn(b"wc: invalid option -- 'x'\n", output)
        self.assertTrue(output.endswith(b"1\n"))

    def test_wc_typed_input_is_counted_at_ctrl_d(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"wc -l\n")
        self.proto.lineReceived(b"one\n")
        self.proto.lineReceived(b"two words\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"2\n" + PROMPT)


if __name__ == "__main__":
    unittest.main()
