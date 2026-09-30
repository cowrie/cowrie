# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The printf builtin must match bash 5 output byte for byte: format
# ABOUTME: conversions, escapes, format reuse, -v and error handling.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class PrintfTests(unittest.TestCase):
    """Expected output is what bash 5.3 prints for the same line."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line)
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_string_argument(self) -> None:
        self.assertEqual(self.run_line(b"printf '%s\\n' c"), b"c\n")

    def test_format_is_reused_for_extra_arguments(self) -> None:
        self.assertEqual(self.run_line(b"printf '%s-%s\\n' 1 2 3"), b"1-2\n3-\n")

    def test_missing_arguments_are_empty_or_zero(self) -> None:
        self.assertEqual(self.run_line(b"printf '%d|%s|\\n'"), b"0||\n")

    def test_width_precision_and_flags(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf '%5.2f|%-4s|%04d|%x|%o|%c|%X|%+d|% d\\n' "
                b"3.14159 ab 7 255 8 hello 255 5 5"
            ),
            b" 3.14|ab  |0007|ff|10|h|FF|+5| 5\n",
        )

    def test_star_width_and_precision(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%*d|%.*f|\\n' 5 42 2 3.14159"), b"   42|3.14|\n"
        )

    def test_string_precision_truncates(self) -> None:
        self.assertEqual(self.run_line(b"printf '%.3s|\\n' abcdef"), b"abc|\n")

    def test_integer_bases_and_char_code(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%i\\n' 0x1f 010 -3 \"'A\""), b"31\n8\n-3\n65\n"
        )

    def test_unsigned_wraps_negative(self) -> None:
        self.assertEqual(self.run_line(b"printf '%u\\n' -1"), b"18446744073709551615\n")

    def test_float_conversions(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%e|%g|%G\\n' 12345.678 0.0001 1e20"),
            b"1.234568e+04|0.0001|1E+20\n",
        )

    def test_hex_float(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%a|%a|%A\\n' 1.5 0 10"),
            b"0x1.8p+0|0x0p+0|0X1.4P+3\n",
        )

    def test_format_escapes(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '\\x41\\101\\u00e9\\q\\n'"),
            "AAé\\q\n".encode(),
        )

    def test_backslash_c_in_format_is_literal(self) -> None:
        self.assertEqual(self.run_line(b"printf 'a\\cb|'"), b"a\\cb|")

    def test_percent_b_expands_escapes_and_stops_at_backslash_c(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%b\\n' 'a\\tb\\0101\\101'"), b"a\tbAA\n"
        )
        self.assertEqual(self.run_line(b"printf '%b|' 'x\\cy'"), b"x")

    def test_percent_q_quotes_for_the_shell(self) -> None:
        self.assertEqual(self.run_line(b"printf '%q\\n' \"a b'c\""), b"a\\ b\\'c\n")

    def test_invalid_number(self) -> None:
        self.assertEqual(
            self.run_line(b"printf '%d\\n' 12abc; echo rc=$?"),
            b"-bash: printf: 12abc: invalid number\n12\nrc=1\n",
        )

    def test_invalid_format_character_stops_output(self) -> None:
        """bash writes the error at once and its buffered output after."""
        self.assertEqual(
            self.run_line(b"printf 'a%kb\\n' 1; echo rc=$?"),
            b"-bash: printf: `k': invalid format character\narc=1\n",
        )

    def test_missing_format_character(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'abc%'; echo rc=$?"),
            b"-bash: printf: `%': missing format character\nabcrc=1\n",
        )

    def test_no_arguments_prints_usage(self) -> None:
        self.assertEqual(
            self.run_line(b"printf; echo rc=$?"),
            b"printf: usage: printf [-v var] format [arguments]\nrc=2\n",
        )

    def test_double_dash_ends_options(self) -> None:
        self.assertEqual(self.run_line(b"printf -- '%s\\n' b"), b"b\n")
        self.assertEqual(self.run_line(b"printf '%s\\n' -- a"), b"--\na\n")

    def test_v_assigns_to_a_variable(self) -> None:
        self.assertEqual(
            self.run_line(b"printf -v v '%s=%d' x 5; echo \"$v\""), b"x=5\n"
        )

    def test_writes_raw_bytes_for_binary_payloads(self) -> None:
        """Attackers build ELF headers with printf; the bytes must be exact."""
        self.assertEqual(
            self.run_line(b"printf '\\x7fELF\\x01\\x00'"), b"\x7fELF\x01\x00"
        )


if __name__ == "__main__":
    unittest.main()
