# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the read builtin, with expected values taken from bash 5.3:
# ABOUTME: field splitting by IFS, backslashes, EOF status and line-at-a-time stdin.

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


class ReadBuiltinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        """Send one line, return only the bytes it produced (prompt stripped)."""
        self.tr.clear()
        self.proto.lineReceived(line)
        out: bytes = self.tr.value()
        if out.endswith(PROMPT):
            out = out[: -len(PROMPT)]
        return out

    def test_assigns_variables_in_the_shell(self) -> None:
        self.proto.lineReceived(b"read -r x <<< hello")
        self.assertEqual(self.run_line(b'echo "[$x] $?"'), b"[hello] 0\n")

    def test_splits_fields_on_default_ifs(self) -> None:
        self.assertEqual(
            self.run_line(b'read -r a b <<< "  x   y  z  "; echo "[$a][$b]"'),
            b"[x][y  z]\n",
        )

    def test_missing_fields_are_empty(self) -> None:
        self.assertEqual(
            self.run_line(b'read -r a b c <<< x; echo "[$a][$b][$c]"'),
            b"[x][][]\n",
        )

    def test_non_whitespace_ifs(self) -> None:
        for line, expected in (
            (b'IFS=: read -r a b <<< "x:y:"; echo "[$a][$b]"', b"[x][y]\n"),
            (b'IFS=: read -r a b <<< "x:y::"; echo "[$a][$b]"', b"[x][y::]\n"),
            (b'IFS=: read -r a b <<< "x:y:z:"; echo "[$a][$b]"', b"[x][y:z:]\n"),
            (b'IFS=: read -r a b c <<< "x::z"; echo "[$a][$b][$c]"', b"[x][][z]\n"),
            (b'IFS=" :" read -r a b <<< "  x : y  "; echo "[$a][$b]"', b"[x][y]\n"),
        ):
            with self.subTest(line=line):
                self.assertEqual(self.run_line(line), expected)

    # The /proc/self/status layout: the value keeps its leading tab
    def test_colon_ifs_keeps_tab(self) -> None:
        self.assertEqual(
            self.run_line(b'IFS=: read -r k v <<< "Pid:\t123"; echo "[$k][$v]"'),
            b"[Pid][\t123]\n",
        )

    def test_prefix_ifs_applies_to_read_only(self) -> None:
        self.assertEqual(
            self.run_line(
                b'IFS=: read -r a b <<< "x:y"; read -r c d <<< "p:q r"; echo "[$c][$d]"'
            ),
            b"[p:q][r]\n",
        )

    def test_shell_ifs_is_used(self) -> None:
        self.assertEqual(
            self.run_line(b'IFS=x; read -r a b <<< 1x2; echo "[$a][$b]"'),
            b"[1][2]\n",
        )

    def test_reply_keeps_the_line_unmodified(self) -> None:
        self.assertEqual(
            self.run_line(b'read -r <<< "  sp  "; echo "[$REPLY]"'), b"[  sp  ]\n"
        )

    def test_empty_ifs_does_not_split_or_trim(self) -> None:
        self.assertEqual(
            self.run_line(b'IFS= read -r a <<< "  sp  "; echo "[$a]"'), b"[  sp  ]\n"
        )

    def test_backslash_escapes_without_r(self) -> None:
        self.assertEqual(
            self.run_line(b'read a b <<< "x\\\\ y z"; echo "[$a][$b]"'),
            b"[x y][z]\n",
        )
        self.assertEqual(
            self.run_line(b'read -r a b <<< "x\\\\ y z"; echo "[$a][$b]"'),
            b"[x\\][y z]\n",
        )

    def test_backslash_newline_continues_the_line(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf 'a\\\\\\nb c\\n' | { read x y; echo \"[$x][$y]\"; }"
            ),
            b"[ab][c]\n",
        )

    def test_eof_without_newline_assigns_and_fails(self) -> None:
        self.assertEqual(
            self.run_line(b'printf abc | { read x; echo "$?[$x]"; }'), b"1[abc]\n"
        )

    def test_empty_input_clears_variable_and_fails(self) -> None:
        self.assertEqual(
            self.run_line(b"x=old; printf '' | { read x; echo \"$?[$x]\"; }"),
            b"1[]\n",
        )

    def test_reads_one_line_at_a_time(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf 'a\\nb\\n' | { read x; read y; read z; echo \"$?[$x][$y][$z]\"; }"
            ),
            b"1[a][b][]\n",
        )

    def test_while_read_loop_over_a_pipe(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf 'a\\nb\\n' | while IFS= read -r l; do echo \"l=$l\"; done"
            ),
            b"l=a\nl=b\n",
        )

    def test_while_read_loop_over_a_file(self) -> None:
        self.proto.lineReceived(b"printf 'Name:\\tx\\nPid:\\t42\\n' > /tmp/status")
        self.assertEqual(
            self.run_line(
                b'while IFS=: read -r k v; do case "$k" in Pid) p=$v;; esac; '
                b'done < /tmp/status; echo "[$p]"'
            ),
            b"[\t42]\n",
        )

    def test_reads_a_line_typed_at_the_terminal(self) -> None:
        self.assertEqual(self.run_line(b"read -p 'name? ' x"), b"name? ")
        self.proto.lineReceived(b"typed words")
        self.assertEqual(self.run_line(b'echo "[$x]"'), b"[typed words]\n")

    def test_invalid_identifier(self) -> None:
        self.assertEqual(
            self.run_line(b"read 1x <<< a; echo $?"),
            b"-bash: read: `1x': not a valid identifier\n1\n",
        )

    def test_failed_read_leaves_the_input(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf 'a\\nb\\n' | { read 1x 2>/dev/null; read y; echo \"[$y]\"; }"
            ),
            b"[a]\n",
        )

    def test_invalid_option(self) -> None:
        self.assertEqual(
            self.run_line(b"read -z <<< a; echo $?"),
            b"-bash: read: -z: invalid option\n"
            b"read: usage: read [-Eers] [-a array] [-d delim] [-i text] [-n nchars] "
            b"[-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]\n2\n",
        )


if __name__ == "__main__":
    unittest.main()
