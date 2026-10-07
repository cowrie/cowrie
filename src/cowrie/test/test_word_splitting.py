# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Unquoted expansions split into fields and empty ones vanish, as in bash;
# ABOUTME: expected outputs were taken from bash 5.3 running the same lines.

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


class WordSplittingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: str) -> str:
        """Send one line, return only the output it produced (prompt stripped)."""
        self.tr.clear()
        self.proto.lineReceived(line.encode())
        out: bytes = self.tr.value()
        if out.endswith(PROMPT):
            out = out[: -len(PROMPT)]
        return out.decode()

    def check(self, cases: list[tuple[str, str]]) -> None:
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(self.run_line(line), expected)

    def test_empty_substitution_runs_no_command(self) -> None:
        self.check(
            [
                ('$(); echo "rc=$?"', "rc=0\n"),
                ('$( ); echo "rc=$?"', "rc=0\n"),
                ('``; echo "rc=$?"', "rc=0\n"),
                ('$(true); echo "rc=$?"', "rc=0\n"),
                ('$(:); echo "rc=$?"', "rc=0\n"),
                ('$(echo); echo "rc=$?"', "rc=0\n"),
            ]
        )

    def test_empty_command_keeps_the_substitution_status(self) -> None:
        self.check(
            [
                ('$(false); echo "rc=$?"', "rc=1\n"),
                ('$(exit 3); echo "rc=$?"', "rc=3\n"),
            ]
        )

    def test_quoted_empty_substitution_is_still_a_command(self) -> None:
        self.assertEqual(
            self.run_line('"$()"; echo "rc=$?"'),
            "-bash: : command not found\nrc=127\n",
        )

    def test_substitution_output_splits_into_command_and_arguments(self) -> None:
        self.check(
            [
                ("$() echo hi", "hi\n"),
                ("$(echo echo hi)", "hi\n"),
            ]
        )

    def test_unquoted_substitution_splits_into_fields(self) -> None:
        self.check(
            [
                ("printf '[%s]' $(echo a b); echo", "[a][b]\n"),
                ("printf '[%s]' $(printf 'a\\n\\nb'); echo", "[a][b]\n"),
                ("printf '[%s]' a$(echo \"b c\")d; echo", "[ab][cd]\n"),
            ]
        )

    def test_quoted_substitution_stays_one_field(self) -> None:
        self.check(
            [
                ("printf '[%s]' \"$(echo a b)\"; echo", "[a b]\n"),
                ("printf '[%s]' x \"$()\" y; echo", "[x][][y]\n"),
                ("printf '[%s]' '' \"\"; echo", "[][]\n"),
            ]
        )

    def test_unquoted_empty_substitution_vanishes(self) -> None:
        self.assertEqual(self.run_line("printf '[%s]' x $() y; echo"), "[x][y]\n")

    def test_unquoted_variable_splits_into_fields(self) -> None:
        self.check(
            [
                ("x=$(echo a b); printf '[%s]' $x; echo", "[a][b]\n"),
                ("x=$(echo a b); printf '[%s]' \"$x\"; echo", "[a b]\n"),
                ("x=\"  a  b  \"; printf '[%s]' $x; echo", "[a][b]\n"),
                ("x=\"  a  b  \"; printf '[%s]' pre$x; echo", "[pre][a][b]\n"),
                ('x="  a  b  "; printf \'[%s]\' $x"q"; echo', "[a][b][q]\n"),
            ]
        )

    def test_assignment_values_are_not_split(self) -> None:
        self.check(
            [
                ("x=$(echo 'a   b'); printf '[%s]' \"$x\"; echo", "[a   b]\n"),
                ("export y=$(echo a b); printf '[%s]' \"$y\"; echo", "[a b]\n"),
            ]
        )

    def test_for_list_splits_into_fields(self) -> None:
        self.check(
            [
                ("for i in $(echo 1 2 3); do echo $i; done", "1\n2\n3\n"),
                ('x="a b"; for i in $x; do echo "[$i]"; done', "[a]\n[b]\n"),
            ]
        )

    def test_case_word_is_not_split(self) -> None:
        self.assertEqual(
            self.run_line(
                'x="a b"; case $x in "a b") echo matched;; *) echo no;; esac'
            ),
            "matched\n",
        )


if __name__ == "__main__":
    unittest.main()
