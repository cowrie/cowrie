# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The sed command must edit streams as GNU sed does for the commands
# ABOUTME: attackers use: s, d, p, q, y, a/i/c, =, addresses, -n, -E and -i.

from __future__ import annotations

import os
import unittest

from cowrie.commands.sed import split_in_place
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class SedTests(unittest.TestCase):
    """Expected output is what GNU sed 4 prints in the C locale."""

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

    def test_substitute(self) -> None:
        self.assertEqual(self.run_line(b"echo hello | sed 's/l/L/'"), b"heLlo\n")
        self.assertEqual(self.run_line(b"echo hello | sed 's/l/L/g'"), b"heLLo\n")
        self.assertEqual(self.run_line(b"echo hello | sed 's/l/L/2'"), b"helLo\n")
        self.assertEqual(self.run_line(b"echo HeLLo | sed 's/l/_/Ig'"), b"He__o\n")

    def test_substitute_groups_and_ampersand(self) -> None:
        self.assertEqual(
            self.run_line(b"echo abc | sed 's/\\(b\\)/[\\1]/'"), b"a[b]c\n"
        )
        self.assertEqual(self.run_line(b"echo abc | sed -E 's/(b)/[\\1]/'"), b"a[b]c\n")
        self.assertEqual(self.run_line(b"echo abc | sed 's/b/&&/'"), b"abbc\n")
        self.assertEqual(self.run_line(b"echo abc | sed 's/b/\\n/'"), b"a\nc\n")

    def test_basic_regex_syntax(self) -> None:
        self.assertEqual(self.run_line(b"echo a.b | sed 's/\\./X/'"), b"aXb\n")
        self.assertEqual(self.run_line(b"echo aaa | sed 's/a\\{2\\}/X/'"), b"Xa\n")
        self.assertEqual(self.run_line(b"echo aab | sed 's/a\\+/X/'"), b"Xb\n")
        self.assertEqual(self.run_line(b"echo ab | sed 's/\\(a\\|b\\)/X/g'"), b"XX\n")

    def test_bracket_classes_and_anchors(self) -> None:
        self.assertEqual(
            self.run_line(
                b"echo '  x y  ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'"
            ),
            b"x y\n",
        )

    def test_other_delimiters(self) -> None:
        self.assertEqual(self.run_line(b"echo x | sed 's/x/a\\/b/'"), b"a/b\n")
        self.assertEqual(self.run_line(b"echo x | sed 's|x|a/b|'"), b"a/b\n")

    def test_print_and_delete_with_addresses(self) -> None:
        abc = b"printf 'a\\nb\\nc\\n' | "
        self.assertEqual(self.run_line(abc + b"sed -n '2p'"), b"b\n")
        self.assertEqual(self.run_line(abc + b"sed '2d'"), b"a\nc\n")
        self.assertEqual(self.run_line(abc + b"sed '$d'"), b"a\nb\n")
        self.assertEqual(self.run_line(abc + b"sed -n '/b/,$p'"), b"b\nc\n")
        self.assertEqual(self.run_line(abc + b"sed -n '/a/!p'"), b"b\nc\n")
        self.assertEqual(
            self.run_line(b"printf 'a\\n\\nb\\n' | sed '/^$/d'"), b"a\nb\n"
        )

    def test_quit_and_line_number(self) -> None:
        abc = b"printf 'a\\nb\\nc\\n' | "
        self.assertEqual(self.run_line(abc + b"sed '2q'"), b"a\nb\n")
        self.assertEqual(self.run_line(abc + b"sed -n '$='"), b"3\n")

    def test_transliterate(self) -> None:
        self.assertEqual(
            self.run_line(b"echo hello | sed 'y/abcdefghij/ABCDEFGHIJ/'"), b"HEllo\n"
        )

    def test_append_insert_change(self) -> None:
        ab = b"printf 'a\\nb\\n' | "
        self.assertEqual(self.run_line(ab + b"sed '1a added'"), b"a\nadded\nb\n")
        self.assertEqual(self.run_line(ab + b"sed '1i before'"), b"before\na\nb\n")
        self.assertEqual(self.run_line(ab + b"sed '2c changed'"), b"a\nchanged\n")

    def test_multiple_expressions_and_blocks(self) -> None:
        self.assertEqual(
            self.run_line(b"echo 'a b' | sed -e 's/a/1/' -e 's/b/2/'"), b"1 2\n"
        )
        self.assertEqual(
            self.run_line(b"printf 'a\\nb\\n' | sed '/a/{s/a/A/;p}'"), b"A\nA\nb\n"
        )

    def test_hold_space(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\nb\\nc\\n' | sed -n '1!G;h;$p'"), b"c\nb\na\n"
        )

    def test_labels_and_branches_join_lines(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a b\\nc d\\n' | sed ':a;N;$!ba;s/\\n/ /g'"),
            b"a b c d\n",
        )

    def test_print_only_substituted_lines(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'root:x:0\\nbin:x:1\\n' | sed -n 's/:.*//p'"),
            b"root\nbin\n",
        )

    def test_delete_first_line_of_pattern_space_restarts_cycle(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'a\\n\\n\\nb\\n' | sed '/^$/N;/\\n$/D'"),
            b"a\n\nb\n",
        )

    def test_in_place_edit(self) -> None:
        self.run_line(b"printf 'PermitRootLogin no\\n' > /tmp/sshd_config")
        self.assertEqual(
            self.run_line(
                b"sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /tmp/sshd_config"
            ),
            b"",
        )
        self.assertEqual(
            self.run_line(b"cat /tmp/sshd_config"), b"PermitRootLogin yes\n"
        )

    def test_in_place_forms(self) -> None:
        """-i with a backup suffix, clustered with -n, and after the script."""
        self.run_line(b"printf 'a\\nb\\n' > f; sed -i.bak 's/a/A/' f")
        self.assertEqual(self.run_line(b"cat f f.bak"), b"A\nb\na\nb\n")
        self.run_line(b"printf 'a\\nb\\n' > g; sed -ni 's/a/A/p' g")
        self.assertEqual(self.run_line(b"cat g"), b"A\n")
        self.run_line(b"printf 'a\\n' > h; sed 's/a/Z/' -i h")
        self.assertEqual(self.run_line(b"cat h"), b"Z\n")

    def test_unknown_command(self) -> None:
        self.assertEqual(
            self.run_line(b"echo x | sed 'k'; echo rc=$?"),
            b"sed: -e expression #1, char 1: unknown command: `k'\nrc=1\n",
        )

    def test_unterminated_substitute(self) -> None:
        self.assertEqual(
            self.run_line(b"echo x | sed 's/x/y'; echo rc=$?"),
            b"sed: -e expression #1, char 5: unterminated `s' command\nrc=1\n",
        )

    def test_missing_file(self) -> None:
        self.assertEqual(
            self.run_line(b"sed 's/x/y/' /nonexist; echo rc=$?"),
            b"sed: can't read /nonexist: No such file or directory\nrc=2\n",
        )

    def test_no_script_prints_usage(self) -> None:
        output = self.run_line(b"sed; echo rc=$?")
        self.assertTrue(output.startswith(b"Usage: sed [OPTION]..."), output)
        self.assertTrue(output.endswith(b"rc=1\n"), output)


class SplitInPlaceTests(unittest.TestCase):
    """-i takes an optional suffix glued to it, which getopt cannot parse
    before Python 3.14."""

    def test_forms(self) -> None:
        self.assertEqual(split_in_place(["-i", "s/a/b/", "f"]), (["s/a/b/", "f"], ""))
        self.assertEqual(split_in_place(["-i.bak", "s/a/b/"]), (["s/a/b/"], ".bak"))
        self.assertEqual(split_in_place(["-ni", "p"]), (["-n", "p"], ""))
        self.assertEqual(split_in_place(["--in-place=~", "p"]), (["p"], "~"))
        self.assertEqual(split_in_place(["s/a/b/", "-i", "f"]), (["s/a/b/", "f"], ""))

    def test_option_values_are_not_mistaken_for_i(self) -> None:
        self.assertEqual(
            split_in_place(["-e", "-iffy", "f"]), (["-e", "-iffy", "f"], None)
        )
        self.assertEqual(split_in_place(["-es/i/j/", "f"]), (["-es/i/j/", "f"], None))
        self.assertEqual(split_in_place(["--", "-i"]), (["--", "-i"], None))


if __name__ == "__main__":
    unittest.main()
