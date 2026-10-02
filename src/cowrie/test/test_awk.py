# SPDX-FileCopyrightText: 2020-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
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


class ShellEchoCommandTests(unittest.TestCase):
    """Tests for cowrie/commands/awk.py."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_awk_command_001(self) -> None:
        self.proto.lineReceived(b"echo \"test test\" | awk '{ print $0 }'\n")
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_awk_command_002(self) -> None:
        self.proto.lineReceived(b"echo \"test\" | awk '{ print $1 }'\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_awk_command_003(self) -> None:
        self.proto.lineReceived(b"echo \"test test\" | awk '{ print $1 $2 }'\n")
        self.assertEqual(self.tr.value(), b"testtest\n" + PROMPT)

    def test_awk_command_004(self) -> None:
        self.proto.lineReceived(b"echo \"test test\" | awk '{ print $1,$2 }'\n")
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line)
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_field_separator(self) -> None:
        self.assertEqual(self.run_line(b"echo a:b | awk -F: '{print $2}'"), b"b\n")
        self.assertEqual(self.run_line(b"echo a:b | awk -F : '{print $1}'"), b"a\n")

    def test_field_separator_regex(self) -> None:
        self.assertEqual(
            self.run_line(b"echo a,b:c | awk -F'[:,]' '{print $3}'"), b"c\n"
        )

    def test_pattern_with_space_keeps_field_whitespace(self) -> None:
        self.assertEqual(
            self.run_line(
                b"printf 'Model name:   Xeon\\nx: y\\n' | "
                b"awk -F: '/Model name/ {print $2}'"
            ),
            b"   Xeon\n",
        )

    def test_pattern_matches_anywhere_in_the_line(self) -> None:
        self.assertEqual(
            self.run_line(b"printf 'foo bar\\n' | awk '/o b/ { print $2 }'"), b"bar\n"
        )

    def test_pattern_without_action_prints_the_line(self) -> None:
        self.assertEqual(self.run_line(b"printf 'foo\\nbar\\n' | awk '/ar/'"), b"bar\n")

    def test_print_comma_uses_output_separator(self) -> None:
        self.assertEqual(self.run_line(b"echo 'a  b' | awk '{print $1, $2}'"), b"a b\n")

    def test_print_concatenates_strings_and_fields(self) -> None:
        self.assertEqual(
            self.run_line(b"echo a:b:c | awk -F':' '{print $1\"-\"$3}'"), b"a-c\n"
        )

    def test_print_builtin_variables(self) -> None:
        self.assertEqual(self.run_line(b"echo a b c | awk '{print $NF}'"), b"c\n")
        self.assertEqual(self.run_line(b"echo a b c | awk '{print NF}'"), b"3\n")
        self.assertEqual(
            self.run_line(b"printf 'x\\ny\\n' | awk '{print NR\": \"$0}'"),
            b"1: x\n2: y\n",
        )

    def test_bare_print_prints_the_line_unchanged(self) -> None:
        self.assertEqual(self.run_line(b"echo 'a  b' | awk '{print}'"), b"a  b\n")

    def test_invalid_separator_regex_does_not_wedge(self) -> None:
        self.assertEqual(
            self.run_line(b"echo 'a[(b' | awk -F'[(' '{print $2}'"), b"b\n"
        )

    def test_program_from_file(self) -> None:
        self.run_line(b"echo '{print $2}' > /tmp/prog.awk")
        self.assertEqual(self.run_line(b"echo a b | awk -f /tmp/prog.awk"), b"b\n")

    def test_bad_escape_in_string_does_not_wedge(self) -> None:
        self.assertEqual(self.run_line(b"echo a | awk '{print \"x\\q\"}'"), b"xq\n")

    def test_awk_command_005(self) -> None:
        self.proto.lineReceived(b"echo \"test test\" | awk '{ print $1$2 }'\n")
        self.assertEqual(self.tr.value(), b"testtest\n" + PROMPT)
