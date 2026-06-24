# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the test / [ conditional utility and the true / false programs.
# ABOUTME: Exit codes are observed through $? so the shell integration is exercised too.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class TestTrueFalseTests(unittest.TestCase):
    """The true / false utilities and the test / [ conditional."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _status(self, line: str) -> bytes:
        """Run ``line`` then return what ``echo $?`` prints (without the prompt)."""
        self.tr.clear()
        self.proto.lineReceived(f"{line}; echo $?".encode())
        return bytes(self.tr.value())[: -len(PROMPT)]

    # -- true / false -------------------------------------------------------

    def test_true_exit_zero(self) -> None:
        self.assertEqual(self._status("true"), b"0\n")

    def test_false_exit_one(self) -> None:
        self.assertEqual(self._status("false"), b"1\n")

    def test_true_short_circuit(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"true && echo yes")
        self.assertEqual(self.tr.value(), b"yes\n" + PROMPT)

    def test_false_short_circuit(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"false || echo recovered")
        self.assertEqual(self.tr.value(), b"recovered\n" + PROMPT)

    # -- file tests ---------------------------------------------------------

    def test_dir_exists(self) -> None:
        self.assertEqual(self._status("test -d /etc"), b"0\n")

    def test_dir_on_file_is_false(self) -> None:
        self.assertEqual(self._status("test -d /etc/passwd"), b"1\n")

    def test_file_exists(self) -> None:
        self.assertEqual(self._status("test -f /etc/passwd"), b"0\n")

    def test_file_missing(self) -> None:
        self.assertEqual(self._status("test -f /no/such/path"), b"1\n")

    def test_exists_operator(self) -> None:
        self.assertEqual(self._status("test -e /etc"), b"0\n")

    def test_bracket_file_exists(self) -> None:
        self.assertEqual(self._status("[ -f /etc/passwd ]"), b"0\n")

    # -- string tests -------------------------------------------------------

    def test_string_equal(self) -> None:
        self.assertEqual(self._status("[ abc = abc ]"), b"0\n")

    def test_string_not_equal(self) -> None:
        self.assertEqual(self._status("[ abc != xyz ]"), b"0\n")

    def test_string_empty(self) -> None:
        self.assertEqual(self._status("[ -z '' ]"), b"0\n")

    def test_string_nonempty(self) -> None:
        self.assertEqual(self._status("[ -n hello ]"), b"0\n")

    def test_single_arg_nonempty_true(self) -> None:
        self.assertEqual(self._status("[ hello ]"), b"0\n")

    def test_single_arg_empty_false(self) -> None:
        self.assertEqual(self._status("[ '' ]"), b"1\n")

    # -- integer tests ------------------------------------------------------

    def test_int_eq(self) -> None:
        self.assertEqual(self._status("[ 5 -eq 5 ]"), b"0\n")

    def test_int_lt(self) -> None:
        self.assertEqual(self._status("[ 3 -lt 5 ]"), b"0\n")

    def test_int_ge_false(self) -> None:
        self.assertEqual(self._status("[ 3 -ge 5 ]"), b"1\n")

    def test_int_non_numeric_errors(self) -> None:
        # A non-integer operand is a usage error: exit status 2.
        out = self._status("[ x -eq 5 ]")
        self.assertIn(b"integer expression expected", out)
        self.assertTrue(out.endswith(b"2\n"))

    # -- negation and combination ------------------------------------------

    def test_negation(self) -> None:
        self.assertEqual(self._status("[ ! -f /no/such/path ]"), b"0\n")

    def test_and_combiner(self) -> None:
        self.assertEqual(self._status("[ -d /etc -a -f /etc/passwd ]"), b"0\n")

    def test_or_combiner(self) -> None:
        self.assertEqual(self._status("[ -f /no/such -o -d /etc ]"), b"0\n")

    # -- malformed ----------------------------------------------------------

    def test_bracket_missing_close(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(b"[ -d /etc ")
        self.assertIn(b"missing `]'", self.tr.value())


if __name__ == "__main__":
    unittest.main()
