# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: End-to-end tests for shell flow control (for/if/while/until/case,
# ABOUTME: brace groups, functions, break/continue) driven through the protocol.

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


class FlowControlTests(unittest.TestCase):
    """for / if / while / until / case / functions, run through the shell."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _run(self, line: str) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line.encode())
        value = bytes(self.tr.value())
        if value.endswith(PROMPT):
            value = value[: -len(PROMPT)]
        return value

    # -- for ----------------------------------------------------------------

    def test_for_literal_list(self) -> None:
        self.assertEqual(self._run("for i in 1 2 3; do echo $i; done"), b"1\n2\n3\n")

    def test_for_over_variable_value(self) -> None:
        self.assertEqual(
            self._run("for w in a b c; do echo got $w; done"),
            b"got a\ngot b\ngot c\n",
        )

    def test_for_multiline(self) -> None:
        script = "for i in x y\ndo\n  echo $i\ndone"
        self.assertEqual(self._run(script), b"x\ny\n")

    def test_nested_for(self) -> None:
        self.assertEqual(
            self._run("for i in 1 2; do for j in a b; do echo $i$j; done; done"),
            b"1a\n1b\n2a\n2b\n",
        )

    # -- if -----------------------------------------------------------------

    def test_if_true_branch(self) -> None:
        self.assertEqual(
            self._run("if [ -f /etc/passwd ]; then echo yes; else echo no; fi"),
            b"yes\n",
        )

    def test_if_else_branch(self) -> None:
        self.assertEqual(
            self._run("if [ -f /no/such ]; then echo yes; else echo no; fi"),
            b"no\n",
        )

    def test_if_elif(self) -> None:
        self.assertEqual(
            self._run("if false; then echo a; elif true; then echo b; else echo c; fi"),
            b"b\n",
        )

    def test_if_uses_command_status(self) -> None:
        self.assertEqual(self._run("if true; then echo ran; fi"), b"ran\n")

    def test_and_chained_conditions(self) -> None:
        self.assertEqual(
            self._run("if [ -d /etc ] && [ -f /etc/passwd ]; then echo both; fi"),
            b"both\n",
        )

    # -- while / until ------------------------------------------------------

    def test_while_breaks_out(self) -> None:
        self.assertEqual(
            self._run("while true; do echo once; break; done"),
            b"once\n",
        )

    def test_until_runs_until_true(self) -> None:
        self.assertEqual(
            self._run("until [ -f /etc/passwd ]; do echo loop; done"),
            b"",
        )

    def test_while_infinite_is_capped(self) -> None:
        # A runaway loop must terminate at the safety cap rather than hang.
        from cowrie.shell.honeypot import MAX_WHILE_ITERATIONS

        output = self._run("while true; do echo x; done")
        self.assertEqual(output.count(b"x\n"), MAX_WHILE_ITERATIONS)

    # -- break / continue ---------------------------------------------------

    def test_break_stops_loop(self) -> None:
        self.assertEqual(
            self._run(
                "for i in 1 2 3 4 5; do echo $i; "
                "if [ $i -eq 3 ]; then break; fi; done"
            ),
            b"1\n2\n3\n",
        )

    def test_continue_skips_iteration(self) -> None:
        self.assertEqual(
            self._run(
                "for i in 1 2 3 4; do if [ $i -eq 2 ]; then continue; fi; "
                "echo $i; done"
            ),
            b"1\n3\n4\n",
        )

    def test_break_only_inner_loop(self) -> None:
        self.assertEqual(
            self._run(
                "for i in 1 2; do for j in a b c; do "
                "if [ $j = b ]; then break; fi; echo $i$j; done; done"
            ),
            b"1a\n2a\n",
        )

    # -- case ---------------------------------------------------------------

    def test_case_glob_match(self) -> None:
        self.assertEqual(
            self._run("case abc in a*) echo starts-a;; *) echo other;; esac"),
            b"starts-a\n",
        )

    def test_case_default(self) -> None:
        self.assertEqual(
            self._run("case xyz in a*) echo a;; *) echo default;; esac"),
            b"default\n",
        )

    def test_case_alternation(self) -> None:
        self.assertEqual(
            self._run("case b in a) echo A;; b|c) echo BC;; esac"),
            b"BC\n",
        )

    # -- brace group --------------------------------------------------------

    def test_brace_group(self) -> None:
        self.assertEqual(self._run("{ echo a; echo b; }"), b"a\nb\n")

    # -- functions ----------------------------------------------------------

    def test_function_definition_and_call(self) -> None:
        self.assertEqual(
            self._run("greet() { echo hello $1; }; greet world"),
            b"hello world\n",
        )

    def test_function_arg_count(self) -> None:
        self.assertEqual(
            self._run("count() { echo $#; }; count a b c"),
            b"3\n",
        )

    def test_function_keyword_form(self) -> None:
        self.assertEqual(
            self._run("function f { echo from_f; }; f"),
            b"from_f\n",
        )

    # -- exit status propagation -------------------------------------------

    def test_status_after_if(self) -> None:
        self.assertEqual(self._run("if true; then true; fi; echo $?"), b"0\n")

    def test_status_after_for(self) -> None:
        self.assertEqual(self._run("for i in 1; do false; done; echo $?"), b"1\n")

    # -- realistic downloader idiom ----------------------------------------

    def test_download_retry_idiom(self) -> None:
        # The canonical "try each mirror until one works" loop. echo stands in
        # for a downloader; the first success breaks the loop.
        self.assertEqual(
            self._run(
                "for url in http://a/x http://b/x; do "
                "echo fetch $url && break; done"
            ),
            b"fetch http://a/x\n",
        )


if __name__ == "__main__":
    unittest.main()
