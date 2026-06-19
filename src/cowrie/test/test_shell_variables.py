# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for shell variable persistence, expansion and export scope.
# ABOUTME: Covers bare vs exported variables and command-substitution visibility.

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


class ShellVariableTests(unittest.TestCase):
    """Variable assignment, expansion and export-scope behaviour."""

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

    # Cause 1: a bare assignment persists for later commands
    def test_bare_assignment_persists(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b"echo $x"), b"hi\n")

    # Cause 2: $VAR expands inside a larger token
    def test_expand_embedded_in_token(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b'echo "X:$x"'), b"X:hi\n")

    def test_expand_braced_embedded_in_token(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b"echo a${x}b"), b"ahib\n")

    # Cause 3: command substitution sees the live shell's variables
    def test_command_substitution_sees_variable(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b"echo $(echo $x)"), b"hi\n")

    # An unknown reference embedded in a token is left verbatim, so quoted
    # awk/sed/perl field references survive (quoting is lost by the lexer)
    def test_unknown_embedded_left_verbatim(self) -> None:
        self.assertEqual(self.run_line(b'echo "X:$nope"'), b"X:$nope\n")

    def test_awk_field_reference_survives(self) -> None:
        self.assertEqual(
            self.run_line(b'echo "a b" | awk \'{print $1}\''), b"a\n"
        )

    # A bare unset reference drops the word (no spurious spaces)
    def test_unset_whole_token_dropped(self) -> None:
        self.assertEqual(self.run_line(b"echo $nope end"), b"end\n")

    # Regression: inherited environment variables still expand
    def test_inherited_variable_expands(self) -> None:
        self.assertEqual(self.run_line(b"echo $LOGNAME"), b"root\n")

    # Two-scope: a bare variable is NOT in the exported environment
    def test_bare_variable_not_in_env(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertNotIn(b"x=hi", self.run_line(b"env"))

    # Two-scope: a bare variable IS visible to `set`
    def test_bare_variable_in_set(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertIn(b"x=hi", self.run_line(b"set"))

    # export VAR=value sets and exports
    def test_export_assignment_in_env(self) -> None:
        self.proto.lineReceived(b"export y=bye")
        self.assertIn(b"y=bye", self.run_line(b"env"))

    # export VAR marks an existing bare variable as exported
    def test_export_promotes_existing(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.proto.lineReceived(b"export x")
        self.assertIn(b"x=hi", self.run_line(b"env"))

    # unset PATH must not crash later command dispatch
    def test_unset_path_does_not_crash(self) -> None:
        self.proto.lineReceived(b"unset PATH")
        self.assertEqual(self.run_line(b"whoami"), b"root\n")
        self.assertIn(b"command not found", self.run_line(b"definitelynotacommand"))

    # unset removes a variable from both scopes; once unknown its embedded
    # reference is left verbatim, like any other unset name
    def test_unset_removes_variable(self) -> None:
        self.proto.lineReceived(b"export y=bye")
        self.proto.lineReceived(b"unset y")
        self.assertNotIn(b"y=bye", self.run_line(b"env"))
        self.assertEqual(self.run_line(b"echo $y end"), b"end\n")


if __name__ == "__main__":
    unittest.main()
