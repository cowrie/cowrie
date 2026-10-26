# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for shell variable persistence, expansion and export scope.
# ABOUTME: Covers bare vs exported variables and command-substitution visibility.

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

    # Each statement's words are expanded just before it runs, so a same-line
    # assignment is visible to a later statement on the same line.
    def test_same_line_assignment_is_seen(self) -> None:
        self.assertEqual(self.run_line(b"x=hey; echo $x"), b"hey\n")
        self.assertEqual(self.run_line(b'y=ho; echo "$y"'), b"ho\n")
        self.assertEqual(self.run_line(b"a=1; b=2; echo $a$b"), b"12\n")

    # Cause 2: $VAR expands inside a larger token
    def test_expand_embedded_in_token(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b'echo "X:$x"'), b"X:hi\n")

    # Cause 3: command substitution sees the live shell's variables
    def test_command_substitution_sees_variable(self) -> None:
        self.proto.lineReceived(b"x=hi")
        self.assertEqual(self.run_line(b"echo $(echo $x)"), b"hi\n")

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

    # Positional parameters are not variables: `set` does not list them
    def test_set_omits_positional_parameters(self) -> None:
        output = self.run_line(b"f() { set; }; f a")
        for line in (b"1=a", b"#=1", b"@=a", b"*=a"):
            self.assertNotIn(b"\n" + line + b"\n", b"\n" + output)

    # $$ is the shell's process ID: a number, the same for the whole session
    def test_dollar_dollar_is_a_stable_number(self) -> None:
        pid = self.run_line(b"echo $$")
        self.assertRegex(pid, rb"^[1-9][0-9]*\n$")
        self.assertEqual(self.run_line(b'echo "$$" ${$}'), pid.strip() + b" " + pid)

    # A command substitution is a subshell, which keeps its parent's $$
    def test_command_substitution_keeps_parent_pid(self) -> None:
        self.assertEqual(
            self.run_line(b'[ "$(echo $$)" = "$$" ] && echo same'), b"same\n"
        )

    # sh -c starts a new shell process, with a PID of its own
    def test_new_shell_has_its_own_pid(self) -> None:
        pid = self.run_line(b"echo $$")
        child = self.run_line(b"sh -c 'echo $$'")
        self.assertRegex(child, rb"^[1-9][0-9]*\n$")
        self.assertNotEqual(child, pid)

    # $((...)) is integer arithmetic
    def test_arithmetic_expansion(self) -> None:
        self.proto.lineReceived(b"n=4")
        self.assertEqual(
            self.run_line(b'echo $((952*665+17)) "$((n * 2))" $(( $(echo 3) + n ))'),
            b"633097 8 7\n",
        )

    # The probe a payload-dropping bot runs before uploading
    def test_arithmetic_in_sh_c_probe(self) -> None:
        self.assertEqual(
            self.run_line(
                b"sh -c 'printf '\"'\"'\\n%s|%s\\n'\"'\"' '\"'\"'check_small_math'\"'\"'"
                b' "$((952*665+17))"\''
            ),
            b"\ncheck_small_math|633097\n",
        )

    # A rejected expression reports bash's error and fails only that command
    def test_arithmetic_error_fails_the_command(self) -> None:
        self.assertEqual(
            self.run_line(b"echo $((1/0)); echo $?"),
            b'-bash: 1/0: division by 0 (error token is "0")\n1\n',
        )

    # set with operands replaces the positional parameters and prints nothing
    def test_set_double_dash_binds_positional_parameters(self) -> None:
        self.assertEqual(
            self.run_line(b"set -- a 'b c'; echo \"$1|$2|$#\""), b"a|b c|2\n"
        )

    def test_set_operands_bind_positional_parameters(self) -> None:
        self.assertEqual(self.run_line(b'set x y; echo "$@"'), b"x y\n")

    def test_set_replaces_all_previous_positional_parameters(self) -> None:
        self.assertEqual(
            self.run_line(b'set a b c; set -- d; echo "$#|$1|$2"'), b"1|d|\n"
        )

    def test_set_double_dash_alone_clears_positional_parameters(self) -> None:
        self.assertEqual(self.run_line(b'set a b; set --; echo "$#"'), b"0\n")

    # Options alone change shell options, not the positional parameters, and
    # print nothing
    def test_set_options_print_nothing(self) -> None:
        self.assertEqual(self.run_line(b"set -e; set +x; echo ok"), b"ok\n")

    def test_set_option_name_is_not_a_positional_parameter(self) -> None:
        self.assertEqual(self.run_line(b'set -o pipefail; echo "$#"'), b"0\n")

    def test_set_options_then_operands(self) -> None:
        self.assertEqual(self.run_line(b'set -e a b; echo "$#|$1"'), b"2|a\n")

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

    # A word only counts as an assignment when a valid identifier precedes the
    # =; bash treats "=", "=foo" and "1x=5" as command names and reports them
    # as not found
    def test_bare_equals_is_command_not_found(self) -> None:
        self.assertEqual(self.run_line(b"="), b"-bash: =: command not found\n")

    def test_equals_prefixed_word_is_command_not_found(self) -> None:
        self.assertEqual(self.run_line(b"=foo"), b"-bash: =foo: command not found\n")

    def test_invalid_identifier_assignment_is_command_not_found(self) -> None:
        self.assertEqual(self.run_line(b"1x=5"), b"-bash: 1x=5: command not found\n")

    def test_underscore_identifier_assignment_persists(self) -> None:
        self.proto.lineReceived(b"_x=hi")
        self.assertEqual(self.run_line(b"echo $_x"), b"hi\n")

    # unset removes a variable from both scopes; afterwards a bare reference to
    # it drops the word, like any other unset name
    def test_unset_removes_variable(self) -> None:
        self.proto.lineReceived(b"export y=bye")
        self.proto.lineReceived(b"unset y")
        self.assertNotIn(b"y=bye", self.run_line(b"env"))
        self.assertEqual(self.run_line(b"echo $y end"), b"end\n")


if __name__ == "__main__":
    unittest.main()
