# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Shell error messages must carry the prefix bash uses for each kind of
# ABOUTME: shell: "-bash:" at a login prompt, "bash: line N:" for -c and exec.

from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import CaptureSink, make_exec_transport
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


def run_exec(cmd: bytes) -> bytes:
    """Run ``cmd`` as an SSH exec command and return the channel output."""
    out = bytearray()
    transport = make_exec_transport(CaptureSink())
    transport.write = out.extend
    lsp = insults.LoggingServerProtocol(
        protocol.HoneyPotExecProtocol, FakeAvatar(FakeServer()), cmd
    )
    lsp.makeConnection(transport)
    return bytes(out)


class ExecChannelPrefixTests(unittest.TestCase):
    """sshd runs an exec command with `bash -c`: errors name the line."""

    def test_command_not_found(self) -> None:
        self.assertEqual(
            run_exec(b"xxxxxx"), b"bash: line 1: xxxxxx: command not found\n"
        )

    def test_errors_name_their_line(self) -> None:
        self.assertEqual(
            run_exec(
                b"echo a\nxxxxxx\n./nope\ncd /nonexist\n"
                b"echo $(yyyyyy)\necho x > /nonexist/f\nprintf '%d' q"
            ),
            b"a\n"
            b"bash: line 2: xxxxxx: command not found\n"
            b"bash: line 3: ./nope: No such file or directory\n"
            b"bash: line 4: cd: /nonexist: No such file or directory\n"
            b"bash: line 5: yyyyyy: command not found\n"
            b"\n"
            b"bash: line 6: /nonexist/f: No such file or directory\n"
            b"bash: line 7: printf: q: invalid number\n"
            b"0",
        )

    def test_syntax_error_quotes_its_line(self) -> None:
        self.assertEqual(
            run_exec(b"echo a\nfi"),
            b"a\n"
            b"bash: -c: line 2: syntax error near unexpected token `fi'\n"
            b"bash: -c: line 2: `fi'\n",
        )


class InteractivePrefixTests(unittest.TestCase):
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

    def test_login_shell_builtin_error(self) -> None:
        self.assertEqual(
            self.run_line(b"cd /nonexist"),
            b"-bash: cd: /nonexist: No such file or directory\n",
        )

    def test_bash_c_names_its_line(self) -> None:
        self.assertEqual(
            self.run_line(b"bash -c 'xxxxxx'"),
            b"bash: line 1: xxxxxx: command not found\n",
        )

    def test_c_shell_is_named_as_invoked(self) -> None:
        self.assertEqual(
            self.run_line(b"sh -c 'xxxxxx'"), b"sh: line 1: xxxxxx: command not found\n"
        )
        self.assertEqual(
            self.run_line(b"/bin/bash -c 'xxxxxx'"),
            b"/bin/bash: line 1: xxxxxx: command not found\n",
        )

    def test_bash_c_syntax_error(self) -> None:
        self.assertEqual(
            self.run_line(b"bash -c 'echo a; fi'"),
            b"bash: -c: line 1: syntax error near unexpected token `fi'\n"
            b"bash: -c: line 1: `echo a; fi'\n",
        )

    def test_script_names_itself_and_its_line(self) -> None:
        self.run_line(b"printf 'echo s\\nxxxxxx\\n' > s.sh")
        self.assertEqual(
            self.run_line(b"bash s.sh"),
            b"s\ns.sh: line 2: xxxxxx: command not found\n",
        )
        self.run_line(b"printf '#!/bin/bash\\nzzzz\\n' > t.sh; chmod +x t.sh")
        self.assertEqual(
            self.run_line(b"./t.sh"), b"./t.sh: line 2: zzzz: command not found\n"
        )

    def test_nested_interactive_bash_has_no_line_numbers(self) -> None:
        self.run_line(b"bash")
        self.tr.clear()
        self.proto.lineReceived(b"xxxxxx")
        self.assertEqual(self.tr.value(), b"bash: xxxxxx: command not found\n" + PROMPT)


if __name__ == "__main__":
    unittest.main()
