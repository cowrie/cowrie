# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that commands with no incoming input see stdin EOF and exit.
# ABOUTME: Guards against the cmdstack leak when a filter parks for input that never arrives.

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

# Commands that read stdin and would park forever if no input ever arrives.
# /proc/uptime exists in fs.pickle with empty content, so the upstream `cat`
# produces no stdout, which is the trigger for the leak.
TAIL_COMMANDS = ["cut -d. -f1", "uniq", "base64", "tee", "dd", "chpasswd", "sh", "bash"]


def run_line(line: bytes) -> tuple[int, int, bytes]:
    """Run a single line on a fresh connected protocol.

    Returns (cmdstack_before, cmdstack_after, terminal_output).
    """
    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")
    proto.makeConnection(tr)
    tr.clear()
    before = len(proto.cmdstack)
    proto.lineReceived(line)
    after = len(proto.cmdstack)
    return before, after, tr.value()


class PipeEofTests(unittest.TestCase):
    """Tests for stdin EOF delivery to commands with no incoming input."""

    def test_substitution_empty_input_does_not_leak(self) -> None:
        """A command with empty input inside $(...) must exit cleanly.

        The cmdstack must return to its original depth (no leaked shell), and
        the captured substitution must be empty -- in particular a piped
        `sh`/`bash` must not write its prompt into the captured output.
        """
        for tail_cmd in TAIL_COMMANDS:
            with self.subTest(tail_cmd=tail_cmd):
                before, after, output = run_line(
                    f'x=$(cat /proc/uptime 2>/dev/null | {tail_cmd}); echo "X:$x"'.encode()
                )
                self.assertEqual(
                    after,
                    before,
                    f"cmdstack leaked for {tail_cmd!r}: {before} -> {after}",
                )
                self.assertEqual(
                    output,
                    b"X:$x\n" + PROMPT,
                    f"unexpected output for {tail_cmd!r}: {output!r}",
                )

    def test_interactive_empty_pipe_returns_to_prompt(self) -> None:
        """A filter downstream of an empty pipe must exit on EOF, not park."""
        before, after, output = run_line(
            b"cat /proc/uptime 2>/dev/null | cut -d. -f1\n"
        )
        self.assertEqual(after, before, f"cmdstack leaked: {before} -> {after}")
        self.assertTrue(
            output.endswith(PROMPT),
            f"expected prompt after empty pipe, got {output!r}",
        )


class InteractiveStdinPreservedTests(unittest.TestCase):
    """Interactive terminal stdin reading must keep working after the fix."""

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

    def test_interactive_tee_waits_for_terminal_stdin(self) -> None:
        """`tee` typed at the prompt must wait for stdin, not exit immediately."""
        self.proto.lineReceived(b"tee\n")
        # Command is still parked waiting for stdin; feed it a line.
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)


class EofRoutingTests(unittest.TestCase):
    """Terminal CTRL-D and SSH channel EOF both deliver stdin EOF to the
    command currently reading, regardless of which source it came from."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_ctrl_d_keystroke_exits_parked_command(self) -> None:
        """A terminal CTRL-D exits the command reading stdin, back to a prompt."""
        self.proto.lineReceived(b"tee\n")
        self.assertEqual(len(self.proto.cmdstack), 2)
        self.proto.handle_CTRL_D()
        self.assertEqual(len(self.proto.cmdstack), 1)
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_channel_eof_exits_parked_command(self) -> None:
        """A closed SSH channel (eofReceived) exits the command reading stdin
        instead of tearing down the whole session."""
        self.proto.lineReceived(b"tee\n")
        self.assertEqual(len(self.proto.cmdstack), 2)
        self.proto.eofReceived()
        self.assertEqual(len(self.proto.cmdstack), 1)
