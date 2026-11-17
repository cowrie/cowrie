# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Every emulated process has its own process ID and parent ID, as on
# ABOUTME: Linux: builtins run in the shell, other commands are child processes.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class Command_pidprobe(HoneyPotCommand):
    """Prints the process ID and parent process ID it was given."""

    def call(self) -> None:
        self.write(f"{self.pid} {self.ppid}\n")


class ProcessIdTests(unittest.TestCase):
    def setUp(self) -> None:
        # "pidprobe" runs as an external command; "times" is a bash builtin
        # name, so the same probe registered under it runs as a builtin.
        commands = patch.dict(
            HoneyPotInteractiveProtocol.commands,
            {
                "pidprobe": Command_pidprobe,
                "times": Command_pidprobe,
                "/usr/bin/times": Command_pidprobe,
            },
        )
        commands.start()
        self.addCleanup(commands.stop)
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

    def ids(self, line: bytes) -> list[int]:
        return [int(word) for word in self.run_line(line).split()]

    def test_command_is_a_child_of_the_shell(self) -> None:
        shell, pid, ppid = self.ids(b"echo $$; pidprobe")
        self.assertNotEqual(pid, shell)
        self.assertEqual(ppid, shell)

    def test_each_command_gets_a_new_pid(self) -> None:
        first, _, second, _ = self.ids(b"pidprobe; pidprobe")
        self.assertGreater(second, first)

    def test_builtin_runs_in_the_shell(self) -> None:
        shell, pid, _ = self.ids(b"echo $$; times")
        self.assertEqual(pid, shell)

    def test_builtin_called_by_path_is_a_child(self) -> None:
        # A builtin's name only means the builtin when typed bare.
        shell, pid, ppid = self.ids(b"echo $$; /usr/bin/times")
        self.assertNotEqual(pid, shell)
        self.assertEqual(ppid, shell)

    def test_sh_c_runs_as_one_child_process(self) -> None:
        # The sh process is the inner shell: its builtins report the inner
        # $$, whose parent is the outer shell.
        outer, inner, pid, ppid = self.ids(b"echo $$; sh -c 'echo $$; times'")
        self.assertNotEqual(inner, outer)
        self.assertEqual(pid, inner)
        self.assertEqual(ppid, outer)

    def test_command_in_sh_c_is_a_child_of_the_inner_shell(self) -> None:
        inner, pid, ppid = self.ids(b"sh -c 'echo $$; pidprobe'")
        self.assertNotEqual(pid, inner)
        self.assertEqual(ppid, inner)

    def test_subshell_is_its_own_process_but_keeps_dollar_dollar(self) -> None:
        shell, inner, pid, ppid = self.ids(b"echo $$; (echo $$; times)")
        self.assertEqual(inner, shell)
        self.assertNotEqual(pid, shell)
        self.assertEqual(ppid, shell)


if __name__ == "__main__":
    unittest.main()
