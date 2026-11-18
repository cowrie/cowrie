# SPDX-FileCopyrightText: 2026 Sanchitha408
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for which processes the ps command lists.
# ABOUTME: Covers the -e/-A "all processes" options and the BSD aux style (#1413).

from __future__ import annotations

import json
import os
import unittest

from cowrie.core.resources import open_data_binary
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = "root@unitTest:~# "


class PsListingTests(unittest.TestCase):
    """Regression tests for issue #1413: `ps -elf` showed only bash and ps."""

    def setUp(self) -> None:
        server = FakeServer()
        with open_data_binary("cmdoutput.json") as f:
            server.process = json.load(f)["command"]["ps"]
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(server))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _ps(self, command: str) -> list[str]:
        """Run a command and return its output lines, without the prompt."""
        self.tr.clear()
        self.proto.lineReceived(f"{command}\n".encode())
        output: str = self.tr.value().decode()
        self.assertTrue(output.endswith(PROMPT))
        return output[: -len(PROMPT)].splitlines()

    def test_plain_ps_lists_only_the_session(self) -> None:
        lines = self._ps("ps")

        self.assertEqual(len(lines), 3)
        self.assertIn("-bash", lines[1])
        self.assertIn("ps", lines[2])

    def test_dashed_all_options_list_every_process(self) -> None:
        # -e and -A select every process, alone or combined with -f and -l.
        everything = len(self._ps("ps aux"))
        self.assertGreater(everything, 3)

        for command in ("ps -e", "ps -A", "ps -ef", "ps -elf", "ps -e -f"):
            with self.subTest(command=command):
                lines = self._ps(command)

                self.assertGreater(len(lines), 3)
                self.assertTrue(any("[kthreadd]" in line for line in lines))

    def test_dashed_options_without_all_keep_the_session_only(self) -> None:
        # -f and -l change the columns, they do not select more processes.
        for command in ("ps -f", "ps -l", "ps -fl"):
            with self.subTest(command=command):
                self.assertEqual(len(self._ps(command)), 3)

    def test_bsd_aux_is_unchanged(self) -> None:
        # Lines are cut to the terminal width unless "w" is given, so use it
        # to see the command column.
        self.assertTrue(self._ps("ps aux")[0].startswith("USER"))

        lines = self._ps("ps auxw")

        self.assertGreater(len(lines), 3)
        self.assertTrue(any("[kthreadd]" in line for line in lines))

    def test_long_options_are_not_read_as_all(self) -> None:
        # "--version" contains an "e" but is not an -e option.
        lines = self._ps("ps --version")

        self.assertLessEqual(len(lines), 3)


if __name__ == "__main__":
    unittest.main()
