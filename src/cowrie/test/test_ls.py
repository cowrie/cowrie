# SPDX-FileCopyrightText: 2024 Ritvik Dayal <ritvik@doxel.ai>
# SPDX-FileCopyrightText: 2024 Michel Oosterhof <michel@oosterhof.net>
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


class ShellLsCommandTests(unittest.TestCase):
    """Test for cowrie/commands/ls.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_ls_command_001(self) -> None:
        self.proto.lineReceived(b"ls NonExisting; echo $?\n")
        self.assertEqual(
            self.tr.value(),
            b"ls: cannot access 'NonExisting': No such file or directory\n2\n"
            + PROMPT,
        )

    def test_ls_command_002(self) -> None:
        self.proto.lineReceived(b"ls /\n")
        self.assertEqual(
            self.tr.value(),
            b"bin   boot  dev   etc   home  lib   lib64 media mnt   opt   proc  root  run   \nsbin  srv   sys   tmp   usr   var   \n"
            + PROMPT,
        )

    def test_ls_command_003(self) -> None:
        self.proto.lineReceived(b"ls -l /\n")
        output = self.tr.value()
        self.assertIn(b"drwxr-xr-x 1 root root 4096 ", output)
        self.assertIn(b"lrwxrwxrwx 1 root root    7 ", output)
        self.assertIn(b" bin -> usr/bin\n", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_ls_command_004(self) -> None:
        self.proto.lineReceived(b"ls -lh /\n")
        output = self.tr.value()
        # -h prints human-readable sizes (4096 -> 4.0K)
        self.assertIn(b"drwxr-xr-x 1 root root 4.0K ", output)
        self.assertNotIn(b" 4096 ", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_ls_long_names_a_file_as_typed(self) -> None:
        for arg, shown in (
            (b".bashrc", b" .bashrc\n"),
            (b"../root/.bashrc", b" ../root/.bashrc\n"),
            (b"/root/.bashrc", b" /root/.bashrc\n"),
            # the shell would expand ~ before ls sees it
            (b"~/.bashrc", b" /root/.bashrc\n"),
        ):
            with self.subTest(arg=arg):
                self.tr.clear()
                self.proto.lineReceived(b"ls -l " + arg + b"\n")
                self.assertTrue(self.tr.value().endswith(shown + PROMPT))

    def test_ls_names_a_file_as_typed(self) -> None:
        self.proto.lineReceived(b"ls .bashrc\n")
        self.assertTrue(self.tr.value().startswith(b".bashrc"))

    def test_ls_directory_flag_names_the_directory_as_typed(self) -> None:
        self.proto.lineReceived(b"ls -ld .\n")
        self.assertTrue(self.tr.value().endswith(b" .\n" + PROMPT))
