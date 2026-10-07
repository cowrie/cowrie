# SPDX-FileCopyrightText: 2020 Matej Dujava <mdujava@gmail.com>
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


class ShellCatCommandTests(unittest.TestCase):
    """Test for cowrie/commands/cat.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_cat_command_001(self) -> None:
        self.proto.lineReceived(b"cat nonExisting\n")
        self.assertEqual(
            self.tr.value(), b"cat: nonExisting: No such file or directory\n" + PROMPT
        )

    def test_cat_exit_status(self) -> None:
        # GNU cat exits 1 when any file could not be read, after reading the
        # rest, and on an invalid option; otherwise 0.
        for line, expected in (
            (b"cat /etc/hostname > /dev/null; echo $?", b"0\n"),
            (
                b"cat nonExisting; echo $?",
                b"cat: nonExisting: No such file or directory\n1\n",
            ),
            (b"cat /; echo $?", b"cat: /: Is a directory\n1\n"),
            (
                b"cat nonExisting /etc/hostname > /dev/null; echo $?",
                b"cat: nonExisting: No such file or directory\n1\n",
            ),
            (
                b"cat -Z; echo $?",
                b"cat: invalid option -- 'Z'\n"
                b"Try 'cat --help' for more information.\n1\n",
            ),
        ):
            with self.subTest(line=line):
                self.tr.clear()
                self.proto.lineReceived(line)
                self.assertEqual(self.tr.value(), expected + PROMPT)

    def test_cat_command_002(self) -> None:
        self.proto.lineReceived(b"echo test | cat -\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_cat_command_003(self) -> None:
        self.proto.lineReceived(b"echo 1 | cat\n")
        self.proto.lineReceived(b"echo 2\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), b"1\n" + PROMPT + b"2\n" + PROMPT)

    def test_cat_command_004(self) -> None:
        self.proto.lineReceived(b"cat\n")
        self.proto.lineReceived(b"test\n")
        self.proto.handle_CTRL_C()
        self.assertEqual(self.tr.value(), b"test\n^C\n" + PROMPT)
