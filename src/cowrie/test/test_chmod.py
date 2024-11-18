# Copyright (c) 2020 Peter Sufliarsky
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

TRY_CHMOD_HELP_MSG = b"Try 'chmod --help' for more information.\n"
PROMPT = b"root@unitTest:~# "


class ShellChmodCommandTests(unittest.TestCase):
    """Test for cowrie/commands/chmod.py."""

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

    def test_chmod_command_001(self) -> None:
        self.proto.lineReceived(b"chmod")
        self.assertEqual(
            self.tr.value(), b"chmod: missing operand\n" + TRY_CHMOD_HELP_MSG + PROMPT
        )

    def test_chmod_command_002(self) -> None:
        self.proto.lineReceived(b"chmod -x")
        self.assertEqual(
            self.tr.value(), b"chmod: missing operand\n" + TRY_CHMOD_HELP_MSG + PROMPT
        )

    def test_chmod_command_003(self) -> None:
        self.proto.lineReceived(b"chmod +x")
        self.assertEqual(
            self.tr.value(),
            b"chmod: missing operand after \xe2\x80\x98+x\xe2\x80\x99\n"
            + TRY_CHMOD_HELP_MSG
            + PROMPT,
        )

    def test_chmod_command_004(self) -> None:
        self.proto.lineReceived(b"chmod -A")
        self.assertEqual(
            self.tr.value(),
            b"chmod: invalid option -- 'A'\n" + TRY_CHMOD_HELP_MSG + PROMPT,
        )

    def test_chmod_command_005(self) -> None:
        self.proto.lineReceived(b"chmod --A")
        self.assertEqual(
            self.tr.value(),
            b"chmod: unrecognized option '--A'\n" + TRY_CHMOD_HELP_MSG + PROMPT,
        )

    def test_chmod_command_006(self) -> None:
        self.proto.lineReceived(b"chmod -x abcd")
        self.assertEqual(
            self.tr.value(),
            b"chmod: cannot access 'abcd': No such file or directory\n" + PROMPT,
        )

    def test_chmod_command_007(self) -> None:
        self.proto.lineReceived(b"chmod abcd efgh")
        self.assertEqual(
            self.tr.value(),
            b"chmod: invalid mode: \xe2\x80\x98abcd\xe2\x80\x99\n"
            + TRY_CHMOD_HELP_MSG
            + PROMPT,
        )

    def test_chmod_command_008(self) -> None:
        self.proto.lineReceived(b"chmod +x .ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_009(self) -> None:
        self.proto.lineReceived(b"chmod -R +x .ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_010(self) -> None:
        self.proto.lineReceived(b"chmod +x /root/.ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_011(self) -> None:
        self.proto.lineReceived(b"chmod +x ~/.ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_012(self) -> None:
        self.proto.lineReceived(b"chmod a+x .ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_013(self) -> None:
        self.proto.lineReceived(b"chmod ug+x .ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_014(self) -> None:
        self.proto.lineReceived(b"chmod 777 .ssh")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chmod_command_015(self) -> None:
        self.proto.lineReceived(b"chmod 0755 .ssh")
        self.assertEqual(self.tr.value(), PROMPT)
