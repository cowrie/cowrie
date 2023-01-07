# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellEchoCommandTests(unittest.TestCase):
    """Test for echo command from cowrie/commands/base.py."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost("tearDown From Unit Test")

    def setUp(self) -> None:
        self.tr.clear()

    def test_echo_command_001(self) -> None:
        self.proto.lineReceived(b'echo "test"\n')
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_002(self) -> None:
        self.proto.lineReceived(b"echo test  test\n")
        self.assertEqual(self.tr.value(), b"test test\n" + PROMPT)

    def test_echo_command_003(self) -> None:
        self.proto.lineReceived(b'echo -n "test  test"\n')
        self.assertEqual(self.tr.value(), b"test  test" + PROMPT)

    def test_echo_command_005(self) -> None:
        self.proto.lineReceived(b"echo test > test5; cat test5")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_006(self) -> None:
        self.proto.lineReceived(b'echo "\\n"\n')
        self.assertEqual(self.tr.value(), b"\\n\n" + PROMPT)

    def test_echo_command_007(self) -> None:
        self.proto.lineReceived(b"echo test >> test7; cat test7")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_008(self) -> None:
        self.proto.lineReceived(b"echo test > test8; echo test >> test8; cat test8")
        self.assertEqual(self.tr.value(), b"test\ntest\n" + PROMPT)

    def test_echo_command_009(self) -> None:
        self.proto.lineReceived(b"echo test | grep test")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_010(self) -> None:
        self.proto.lineReceived(b"echo test | grep test2")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_echo_command_011(self) -> None:
        self.proto.lineReceived(b"echo test > test011; cat test011 | grep test")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_012(self) -> None:
        self.proto.lineReceived(b"echo test > test012; grep test test012")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_013(self) -> None:
        self.proto.lineReceived(b'echo "ls""ls"')
        self.assertEqual(self.tr.value(), b"lsls\n" + PROMPT)

    def test_echo_command_014(self) -> None:
        self.proto.lineReceived(b"echo '\"ls\"'")
        self.assertEqual(self.tr.value(), b'"ls"\n' + PROMPT)

    def test_echo_command_015(self) -> None:
        self.proto.lineReceived(b"echo \"'ls'\"")
        self.assertEqual(self.tr.value(), b"'ls'\n" + PROMPT)

    def test_echo_command_016(self) -> None:
        self.proto.lineReceived(b'echo -e "\x6b\x61\x6d\x69"')
        self.assertEqual(self.tr.value(), b"kami\n" + PROMPT)

    def test_echo_command_017(self) -> None:
        self.proto.lineReceived(b"echo echo test | bash")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_018(self) -> None:
        self.proto.lineReceived(b"echo $(echo test)")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_019(self) -> None:
        self.proto.lineReceived(b"echo $(echo $(echo test))")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_020(self) -> None:
        self.proto.lineReceived(b"echo test_$(echo test)_test")
        self.assertEqual(self.tr.value(), b"test_test_test\n" + PROMPT)

    def test_echo_command_021(self) -> None:
        self.proto.lineReceived(b"echo test_$(echo test)_test_$(echo test)_test")
        self.assertEqual(self.tr.value(), b"test_test_test_test_test\n" + PROMPT)

    def test_echo_command_022(self) -> None:
        self.proto.lineReceived(b"echo test; (echo test)")
        self.assertEqual(self.tr.value(), b"test\ntest\n" + PROMPT)

    def test_echo_command_023(self) -> None:
        self.proto.lineReceived(b"echo `echo test`")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_echo_command_024(self) -> None:
        self.proto.lineReceived(b"echo test_`echo test`_test")
        self.assertEqual(self.tr.value(), b"test_test_test\n" + PROMPT)

    def test_echo_command_025(self) -> None:
        self.proto.lineReceived(b"echo test_`echo test`_test_`echo test`_test")
        self.assertEqual(self.tr.value(), b"test_test_test_test_test\n" + PROMPT)

    def test_echo_command_026(self) -> None:
        self.proto.lineReceived(b'echo "TEST1: `echo test1`, TEST2: `echo test2`"')
        self.assertEqual(self.tr.value(), b"TEST1: test1, TEST2: test2\n" + PROMPT)

    def test_echo_command_027(self) -> None:
        self.proto.lineReceived(b"echo $LOGNAME")
        self.assertEqual(self.tr.value(), b"root\n" + PROMPT)

    def test_echo_command_028(self) -> None:
        self.proto.lineReceived(b"echo ${LOGNAME}")
        self.assertEqual(self.tr.value(), b"root\n" + PROMPT)

    def test_echo_command_029(self) -> None:
        self.proto.lineReceived(b"echo $(e)")
        self.assertEqual(self.tr.value(), b"-bash: e: command not found\n\n" + PROMPT)
