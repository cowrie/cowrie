# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that cwd is per-shell, like a process: cd in a substitution
# ABOUTME: or nested shell must not change the parent shell's directory.

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
PROMPT_TMP = b"root@unitTest:/tmp# "


class ShellCwdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_top_level_cd_persists(self) -> None:
        self.proto.lineReceived(b"cd /tmp; pwd\n")
        self.assertEqual(self.tr.value(), b"/tmp\n" + PROMPT_TMP)

    def test_substitution_sees_its_own_cd(self) -> None:
        self.proto.lineReceived(b"echo $(cd /tmp; pwd)\n")
        self.assertEqual(self.tr.value(), b"/tmp\n" + PROMPT)

    def test_substitution_cd_does_not_leak(self) -> None:
        self.proto.lineReceived(b"echo $(cd /tmp; pwd); pwd\n")
        self.assertEqual(self.tr.value(), b"/tmp\n/root\n" + PROMPT)

    def test_substitution_inherits_parent_cwd(self) -> None:
        self.proto.lineReceived(b"cd /etc\n")
        self.tr.clear()
        self.proto.lineReceived(b"echo $(pwd)\n")
        self.assertEqual(self.tr.value(), b"/etc\nroot@unitTest:/etc# ")

    def test_nested_sh_cd_does_not_leak(self) -> None:
        self.proto.lineReceived(b"sh -c 'cd /tmp; pwd'; pwd\n")
        self.assertEqual(self.tr.value(), b"/tmp\n/root\n" + PROMPT)

    def test_relative_path_resolves_against_shell_cwd(self) -> None:
        self.proto.lineReceived(b"cd /etc; cat passwd\n")
        out = self.tr.value()
        self.assertIn(b"root:", out)
