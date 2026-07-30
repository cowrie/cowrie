# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Attacker-controlled bytes that are not valid UTF-8 must not crash
# ABOUTME: session setup, the shell pipeline, or download handling.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock

from twisted.conch.ssh.common import NS

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.llm import avatar as llm_avatar
from cowrie.llm import session as llm_session
from cowrie.llm import telnet as llm_telnet
from cowrie.shell import avatar as shell_avatar
from cowrie.shell import session as shell_session
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.ssh import session as ssh_session
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport


class SessionSetupTests(unittest.TestCase):
    """A non-UTF-8 username, TERM or env var must not crash session setup
    right after the honeypot has accepted the login."""

    def test_ssh_username(self) -> None:
        user = shell_avatar.CowrieUser(b"admin\xff", FakeServer())
        self.assertEqual(user.username, "admin�")

    def test_llm_ssh_username(self) -> None:
        user = llm_avatar.CowrieUser(b"admin\xff", FakeServer())
        self.assertEqual(user.username, "admin�")

    def test_llm_telnet_username(self) -> None:
        session = llm_telnet.HoneyPotTelnetSession(b"admin\xff", FakeServer())
        self.assertEqual(session.username, "admin�")

    def test_term_from_pty_request(self) -> None:
        for mod in (shell_session, llm_session):
            with self.subTest(module=mod.__name__):
                sess = mod.SSHSessionForCowrieUser.__new__(mod.SSHSessionForCowrieUser)
                sess.environ = {}
                sess.avatar = MagicMock()
                capture_events(sess.avatar.conn.transport)

                sess.getPty(b"xterm\xff", (24, 80, 0, 0), None)

                self.assertEqual(sess.environ["TERM"], "xterm�")

    def test_env_from_env_request(self) -> None:
        sess = ssh_session.HoneyPotSSHSession.__new__(ssh_session.HoneyPotSSHSession)
        sess.conn = MagicMock()
        capture_events(sess.conn.transport)
        sess.session = MagicMock()
        sess.session.environ = {}

        rc = sess.request_env(NS(b"LA\xffNG") + NS(b"C\xff"))

        self.assertEqual(rc, 0)
        self.assertEqual(sess.session.environ, {"LA�NG": "C�"})


class ShellPipelineTests(unittest.TestCase):
    """The attacker can produce arbitrary bytes inside the shell (echo -e
    escapes); piping or substituting them must not crash the session."""

    PROMPT = b"root@unitTest:~# "

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_non_utf8_bytes_piped_to_awk(self) -> None:
        self.proto.lineReceived(b"echo -e '\\xff' | awk '{ print $0 }'\n")
        self.assertTrue(self.tr.value().endswith(self.PROMPT))

    def test_non_utf8_bytes_piped_to_tee(self) -> None:
        self.proto.lineReceived(b"echo -e '\\xff' | tee /tmp/out\n")
        self.assertTrue(self.tr.value().endswith(self.PROMPT))

    def test_non_utf8_bytes_in_command_substitution(self) -> None:
        self.proto.lineReceived(b"echo $(echo -e '\\xff')\n")
        self.assertTrue(self.tr.value().endswith(self.PROMPT))


if __name__ == "__main__":
    unittest.main()
