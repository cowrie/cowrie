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
from twisted.web.http_headers import Headers

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.commands.curl import Command_curl
from cowrie.commands.wget import Command_wget
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


class HttpResponseMetadataTests(unittest.TestCase):
    """Response metadata comes from an attacker-directed server; non-UTF-8
    bytes in it must not crash download handling."""

    PROMPT = b"root@unitTest:~# "

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_wget_non_utf8_content_type_and_phrase(self) -> None:
        cmd = Command_wget.__new__(Command_wget)
        cmd.protocol = self.proto
        begun: list = []
        cmd._begin_download = (  # type: ignore[method-assign]
            lambda *args: begun.append(args) or False
        )
        response = MagicMock()
        response.headers = Headers({b"content-type": [b"text\xff/html"]})
        response.code = 200
        response.phrase = b"O\xffK"
        response.length = 10

        cmd.success(response)

        self.assertEqual(begun[0][1], "text�/html")
        self.assertIn("O�K", begun[0][2])

    def test_curl_head_non_utf8_headers(self) -> None:
        cmd = Command_curl.__new__(Command_curl)
        cmd.protocol = self.proto
        writes: list[str] = []
        cmd.write = writes.append  # type: ignore[assignment]
        cmd.exit = lambda code=None: None  # type: ignore[method-assign]
        cmd.head_request = True
        response = MagicMock()
        response.length = 0
        response.code = 200
        response.headers = Headers({b"X-Evil": [b"v\xffal"]})

        cmd.success(response)

        self.assertIn("v�al", "".join(writes))

    def test_curl_non_ascii_url(self) -> None:
        """A non-ASCII URL typed by the attacker must not crash curl
        (url.encode('ascii') raised UnicodeEncodeError)."""
        self.proto.lineReceived("curl http://192.168.1.1/päth\n".encode())
        self.assertTrue(self.tr.value().endswith(self.PROMPT))


if __name__ == "__main__":
    unittest.main()
