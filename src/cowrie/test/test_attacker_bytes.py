# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Attacker-controlled bytes that are not valid UTF-8 must not crash
# ABOUTME: session setup, the shell pipeline, or download handling.

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from twisted.conch.ssh import filetransfer
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
from cowrie.ssh_proxy import server_transport as proxy_transport
from cowrie.ssh_proxy.protocols import base_protocol
from cowrie.ssh_proxy.protocols import sftp as proxy_sftp
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


class ProxyModeTests(unittest.TestCase):
    """In proxy mode the client's raw protocol bytes reach these handlers
    directly; non-UTF-8 bytes in them must not crash the connection."""

    def test_kexinit_non_utf8_algorithm_name(self) -> None:
        """The hassh fingerprint decodes the client's algorithm lists; the
        shell backend already tolerates invalid UTF-8 there."""
        t = proxy_transport.FrontendSSHTransport.__new__(
            proxy_transport.FrontendSSHTransport
        )
        capture_events(t)
        with patch.object(
            proxy_transport.transport.SSHServerTransport,
            "ssh_KEXINIT",
            lambda s, p: None,
        ):
            t.ssh_KEXINIT(
                b"\x00" * 16
                + b"".join(
                    NS(field)
                    for field in (
                        b"curve25519-sha256\xff",  # kexAlgs
                        b"ssh-rsa",  # keyAlgs
                        b"aes128-ctr\xff",  # encCS
                        b"aes128-ctr",  # encSC
                        b"hmac-sha2-256\xff",  # macCS
                        b"hmac-sha2-256",  # macSC
                        b"none\xff",  # compCS
                        b"none",  # compSC
                        b"",  # langCS
                        b"",  # langSC
                    )
                )
                + b"\x00\x00\x00\x00\x00"
            )

    def test_sftp_upload_non_utf8_command(self) -> None:
        """The sftp command line is client bytes; deriving the uploaded
        filename from it must not raise UnicodeDecodeError."""
        sftp = proxy_sftp.SFTP.__new__(proxy_sftp.SFTP)
        sftp.events = None
        sftp.downloadPath = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, sftp.downloadPath, True)
        sftp.command = b"put /tmp/ev\xffil"
        sftp.path = b"/tmp/ev\xffil"
        sftp.theFile = b"uploaded-content"
        sftp.handle = b"h"
        # An FXP_CLOSE packet for that handle: type, request id, handle.
        sftp.parentPacket = base_protocol.BaseProtocol()
        sftp.parentPacket.data = (
            bytes([filetransfer.FXP_CLOSE]) + b"\x00\x00\x00\x01" + NS(b"h")
        )
        sftp.parentPacket.packetSize = len(sftp.parentPacket.data)

        sftp.handle_packet("[CLIENT]")

        saved = os.listdir(sftp.downloadPath)
        self.assertEqual(len(saved), 1)


if __name__ == "__main__":
    unittest.main()
