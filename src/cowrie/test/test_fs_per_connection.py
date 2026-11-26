# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that one SSH connection keeps one emulated filesystem: files
# ABOUTME: written in one channel (shell, exec, scp, SFTP) are there in the next.

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from types import SimpleNamespace

from twisted.internet.protocol import connectionDone

from cowrie.insults import insults
from cowrie.shell import fs, protocol
from cowrie.shell.filetransfer import SFTPServerForCowrieUser
from cowrie.shell.realm import HoneyPotRealm
from cowrie.shell.server import CowrieServer
from cowrie.shell.session import SSHSessionForCowrieUser
from cowrie.shell.telnet import HoneyPotTelnetSession
from cowrie.test.eventcapture import CaptureSink, make_exec_transport
from cowrie.test.fake_server import FakeAvatar, FakeServer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"
_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_fs_per_connection_")
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = _DOWNLOAD_DIR


def make_avatar(
    home: str = "/root", username: str = "root", temporary: bool = False
) -> SimpleNamespace:
    """An avatar on a real CowrieServer, as one SSH login gets."""
    uid = 1001 if temporary else 0
    return SimpleNamespace(
        server=CowrieServer(HoneyPotRealm()),
        uid=uid,
        gid=uid,
        username=username,
        home=home,
        temporary=temporary,
        conn=SimpleNamespace(transport=SimpleNamespace(events=None)),
    )


def make_file(filesystem: fs.HoneyPotFilesystem | None, path: str) -> None:
    assert filesystem is not None
    filesystem.mkfile(path, 0, 0, 0, stat.S_IFREG | 0o755)


class FilesystemPerConnectionTests(unittest.TestCase):
    def test_file_from_one_channel_is_there_in_the_next(self) -> None:
        avatar = make_avatar()
        SSHSessionForCowrieUser(avatar)
        make_file(avatar.server.fs, "/tmp/dropper")

        SSHSessionForCowrieUser(avatar)

        assert avatar.server.fs is not None
        self.assertTrue(avatar.server.fs.exists("/tmp/dropper"))

    def test_sftp_upload_is_there_in_a_later_channel(self) -> None:
        avatar = make_avatar()
        sftp = SFTPServerForCowrieUser(avatar)
        make_file(sftp.fs, "/root/.16")

        SSHSessionForCowrieUser(avatar)

        assert avatar.server.fs is not None
        self.assertTrue(avatar.server.fs.exists("/root/.16"))

    def test_sftp_sees_files_from_an_earlier_channel(self) -> None:
        avatar = make_avatar()
        SSHSessionForCowrieUser(avatar)
        make_file(avatar.server.fs, "/tmp/payload")

        sftp = SFTPServerForCowrieUser(avatar)

        self.assertTrue(sftp.fs.exists("/tmp/payload"))

    def test_temporary_home_is_created_once(self) -> None:
        avatar = make_avatar(home="/home/newuser", username="newuser", temporary=True)
        SSHSessionForCowrieUser(avatar)
        SSHSessionForCowrieUser(avatar)

        assert avatar.server.fs is not None
        names = [entry[fs.A_NAME] for entry in avatar.server.fs.get_path("/home")]
        self.assertEqual(names.count("newuser"), 1)

    def test_separate_connections_have_separate_filesystems(self) -> None:
        first = make_avatar()
        second = make_avatar()
        SSHSessionForCowrieUser(first)
        SSHSessionForCowrieUser(second)
        make_file(first.server.fs, "/tmp/only-here")

        assert second.server.fs is not None
        self.assertFalse(second.server.fs.exists("/tmp/only-here"))


def run_exec_channel(avatar: FakeAvatar, command: bytes) -> bytes:
    """Run one exec channel on the avatar's connection to completion and
    return what it wrote. Channels of one connection share the avatar's
    filesystem, as they share the CowrieServer in production."""
    output: list[bytes] = []
    transport = make_exec_transport(CaptureSink())
    transport.write = output.append
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, avatar, command)
    lsp.downloadPath = _DOWNLOAD_DIR
    lsp.has_pty = False
    lsp.makeConnection(transport)
    lsp.eofReceived()
    lsp.connectionLost(connectionDone)
    return b"".join(output)


def stored(content: bytes) -> str:
    return os.path.join(_DOWNLOAD_DIR, hashlib.sha256(content).hexdigest())


class RedirectAcrossChannelsTests(unittest.TestCase):
    """Redirect output is stored by hash when its channel closes and stays
    readable in later channels of the same connection."""

    def test_redirect_output_is_readable_in_the_next_channel(self) -> None:
        avatar = FakeAvatar(FakeServer())
        run_exec_channel(avatar, b"echo hello > /tmp/a")

        self.assertTrue(os.path.isfile(stored(b"hello\n")))
        self.assertEqual(run_exec_channel(avatar, b"cat /tmp/a"), b"hello\n")

    def test_later_append_leaves_the_stored_file_intact(self) -> None:
        avatar = FakeAvatar(FakeServer())
        run_exec_channel(avatar, b"echo one > /tmp/b")
        run_exec_channel(avatar, b"echo two >> /tmp/b")

        with open(stored(b"one\n"), "rb") as f:
            self.assertEqual(f.read(), b"one\n")

    def test_append_in_a_later_channel_stores_the_whole_file(self) -> None:
        """An echo-chunk dropper that runs one exec channel per line builds
        the whole file, and each channel stores what the file holds then."""
        avatar = FakeAvatar(FakeServer())
        run_exec_channel(avatar, b"echo one >> /tmp/c")
        run_exec_channel(avatar, b"echo two >> /tmp/c")

        self.assertEqual(run_exec_channel(avatar, b"cat /tmp/c"), b"one\ntwo\n")
        self.assertTrue(os.path.isfile(stored(b"one\ntwo\n")))

    def test_logout_removes_the_connection_backing_files(self) -> None:
        server = CowrieServer(HoneyPotRealm())
        server.initFileSystem("/root")
        avatar = FakeAvatar(server)
        run_exec_channel(avatar, b"echo gone > /tmp/d")
        assert server.fs is not None
        node = server.fs.getfile("/tmp/d")
        assert node is not None
        backing = node[fs.A_REALFILE]
        self.assertTrue(os.path.isfile(backing))

        server.logout()

        self.assertFalse(os.path.exists(backing))
        self.assertTrue(os.path.isfile(stored(b"gone\n")))

    def test_telnet_disconnect_removes_the_connection_backing_files(self) -> None:
        """Telnet calls logout() only after the session has dropped its
        server, so the session cleans up when its connection is lost."""
        server = CowrieServer(HoneyPotRealm())
        server.initFileSystem("/root")
        run_exec_channel(FakeAvatar(server), b"echo telnet > /tmp/e")
        assert server.fs is not None
        node = server.fs.getfile("/tmp/e")
        assert node is not None
        backing = node[fs.A_REALFILE]

        session = HoneyPotTelnetSession(b"root", server)
        session.connectionLost(connectionDone)
        session.logout()

        self.assertFalse(os.path.exists(backing))
