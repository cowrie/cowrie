# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that one SSH connection keeps one emulated filesystem: files
# ABOUTME: written in one channel are there in the next, and are stored at logout.

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from twisted.internet.protocol import connectionDone

from cowrie.insults import insults
from cowrie.shell import fs, protocol
from cowrie.shell.avatar import CowrieUser
from cowrie.shell.filetransfer import SFTPServerForCowrieUser
from cowrie.shell.realm import HoneyPotRealm
from cowrie.shell.server import CowrieServer
from cowrie.shell.session import SSHSessionForCowrieUser
from cowrie.shell.telnet import HoneyPotTelnetSession
from cowrie.ssh import transport as ssh_transport
from cowrie.telnet import transport as telnet_transport
from cowrie.test.eventcapture import (
    CaptureSink,
    capture_eventlog,
    capture_events,
    events_of,
    make_exec_transport,
)
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
    """Redirect output stays readable in later channels of the same
    connection."""

    def test_redirect_output_is_readable_in_the_next_channel(self) -> None:
        avatar = FakeAvatar(FakeServer())
        run_exec_channel(avatar, b"echo hello > /tmp/a")

        self.assertEqual(run_exec_channel(avatar, b"cat /tmp/a"), b"hello\n")

    def test_append_in_a_later_channel_builds_the_whole_file(self) -> None:
        """An echo-chunk dropper that runs one exec channel per line builds
        the whole file."""
        avatar = FakeAvatar(FakeServer())
        run_exec_channel(avatar, b"echo one >> /tmp/c")
        run_exec_channel(avatar, b"echo two >> /tmp/c")

        self.assertEqual(run_exec_channel(avatar, b"cat /tmp/c"), b"one\ntwo\n")


def new_connection() -> tuple[CowrieServer, FakeAvatar]:
    server = CowrieServer(HoneyPotRealm())
    server.initFileSystem("/root")
    return server, FakeAvatar(server)


def backing_file(server: CowrieServer, path: str) -> str:
    assert server.fs is not None
    node = server.fs.getfile(path)
    assert node is not None
    realfile: str = node[fs.A_REALFILE]
    return realfile


def logout(server: CowrieServer) -> list[dict]:
    """Log the connection out and return the file_download events it sent."""
    events, dispatched = capture_eventlog()
    server.logout(events)
    return events_of(dispatched, "cowrie.session.file_download")


class RedirectStorageTests(unittest.TestCase):
    """What a connection wrote through redirects is stored by hash once,
    when the connection ends, whichever command wrote it and whether or not
    that command finished."""

    def setUp(self) -> None:
        # Other test modules point the download path elsewhere when they are
        # imported; logout reads it from the config when it runs.
        patcher = mock.patch.dict(
            os.environ, {"COWRIE_HONEYPOT_DOWNLOAD_PATH": _DOWNLOAD_DIR}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_output_is_stored_when_the_connection_ends(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo at-logout > /tmp/f")
        self.assertFalse(os.path.exists(stored(b"at-logout\n")))

        downloads = logout(server)

        self.assertTrue(os.path.isfile(stored(b"at-logout\n")))
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["destfile"], "/tmp/f")
        self.assertEqual(downloads[0]["outfile"], stored(b"at-logout\n"))
        self.assertFalse(downloads[0]["duplicate"])

    def test_backing_file_is_moved_into_the_hash_store(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo moved > /tmp/m")
        backing = backing_file(server, "/tmp/m")

        logout(server)

        self.assertFalse(os.path.exists(backing))
        self.assertTrue(os.path.isfile(stored(b"moved\n")))

    def test_each_file_is_stored_once_with_its_final_content(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo chunk-one >> /tmp/c")
        run_exec_channel(avatar, b"echo chunk-two >> /tmp/c")

        downloads = logout(server)

        self.assertEqual(len(downloads), 1)
        self.assertTrue(os.path.isfile(stored(b"chunk-one\nchunk-two\n")))
        self.assertFalse(os.path.exists(stored(b"chunk-one\n")))

    def test_busybox_redirect_is_stored(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"busybox echo via-busybox > /tmp/bb")

        downloads = logout(server)

        self.assertTrue(os.path.isfile(stored(b"via-busybox\n")))
        self.assertEqual([d["destfile"] for d in downloads], ["/tmp/bb"])

    def test_sudo_redirect_is_stored(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"sudo echo via-sudo > /tmp/su")

        logout(server)

        self.assertTrue(os.path.isfile(stored(b"via-sudo\n")))

    def test_output_of_a_command_still_running_is_stored(self) -> None:
        server, avatar = new_connection()
        lsp = insults.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, avatar
        )
        lsp.downloadPath = _DOWNLOAD_DIR
        lsp.makeConnection(make_exec_transport(CaptureSink()))
        lsp.dataReceived(b"cat > /tmp/running\n")
        lsp.dataReceived(b"still-running\n")
        lsp.connectionLost(connectionDone)

        logout(server)

        self.assertTrue(os.path.isfile(stored(b"still-running\n")))

    def test_deleted_file_is_still_stored(self) -> None:
        """A dropper that writes, runs and deletes its file leaves no path."""
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo deleted > /tmp/gone")
        run_exec_channel(avatar, b"rm /tmp/gone")

        downloads = logout(server)

        self.assertTrue(os.path.isfile(stored(b"deleted\n")))
        self.assertEqual([d["destfile"] for d in downloads], [""])

    def test_known_content_is_reported_as_a_duplicate(self) -> None:
        first, avatar = new_connection()
        run_exec_channel(avatar, b"echo twice > /tmp/t")
        logout(first)
        second, avatar = new_connection()
        run_exec_channel(avatar, b"echo twice > /tmp/t")
        backing = backing_file(second, "/tmp/t")

        downloads = logout(second)

        self.assertTrue(downloads[0]["duplicate"])
        self.assertFalse(os.path.exists(backing))

    def test_empty_file_is_removed_without_an_event(self) -> None:
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo -n > /tmp/empty")
        backing = backing_file(server, "/tmp/empty")

        downloads = logout(server)

        self.assertEqual(downloads, [])
        self.assertFalse(os.path.exists(backing))

    def test_ssh_connection_lost_stores_before_session_closed(self) -> None:
        """Output plugins finish a session on session.closed, so the stored
        files must be reported before it."""
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo over-ssh > /tmp/s")
        user = CowrieUser(b"root", server)
        transport = ssh_transport.HoneyPotSSHTransport()
        transport.transport = mock.MagicMock()
        transport.startTime = time.time()
        transport.avatar = user
        transport.logoutFunction = user.logout
        user.conn = SimpleNamespace(transport=transport)
        dispatched = capture_events(transport)

        transport.connectionLost(connectionDone)

        self.assertEqual(
            [
                (d["eventid"], d.get("destfile"))
                for d in dispatched
                if d["eventid"]
                in ("cowrie.session.file_download", "cowrie.session.closed")
            ],
            [
                ("cowrie.session.file_download", "/tmp/s"),
                ("cowrie.session.closed", None),
            ],
        )

    def test_telnet_connection_lost_stores_before_session_closed(self) -> None:
        """Telnet calls logout() only after the session has dropped its
        server, so the session stores what it wrote when its connection is
        lost, before the transport reports session.closed."""
        server, avatar = new_connection()
        run_exec_channel(avatar, b"echo over-telnet > /tmp/e")
        backing = backing_file(server, "/tmp/e")
        transport = telnet_transport.CowrieTelnetTransport()
        transport.startTime = time.time()
        session = HoneyPotTelnetSession(b"root", server)
        session.transport = transport  # type: ignore[assignment]
        transport.protocol = session  # type: ignore[assignment]
        dispatched = capture_events(transport)

        transport.connectionLost(connectionDone)

        self.assertFalse(os.path.exists(backing))
        self.assertTrue(os.path.isfile(stored(b"over-telnet\n")))
        self.assertEqual(
            [
                (d["eventid"], d.get("destfile"))
                for d in dispatched
                if d["eventid"]
                in ("cowrie.session.file_download", "cowrie.session.closed")
            ],
            [
                ("cowrie.session.file_download", "/tmp/e"),
                ("cowrie.session.closed", None),
            ],
        )
