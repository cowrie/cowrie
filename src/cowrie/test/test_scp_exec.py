# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for scp file uploads over the SSH exec channel.
# ABOUTME: Verifies SCP wire framing is decoded so saved files hold only content.

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace

from twisted.internet.protocol import connectionDone
from twisted.python import log

from cowrie.commands import scp
from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.test.fake_server import FakeAvatar, FakeServer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"
_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_scp_exec_")

# Class-level download paths are read from config at import time, so another
# test module importing these classes first can pin them elsewhere. Force them
# to this module's scratch directory regardless of import order.
insults.LoggingServerProtocol.downloadPath = _DOWNLOAD_DIR
scp.Command_scp.download_path = _DOWNLOAD_DIR
scp.Command_scp.download_path_uniq = _DOWNLOAD_DIR


def _make_exec_transport() -> SimpleNamespace:
    """Build the transport.session.conn.transport chain insults expects."""
    peer = SimpleNamespace(host="1.1.1.1", port=2222)
    inner = SimpleNamespace(sessionno=1, getPeer=lambda: peer)
    factory = SimpleNamespace(starttime=0, logDispatch=lambda **kw: None)
    conn_transport = SimpleNamespace(
        transportId="testexec", factory=factory, transport=inner
    )
    conn = SimpleNamespace(transport=conn_transport)
    session = SimpleNamespace(id="chan0", conn=conn)
    return SimpleNamespace(
        session=session,
        write=lambda data: None,
        processEnded=lambda reason=None: None,
    )


def run_exec_scp_push(
    framed_stdin: bytes, chunk_size: int = 0, fs_newcount: int | None = None
) -> tuple[list[bytes], list[dict]]:
    """Drive a full exec-channel `scp -t` push.

    The SCP-framed bytes are delivered after the command has started, exactly as
    the SSH channel delivers them, then a channel EOF and connection close. A
    non-zero chunk_size splits the stdin across multiple dataReceived calls, as
    happens for a large transfer. fs_newcount pre-loads the filesystem's
    new-file counter to drive it over its quota. Returns the contents of every
    saved download file and the captured log events.
    """
    events: list[dict] = []
    log.addObserver(events.append)
    try:
        avatar = FakeAvatar(FakeServer())
        avatar.server.initFileSystem = lambda home: None
        if fs_newcount is not None:
            avatar.server.fs.newcount = fs_newcount

        lsp = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, avatar, b"scp -t /tmp"
        )
        lsp.makeConnection(_make_exec_transport())

        live_stdinlog = lsp.stdinlogFile
        if chunk_size:
            for i in range(0, len(framed_stdin), chunk_size):
                lsp.dataReceived(framed_stdin[i : i + chunk_size])
        else:
            lsp.dataReceived(framed_stdin)
        lsp.eofReceived()
        lsp.connectionLost(connectionDone)
    finally:
        log.removeObserver(events.append)

    saved = []
    for name in os.listdir(_DOWNLOAD_DIR):
        full = os.path.join(_DOWNLOAD_DIR, name)
        if full == live_stdinlog or not os.path.isfile(full):
            continue
        with open(full, "rb") as f:
            saved.append(f.read())
    return saved, events


class ScpExecPushTests(unittest.TestCase):
    """An scp push over the exec channel must be saved as just its content."""

    def setUp(self) -> None:
        for name in os.listdir(_DOWNLOAD_DIR):
            full = os.path.join(_DOWNLOAD_DIR, name)
            if os.path.isfile(full):
                os.remove(full)

    def test_exec_scp_push_strips_header(self) -> None:
        """The SCP `C<mode> <size> <name>` header must not survive into the save.

        The exec channel delivers stdin after the command starts, so EOF must
        reach the running scp command rather than firing on an empty stdin log.
        """
        body = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"PAYLOAD-BODY"
        framed = b"C0755 %d binary\n" % len(body) + body + b"\x00"

        saved, _events = run_exec_scp_push(framed)

        self.assertTrue(saved, "scp push saved no file at all")
        for content in saved:
            self.assertFalse(
                content.startswith(b"C0"), "SCP header leaked into saved file"
            )
            self.assertIn(body, content)

    def test_exec_scp_push_saves_exact_body(self) -> None:
        """The saved file is exactly the uploaded bytes: header and trailing
        ACK byte both removed, declared size honoured."""
        body = b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"PAYLOAD-BODY"
        framed = b"C0755 %d binary\n" % len(body) + body + b"\x00"

        saved, _events = run_exec_scp_push(framed)

        self.assertEqual(saved, [body])

    def test_exec_scp_push_emits_file_upload(self) -> None:
        """A decoded scp push is reported as an upload, not a raw stdin
        download, and the honeyfs is updated to serve the content."""
        body = b"scp-uploaded-content\n"
        framed = b"C0644 %d payload\n" % len(body) + body + b"\x00"

        _saved, events = run_exec_scp_push(framed)

        eventids = [e.get("eventid") for e in events]
        self.assertIn("cowrie.session.file_upload", eventids)
        self.assertNotIn("cowrie.session.file_download", eventids)

    def test_exec_scp_push_chunked_transfer(self) -> None:
        """A push split across many dataReceived calls is reassembled and
        decodes to the exact body, with the declared size honoured across
        chunk boundaries (the header, body and ACK span several chunks)."""
        body = (b"\x7fELF" + bytes(range(256))) * 64
        framed = b"C0644 %d big.bin\n" % len(body) + body + b"\x00"

        saved, _events = run_exec_scp_push(framed, chunk_size=1024)

        self.assertEqual(saved, [body])

    def test_exec_scp_push_into_forbidden_path_does_not_crash(self) -> None:
        """A crafted filename that traverses into a protected path (/proc) must
        be refused cleanly, not raise out of the EOF handler."""
        body = b"x"
        framed = b"C0644 %d ../../../proc/evil\n" % len(body) + body + b"\x00"

        saved, _events = run_exec_scp_push(framed)

        self.assertEqual(saved, [])

    def test_exec_scp_push_over_fs_quota_does_not_crash(self) -> None:
        """When the virtual filesystem is at its new-file quota, mkfile cannot
        create the honeyfs entry. The upload content must still be captured and
        the honeyfs update skipped, not raise out of the EOF handler."""
        body = b"quota-test\n"
        framed = b"C0644 %d quota.bin\n" % len(body) + body + b"\x00"

        saved, events = run_exec_scp_push(framed, fs_newcount=10001)

        self.assertEqual(saved, [body])
        self.assertIn("cowrie.session.file_upload", [e.get("eventid") for e in events])


if __name__ == "__main__":
    unittest.main()
