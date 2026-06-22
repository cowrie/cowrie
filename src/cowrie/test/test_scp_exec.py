# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for scp file uploads over the SSH exec channel.
# ABOUTME: Verifies SCP wire framing is decoded so saved files hold only content.

from __future__ import annotations

import os
import tempfile
import unittest

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


class _Container:
    """Placeholder object onto which fake transport attributes are attached."""


def _make_exec_transport() -> _Container:
    """Build the transport.session.conn.transport chain insults expects."""
    peer = _Container()
    peer.host = "1.1.1.1"
    peer.port = 2222

    inner = _Container()
    inner.sessionno = 1
    inner.getPeer = lambda: peer

    factory = _Container()
    factory.starttime = 0
    factory.logDispatch = lambda **kw: None

    conn_transport = _Container()
    conn_transport.transportId = "testexec"
    conn_transport.factory = factory
    conn_transport.transport = inner

    conn = _Container()
    conn.transport = conn_transport

    session = _Container()
    session.id = "chan0"
    session.conn = conn

    transport = _Container()
    transport.written = b""
    transport.session = session
    transport.write = lambda data: None
    transport.processEnded = lambda reason=None: None
    return transport


def run_exec_scp_push(framed_stdin: bytes) -> list[bytes]:
    """Drive a full exec-channel `scp -t` push and return saved download contents.

    The SCP-framed bytes are delivered after the command has started, exactly as
    the SSH channel delivers them, then a channel EOF and connection close.
    """
    avatar = FakeAvatar(FakeServer())
    avatar.server.initFileSystem = lambda home: None

    lsp = insults.LoggingServerProtocol(
        protocol.HoneyPotExecProtocol, avatar, b"scp -t /tmp"
    )
    lsp.makeConnection(_make_exec_transport())

    live_stdinlog = lsp.stdinlogFile
    lsp.dataReceived(framed_stdin)
    lsp.eofReceived()
    lsp.connectionLost("done")

    saved = []
    for name in os.listdir(_DOWNLOAD_DIR):
        full = os.path.join(_DOWNLOAD_DIR, name)
        if full == live_stdinlog or not os.path.isfile(full):
            continue
        with open(full, "rb") as f:
            saved.append(f.read())
    return saved


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

        saved = run_exec_scp_push(framed)

        self.assertTrue(saved, "scp push saved no file at all")
        for content in saved:
            self.assertFalse(
                content.startswith(b"C0"), "SCP header leaked into saved file"
            )
            self.assertIn(body, content)


if __name__ == "__main__":
    unittest.main()
