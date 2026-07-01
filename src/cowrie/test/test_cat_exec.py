# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests `cat > file` over the SSH exec channel captures piped stdin.
# ABOUTME: Guards against the redirect backing file being left empty.

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace

from twisted.internet.protocol import connectionDone

from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.test.fake_server import FakeAvatar, FakeServer

_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_cat_exec_")
os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = _DOWNLOAD_DIR
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

insults.LoggingServerProtocol.downloadPath = _DOWNLOAD_DIR


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


def run_exec_cat_redirect(payload: bytes) -> bytes:
    """Drive `cat > /tmp/cowrietest` over an exec channel with piped stdin.

    Returns the bytes written to the redirect backing file after EOF, before
    the session teardown finalizes it.
    """
    avatar = FakeAvatar(FakeServer())
    avatar.server.initFileSystem = lambda home: None

    lsp = insults.LoggingServerProtocol(
        protocol.HoneyPotExecProtocol, avatar, b"cat > /tmp/cowrietest"
    )
    lsp.makeConnection(_make_exec_transport())

    lsp.dataReceived(payload)
    lsp.eofReceived()

    redir_files = [rp[0] for rp in lsp.redirFiles]
    try:
        assert len(redir_files) == 1, f"expected one redirect file, got {redir_files}"
        with open(redir_files[0], "rb") as f:
            return f.read()
    finally:
        lsp.connectionLost(connectionDone)


class CatExecRedirectTests(unittest.TestCase):
    """`cat > file` on an exec channel must write piped stdin to the file."""

    def test_cat_redirect_captures_piped_stdin(self) -> None:
        payload = b"one\ntwo\nthree\n"
        self.assertEqual(run_exec_cat_redirect(payload), payload)

    def test_cat_redirect_preserves_binary_exactly(self) -> None:
        """Binary content with embedded NULs and no trailing newline must be
        copied verbatim, not reflowed line by line."""
        payload = b"\x7fELF\x00\x01\x02\nmiddle\x00\xffno-trailing-newline"
        self.assertEqual(run_exec_cat_redirect(payload), payload)


if __name__ == "__main__":
    unittest.main()
