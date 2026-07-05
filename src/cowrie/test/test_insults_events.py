# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts the insults terminal wrapper and SSH session channel
# ABOUTME: dispatch their events through the session EventLog.

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import Any

from twisted.conch.ssh.common import NS
from twisted.internet.protocol import connectionDone

from cowrie.core.events import EventDispatcher, EventLog
from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.test.eventcapture import CaptureSink
from cowrie.test.fake_server import FakeAvatar, FakeServer

_DOWNLOAD_DIR = tempfile.mkdtemp(prefix="cowrie_insults_events_")
_TTYLOG_DIR = tempfile.mkdtemp(prefix="cowrie_insults_ttylog_")
os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = _DOWNLOAD_DIR
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

insults.LoggingServerProtocol.downloadPath = _DOWNLOAD_DIR


def _make_exec_transport(sink: CaptureSink) -> SimpleNamespace:
    """The transport.session.conn.transport chain insults expects, with an
    EventLog whose events land in ``sink``."""
    peer = SimpleNamespace(host="1.1.1.1", port=2222)
    inner = SimpleNamespace(sessionno=1, getPeer=lambda: peer)
    factory = SimpleNamespace(starttime=0)
    events = EventLog(
        EventDispatcher([sink], logmsg=lambda *args, **kwargs: None),
        session="testexec",
        protocol="ssh",
        src_ip="1.1.1.1",
    )
    conn_transport = SimpleNamespace(
        transportId="testexec", factory=factory, transport=inner, events=events
    )
    conn = SimpleNamespace(transport=conn_transport)
    session = SimpleNamespace(id="chan0", conn=conn)
    return SimpleNamespace(
        session=session,
        write=lambda data: None,
        processEnded=lambda reason=None: None,
    )


def events_of(events: list[dict[str, Any]], eventid: str) -> list[dict[str, Any]]:
    return [e for e in events if e["eventid"] == eventid]


class StdinCaptureEventTests(unittest.TestCase):
    def run_exec(self, cmd: bytes, payload: bytes) -> list[dict[str, Any]]:
        sink = CaptureSink()
        avatar = FakeAvatar(FakeServer())
        avatar.server.initFileSystem = lambda home: None
        lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, avatar, cmd)
        lsp.makeConnection(_make_exec_transport(sink))
        lsp.dataReceived(payload)
        lsp.eofReceived()
        lsp.connectionLost(connectionDone)
        return sink.events

    def test_stdin_capture_dispatches_file_download(self) -> None:
        dispatched = self.run_exec(b"cat", b"captured stdin payload")
        downloads = events_of(dispatched, "cowrie.session.file_download")
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["session"], "testexec")
        self.assertEqual(downloads[0]["destfile"], "")
        self.assertIn("shasum", downloads[0])

    def test_ttylog_closed_dispatches_log_closed(self) -> None:
        old_enabled = insults.LoggingServerProtocol.ttylogEnabled
        old_path = insults.LoggingServerProtocol.ttylogPath
        insults.LoggingServerProtocol.ttylogEnabled = True
        insults.LoggingServerProtocol.ttylogPath = _TTYLOG_DIR
        try:
            dispatched = self.run_exec(b"echo hi", b"")
            closed = events_of(dispatched, "cowrie.log.closed")
            self.assertEqual(len(closed), 1)
            self.assertEqual(closed[0]["session"], "testexec")
            self.assertIsInstance(closed[0]["duration_ms"], int)
        finally:
            insults.LoggingServerProtocol.ttylogEnabled = old_enabled
            insults.LoggingServerProtocol.ttylogPath = old_path


class SshRequestEnvEventTests(unittest.TestCase):
    def test_request_env_dispatches_client_var(self) -> None:
        from cowrie.ssh.session import HoneyPotSSHSession

        sink = CaptureSink()
        events = EventLog(
            EventDispatcher([sink], logmsg=lambda *args, **kwargs: None),
            session="testexec",
            protocol="ssh",
            src_ip="1.1.1.1",
        )
        conn = SimpleNamespace(transport=SimpleNamespace(events=events))
        channel = HoneyPotSSHSession(conn=conn)
        result = channel.request_env(NS(b"LANG") + NS(b"en_US.UTF-8"))
        self.assertEqual(result, 0)
        client_vars = events_of(sink.events, "cowrie.client.var")
        self.assertEqual(len(client_vars), 1)
        self.assertEqual(client_vars[0]["name"], "LANG")
        self.assertEqual(client_vars[0]["value"], "en_US.UTF-8")
        self.assertEqual(client_vars[0]["session"], "testexec")
