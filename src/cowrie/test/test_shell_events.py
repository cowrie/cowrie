# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts that the shell, session, SFTP, and LLM layers dispatch
# ABOUTME: their events through the session EventLog with bound identity.

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import Any

from twisted.conch.ssh.filetransfer import FXF_CREAT, FXF_WRITE

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_eventlog, events_of
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.mkdtemp(
    prefix="cowrie_shell_events_"
)
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class ShellEventTests(unittest.TestCase):
    """The interactive shell's command events carry the bound identity."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_command_input_event(self) -> None:
        self.proto.lineReceived(b"echo hello")
        events = events_of(self.tr.dispatchedEvents, "cowrie.command.input")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["input"], "echo hello")
        self.assertEqual(events[0]["message"], "CMD: echo hello")
        self.assertEqual(events[0]["session"], "test-suite")

    def test_command_failed_event(self) -> None:
        self.proto.lineReceived(b"nosuchcommand --foo")
        events = events_of(self.tr.dispatchedEvents, "cowrie.command.failed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["input"], "nosuchcommand --foo")
        self.assertEqual(events[0]["session"], "test-suite")


class SessionParamsEventTests(unittest.TestCase):
    def test_session_params_dispatched_on_connection(self) -> None:
        proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        try:
            events = events_of(tr.dispatchedEvents, "cowrie.session.params")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["arch"], "linux-x64-lsb")
            self.assertEqual(events[0]["session"], "test-suite")
        finally:
            proto.connectionLost()


class ClientSizeEventTests(unittest.TestCase):
    """getPty dispatches the client's terminal size on both session types."""

    def make_session(self, sessionclass: type) -> tuple[Any, list[dict[str, Any]]]:
        events, dispatched = capture_eventlog(session="test-suite", src_ip="1.1.1.1")
        server = FakeServer()
        avatar = SimpleNamespace(
            server=server,
            uid=0,
            gid=0,
            username="root",
            home="/root",
            temporary=False,
            conn=SimpleNamespace(transport=SimpleNamespace(events=events)),
        )
        return sessionclass(avatar), dispatched

    def assert_client_size_event(self, session: Any, dispatched: list) -> None:
        session.getPty(b"xterm", (24, 80, 0, 0), None)
        events = events_of(dispatched, "cowrie.client.size")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["width"], 80)
        self.assertEqual(events[0]["height"], 24)
        self.assertEqual(events[0]["session"], "test-suite")

    def test_shell_session_client_size_event(self) -> None:
        from cowrie.shell.session import SSHSessionForCowrieUser

        session, dispatched = self.make_session(SSHSessionForCowrieUser)
        self.assert_client_size_event(session, dispatched)

    def test_llm_session_client_size_event(self) -> None:
        from cowrie.llm.session import SSHSessionForCowrieUser

        session, dispatched = self.make_session(SSHSessionForCowrieUser)
        self.assert_client_size_event(session, dispatched)


class SftpUploadEventTests(unittest.TestCase):
    def test_sftp_upload_dispatches_file_upload(self) -> None:
        from cowrie.shell import fs
        from cowrie.shell.filetransfer import SFTPServerForCowrieUser

        events, dispatched = capture_eventlog(session="test-suite", src_ip="1.1.1.1")
        server = SFTPServerForCowrieUser.__new__(SFTPServerForCowrieUser)
        server.fs = fs.HoneyPotFilesystem("linux-x64-lsb", "/root")
        server.fs.events = events
        server.avatar = SimpleNamespace(home="/root")

        handle = server.openFile("/root/payload.bin", FXF_WRITE | FXF_CREAT, {})
        handle.writeChunk(0, b"malicious payload")
        handle.close()

        uploads = events_of(dispatched, "cowrie.session.file_upload")
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["filename"], "payload.bin")
        self.assertEqual(uploads[0]["session"], "test-suite")
        self.assertIn("shasum", uploads[0])


class LlmCommandInputEventTests(unittest.TestCase):
    def test_llm_command_input_event(self) -> None:
        from cowrie.llm import protocol as llmprotocol

        proto = llmprotocol.HoneyPotBaseProtocol(FakeAvatar(FakeServer()))
        proto._process_command_with_llm = lambda command: None  # type: ignore[method-assign]
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        try:
            tr.clear()
            proto.lineReceived(b"uname -a")
            events = events_of(tr.dispatchedEvents, "cowrie.command.input")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["input"], "uname -a")
            self.assertEqual(events[0]["session"], "test-suite")
        finally:
            proto.connectionLost(None)
