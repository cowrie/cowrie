# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/commands/wget.py, focused on artifact lifecycle.
# ABOUTME: Verifies that a failed download leaves no orphaned temp file behind.

from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest import mock

from twisted.internet import error
from twisted.python.failure import Failure

from cowrie.commands.wget import Command_wget
from cowrie.core.artifact import Artifact
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class WgetArtifactCleanupTests(unittest.TestCase):
    """A failed wget download must not leave an orphaned temp file behind."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.events = capture_events(self.proto)

        self.tmpdir = tempfile.mkdtemp()
        self._orig_artifact_dir = Artifact.artifactDir
        Artifact.artifactDir = self.tmpdir

    def tearDown(self) -> None:
        Artifact.artifactDir = self._orig_artifact_dir
        self.proto.connectionLost()
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def test_failed_download_removes_temp_artifact(self) -> None:
        # Bypass HoneyPotCommand.__init__: its stdout/stderr wiring needs a
        # running process protocol (self.protocol.pp), which is irrelevant to
        # the artifact lifecycle under test here.
        cmd = Command_wget.__new__(Command_wget)
        cmd.protocol = self.proto
        cmd.errorWritefn = lambda _data: None
        cmd.exit = lambda code=None: None  # type: ignore[method-assign]  # process teardown is unrelated here
        cmd.url = b"http://no.such.host/file"
        cmd.host = "no.such.host"
        cmd.port = 80
        cmd.artifact = Artifact("wget-download")
        temp_filename = cmd.artifact.tempFilename
        self.assertTrue(os.path.exists(temp_filename))

        cmd.error(Failure(error.DNSLookupError()))

        self.assertFalse(
            os.path.exists(temp_filename),
            "failed download left an orphaned temp file behind",
        )
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_failed_download_emits_attributed_event(self) -> None:
        # error() runs in a deferred callback; the event it emits must carry
        # the session identity (bound on the EventLog) even though it fires
        # outside the transport's execution context.
        cmd = Command_wget.__new__(Command_wget)
        cmd.protocol = self.proto
        cmd.errorWritefn = lambda _data: None
        cmd.exit = lambda code=None: None  # type: ignore[method-assign]
        cmd.url = b"http://no.such.host/file"
        cmd.host = "no.such.host"
        cmd.port = 80
        cmd.artifact = Artifact("wget-download")

        cmd.error(Failure(error.DNSLookupError()))

        failed = [
            e
            for e in self.events
            if e["eventid"] == "cowrie.session.file_download.failed"
        ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["session"], "test0000")
        self.assertEqual(failed[0]["url"], "http://no.such.host/file")

    def test_exit_removes_empty_artifact(self) -> None:
        # An aborted download (CTRL-C, size limit) reaches exit() with an empty
        # artifact; exit() must remove its temp file (#40216).
        cmd = Command_wget.__new__(Command_wget)
        cmd.protocol = self.proto
        cmd.exit_code = 0
        cmd.artifact = Artifact("wget-download")
        temp_filename = cmd.artifact.tempFilename
        self.assertTrue(os.path.exists(temp_filename))
        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd.exit()
        self.assertFalse(
            os.path.exists(temp_filename),
            "early exit left an orphaned temp file behind",
        )

    def test_late_download_callbacks_after_exit_are_inert(self) -> None:
        # The command can exit while treq is still delivering the body (size
        # limit in collect(), CTRL-C). The late callbacks must not write to the
        # closed artifact, dispatch file_download events for a dead command, or
        # exit again.
        cmd = Command_wget.__new__(Command_wget)
        cmd.protocol = self.proto
        cmd.writefn = lambda _data: None
        cmd.errorWritefn = lambda _data: None
        cmd.exit_code = 0
        cmd.url = b"http://198.51.100.1/binary"
        cmd.host = "198.51.100.1"
        cmd.port = 80
        cmd.quiet = True
        cmd.started = time.time()
        cmd.artifact = Artifact("wget-download")
        events: list[dict] = []
        self.proto.logDispatch = lambda **kw: events.append(kw)  # type: ignore[method-assign]
        self.proto.cmdstack.append(cmd)

        cmd.artifact.write(b"partial data")
        cmd.exit(130)  # CTRL-C while the transfer is still in flight

        cmd.collect(b"late chunk")
        cmd.collectioncomplete(None)
        cmd.error(Failure(error.ConnectionDone()))

        self.assertEqual(
            [
                ev
                for ev in events
                if str(ev.get("eventid", "")).startswith("cowrie.session.file_download")
            ],
            [],
            "late download callbacks reported events for an exited command",
        )
