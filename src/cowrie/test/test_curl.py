# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/commands/curl.py, focused on artifact lifecycle.
# ABOUTME: Verifies that a failed download leaves no orphaned temp file behind.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from twisted.internet import error
from twisted.python.failure import Failure

from cowrie.commands.curl import Command_curl
from cowrie.core.artifact import Artifact
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class CurlArtifactCleanupTests(unittest.TestCase):
    """A failed curl download must not leave an orphaned temp file behind."""

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
        cmd = Command_curl.__new__(Command_curl)
        cmd.protocol = self.proto
        cmd.errorWritefn = lambda _data: None
        cmd.exit = lambda code=None: None  # type: ignore[method-assign]  # process teardown is unrelated here
        cmd.url = b"http://no.such.host/file"
        cmd.host = "no.such.host"
        cmd.port = 80
        cmd.artifact = Artifact("curl-download")
        temp_filename = cmd.artifact.tempFilename
        self.assertTrue(os.path.exists(temp_filename))

        cmd.error(Failure(error.DNSLookupError()))

        self.assertFalse(
            os.path.exists(temp_filename),
            "failed download left an orphaned temp file behind",
        )
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_missing_host_reports_error_without_crashing(self) -> None:
        # A URL with no host must report an error and stop, not fall through
        # to the download path and crash on the unset self.host.
        self.proto.lineReceived(b"curl http://; echo rc=$?")
        out = self.tr.value()
        self.assertIn(b"curl: (3)", out)
        self.assertIn(b"rc=3", out)

    def test_exit_removes_empty_artifact(self) -> None:
        # An aborted download (CTRL-C, HEAD request, size limit) reaches exit()
        # with an empty artifact; exit() must remove its temp file (#40216).
        cmd = Command_curl.__new__(Command_curl)
        cmd.protocol = self.proto
        cmd.exit_code = 0
        cmd.artifact = Artifact("curl-download")
        temp_filename = cmd.artifact.tempFilename
        self.assertTrue(os.path.exists(temp_filename))
        with mock.patch.object(HoneyPotCommand, "exit"):
            cmd.exit()
        self.assertFalse(
            os.path.exists(temp_filename),
            "early exit left an orphaned temp file behind",
        )

    def test_artifact_close_is_idempotent(self) -> None:
        # The normal path closes the artifact and exit() closes it again.
        artifact = Artifact("curl-download")
        artifact.close()
        artifact.close()  # must not raise on the already-closed file

    def test_late_download_callbacks_after_exit_are_inert(self) -> None:
        # The command can exit while treq is still delivering the body (size
        # limit in collect(), CTRL-C). The late callbacks must not write to the
        # closed artifact, dispatch file_download events for a dead command, or
        # exit again.
        cmd = Command_curl.__new__(Command_curl)
        cmd.protocol = self.proto
        cmd.writefn = lambda _data: None
        cmd.errorWritefn = lambda _data: None
        cmd.exit_code = 0
        cmd.url = b"http://198.51.100.1/binary"
        cmd.host = "198.51.100.1"
        cmd.port = 80
        cmd.artifact = Artifact("curl-download")
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
