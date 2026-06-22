# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/commands/wget.py, focused on artifact lifecycle.
# ABOUTME: Verifies that a failed download leaves no orphaned temp file behind.

from __future__ import annotations

import os
import tempfile
import unittest

from twisted.internet import error
from twisted.python.failure import Failure

from cowrie.commands.wget import Command_wget
from cowrie.core.artifact import Artifact
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
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
        # The fake factory has no logDispatch; error() dispatches a log event.
        self.proto.logDispatch = lambda **_kw: None  # type: ignore[method-assign]

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
        cmd.exit = lambda: None  # type: ignore[method-assign]  # process teardown is unrelated here
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
