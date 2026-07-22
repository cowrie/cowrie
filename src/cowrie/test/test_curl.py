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

from twisted.internet import defer, error
from twisted.python.failure import Failure

from cowrie.commands import curl as curl_module
from cowrie.commands.curl import Command_curl
from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
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

    def test_tcp_timeout_reports_connection_timed_out(self) -> None:
        # A TCP connect that times out yields TCPTimedOutError, built by the
        # reactor (so its Failure has no traceback frames). error() must report
        # a curl-style timeout message and exit cleanly, not fall through to the
        # CRITICAL "Unhandled curl error" branch that writes a bare newline
        # (issue #40335).
        cmd = Command_curl.__new__(Command_curl)
        cmd.protocol = self.proto
        writes: list[bytes] = []
        cmd.writefn = lambda data: writes.append(data)
        cmd.errorWritefn = lambda data: writes.append(data)
        cmd.exit = lambda code=None: None  # type: ignore[method-assign]
        cmd.url = b"http://192.0.2.1/file"
        cmd.host = "192.0.2.1"
        cmd.port = 80
        cmd.artifact = Artifact("curl-download")

        cmd.error(Failure(error.TCPTimedOutError()))

        self.assertIn(b"Connection timed out", b"".join(writes))

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

    def test_embedded_ipv6_url_does_not_hang(self) -> None:
        # An IPv4-embedded IPv6 URL literal such as [::ffff:8.8.8.8] passes the
        # network guard (globally routable) but makes treq.get() raise
        # idna.core.InvalidCodepoint synchronously. That raise must be caught so
        # the command exits, instead of orphaning it on the cmdstack (a session
        # hang / DoS) until the session times out.
        self.proto.lineReceived(b"curl -s 'http://[::ffff:8.8.8.8]/'; echo rc=$?")
        out = self.tr.value()
        self.assertIn(
            b"rc=",
            out,
            "shell never resumed: the command hung instead of exiting",
        )

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
        self.proto.cmdstack.append(cmd)

        cmd.artifact.write(b"partial data")
        cmd.exit(130)  # CTRL-C while the transfer is still in flight

        cmd.collect(b"late chunk")
        cmd.collectioncomplete(None)
        cmd.error(Failure(error.ConnectionDone()))

        self.assertEqual(
            [
                ev
                for ev in self.events
                if str(ev.get("eventid", "")).startswith("cowrie.session.file_download")
            ],
            [],
            "late download callbacks reported events for an exited command",
        )


class CurlOutboundBindTests(unittest.TestCase):
    """Downloads must bind to the configured out_addr so they do not leak the
    honeypot's real interface IP (issue #752)."""

    def tearDown(self) -> None:
        CowrieConfig.remove_option("honeypot", "out_addr")

    def _capture_agent(self, head_request: bool, verb: str) -> object:
        cmd = Command_curl.__new__(Command_curl)
        cmd.head_request = head_request

        captured: dict[str, object] = {}

        def fake_verb(url: str, agent: object = None, **kwargs: object) -> object:
            captured["agent"] = agent
            return defer.succeed(None)

        with mock.patch.object(curl_module.treq, verb, fake_verb):
            cmd.treqDownload("http://198.51.100.1/x")

        return captured["agent"]

    def test_get_binds_agent_to_out_addr(self) -> None:
        CowrieConfig.set("honeypot", "out_addr", "127.0.0.1")
        agent = self._capture_agent(head_request=False, verb="get")
        self.assertEqual(agent._endpointFactory._bindAddress, ("127.0.0.1", 0))

    def test_head_binds_agent_to_out_addr(self) -> None:
        CowrieConfig.set("honeypot", "out_addr", "127.0.0.1")
        agent = self._capture_agent(head_request=True, verb="head")
        self.assertEqual(agent._endpointFactory._bindAddress, ("127.0.0.1", 0))

    def test_default_bind_is_wildcard(self) -> None:
        agent = self._capture_agent(head_request=False, verb="get")
        self.assertEqual(agent._endpointFactory._bindAddress, ("0.0.0.0", 0))
