# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: End-to-end tests that a stalled HTTP download in wget and curl is stopped
# ABOUTME: when its artifact ends it: connection closed, failure reported, data kept.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import TYPE_CHECKING, Any, cast
from unittest import mock

from twisted.internet import defer, reactor
from twisted.web import resource, server

from cowrie.core.artifact import Artifact
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_events
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport
from cowrie.test.reactorpump import pump

if TYPE_CHECKING:
    from twisted.internet.address import IPv4Address
    from twisted.web.server import Request

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "
SENT = b"A" * 1000


class StallingResource(resource.Resource):
    """Promises 3000 bytes, sends 1000, then sends nothing more."""

    isLeaf = True

    def __init__(self) -> None:
        super().__init__()
        self.closed: list[bool] = []

    def render_GET(self, request: Request) -> Any:
        request.setHeader(b"content-length", b"3000")
        request.write(SENT)
        request.notifyFinish().addErrback(lambda _: self.closed.append(True))
        return server.NOT_DONE_YET


class StalledDownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.events = capture_events(self.proto)

        self.tmpdir = tempfile.mkdtemp()
        patches = (
            mock.patch.object(Artifact, "artifactDir", self.tmpdir),
            # The server is on loopback, which the outbound guard refuses.
            mock.patch(
                "cowrie.commands.wget.communication_allowed",
                lambda _host: defer.succeed(True),
            ),
            mock.patch(
                "cowrie.commands.curl.communication_allowed",
                lambda _host: defer.succeed(True),
            ),
            mock.patch(
                "cowrie.core.download.resolve_allowed",
                lambda _host: defer.succeed("127.0.0.1"),
            ),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        # The HTTP client resolves even an IP literal on the reactor's thread
        # pool, which only starts with reactor.run(); pump() just iterates.
        pool = reactor.getThreadPool()  # type: ignore[attr-defined]
        pool.start()
        self.addCleanup(pool.stop)

        self.resource = StallingResource()
        site = cast("Any", server.Site(self.resource))
        port = reactor.listenTCP(0, site, interface="127.0.0.1")
        self.addCleanup(port.stopListening)
        self.port = cast("IPv4Address", port.getHost()).port

    def tearDown(self) -> None:
        self.proto.connectionLost()
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def failed(self) -> list[dict[str, Any]]:
        return [
            e
            for e in self.events
            if e["eventid"] == "cowrie.session.file_download.failed"
        ]

    def test_ending_the_artifact_stops_the_download(self) -> None:
        url = f"http://127.0.0.1:{self.port}/payload"
        for line in (f"wget -q {url}", f"curl -s -o payload {url}"):
            with self.subTest(line=line):
                self.events.clear()
                self.resource.closed.clear()
                self.tr.clear()
                self.proto.lineReceived(f"{line}\n".encode())
                artifact: Artifact = self.proto.cmdstack[-1].artifact

                def arrived(a: Artifact = artifact) -> bool:
                    return a.fp.tell() == len(SENT)

                self.assertTrue(pump(arrived), "no data arrived")

                artifact.abort()

                self.assertTrue(
                    pump(lambda: self.resource.closed), "connection left open"
                )
                self.assertEqual(len(self.failed()), 1)
                self.assertTrue(pump(lambda: self.tr.value().endswith(PROMPT)))
                self.assertNotIn(b"\n\n" + PROMPT, self.tr.value())
                with open(artifact.shasumFilename, "rb") as f:
                    self.assertEqual(f.read(), SENT)


if __name__ == "__main__":
    unittest.main()
