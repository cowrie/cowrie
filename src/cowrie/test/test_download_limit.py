# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that downloads exceeding download_limit_size abort the
# ABOUTME: transfer instead of draining it (issue #1500), for wget and curl.

from __future__ import annotations

import os
import tempfile
import time
import unittest
from typing import Any

from twisted.web.http_headers import Headers

from cowrie.commands.curl import Command_curl
from cowrie.commands.wget import Command_wget
from cowrie.core.artifact import Artifact
from cowrie.core.network import DownloadLimitExceeded
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class FakeBodyTransport:
    """Records whether the response body producer was stopped."""

    def __init__(self) -> None:
        self.stopped = False

    def stopProducing(self) -> None:
        self.stopped = True


class FakeResponse:
    """Minimal treq response: headers, length, and a recordable body."""

    def __init__(self, length: int) -> None:
        self.length = length
        self.code = 200
        self.phrase = b"OK"
        self.headers = Headers({b"content-type": [b"application/octet-stream"]})
        self.transport = FakeBodyTransport()
        self.delivered_to: Any = None

    def deliverBody(self, protocol: Any) -> None:
        self.delivered_to = protocol
        protocol.makeConnection(self.transport)


class DownloadSizeLimitTests(unittest.TestCase):
    """Exceeding download_limit_size must abort the transfer, not merely stop
    saving it (issue #1500)."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

        self.tmpdir = tempfile.mkdtemp()
        self._orig_artifact_dir = Artifact.artifactDir
        Artifact.artifactDir = self.tmpdir

    def tearDown(self) -> None:
        Artifact.artifactDir = self._orig_artifact_dir
        self.proto.connectionLost()
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _make_cmd(self, cls: type[Command_wget | Command_curl], **extra: Any) -> Any:
        cmd = cls.__new__(cls)
        cmd.protocol = self.proto
        cmd.writefn = lambda _data: None
        cmd.errorWritefn = lambda _data: None
        cmd.exit_code = 0
        cmd.url = b"http://198.51.100.1/big.bin"
        cmd.host = "198.51.100.1"
        cmd.port = 80
        cmd.limit_size = 10
        cmd.artifact = Artifact("download")
        for key, value in extra.items():
            setattr(cmd, key, value)
        self.proto.cmdstack.append(cmd)
        return cmd

    def _commands(self) -> list[Any]:
        return [
            self._make_cmd(Command_wget, quiet=True, started=time.time()),
            self._make_cmd(Command_curl, silent=True, outfile=None, head_request=False),
        ]

    # treq closes the connection when the collector raises, so collect must
    # raise once the transfer exceeds the limit instead of draining the rest
    # of the body into the void.
    def test_over_limit_chunk_raises_to_close_connection(self) -> None:
        for cmd in self._commands():
            with self.subTest(command=type(cmd).__name__):
                cmd.currentlength = 0
                with self.assertRaises(DownloadLimitExceeded):
                    cmd.collect(b"x" * 20)
                self.assertTrue(cmd.exited)

    # A Content-Length over the limit must abort the body instead of leaving
    # it undelivered (twisted buffers an undelivered body in memory while the
    # server keeps sending).
    def test_content_length_over_limit_aborts_body(self) -> None:
        for cmd in self._commands():
            with self.subTest(command=type(cmd).__name__):
                response = FakeResponse(length=1000)
                cmd.success(response)
                self.assertTrue(cmd.exited)
                self.assertIsNotNone(response.delivered_to)
                self.assertTrue(response.transport.stopped)


if __name__ == "__main__":
    unittest.main()
