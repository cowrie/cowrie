# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests the unzip command's extraction into the honeypot filesystem.
# ABOUTME: Guards that extracted directories are stored with a directory mode.

from __future__ import annotations

import os
import stat
import tempfile
import unittest
import zipfile

from cowrie.shell import fs
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport


class UnzipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()
        self.tmpdir = tempfile.mkdtemp()
        self.zippath = os.path.join(self.tmpdir, "payload.zip")
        with zipfile.ZipFile(self.zippath, "w") as z:
            z.writestr("explicit/", "")
            z.writestr("implicit/nested/file.txt", "hello")
        self.proto.fs.mkfile("/root/payload.zip", 0, 0, 0, stat.S_IFREG | 0o644)
        self.proto.fs.update_realfile(
            self.proto.fs.getfile("/root/payload.zip"), self.zippath
        )

    def tearDown(self) -> None:
        self.proto.connectionLost()
        os.remove(self.zippath)
        os.rmdir(self.tmpdir)

    def _mode(self, path: str) -> str:
        entry = self.proto.fs.getfile(path)
        assert entry is not None
        self.assertEqual(entry[fs.A_TYPE], fs.T_DIR)
        return stat.filemode(entry[fs.A_MODE])

    def test_extracted_directories_have_directory_mode(self) -> None:
        self.proto.lineReceived(b"unzip payload.zip\n")
        self.assertEqual(self._mode("/root/explicit"), "drwxr-xr-x")
        self.assertEqual(self._mode("/root/implicit"), "drwxr-xr-x")
        self.assertEqual(self._mode("/root/implicit/nested"), "drwxr-xr-x")
        self.assertEqual(
            stat.filemode(
                self.proto.fs.getfile("/root/implicit/nested/file.txt")[fs.A_MODE]
            ),
            "-rw-r--r--",
        )
