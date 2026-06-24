# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/filetransfer.py — the SFTP server adapter
# ABOUTME: covers translating the emulated fs exceptions into OSError for conch

from __future__ import annotations

import errno
import os
import unittest
from types import SimpleNamespace

from twisted.conch.ssh.filetransfer import FXF_CREAT, FXF_WRITE

from cowrie.shell import fs
from cowrie.shell.filetransfer import SFTPServerForCowrieUser

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class SFTPErrorTranslationTests(unittest.TestCase):
    """The SFTP adapter must surface OSError (not a bare cowrie exception) so
    conch returns a proper status instead of a critical traceback."""

    def setUp(self) -> None:
        # Build the server without its avatar/initFileSystem wiring; only the
        # filesystem and home directory matter for these operations.
        self.server = SFTPServerForCowrieUser.__new__(SFTPServerForCowrieUser)
        self.server.fs = fs.HoneyPotFilesystem("linux-x64-lsb", "/root")
        self.server.avatar = SimpleNamespace(home="/root")

    def test_open_directory_missing_raises_enoent(self) -> None:
        # listdir() raises the cowrie FileNotFound for a missing directory.
        with self.assertRaises(OSError) as ctx:
            self.server.openDirectory("/nonexistent-dir")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_open_file_for_write_missing_parent_raises_enoent(self) -> None:
        # open() -> mkfile() raises the cowrie FileNotFound for a missing parent.
        with self.assertRaises(OSError) as ctx:
            self.server.openFile("/nonexistent-dir/clean.sh", FXF_WRITE | FXF_CREAT, {})
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_open_file_under_special_path_raises_eacces(self) -> None:
        # mkfile() raises the cowrie PermissionDenied for a write under /proc.
        with self.assertRaises(OSError) as ctx:
            self.server.openFile("/proc/clean.sh", FXF_WRITE | FXF_CREAT, {})
        self.assertEqual(ctx.exception.errno, errno.EACCES)

    def test_get_attrs_missing_raises_enoent(self) -> None:
        # stat() already raises OSError(ENOENT); it must pass through unchanged.
        with self.assertRaises(OSError) as ctx:
            self.server.getAttrs("/nonexistent-file", followLinks=True)
        self.assertEqual(ctx.exception.errno, errno.ENOENT)


if __name__ == "__main__":
    unittest.main()
