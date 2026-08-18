# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/filetransfer.py — the SFTP server adapter
# ABOUTME: covers translating the emulated fs exceptions into OSError for conch

from __future__ import annotations

import errno
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from twisted.conch.ssh.filetransfer import FXF_CREAT, FXF_WRITE

from cowrie.shell import fs
from cowrie.shell.filetransfer import SFTPServerForCowrieUser

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
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


class SFTPPathJoinTests(unittest.TestCase):
    """Virtual SFTP paths must be joined with "/" regardless of host OS;
    os.path.join would use "\\" on Windows (issue #40388)."""

    def setUp(self) -> None:
        self.server = SFTPServerForCowrieUser.__new__(SFTPServerForCowrieUser)
        self.server.fs = fs.HoneyPotFilesystem("linux-x64-lsb", "/root")
        self.server.avatar = SimpleNamespace(home="/home/phil")

    def test_abspath_joins_with_forward_slash(self) -> None:
        result = self.server._absPath("file.txt")
        self.assertEqual(result, "/home/phil/file.txt")
        self.assertNotIn("\\", result)

    def test_abspath_of_absolute_path_is_unchanged(self) -> None:
        self.assertEqual(self.server._absPath("/etc/passwd"), "/etc/passwd")


class UploadSizeTests(unittest.TestCase):
    """SFTP writes are offset-addressed, so the size reported to the honeyfs
    is the highest offset written, not the sum of the chunk lengths."""

    def setUp(self) -> None:
        self.server = SFTPServerForCowrieUser.__new__(SFTPServerForCowrieUser)
        self.server.fs = fs.HoneyPotFilesystem("linux-x64-lsb", "/root")
        self.server.avatar = SimpleNamespace(home="/root")
        self.server.fs.events = MagicMock()

    def _upload(self, chunks: list[tuple[int, bytes]]) -> int:
        """Write these (offset, data) chunks to an uploaded file; returns the
        size the honeyfs ends up recording."""
        handle = self.server.openFile("/tmp/up.bin", FXF_WRITE | FXF_CREAT, {})
        for offset, data in chunks:
            handle.writeChunk(offset, data)
        handle.close()
        node = self.server.fs.getfile("/tmp/up.bin")
        assert node is not None
        size: int = node[fs.A_SIZE]
        return size

    def test_sequential_write(self) -> None:
        self.assertEqual(self._upload([(0, b"0123456789")]), 10)

    def test_sequential_chunks(self) -> None:
        self.assertEqual(self._upload([(0, b"01234"), (5, b"56789")]), 10)

    def test_retransmitted_chunk_is_not_counted_twice(self) -> None:
        """A resumed or retried transfer re-sends a chunk it already sent;
        summing the lengths would report the file as larger than it is."""
        self.assertEqual(
            self._upload([(0, b"01234"), (5, b"56789"), (5, b"56789")]), 10
        )

    def test_write_past_the_end_counts_the_gap(self) -> None:
        """Seeking past the end makes a sparse file, whose size includes the
        hole that was never written."""
        self.assertEqual(self._upload([(0, b"ab"), (100, b"yz")]), 102)

    def test_out_of_order_chunks(self) -> None:
        self.assertEqual(self._upload([(5, b"56789"), (0, b"01234")]), 10)


if __name__ == "__main__":
    unittest.main()
