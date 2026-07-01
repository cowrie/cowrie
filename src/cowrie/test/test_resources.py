# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/core/resources.py — bundled cowrie.data read helpers
# ABOUTME: covers read_data_bytes and open_data_binary

from __future__ import annotations

import unittest

from cowrie.core import resources


class ReadDataBytesTests(unittest.TestCase):
    """read_data_bytes() — bundled-only lookup under cowrie.data."""

    def test_returns_bytes_for_existing_resource(self) -> None:
        data = resources.read_data_bytes("arch", "bsd-aarch64-lsb")
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

    def test_raises_file_not_found_for_missing_resource(self) -> None:
        with self.assertRaises(FileNotFoundError):
            resources.read_data_bytes("does-not-exist")

    def test_raises_file_not_found_for_missing_subpath(self) -> None:
        with self.assertRaises(FileNotFoundError):
            resources.read_data_bytes("arch", "no-such-arch")

    def test_raises_file_not_found_for_directory(self) -> None:
        # A resource that resolves to a directory (e.g. `/` -> the txtcmds
        # directory itself) must raise FileNotFoundError on every platform,
        # not the platform-dependent IsADirectoryError / PermissionError that
        # opening a directory produces.
        with self.assertRaises(FileNotFoundError):
            resources.read_data_bytes("txtcmds")

    def test_raises_file_not_found_for_directory_via_empty_subpath(self) -> None:
        # The exact `/` command path: relpath "" -> "".split("/") == [""] ->
        # read_data_bytes("txtcmds", "") resolves to the txtcmds directory.
        with self.assertRaises(FileNotFoundError):
            resources.read_data_bytes("txtcmds", "")


class OpenDataBinaryTests(unittest.TestCase):
    """open_data_binary() — bundled-only binary stream."""

    def test_yields_readable_binary_stream(self) -> None:
        with resources.open_data_binary("fs.pickle") as fh:
            chunk = fh.read(16)
        self.assertIsInstance(chunk, bytes)
        self.assertGreater(len(chunk), 0)

    def test_raises_file_not_found_for_missing_resource(self) -> None:
        with self.assertRaises(FileNotFoundError):
            with resources.open_data_binary("does-not-exist"):
                pass

    def test_raises_file_not_found_for_directory(self) -> None:
        # Opening a resource that resolves to a directory must raise
        # FileNotFoundError on every platform, not IsADirectoryError /
        # PermissionError.
        with self.assertRaises(FileNotFoundError):
            with resources.open_data_binary("txtcmds"):
                pass
