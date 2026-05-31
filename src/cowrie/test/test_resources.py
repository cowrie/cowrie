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
