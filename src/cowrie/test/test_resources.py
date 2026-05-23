# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/core/resources.py — bundled-data and honeyfs reading helpers
# ABOUTME: covers operator-override cascade and bundled-only access

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cowrie.core import resources

ENV_CONTENTS = "COWRIE_HONEYPOT_CONTENTS_PATH"


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


class ReadHoneyfsBytesTests(unittest.TestCase):
    """read_honeyfs_bytes() — operator override cascading to bundled."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._prior_env = os.environ.get(ENV_CONTENTS)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self._prior_env is None:
            os.environ.pop(ENV_CONTENTS, None)
        else:
            os.environ[ENV_CONTENTS] = self._prior_env

    def _set_contents_path(self, path: str) -> None:
        os.environ[ENV_CONTENTS] = path

    def test_operator_file_present_wins(self) -> None:
        etc_dir = Path(self.tmpdir) / "etc"
        etc_dir.mkdir()
        (etc_dir / "issue.net").write_bytes(b"OPERATOR BANNER")
        self._set_contents_path(self.tmpdir)

        self.assertEqual(
            resources.read_honeyfs_bytes("etc/issue.net"),
            b"OPERATOR BANNER",
        )

    def test_operator_file_missing_falls_through_to_bundled(self) -> None:
        # contents_path is set but the file is not in it.
        # In git-repo mode src/cowrie/data/honeyfs/ does not exist yet, so
        # the bundled side raises FileNotFoundError. Once Stage 1 lands and
        # honeyfs/ moves into the package, this same code path will return
        # the bundled bytes; the test will be updated to assert that.
        self._set_contents_path(self.tmpdir)

        with self.assertRaises(FileNotFoundError):
            resources.read_honeyfs_bytes("etc/issue.net")

    def test_empty_contents_path_falls_through_to_bundled(self) -> None:
        self._set_contents_path("")

        with self.assertRaises(FileNotFoundError):
            resources.read_honeyfs_bytes("etc/issue.net")

    def test_operator_directory_entry_is_ignored(self) -> None:
        # If <contents_path>/<relpath> exists but is a directory, treat it
        # as "not the file we wanted" and fall through to bundled.
        (Path(self.tmpdir) / "etc").mkdir()
        self._set_contents_path(self.tmpdir)

        with self.assertRaises(FileNotFoundError):
            resources.read_honeyfs_bytes("etc")
