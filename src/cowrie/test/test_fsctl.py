# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/scripts/fsctl.py — pickle filesystem editor
# ABOUTME: covers embed_directory bulk-load of file contents into the pickle

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from cowrie.scripts import fsctl


def _file_entry(name: str) -> list:
    """Build a T_FILE pickle entry with empty A_CONTENTS."""
    return [name, fsctl.T_FILE, 0, 0, 0, 0o644, 0, [], None, None]


def _dir_entry(name: str, children: list) -> list:
    """Build a T_DIR entry."""
    return [name, fsctl.T_DIR, 0, 0, 0, 0o755, 0, children, None, None]


def _root(children: list) -> list:
    return _dir_entry("/", children)


def _find_in(tree, path):
    """Walk to entry at path. Test helper, asserts found."""
    return fsctl.getpath(tree, path)


class EmbedDirectoryTests(unittest.TestCase):
    """fsctl.embed_directory walks a local dir and sets A_CONTENTS."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write(self, relpath: str, data: bytes) -> None:
        target = Path(self.tmpdir) / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def test_loads_matching_file(self) -> None:
        tree = _root([_dir_entry("etc", [_file_entry("passwd")])])
        self._write("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n")

        loaded, skipped_count, skipped = fsctl.embed_directory(tree, self.tmpdir)

        self.assertEqual(loaded, 1)
        self.assertEqual(skipped_count, 0)
        self.assertEqual(skipped, [])
        self.assertEqual(
            _find_in(tree, "/etc/passwd")[fsctl.A_CONTENTS],
            b"root:x:0:0:root:/root:/bin/bash\n",
        )

    def test_skips_files_without_pickle_entry(self) -> None:
        tree = _root([_dir_entry("etc", [_file_entry("passwd")])])
        self._write("etc/passwd", b"PASSWD")
        self._write("etc/extra", b"EXTRA")  # not in pickle

        loaded, skipped_count, skipped = fsctl.embed_directory(tree, self.tmpdir)

        self.assertEqual(loaded, 1)
        self.assertEqual(skipped_count, 1)
        self.assertIn("/etc/extra", skipped)

    def test_pickle_entries_without_files_keep_empty_contents(self) -> None:
        tree = _root(
            [
                _dir_entry(
                    "etc", [_file_entry("passwd"), _file_entry("untouched")]
                )
            ]
        )
        self._write("etc/passwd", b"PASSWD")

        fsctl.embed_directory(tree, self.tmpdir)

        # untouched file is not on disk; A_CONTENTS stays as [].
        self.assertEqual(_find_in(tree, "/etc/untouched")[fsctl.A_CONTENTS], [])

    def test_walks_nested_directories(self) -> None:
        tree = _root(
            [
                _dir_entry(
                    "proc",
                    [_dir_entry("net", [_file_entry("arp")])],
                )
            ]
        )
        self._write("proc/net/arp", b"IP address  HW type  Flags\n")

        loaded, _, _ = fsctl.embed_directory(tree, self.tmpdir)

        self.assertEqual(loaded, 1)
        self.assertEqual(
            _find_in(tree, "/proc/net/arp")[fsctl.A_CONTENTS],
            b"IP address  HW type  Flags\n",
        )

    def test_skips_when_pickle_entry_is_directory(self) -> None:
        # local 'etc' exists as a file, but pickle has 'etc' as a directory
        tree = _root([_dir_entry("etc", [])])
        # Build local: tmpdir/etc is a single regular file (no children).
        (Path(self.tmpdir) / "etc").write_bytes(b"oops")

        loaded, skipped_count, skipped = fsctl.embed_directory(tree, self.tmpdir)

        self.assertEqual(loaded, 0)
        self.assertEqual(skipped_count, 1)
        self.assertIn("/etc", skipped)
