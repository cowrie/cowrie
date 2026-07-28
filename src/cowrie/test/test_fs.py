# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/fs.py path resolution and directory-entry linking
# ABOUTME: covers resolve_path normalization, empty-path robustness, link/unlink_entry

from __future__ import annotations

import os
import unittest
from typing import Any

from cowrie.shell import fs

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def _file_entry(name: str) -> list[Any]:
    """Build a minimal T_FILE directory entry."""
    return [name, fs.T_FILE, 0, 0, 0, 0o644, 0, b"", None, None]


class ResolvePathTests(unittest.TestCase):
    """resolve_path() normalizes a pathspec against a working directory."""

    def setUp(self) -> None:
        self.fs = fs.HoneyPotFilesystem("arch", "/root")

    def test_absolute_path_is_returned_normalized(self) -> None:
        self.assertEqual(self.fs.resolve_path("/etc/passwd", "/root"), "/etc/passwd")

    def test_relative_path_joins_cwd(self) -> None:
        self.assertEqual(self.fs.resolve_path("foo", "/home/user"), "/home/user/foo")

    def test_dot_resolves_to_cwd(self) -> None:
        self.assertEqual(self.fs.resolve_path(".", "/home/user"), "/home/user")

    def test_empty_path_resolves_to_cwd_without_crashing(self) -> None:
        # An empty pathspec must not raise IndexError on path[0]. It is reachable
        # from any command that forwards an unset shell variable, e.g. an
        # attacker's `[ -w "$mnt" ]` where $mnt expanded to nothing.
        self.assertEqual(self.fs.resolve_path("", "/home/user"), "/home/user")


class EntryLinkingTests(unittest.TestCase):
    """link_entry/unlink_entry are the encapsulated directory mutators that
    cp, mv and rm use instead of poking get_path() lists directly."""

    def setUp(self) -> None:
        self.fs = fs.HoneyPotFilesystem("arch", "/root")

    def test_link_entry_adds_file_to_directory(self) -> None:
        self.fs.link_entry(_file_entry("cowrie_test_file"), "/")
        self.assertIn("cowrie_test_file", self.fs.listdir("/"))
        self.assertIsNotNone(self.fs.getfile("/cowrie_test_file"))

    def test_link_entry_replaces_same_name(self) -> None:
        # A directory can never hold two entries under one name.
        self.fs.link_entry(_file_entry("dup"), "/")
        self.fs.link_entry(_file_entry("dup"), "/")
        self.assertEqual(self.fs.listdir("/").count("dup"), 1)

    def test_unlink_entry_removes_file(self) -> None:
        entry = _file_entry("to_remove")
        self.fs.link_entry(entry, "/")
        self.fs.unlink_entry(entry, "/")
        self.assertNotIn("to_remove", self.fs.listdir("/"))

    def test_link_entry_into_subdirectory(self) -> None:
        self.fs.link_entry(_file_entry("in_tmp"), "/tmp")
        self.assertIn("in_tmp", self.fs.listdir("/tmp"))


if __name__ == "__main__":
    unittest.main()
