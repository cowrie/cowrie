# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/fs.py path resolution
# ABOUTME: covers resolve_path normalization and empty-path robustness

from __future__ import annotations

import os
import unittest

from cowrie.shell import fs

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


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


if __name__ == "__main__":
    unittest.main()
