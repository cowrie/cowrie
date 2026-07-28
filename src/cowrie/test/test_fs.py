# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/fs.py path resolution, tree walking and mutation
# ABOUTME: covers resolve_path, getfile/get_path, link/unlink_entry, rename/remove

from __future__ import annotations

import copy
import os
import unittest
from typing import Any

from cowrie.shell import fs, honeyfs

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def _file_entry(name: str, contents: bytes = b"") -> list[Any]:
    """Build a minimal T_FILE directory entry."""
    return [name, fs.T_FILE, 0, 0, len(contents), 0o644, 0, contents, None, None]


def _dir_entry(name: str, children: list[Any]) -> list[Any]:
    """Build a T_DIR directory entry."""
    return [name, fs.T_DIR, 0, 0, 0, 0o755, 0, children, None, None]


def _link_entry(name: str, target: str) -> list[Any]:
    """Build a T_LINK entry pointing at an absolute in-tree path."""
    return [name, fs.T_LINK, 0, 0, 0, 0o777, 0, [], target, None]


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


class RenameRemoveTests(unittest.TestCase):
    """fs.rename/fs.remove model the rename(2)/unlink(2) syscalls and back
    both the shell (mv, rm) and the SFTP server."""

    def setUp(self) -> None:
        self.fs = fs.HoneyPotFilesystem("arch", "/root")

    def test_rename_moves_file_to_new_name(self) -> None:
        self.fs.link_entry(_file_entry("r_old"), "/tmp")
        self.fs.rename("/tmp/r_old", "/tmp/r_new")
        names = self.fs.listdir("/tmp")
        self.assertNotIn("r_old", names)
        self.assertIn("r_new", names)

    def test_rename_overwrites_existing_destination(self) -> None:
        self.fs.link_entry(_file_entry("r_src"), "/tmp")
        self.fs.link_entry(_file_entry("r_dst"), "/tmp")
        self.fs.rename("/tmp/r_src", "/tmp/r_dst")
        names = self.fs.listdir("/tmp")
        self.assertNotIn("r_src", names)
        self.assertEqual(names.count("r_dst"), 1)

    def test_rename_across_directories(self) -> None:
        self.fs.link_entry(_file_entry("x_move"), "/tmp")
        self.fs.rename("/tmp/x_move", "/root/x_moved")
        self.assertNotIn("x_move", self.fs.listdir("/tmp"))
        self.assertIn("x_moved", self.fs.listdir("/root"))

    def test_rename_missing_source_raises(self) -> None:
        with self.assertRaises(OSError):
            self.fs.rename("/tmp/nope_src_xyz", "/tmp/whatever")

    def test_remove_deletes_file(self) -> None:
        self.fs.link_entry(_file_entry("rm_me"), "/tmp")
        self.fs.remove("/tmp/rm_me")
        self.assertNotIn("rm_me", self.fs.listdir("/tmp"))

    def test_remove_missing_raises(self) -> None:
        with self.assertRaises(OSError):
            self.fs.remove("/tmp/not_here_xyz")


class WalkerTests(unittest.TestCase):
    """getfile() resolves a path to a node; get_path() returns that node's
    contents. Both must agree on missing paths, walking through a file, and
    symlink resolution."""

    def setUp(self) -> None:
        self.fs = fs.HoneyPotFilesystem("arch", "/root")
        self.fs.fs = _dir_entry(
            "/",
            [
                _dir_entry(
                    "etc",
                    [
                        _file_entry("passwd", b"root:x"),
                        _link_entry("plink", "/etc/passwd"),
                    ],
                ),
                _dir_entry("tmp", []),
                _link_entry("dirlink", "/etc"),
                _link_entry("broken", "/nope"),
            ],
        )

    def _getfile(self, path: str, follow_symlinks: bool = True) -> list[Any]:
        """getfile() that asserts a node was found, for tests that inspect it."""
        node = self.fs.getfile(path, follow_symlinks=follow_symlinks)
        assert node is not None
        return node

    # --- getfile ---
    def test_getfile_returns_file_node(self) -> None:
        self.assertEqual(self._getfile("/etc/passwd")[fs.A_CONTENTS], b"root:x")

    def test_getfile_missing_returns_none(self) -> None:
        self.assertIsNone(self.fs.getfile("/etc/nope"))

    def test_getfile_through_a_file_returns_none(self) -> None:
        # Descending past a regular file must not crash — it is not a directory.
        self.assertIsNone(self.fs.getfile("/etc/passwd/foo"))

    def test_getfile_empty_path_is_root(self) -> None:
        self.assertIs(self.fs.getfile(""), self.fs.fs)

    def test_getfile_double_slash_is_ignored(self) -> None:
        self.assertEqual(self._getfile("/etc//passwd")[fs.A_CONTENTS], b"root:x")

    def test_getfile_follows_terminal_symlink(self) -> None:
        self.assertEqual(self._getfile("/etc/plink")[fs.A_CONTENTS], b"root:x")

    def test_getfile_no_follow_returns_link_node(self) -> None:
        node = self._getfile("/etc/plink", follow_symlinks=False)
        self.assertEqual(node[fs.A_TYPE], fs.T_LINK)

    def test_getfile_broken_symlink_returns_none(self) -> None:
        self.assertIsNone(self.fs.getfile("/broken"))

    def test_getfile_empty_target_symlink_returns_none(self) -> None:
        # Some /proc/<pid>/cwd links ship with an empty target; resolving them
        # must not crash on target[0] (issue: IndexError in getfile).
        self.fs.fs[fs.A_CONTENTS].append(_link_entry("emptylink", ""))
        self.assertIsNone(self.fs.getfile("/emptylink"))

    def test_getfile_follows_intermediate_symlink(self) -> None:
        self.assertEqual(self._getfile("/dirlink/passwd")[fs.A_CONTENTS], b"root:x")

    # --- get_path ---
    def test_get_path_returns_directory_children(self) -> None:
        names = [c[fs.A_NAME] for c in self.fs.get_path("/etc")]
        self.assertEqual(sorted(names), ["passwd", "plink"])

    def test_get_path_of_file_returns_its_bytes(self) -> None:
        self.assertEqual(self.fs.get_path("/etc/passwd"), b"root:x")

    def test_get_path_missing_raises(self) -> None:
        with self.assertRaises(fs.FileNotFound):
            self.fs.get_path("/etc/nope")

    def test_get_path_through_a_file_raises(self) -> None:
        with self.assertRaises(fs.FileNotFound):
            self.fs.get_path("/etc/passwd/foo")

    def test_get_path_empty_is_root_children(self) -> None:
        names = [c[fs.A_NAME] for c in self.fs.get_path("")]
        self.assertEqual(sorted(names), ["broken", "dirlink", "etc", "tmp"])

    def test_get_path_follows_symlink_to_directory(self) -> None:
        names = [c[fs.A_NAME] for c in self.fs.get_path("/dirlink")]
        self.assertEqual(sorted(names), ["passwd", "plink"])


class CopyOnWriteTests(unittest.TestCase):
    """Sessions share the base tree until they mutate it, then copy it once.
    The shared base must never be mutated by a session."""

    def setUp(self) -> None:
        honeyfs._tree.cache_clear()
        self.addCleanup(honeyfs._tree.cache_clear)

    def test_new_session_shares_the_base_tree(self) -> None:
        session = fs.HoneyPotFilesystem("arch", "/root")
        self.assertIs(session.fs, honeyfs.get_tree())

    def test_two_sessions_share_until_one_mutates(self) -> None:
        a = fs.HoneyPotFilesystem("arch", "/root")
        b = fs.HoneyPotFilesystem("arch", "/root")
        self.assertIs(a.fs, b.fs)
        a.mkfile("/tmp/only_in_a", 0, 0, 0, 0o644)
        self.assertIsNot(a.fs, b.fs)
        self.assertIn("only_in_a", a.listdir("/tmp"))
        self.assertNotIn("only_in_a", b.listdir("/tmp"))

    def test_second_mutation_does_not_copy_again(self) -> None:
        a = fs.HoneyPotFilesystem("arch", "/root")
        a.mkfile("/tmp/one", 0, 0, 0, 0o644)
        private = a.fs
        a.mkfile("/tmp/two", 0, 0, 0, 0o644)
        self.assertIs(a.fs, private)

    def test_base_tree_is_never_mutated(self) -> None:
        base = honeyfs.get_tree()
        snapshot = copy.deepcopy(base)
        a = fs.HoneyPotFilesystem("arch", "/root")
        a.mkfile("/tmp/x", 0, 0, 0, 0o644)
        a.chmod("/etc/passwd", 0o600)
        a.remove("/tmp/x")
        self.assertEqual(base, snapshot)


if __name__ == "__main__":
    unittest.main()
