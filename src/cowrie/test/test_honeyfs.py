# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/honeyfs.py — pickle-backed filesystem cache and reads
# ABOUTME: covers get_tree deepcopy, read_file extraction, read_honeyfs_bytes cascade

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cowrie.shell import honeyfs

ENV_CONTENTS = "COWRIE_HONEYPOT_CONTENTS_PATH"


def _file_entry(name: str, contents: bytes | list) -> list:
    """Build a T_FILE pickle entry: [name, T_FILE, uid, gid, size, mode, ctime,
    contents, target, realfile]."""
    return [name, honeyfs.T_FILE, 0, 0, len(contents) if isinstance(contents, bytes) else 0, 0o644, 0, contents, None, None]


def _dir_entry(name: str, children: list) -> list:
    """Build a T_DIR entry."""
    return [name, honeyfs.T_DIR, 0, 0, 0, 0o755, 0, children, None, None]


def _link_entry(name: str, target: str) -> list:
    """Build a T_LINK entry pointing at an absolute path inside the tree."""
    return [name, honeyfs.T_LINK, 0, 0, 0, 0o777, 0, [], target, None]


def _root(children: list) -> list:
    """Build the root pickle entry (a T_DIR named '/')."""
    return _dir_entry("/", children)


class GetTreeTests(unittest.TestCase):
    """get_tree() returns a deep copy of the cached tree."""

    def test_returns_a_list(self) -> None:
        tree = honeyfs.get_tree()
        self.assertIsInstance(tree, list)

    def test_returns_fresh_copy_each_call(self) -> None:
        first = honeyfs.get_tree()
        second = honeyfs.get_tree()
        self.assertIsNot(first, second)
        first.append("mutation")
        self.assertNotIn("mutation", second)


class ReadFileTests(unittest.TestCase):
    """read_file extracts bytes from A_CONTENTS, otherwise raises."""

    def _patch_tree(self, root: list) -> None:
        patcher = patch.object(honeyfs, "_tree", return_value=root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_returns_bytes_for_file_with_embedded_contents(self) -> None:
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", b"HELLO\n")])])
        )

        self.assertEqual(honeyfs.read_file("/etc/issue.net"), b"HELLO\n")

    def test_raises_when_contents_is_empty_list(self) -> None:
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", [])])])
        )

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc/issue.net")

    def test_raises_when_path_missing(self) -> None:
        self._patch_tree(_root([_dir_entry("etc", [])]))

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc/nope")

    def test_raises_when_intermediate_dir_missing(self) -> None:
        self._patch_tree(_root([]))

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc/issue.net")

    def test_raises_when_target_is_a_directory(self) -> None:
        self._patch_tree(_root([_dir_entry("etc", [])]))

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc")

    def test_follows_terminal_symlink_to_file(self) -> None:
        self._patch_tree(
            _root(
                [
                    _dir_entry("etc", [_link_entry("issue.net", "/usr/issue.net")]),
                    _dir_entry("usr", [_file_entry("issue.net", b"LINKED")]),
                ]
            )
        )

        self.assertEqual(honeyfs.read_file("/etc/issue.net"), b"LINKED")

    def test_follows_intermediate_directory_symlink(self) -> None:
        self._patch_tree(
            _root(
                [
                    _link_entry("etc", "/real/etc"),
                    _dir_entry(
                        "real",
                        [_dir_entry("etc", [_file_entry("passwd", b"BEHIND-LINK")])],
                    ),
                ]
            )
        )

        self.assertEqual(honeyfs.read_file("/etc/passwd"), b"BEHIND-LINK")

    def test_raises_on_broken_symlink(self) -> None:
        self._patch_tree(
            _root(
                [_dir_entry("etc", [_link_entry("issue.net", "/nope/issue.net")])]
            )
        )

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc/issue.net")

    def test_raises_on_symlink_loop(self) -> None:
        self._patch_tree(
            _root(
                [
                    _dir_entry(
                        "etc",
                        [
                            _link_entry("a", "/etc/b"),
                            _link_entry("b", "/etc/a"),
                        ],
                    )
                ]
            )
        )

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_file("/etc/a")


class BundledPickleContentsTests(unittest.TestCase):
    """Sanity-check that the bundled fs.pickle has embedded bytes for the
    paths cowrie reads at startup. Guards against accidentally dropping
    A_CONTENTS bytes in a future pickle regeneration."""

    def setUp(self) -> None:
        honeyfs._tree.cache_clear()
        self.addCleanup(honeyfs._tree.cache_clear)
        self._prior_env = os.environ.pop(ENV_CONTENTS, None)
        self.addCleanup(self._restore_env)
        # Force the bundled side of the cascade by clearing contents_path.
        os.environ[ENV_CONTENTS] = ""

    def _restore_env(self) -> None:
        if self._prior_env is None:
            os.environ.pop(ENV_CONTENTS, None)
        else:
            os.environ[ENV_CONTENTS] = self._prior_env

    def test_passwd_has_root_entry(self) -> None:
        data = honeyfs.read_honeyfs_bytes("etc/passwd")
        self.assertIn(b"root:", data)

    def test_group_has_root_entry(self) -> None:
        data = honeyfs.read_honeyfs_bytes("etc/group")
        self.assertIn(b"root:", data)

    def test_issue_net_resolves_without_error(self) -> None:
        # issue.net intentionally ships as a zero-byte file
        data = honeyfs.read_honeyfs_bytes("etc/issue.net")
        self.assertIsInstance(data, bytes)


class ReadHoneyfsBytesTests(unittest.TestCase):
    """read_honeyfs_bytes cascades operator override to pickle extraction."""

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

    def _patch_tree(self, root: list) -> None:
        patcher = patch.object(honeyfs, "_tree", return_value=root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_operator_file_wins_over_pickle(self) -> None:
        etc = Path(self.tmpdir) / "etc"
        etc.mkdir()
        (etc / "issue.net").write_bytes(b"OPERATOR")
        self._set_contents_path(self.tmpdir)
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", b"PICKLE")])])
        )

        self.assertEqual(honeyfs.read_honeyfs_bytes("etc/issue.net"), b"OPERATOR")

    def test_falls_through_to_pickle_when_operator_file_missing(self) -> None:
        self._set_contents_path(self.tmpdir)
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", b"PICKLE")])])
        )

        self.assertEqual(honeyfs.read_honeyfs_bytes("etc/issue.net"), b"PICKLE")

    def test_falls_through_to_pickle_when_contents_path_unset(self) -> None:
        self._set_contents_path("")
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", b"PICKLE")])])
        )

        self.assertEqual(honeyfs.read_honeyfs_bytes("etc/issue.net"), b"PICKLE")

    def test_raises_when_both_missing(self) -> None:
        self._set_contents_path(self.tmpdir)
        self._patch_tree(_root([]))

        with self.assertRaises(FileNotFoundError):
            honeyfs.read_honeyfs_bytes("etc/issue.net")

    def test_operator_directory_entry_is_ignored(self) -> None:
        (Path(self.tmpdir) / "etc").mkdir()
        self._set_contents_path(self.tmpdir)
        self._patch_tree(
            _root([_dir_entry("etc", [_file_entry("issue.net", b"PICKLE")])])
        )

        # 'etc' on operator side is a dir, not a regular file → fall through
        with self.assertRaises(FileNotFoundError):
            honeyfs.read_honeyfs_bytes("etc")
