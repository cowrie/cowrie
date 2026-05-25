# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/scripts/createfs.py — pickle tree builder
# ABOUTME: covers A_CONTENTS embed for paths in EMBED_PATHS

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cowrie.scripts import createfs


def _find_child(parent_contents, name):
    for c in parent_contents:
        if c[createfs.A_NAME] == name:
            return c
    msg = f"no child named {name!r} in tree"
    raise AssertionError(msg)


class RecurseEmbedTests(unittest.TestCase):
    """createfs.recurse embeds bytes into A_CONTENTS for paths in EMBED_PATHS."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write(self, relpath: str, data: bytes) -> None:
        target = Path(self.tmpdir) / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def _build_tree(self) -> list:
        tree: list = []
        createfs.recurse(self.tmpdir, "/", tree)
        return tree

    def test_embeds_file_when_virtual_path_in_embed_paths(self) -> None:
        self._write("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n")

        with patch.object(createfs, "EMBED_PATHS", {"/etc/passwd"}):
            tree = self._build_tree()

        etc = _find_child(tree, "etc")
        passwd = _find_child(etc[createfs.A_CONTENTS], "passwd")
        self.assertEqual(
            passwd[createfs.A_CONTENTS], b"root:x:0:0:root:/root:/bin/bash\n"
        )

    def test_leaves_unlisted_files_empty(self) -> None:
        self._write("etc/sudoers", b"root ALL=(ALL) ALL\n")

        with patch.object(createfs, "EMBED_PATHS", {"/etc/passwd"}):
            tree = self._build_tree()

        etc = _find_child(tree, "etc")
        sudoers = _find_child(etc[createfs.A_CONTENTS], "sudoers")
        self.assertEqual(sudoers[createfs.A_CONTENTS], [])

    def test_embeds_only_listed_when_multiple_files_present(self) -> None:
        self._write("etc/passwd", b"PASSWD")
        self._write("etc/shadow", b"SHADOW")
        self._write("etc/hostname", b"HOSTNAME")

        with patch.object(
            createfs, "EMBED_PATHS", {"/etc/passwd", "/etc/hostname"}
        ):
            tree = self._build_tree()

        etc = _find_child(tree, "etc")
        self.assertEqual(
            _find_child(etc[createfs.A_CONTENTS], "passwd")[createfs.A_CONTENTS],
            b"PASSWD",
        )
        self.assertEqual(
            _find_child(etc[createfs.A_CONTENTS], "hostname")[createfs.A_CONTENTS],
            b"HOSTNAME",
        )
        self.assertEqual(
            _find_child(etc[createfs.A_CONTENTS], "shadow")[createfs.A_CONTENTS],
            [],
        )

    def test_dir_entries_keep_their_children_list(self) -> None:
        # Make sure the embed logic doesn't accidentally overwrite a dir's
        # A_CONTENTS (which holds child entries).
        self._write("etc/passwd", b"x")

        with patch.object(createfs, "EMBED_PATHS", {"/etc/passwd"}):
            tree = self._build_tree()

        etc = _find_child(tree, "etc")
        self.assertEqual(etc[createfs.A_TYPE], createfs.T_DIR)
        self.assertIsInstance(etc[createfs.A_CONTENTS], list)
        self.assertGreater(len(etc[createfs.A_CONTENTS]), 0)


class EmbedPathsConstantTests(unittest.TestCase):
    """The default EMBED_PATHS set covers the paths cowrie reads at startup."""

    def test_contains_paths_cowrie_reads(self) -> None:
        # banner / passwd / group are read by cowrie itself, not just
        # served to attackers. Losing these from EMBED_PATHS would make
        # the bundled pickle insufficient for a no-honeyfs install.
        self.assertIn("/etc/issue.net", createfs.EMBED_PATHS)
        self.assertIn("/etc/passwd", createfs.EMBED_PATHS)
        self.assertIn("/etc/group", createfs.EMBED_PATHS)
