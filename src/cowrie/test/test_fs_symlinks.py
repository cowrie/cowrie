# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Symlink resolution in the emulated filesystem: targets are literal
# ABOUTME: (relative or absolute) and a loop must not exhaust the stack.

from __future__ import annotations

import os
import unittest

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.shell.fs import (
    A_CONTENTS,
    A_NAME,
    T_DIR,
    T_FILE,
    T_LINK,
    HoneyPotFilesystem,
)


def _entry(name: str, etype: int, target: str | None = None) -> list:
    """A filesystem entry tuple: name, type, uid, gid, size, mode, ctime,
    contents, target, realfile."""
    return [name, etype, 0, 0, 0, 0o755, 0, [], target, None]


def _fs_with(*entries: list) -> HoneyPotFilesystem:
    """A filesystem whose root holds only the given entries.

    The constructor loads the shared honeyfs tree, so replace it with the
    synthetic one under test.
    """
    root = _entry("/", T_DIR)
    root[A_CONTENTS] = list(entries)
    fs = HoneyPotFilesystem("arch", "/root")
    fs.fs = root
    return fs


class SymlinkLoopTests(unittest.TestCase):
    """A cycle must resolve to a broken link, not exhaust the stack."""

    def test_two_link_cycle(self) -> None:
        fs = _fs_with(
            _entry("a", T_LINK, "/b"),
            _entry("b", T_LINK, "/a"),
        )

        self.assertIsNone(fs.getfile("/a"))

    def test_self_referential_link(self) -> None:
        fs = _fs_with(_entry("loop", T_LINK, "/loop"))

        self.assertIsNone(fs.getfile("/loop"))

    def test_long_chain_within_cap_still_resolves(self) -> None:
        """A legitimate chain shorter than the cap must still work."""
        entries = [_entry("target", T_FILE)]
        entries += [_entry("l0", T_LINK, "/target")]
        for i in range(1, 8):
            entries.append(_entry(f"l{i}", T_LINK, f"/l{i - 1}"))
        fs = _fs_with(*entries)

        node = fs.getfile("/l7")

        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node[A_NAME], "target")


if __name__ == "__main__":
    unittest.main()
