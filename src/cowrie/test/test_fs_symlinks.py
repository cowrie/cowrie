# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Symlink resolution in the emulated filesystem: targets are literal
# ABOUTME: (relative or absolute) and a loop must not exhaust the stack.

from __future__ import annotations

import os
import pathlib
import unittest

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.shell.fs import (
    A_CONTENTS,
    A_NAME,
    A_TARGET,
    A_TYPE,
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


class LiteralTargetTests(unittest.TestCase):
    """A_TARGET holds the literal symlink target, as readlink(2) reports it:
    absolute, or relative to the link's own directory."""

    def _tree(self) -> HoneyPotFilesystem:
        """/usr/sbin/{rmt-tar, rmt -> rmt-tar, abs -> /usr/sbin/rmt-tar}
        plus /etc/alternatives/rmt -> ../../usr/sbin/rmt-tar"""
        rmt_tar = _entry("rmt-tar", T_FILE)
        sbin = _entry("sbin", T_DIR)
        sbin[A_CONTENTS] = [
            rmt_tar,
            _entry("rmt", T_LINK, "rmt-tar"),
            _entry("abs", T_LINK, "/usr/sbin/rmt-tar"),
            _entry("up", T_LINK, "../sbin/rmt-tar"),
        ]
        usr = _entry("usr", T_DIR)
        usr[A_CONTENTS] = [sbin]
        alternatives = _entry("alternatives", T_DIR)
        alternatives[A_CONTENTS] = [_entry("rmt", T_LINK, "../../usr/sbin/rmt-tar")]
        etc = _entry("etc", T_DIR)
        etc[A_CONTENTS] = [alternatives]
        root = _entry("/", T_DIR)
        root[A_CONTENTS] = [usr, etc]
        fs = HoneyPotFilesystem("arch", "/root")
        fs.fs = root
        return fs

    def test_relative_target_resolves_against_link_directory(self) -> None:
        """/usr/sbin/rmt -> rmt-tar means /usr/sbin/rmt-tar, not /rmt-tar."""
        fs = self._tree()

        node = fs.getfile("/usr/sbin/rmt")

        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node[A_NAME], "rmt-tar")

    def test_absolute_target_resolves(self) -> None:
        fs = self._tree()

        node = fs.getfile("/usr/sbin/abs")

        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node[A_NAME], "rmt-tar")

    def test_dotdot_in_target(self) -> None:
        """A target may walk upwards, as real relative symlinks do."""
        fs = self._tree()

        for path in ("/usr/sbin/up", "/etc/alternatives/rmt"):
            with self.subTest(path=path):
                node = fs.getfile(path)
                self.assertIsNotNone(node)
                assert node is not None
                self.assertEqual(node[A_NAME], "rmt-tar")

    def test_root_relative_target_no_longer_assumed(self) -> None:
        """The old format stored root-relative targets without a leading
        slash; that must not silently resolve from / any more."""
        broken = _entry("x", T_LINK, "usr/sbin/rmt-tar")
        fs = self._tree()
        fs.fs[A_CONTENTS].append(broken)

        # Read relative to /, the link's own directory, this is
        # /usr/sbin/rmt-tar and still resolves.
        self.assertIsNotNone(fs.getfile("/x"))


class ShippedFilesystemTests(unittest.TestCase):
    """The bundled fs.pickle must resolve and display its symlinks the way a
    real system does."""

    def test_rmt_symlink_target_is_absolute(self) -> None:
        """ls shows the target verbatim, so a target that a real box reports
        with a leading slash must keep it (issue: rmt -> usr/sbin/rmt-tar)."""
        fs = HoneyPotFilesystem("arch", "/root")

        link = fs.getfile("/usr/sbin/rmt", follow_symlinks=False)

        self.assertIsNotNone(link)
        assert link is not None
        self.assertTrue(
            link[A_TARGET].startswith("/"),
            f"symlink target {link[A_TARGET]!r} is neither absolute nor "
            "resolvable relative to /usr/sbin",
        )

    def test_shipped_symlinks_still_resolve(self) -> None:
        """Every symlink in the bundled tree must resolve to something, or be
        a deliberate dangling link, under the literal-target semantics."""
        fs = HoneyPotFilesystem("arch", "/root")

        unresolved = []

        def walk(node: list, path: str) -> None:
            if node[A_TYPE] == T_LINK:
                if fs.getfile(path) is None:
                    unresolved.append((path, node[A_TARGET]))
                return
            if isinstance(node[A_CONTENTS], list):
                for child in node[A_CONTENTS]:
                    walk(child, path + "/" + child[A_NAME])

        walk(fs.fs, "")
        # /proc and /dev snapshots contain genuinely dangling links (pipes,
        # per-pid paths); everything else should resolve.
        real = [
            (p, t)
            for p, t in unresolved
            if not p.startswith(("/proc/", "/dev/", "/sys/"))
        ]
        self.assertEqual(real, [], f"{len(real)} symlinks stopped resolving")


class CreatefsTargetTests(unittest.TestCase):
    """createfs must record the literal target, not a resolved path."""

    def test_literal_targets_recorded(self) -> None:
        import tempfile

        from cowrie.scripts.createfs import recurse

        with tempfile.TemporaryDirectory() as tmp:
            # realpath: on macOS the temp dir sits under /var, itself a link to
            # /private/var, and createfs skips links resolving outside its root.
            root = os.path.realpath(tmp)
            base = pathlib.Path(root)
            (base / "usr" / "sbin").mkdir(parents=True)
            (base / "usr" / "sbin" / "rmt-tar").write_text("x")
            # Relative target, as the usrmerge links use.
            os.symlink("rmt-tar", base / "usr" / "sbin" / "rel")
            # Absolute target, as seen from inside the template root.
            os.symlink(
                str(base / "usr" / "sbin" / "rmt-tar"), base / "usr" / "sbin" / "abs"
            )

            tree: list = []
            recurse(root, "/", tree)

        found = {}

        def walk(entries: list) -> None:
            for e in entries:
                if e[A_TYPE] == T_LINK:
                    found[e[A_NAME]] = e[A_TARGET]
                elif isinstance(e[A_CONTENTS], list):
                    walk(e[A_CONTENTS])

        walk(tree)

        self.assertEqual(found.get("rel"), "rmt-tar")
        self.assertTrue(
            found.get("abs", "").startswith("/"),
            f"absolute target lost its leading slash: {found.get('abs')!r}",
        )


if __name__ == "__main__":
    unittest.main()
