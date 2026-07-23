# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/shell/fs.py path resolution and home provisioning
# ABOUTME: covers resolve_path normalization, empty-path robustness, and ~/.ssh setup

from __future__ import annotations

import os
import stat
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


class ProvisionHomeTests(unittest.TestCase):
    """provision_home() gives the session user a home directory and ~/.ssh."""

    def test_missing_home_is_created_owned_by_user(self) -> None:
        # The default image has no /home/admin; a user allowed in by a
        # wildcard credential must still land in a real home directory.
        hpfs = fs.HoneyPotFilesystem("arch", "/home/admin")
        hpfs.provision_home("/home/admin", 1000, 1000)
        self.assertTrue(hpfs.isdir("/home/admin"))
        entry = hpfs.getfile("/home/admin")
        assert entry is not None
        self.assertEqual(entry[fs.A_UID], 1000)
        self.assertEqual(entry[fs.A_GID], 1000)

    def test_ssh_dir_is_created_mode_0700(self) -> None:
        hpfs = fs.HoneyPotFilesystem("arch", "/home/admin")
        hpfs.provision_home("/home/admin", 1000, 1000)
        self.assertTrue(hpfs.isdir("/home/admin/.ssh"))
        entry = hpfs.getfile("/home/admin/.ssh")
        assert entry is not None
        self.assertEqual(stat.S_IMODE(entry[fs.A_MODE]), 0o700)
        self.assertEqual(entry[fs.A_UID], 1000)

    def test_authorized_keys_can_be_written_after_provisioning(self) -> None:
        # The point of the feature: an attacker's key install succeeds so the
        # key is captured instead of failing with "No such file or directory".
        hpfs = fs.HoneyPotFilesystem("arch", "/home/admin")
        hpfs.provision_home("/home/admin", 1000, 1000)
        path = "/home/admin/.ssh/authorized_keys"
        self.assertTrue(hpfs.mkfile(path, 1000, 1000, 0, stat.S_IFREG | 0o644))
        self.assertTrue(hpfs.isfile(path))

    def test_ssh_added_when_home_already_exists(self) -> None:
        # The image ships /root without a .ssh; provisioning adds it without
        # disturbing the existing home.
        hpfs = fs.HoneyPotFilesystem("arch", "/root")
        self.assertTrue(hpfs.isdir("/root"))
        self.assertFalse(hpfs.isdir("/root/.ssh"))
        hpfs.provision_home("/root", 0, 0)
        self.assertTrue(hpfs.isdir("/root/.ssh"))
        # Existing contents are preserved.
        self.assertTrue(hpfs.exists("/root/.bashrc"))

    def test_provisioning_is_idempotent(self) -> None:
        hpfs = fs.HoneyPotFilesystem("arch", "/home/admin")
        hpfs.provision_home("/home/admin", 1000, 1000)
        hpfs.provision_home("/home/admin", 1000, 1000)
        # A second call must not create a duplicate .ssh entry.
        ssh_dirs = [c for c in hpfs.get_path("/home/admin") if c[fs.A_NAME] == ".ssh"]
        self.assertEqual(len(ssh_dirs), 1)


if __name__ == "__main__":
    unittest.main()
