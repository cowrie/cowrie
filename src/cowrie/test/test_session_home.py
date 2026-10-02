# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests the home directory an SSH session creates for a login name
# ABOUTME: that is not in /etc/passwd: it must look like a real directory.

from __future__ import annotations

import stat
import unittest
from types import SimpleNamespace

from cowrie.shell import fs
from cowrie.shell.session import SSHSessionForCowrieUser
from cowrie.test.fake_server import FakeServer


class TemporaryUserHomeTests(unittest.TestCase):
    def test_home_is_created_as_a_directory(self) -> None:
        server = FakeServer()
        avatar = SimpleNamespace(
            server=server,
            uid=1001,
            gid=1001,
            username="newuser",
            home="/home/newuser",
            temporary=True,
        )

        SSHSessionForCowrieUser(avatar)

        entry = server.fs.getfile("/home/newuser")
        assert entry is not None
        self.assertEqual(entry[fs.A_TYPE], fs.T_DIR)
        self.assertEqual(stat.filemode(entry[fs.A_MODE]), "drwxr-xr-x")
        self.assertEqual(entry[fs.A_UID], 1001)
        self.assertEqual(entry[fs.A_GID], 1001)
