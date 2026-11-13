# ABOUTME: Tests for the find command (cowrie/commands/find.py).
# ABOUTME: Covers symlink handling, which must list links without following them.
# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellFindCommandTests(unittest.TestCase):
    """Test for cowrie/commands/find.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_find_does_not_descend_into_symlinked_directory(self) -> None:
        # /bin links to usr/bin, so following it would also find /bin/dash
        self.proto.lineReceived(b"find / -maxdepth 3 -name dash\n")
        self.assertEqual(self.tr.value(), b"/usr/bin/dash\n" + PROMPT)

    def test_find_lists_broken_symlink(self) -> None:
        # /proc/1/root has an empty target, which the filesystem treats as broken
        self.proto.lineReceived(b"find /proc/1 -maxdepth 1 -name root\n")
        self.assertEqual(self.tr.value(), b"/proc/1/root\n" + PROMPT)

    def test_find_type_d_does_not_match_symlink_to_directory(self) -> None:
        # /bin is a link to usr/bin
        self.proto.lineReceived(b"find / -maxdepth 1 -type d -name bin\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_find_type_f_does_not_match_symlink_to_file(self) -> None:
        # /proc/1/exe is a link to usr/bin/dash
        self.proto.lineReceived(b"find /proc/1 -maxdepth 1 -type f -name exe\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_find_whole_filesystem_finishes(self) -> None:
        # the default filesystem has links back to / under /proc
        self.proto.lineReceived(b"find / -name compose.yaml\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_find_resolves_paths_once_per_start_point(self) -> None:
        # find runs in the reactor thread, so a walk that looks up every
        # entry's path from / again stalls all sessions for over a second
        with mock.patch.object(
            self.proto.fs, "getfile", wraps=self.proto.fs.getfile
        ) as getfile:
            self.proto.lineReceived(b"find / -name compose.yaml\n")
        self.assertEqual(self.tr.value(), PROMPT)
        self.assertLess(getfile.call_count, 10)

    def test_find_follows_symlink_given_as_start_path(self) -> None:
        # /bin is a link to usr/bin
        self.proto.lineReceived(b"find /bin -maxdepth 1 -name dash\n")
        self.assertEqual(self.tr.value(), b"/bin/dash\n" + PROMPT)
