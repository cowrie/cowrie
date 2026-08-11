# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: finger reads /etc/passwd, which an attacker can overwrite over
# ABOUTME: SFTP, so a malformed record must not crash the session.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "

WELL_FORMED = (
    b"root:x:0:0:root:/root:/bin/bash\nphil:x:1000:1000:Phil:/home/phil:/bin/sh\n"
)


class ShellFingerCommandTests(unittest.TestCase):
    """Test for cowrie/commands/finger.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def _passwd(self, contents: bytes):
        return patch.object(self.proto.fs, "file_contents", return_value=contents)

    def test_lists_users(self) -> None:
        with self._passwd(WELL_FORMED):
            self.proto.lineReceived(b"finger\n")

        out = self.tr.value()
        self.assertIn(b"root", out)
        self.assertIn(b"phil", out)
        self.assertTrue(out.endswith(PROMPT))

    def test_shows_one_user(self) -> None:
        with self._passwd(WELL_FORMED):
            self.proto.lineReceived(b"finger phil\n")

        out = self.tr.value()
        self.assertIn(b"Login: phil", out)
        self.assertIn(b"/home/phil", out)
        self.assertIn(b"/bin/sh", out)

    def test_truncated_record_does_not_crash(self) -> None:
        """A line without all seven fields must be skipped, not throw off the
        parse of every following line."""
        with self._passwd(b"truncated:x:0\n" + WELL_FORMED):
            self.proto.lineReceived(b"finger\n")

        out = self.tr.value()
        self.assertTrue(out.endswith(PROMPT))
        self.assertIn(b"root", out)
        self.assertIn(b"phil", out)

    def test_named_user_after_truncated_record(self) -> None:
        with self._passwd(b"truncated:x:0\n" + WELL_FORMED):
            self.proto.lineReceived(b"finger phil\n")

        self.assertIn(b"Login: phil", self.tr.value())

    def test_garbage_passwd_does_not_crash(self) -> None:
        with self._passwd(b"not a passwd file at all\n\n:::\n"):
            self.proto.lineReceived(b"finger\n")

        self.assertTrue(self.tr.value().endswith(PROMPT))


if __name__ == "__main__":
    unittest.main()
