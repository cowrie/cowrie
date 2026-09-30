# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: last must show a wtmp that began no later than the session it lists,
# ABOUTME: at the emulated boot time, with util-linux's space-padded dates.

from __future__ import annotations

import os
import time
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


def util_linux_date(stamp: float, seconds: bool) -> str:
    t = time.localtime(stamp)
    text = time.strftime("%a %b ", t) + f"{t.tm_mday:2d}" + time.strftime(" %H:%M", t)
    if seconds:
        text += time.strftime(":%S %Y", t)
    return text


class LastTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_wtmp_begins_at_boot_not_after_the_login(self) -> None:
        # A login shortly after midnight; cowrie started two hours before.
        midnight = time.mktime((2026, 9, 5, 0, 0, 0, 0, 0, -1))
        self.proto.logintime = midnight + 13
        self.proto.getProtoTransport().factory.starttime = midnight - 7200
        boot = self.proto.boot_time()

        self.proto.lineReceived(b"last\n")

        self.assertEqual(
            self.tr.value().decode(),
            f"root     pts/0        {self.proto.clientIP:16s} "
            f"{util_linux_date(midnight + 13, False)}   still logged in\n"
            "\n"
            f"wtmp begins {util_linux_date(boot, True)}\n" + PROMPT.decode(),
        )


if __name__ == "__main__":
    unittest.main()
