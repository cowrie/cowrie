# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Generated /proc files must read like a live kernel's and agree with
# ABOUTME: the commands that report the same facts (uptime, nproc).

from __future__ import annotations

import os
import re
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ProcUptimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_proc_uptime_reports_seconds_since_boot(self) -> None:
        self.proto.lineReceived(b"cat /proc/uptime\n")
        output = self.tr.value()
        match = re.fullmatch(rb"(\d+\.\d\d) (\d+\.\d\d)\n" + re.escape(PROMPT), output)
        assert match is not None, output
        uptime, idle = float(match.group(1)), float(match.group(2))
        self.assertAlmostEqual(uptime, self.proto.uptime(), delta=2)
        # Idle time is summed over the CPUs, so it can exceed the uptime.
        self.assertGreater(idle, 0)


if __name__ == "__main__":
    unittest.main()
