# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Generated /proc files must read like a live kernel's and agree with
# ABOUTME: the commands that report the same facts (uptime, nproc).

from __future__ import annotations

import os
import re
import unittest

from cowrie.core.config import CowrieConfig
from cowrie.shell import protocol
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


class BootOffsetTests(unittest.TestCase):
    """The emulated machine booted before cowrie started, so a restarted
    honeypot does not report a few seconds of uptime."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.getProtoTransport().factory.starttime = 1_000_000.0
        protocol.boot_offset.cache_clear()
        self.addCleanup(protocol.boot_offset.cache_clear)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_configured_offset(self) -> None:
        CowrieConfig.set("honeypot", "boot_offset", "86400")
        self.addCleanup(CowrieConfig.remove_option, "honeypot", "boot_offset")
        self.assertEqual(self.proto.boot_time(), 1_000_000.0 - 86400)

    def test_default_offset_is_between_one_and_ninety_days(self) -> None:
        offset = 1_000_000.0 - self.proto.boot_time()
        self.assertGreaterEqual(offset, 86400)
        self.assertLessEqual(offset, 90 * 86400)

    def test_offset_is_the_same_for_every_session(self) -> None:
        other = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        other.makeConnection(FakeTransport("", "31338"))
        self.addCleanup(other.connectionLost)
        other.getProtoTransport().factory.starttime = 1_000_000.0
        self.assertEqual(other.boot_time(), self.proto.boot_time())


if __name__ == "__main__":
    unittest.main()
