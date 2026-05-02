from __future__ import annotations

import os
import re
import time
import unittest

from cowrie.shell.fs import HoneyPotFilesystem
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "
UPTIME_LINE = re.compile(rb"^\d+\.\d{2} \d+\.\d{2}\n")


class ProcUptimeTests(unittest.TestCase):
    """Regression test for cowrie/cowrie#1464."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_cat_proc_uptime_returns_two_floats(self) -> None:
        self.proto.lineReceived(b"cat /proc/uptime\n")
        out = self.tr.value()
        self.assertTrue(
            out.endswith(PROMPT),
            f"unexpected suffix: {out!r}",
        )
        body = out[: -len(PROMPT)]
        self.assertRegex(body, UPTIME_LINE)


class HoneyPotFilesystemUptimeAnchorTests(unittest.TestCase):
    """Verify /proc/uptime synthesis honours the process-start anchor."""

    def setUp(self) -> None:
        self._saved_anchor = HoneyPotFilesystem._process_starttime

    def tearDown(self) -> None:
        HoneyPotFilesystem._process_starttime = self._saved_anchor

    def test_anchor_drives_uptime(self) -> None:
        fs = FakeServer().fs
        HoneyPotFilesystem._process_starttime = time.time() - 12345.0
        body = fs.file_contents("/proc/uptime").decode()
        first = float(body.split()[0])
        self.assertGreaterEqual(first, 12345.0)
        self.assertLess(first, 12345.0 + 5.0)

    def test_anchor_unset_falls_back_to_zero(self) -> None:
        fs = FakeServer().fs
        HoneyPotFilesystem._process_starttime = None
        body = fs.file_contents("/proc/uptime").decode()
        self.assertRegex(body, r"^\d+\.\d{2} \d+\.\d{2}\n")
        first = float(body.split()[0])
        self.assertLess(first, 1.0)
