# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: lscpu must describe the same CPU as /proc/cpuinfo, in the indented
# ABOUTME: layout util-linux 2.38+ prints; scripts cross-check the two.

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


class LscpuTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def lscpu_fields(self) -> dict[str, str]:
        self.proto.lineReceived(b"lscpu\n")
        text = self.tr.value()[: -len(PROMPT)].decode()
        fields = {}
        for line in text.splitlines():
            if ":" in line:
                label, value = line.split(":", 1)
                fields[label.strip()] = value.strip()
        return fields

    def cpuinfo_fields(self) -> tuple[dict[str, str], int]:
        text = self.proto.fs.file_contents("/proc/cpuinfo").decode()
        first = text.split("\n\n")[0]
        fields = {}
        for line in first.splitlines():
            if ":" in line:
                label, value = line.split(":", 1)
                fields[label.strip()] = value.strip()
        return fields, len(re.findall(r"^processor\s*:", text, re.MULTILINE))

    def test_agrees_with_proc_cpuinfo(self) -> None:
        lscpu = self.lscpu_fields()
        cpuinfo, processors = self.cpuinfo_fields()
        self.assertEqual(lscpu["Model name"], cpuinfo["model name"])
        self.assertEqual(lscpu["Vendor ID"], cpuinfo["vendor_id"])
        self.assertEqual(lscpu["CPU family"], cpuinfo["cpu family"])
        self.assertEqual(lscpu["Model"], cpuinfo["model"])
        self.assertEqual(lscpu["Stepping"], cpuinfo["stepping"])
        self.assertEqual(lscpu["BogoMIPS"], cpuinfo["bogomips"])
        self.assertEqual(lscpu["Flags"], cpuinfo["flags"])
        self.assertEqual(lscpu["Address sizes"], cpuinfo["address sizes"])
        self.assertEqual(int(lscpu["CPU(s)"]), processors)

    def test_model_name_is_indented_under_vendor(self) -> None:
        """util-linux 2.38+ nests the model under the vendor."""
        self.proto.lineReceived(b"lscpu\n")
        self.assertRegex(
            self.tr.value().decode(), r"\nVendor ID: +GenuineIntel\n  Model name: +"
        )


if __name__ == "__main__":
    unittest.main()
