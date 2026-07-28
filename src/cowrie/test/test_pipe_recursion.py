# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: A long pipeline (a | b | c | ...) must not exhaust the Python stack.
# ABOUTME: Guards issue #40352 where each pipe stage recursed call_command.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class LongPipelineTests(unittest.TestCase):
    """A pipeline of many stages must run flat, not recurse per stage."""

    def test_long_pipeline_does_not_crash(self) -> None:
        proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        tr.clear()

        # Far more stages than the recursive design could handle before hitting
        # Python's default recursion limit; the data passes through each `cat`.
        line = ("echo hi" + " | cat" * 600 + "\n").encode()
        proto.lineReceived(line)

        self.assertEqual(tr.value(), b"hi\n" + PROMPT)
        # The whole pipeline drained: nothing left parked on the stack.
        self.assertEqual(len(proto.cmdstack), 1)


if __name__ == "__main__":
    unittest.main()
