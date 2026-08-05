# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts the tty log writer creates its log file even when the
# ABOUTME: configured tty log directory was removed after startup.

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from cowrie.core import ttylog


class TtylogOpenTests(unittest.TestCase):
    def test_open_creates_missing_directory(self) -> None:
        """ttylog_open() recreates a tty log directory removed after startup."""
        base = tempfile.mkdtemp(prefix="cowrie_ttylog_")
        logfile = os.path.join(base, "tty", "20260728", "abcdef")

        ttylog.ttylog_open(logfile, 1234.5)

        self.assertTrue(os.path.exists(logfile))
        with open(logfile, "rb") as f:
            op = struct.unpack(
                ttylog.TTYSTRUCT, f.read(struct.calcsize(ttylog.TTYSTRUCT))
            )[0]
        self.assertEqual(op, ttylog.OP_OPEN)
