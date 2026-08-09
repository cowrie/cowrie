# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: A ttylog holds the raw bytes of a session, so converting one to
# ABOUTME: asciinema must not stop at the first byte that is not UTF-8.

from __future__ import annotations

import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from cowrie.scripts import asciinema


def _ttylog(*chunks: bytes) -> io.BytesIO:
    """A ttylog of one session writing these chunks, then closing."""
    out = b""
    for i, data in enumerate(chunks):
        out += struct.pack(
            "<iLiiLL",
            asciinema.OP_WRITE,
            1,  # tty
            len(data),
            asciinema.TYPE_OUTPUT,
            i,  # sec
            0,  # usec
        )
        out += data
    out += struct.pack("<iLiiLL", asciinema.OP_CLOSE, 1, 0, 0, len(chunks), 0)
    return io.BytesIO(out)


class PlaylogDecodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.outfile = str(Path(self.tmpdir) / "out.cast")

    def _convert(self, *chunks: bytes) -> dict:
        asciinema.playlog(_ttylog(*chunks), {"colorify": False, "output": self.outfile})
        with open(self.outfile) as f:
            return json.load(f)

    def test_plain_output_is_converted(self) -> None:
        log = self._convert(b"hello\n")

        self.assertEqual([entry[1] for entry in log["stdout"]], ["hello\r\n"])

    def test_non_utf8_byte_does_not_abort_the_conversion(self) -> None:
        """Binary program output, odd escape sequences and pasted junk are all
        ordinary in a real session."""
        log = self._convert(b"before\n", b"\xff\xfe", b"after\n")

        written = [entry[1] for entry in log["stdout"]]
        self.assertEqual(written[0], "before\r\n")
        self.assertEqual(written[2], "after\r\n")

    def test_non_utf8_byte_becomes_the_replacement_character(self) -> None:
        log = self._convert(b"a\xffb")

        self.assertEqual(log["stdout"][0][1], "a�b")


if __name__ == "__main__":
    unittest.main()
