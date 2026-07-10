# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the jsonlog output plugin: a daily log rotation must
# ABOUTME: never split a serialized event across two files.

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class JsonlogRotationTests(unittest.TestCase):
    """Every line in every rotated file must be one complete JSON object."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        os.environ["COWRIE_HONEYPOT_LOGTYPE"] = "rotating"
        os.environ["COWRIE_OUTPUT_JSONLOG_LOGFILE"] = str(Path(self.dir, "cowrie.json"))

    def tearDown(self) -> None:
        del os.environ["COWRIE_HONEYPOT_LOGTYPE"]
        del os.environ["COWRIE_OUTPUT_JSONLOG_LOGFILE"]
        shutil.rmtree(self.dir)

    def test_rotation_never_splits_an_event(self) -> None:
        from cowrie.output.jsonlog import Output

        output = Output()  # Output.__init__ runs start(), opening the logfile
        output.write({"eventid": "cowrie.test", "msg": "first"})

        # Simulate midnight passing while an event is being written: after
        # any chunk reaches the file, the date flips, so a serialization
        # that writes in multiple chunks rotates between them and splits
        # the line across the old and new file.
        logfile = output.outfile
        original_write = logfile.write

        def write_then_midnight(data: str) -> None:
            original_write(data)
            logfile.lastDate = (1970, 1, 1)

        logfile.write = write_then_midnight
        output.write({"eventid": "cowrie.test", "msg": "second"})
        output.write({"eventid": "cowrie.test", "msg": "third"})
        output.stop()
        logfile.close()

        # Dated (rotated) files hold the older events; the bare logfile is
        # the current one, so it reads last.
        paths = sorted(
            Path(self.dir).iterdir(), key=lambda p: (p.name == "cowrie.json", p.name)
        )
        events = []
        for path in paths:
            for line in path.read_text().splitlines():
                events.append(json.loads(line))
        self.assertEqual([e["msg"] for e in events], ["first", "second", "third"])
