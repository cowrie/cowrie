# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The sqlite output plugin must survive a failed pool construction
# ABOUTME: and record failed downloads with SQL NULL, not the string "NULL".

from __future__ import annotations

import os
import sqlite3
import unittest
from typing import Any
from unittest.mock import Mock, patch

from twisted.enterprise import adbapi
from twisted.internet import defer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.output import sqlite as sqlite_output


def _make() -> Any:
    """Construct the plugin without running its config-reading start()."""
    with patch.object(sqlite_output.Output, "start", lambda self: None):
        return sqlite_output.Output()


class OutputSqliteHardeningTests(unittest.TestCase):
    def test_start_failure_is_logged(self) -> None:
        """A pool construction error must not raise from start() itself."""
        out = _make()
        config = Mock()
        config.get.return_value = "/nonexistent/cowrie.db"
        with (
            patch.object(sqlite_output, "CowrieConfig", config),
            patch.object(
                adbapi,
                "ConnectionPool",
                side_effect=sqlite3.OperationalError(),
            ),
        ):
            out.start()

    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never created the pool."""
        out = _make()
        out.stop()

    def test_failed_download_records_sql_null(self) -> None:
        """file_download.failed must store NULL, not the string 'NULL'."""
        out = _make()
        out.db = Mock()
        out.db.runQuery.return_value = defer.succeed(None)
        out.write(
            {
                "eventid": "cowrie.session.file_download.failed",
                "session": "s1",
                "timestamp": "2026-01-01T00:00:00.000000Z",
                "url": "http://example.invalid/x",
            }
        )
        args = out.db.runQuery.call_args[0][1]
        self.assertEqual(args[-2:], (None, None))


if __name__ == "__main__":
    unittest.main()
