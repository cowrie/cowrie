# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The mysql output plugin must survive exceptions with unusual args
# ABOUTME: and record failed downloads with SQL NULL, not the string "NULL".

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from typing import Any
from unittest.mock import Mock, patch

from twisted.internet import defer
from twisted.python.failure import Failure

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import mysql.connector  # noqa: F401
except ImportError:
    # The driver is an optional dependency; stub it so the plugin imports.
    _mysql = types.ModuleType("mysql")
    _connector = types.ModuleType("mysql.connector")
    _connector.Error = type("Error", (Exception,), {})  # type: ignore[attr-defined]
    _connector.errorcode = types.SimpleNamespace(  # type: ignore[attr-defined]
        CR_CONN_HOST_ERROR=2003,
        CR_SERVER_GONE_ERROR=2006,
        CR_SERVER_LOST=2013,
        ER_LOCK_DEADLOCK=1213,
    )
    _mysql.connector = _connector  # type: ignore[attr-defined]
    sys.modules["mysql"] = _mysql
    sys.modules["mysql.connector"] = _connector

from cowrie.output import mysql as mysql_output


def _make() -> Any:
    """Construct the plugin without running its config-reading start()."""
    with patch.object(mysql_output.Output, "start", lambda self: None):
        return mysql_output.Output()


class OutputMysqlHardeningTests(unittest.TestCase):
    def test_start_failure_with_argless_exception_is_logged(self) -> None:
        """A pool construction error without two args must not raise IndexError."""
        out = _make()
        config = Mock()
        config.getboolean.return_value = False
        config.getint.return_value = 3306
        config.get.return_value = "example.invalid"
        with (
            patch.object(mysql_output, "CowrieConfig", config),
            patch.object(
                mysql_output,
                "ReconnectingConnectionPool",
                side_effect=TypeError(),
            ),
        ):
            out.start()

    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never created the pool."""
        out = _make()
        out.stop()

    def test_sqlerror_with_empty_args(self) -> None:
        """An errback whose exception has no args must not raise IndexError."""
        out = _make()
        out.sqlerror(Failure(Exception()))

    def test_sqlerror_with_schema_error(self) -> None:
        out = _make()
        out.sqlerror(Failure(Exception(1146, "Table 'auth' doesn't exist")))

    def test_failed_download_records_sql_null(self) -> None:
        """file_download.failed must store NULL, not the string 'NULL'."""
        out = _make()
        out.db = Mock()
        out.db.runQuery.return_value = defer.succeed(None)
        out.write(
            {
                "eventid": "cowrie.session.file_download.failed",
                "session": "s1",
                "time": 1234567890,
                "url": "http://example.invalid/x",
            }
        )
        args = out.db.runQuery.call_args[0][1]
        self.assertEqual(args[-2:], (None, None))


if __name__ == "__main__":
    unittest.main()
