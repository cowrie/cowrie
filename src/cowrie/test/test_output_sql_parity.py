# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The mysql, postgresql and sqlite output plugins are ports of one
# ABOUTME: another; this pins the events all three must store to a database.

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from typing import Any
from unittest.mock import Mock, patch

from twisted.internet import defer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def _stub_drivers() -> None:
    """The database drivers are optional dependencies; stub the missing ones
    so the plugins import and their SQL can be inspected."""
    try:
        import mysql.connector  # noqa: F401
    except ImportError:
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

    try:
        import psycopg2  # noqa: F401
    except ImportError:
        _psycopg2 = types.ModuleType("psycopg2")
        _psycopg2.Error = type("Error", (Exception,), {})  # type: ignore[attr-defined]
        _psycopg2.OperationalError = type(  # type: ignore[attr-defined]
            "OperationalError", (Exception,), {}
        )
        _extras = types.ModuleType("psycopg2.extras")
        _psycopg2.extras = _extras  # type: ignore[attr-defined]
        sys.modules["psycopg2"] = _psycopg2
        sys.modules["psycopg2.extras"] = _extras


_stub_drivers()

from cowrie.output import mysql as mysql_output  # noqa: E402
from cowrie.output import postgresql as postgresql_output  # noqa: E402
from cowrie.output import sqlite as sqlite_output  # noqa: E402

PLUGINS = {
    "mysql": mysql_output,
    "postgresql": postgresql_output,
    "sqlite": sqlite_output,
}

# One event per branch, carrying every field any of the three plugins reads.
# 'time' is what mysql and postgresql pass to their timestamp conversion;
# 'timestamp' is what sqlite stores directly.
COMMON = {
    "session": "s1",
    "time": 1767225600.0,
    "timestamp": "2026-01-01T00:00:00.000000Z",
    "sensor": "unittest",
}

EVENTS: dict[str, dict[str, Any]] = {
    "cowrie.session.connect": {
        **COMMON,
        "src_ip": "192.0.2.1",
        "src_port": 4444,
        "dst_ip": "198.51.100.1",
        "dst_port": 2222,
        "protocol": "ssh",
    },
    "cowrie.login.success": {**COMMON, "username": "root", "password": "toor"},
    "cowrie.login.failed": {**COMMON, "username": "root", "password": "hunter2"},
    "cowrie.session.params": {**COMMON, "arch": "linux-x64-lsb"},
    "cowrie.command.input": {**COMMON, "input": "uname -a"},
    "cowrie.command.failed": {**COMMON, "input": "nosuchcmd"},
    "cowrie.session.file_download": {
        **COMMON,
        "url": "http://example.invalid/x",
        "outfile": "/tmp/x",
        "shasum": "a" * 64,
    },
    "cowrie.session.file_download.failed": {
        **COMMON,
        "url": "http://example.invalid/x",
    },
    "cowrie.session.file_upload": {
        **COMMON,
        "outfile": "/tmp/x",
        "shasum": "b" * 64,
        "filename": "payload.bin",
    },
    "cowrie.session.input": {**COMMON, "realm": "shell", "input": "id"},
    "cowrie.client.version": {**COMMON, "version": "SSH-2.0-OpenSSH_9.6"},
    "cowrie.client.size": {**COMMON, "width": 80, "height": 24},
    "cowrie.session.closed": {**COMMON, "duration": 12.5},
    "cowrie.log.closed": {**COMMON, "ttylog": "log/tty/x.log", "size": 42},
    "cowrie.client.fingerprint": {**COMMON, "username": "root", "fingerprint": "aa:bb"},
}


def _plugin(module: Any) -> Any:
    """Construct a plugin without running its config-reading start()."""
    with patch.object(module.Output, "start", lambda self: None):
        out = module.Output()
    out.db = Mock()
    # Enough shape for the "look up the id, else insert" branches.
    out.db.runQuery.return_value = defer.succeed([(1,)])
    out.db.runOperation.return_value = defer.succeed(None)
    out.db.runInteraction.return_value = defer.succeed(1)
    return out


def _statements(out: Any) -> list[str]:
    calls = out.db.runQuery.call_args_list + out.db.runOperation.call_args_list
    return [call[0][0] for call in calls if call[0]]


class SqlOutputParityTests(unittest.TestCase):
    """Every event one plugin stores, all three must store."""

    def test_every_plugin_stores_every_event(self) -> None:
        missing: list[str] = []

        for eventid, payload in EVENTS.items():
            for name, module in PLUGINS.items():
                out = _plugin(module)
                out.write({"eventid": eventid, **payload})
                if not _statements(out):
                    missing.append(f"{name} drops {eventid}")

        self.assertEqual(missing, [], "\n".join(missing))

    def test_plugins_write_to_the_same_tables(self) -> None:
        """A port that reaches a different table records different history."""
        divergent: list[str] = []

        for eventid, payload in EVENTS.items():
            tables: dict[str, set[str]] = {}
            for name, module in PLUGINS.items():
                out = _plugin(module)
                out.write({"eventid": eventid, **payload})
                tables[name] = {
                    word.strip("`\"';")
                    for statement in _statements(out)
                    for keyword, word in zip(
                        statement.split(), statement.split()[1:], strict=False
                    )
                    if keyword.upper() in ("INTO", "FROM", "UPDATE")
                }

            if len(set(map(frozenset, tables.values()))) > 1:
                divergent.append(f"{eventid}: {tables}")

        self.assertEqual(divergent, [], "\n".join(divergent))


if __name__ == "__main__":
    unittest.main()
