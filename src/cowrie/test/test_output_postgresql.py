# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The postgresql output plugin must survive connection errors with
# ABOUTME: unusual args and shut down cleanly when start() never connected.

from __future__ import annotations

import os
import sys
import types
import unittest
from typing import Any
from unittest.mock import Mock, patch

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import psycopg2  # noqa: F401
except ImportError:
    # The driver is an optional dependency; stub it so the plugin imports.
    _psycopg2 = types.ModuleType("psycopg2")
    _psycopg2.OperationalError = type(  # type: ignore[attr-defined]
        "OperationalError", (Exception,), {}
    )
    sys.modules["psycopg2"] = _psycopg2

from cowrie.output import postgresql


def _make() -> Any:
    """Construct the plugin without running its config-reading start()."""
    with patch.object(postgresql.Output, "start", lambda self: None):
        return postgresql.Output()


class OutputPostgresqlHardeningTests(unittest.TestCase):
    def test_start_failure_with_argless_exception_is_logged(self) -> None:
        """A pool construction error without two args must not raise IndexError."""
        out = _make()
        config = Mock()
        config.getboolean.return_value = False
        config.getint.return_value = 5432
        config.get.return_value = "example.invalid"
        with (
            patch.object(postgresql, "CowrieConfig", config),
            patch.object(
                postgresql,
                "ReconnectingPostgreSQLConnectionPool",
                side_effect=TypeError(),
            ),
        ):
            out.start()

    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never created the pool."""
        out = _make()
        out.stop()


if __name__ == "__main__":
    unittest.main()
