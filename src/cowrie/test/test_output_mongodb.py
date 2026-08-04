# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The mongodb output plugin must shut down cleanly when start()
# ABOUTME: never connected to the database.

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from typing import Any
from unittest.mock import patch

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import pymongo  # noqa: F401
except ImportError:
    # The driver is an optional dependency; stub it so the plugin imports.
    sys.modules["pymongo"] = types.ModuleType("pymongo")

from cowrie.output import mongodb


def _make() -> Any:
    """Construct the plugin without running its config-reading start()."""
    with patch.object(mongodb.Output, "start", lambda self: None):
        return mongodb.Output()


class OutputMongodbHardeningTests(unittest.TestCase):
    def test_stop_without_successful_start(self) -> None:
        """stop() must not raise when start() never connected."""
        out = _make()
        out.stop()


if __name__ == "__main__":
    unittest.main()
