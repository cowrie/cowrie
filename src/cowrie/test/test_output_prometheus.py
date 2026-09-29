# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The prometheus output plugin labels its metrics with the hostname
# ABOUTME: configured when it starts, not the one configured at import time.

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from cowrie.core.config import CowrieConfig

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import prometheus_client  # noqa: F401
except ImportError:
    # The client is an optional dependency; stub it so the plugin imports.
    sys.modules["prometheus_client"] = MagicMock()

from cowrie.output import prometheus


class PrometheusHostLabelTests(unittest.TestCase):
    def test_host_label_set_after_import(self) -> None:
        old = CowrieConfig.get("honeypot", "hostname", fallback=None)
        CowrieConfig.set("honeypot", "hostname", "sensor-after-import")
        if old is None:
            self.addCleanup(CowrieConfig.remove_option, "honeypot", "hostname")
        else:
            self.addCleanup(CowrieConfig.set, "honeypot", "hostname", old)

        with patch.object(prometheus, "start_http_server"):
            out = prometheus.Output()
        self.addCleanup(out.stop)

        with patch.object(prometheus, "commands_total") as commands_total:
            out.write({"eventid": "cowrie.command.input", "input": "ls -la"})

        commands_total.labels.assert_called_once_with("ls", "sensor-after-import")


if __name__ == "__main__":
    unittest.main()
