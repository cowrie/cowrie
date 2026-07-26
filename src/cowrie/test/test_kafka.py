# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the kafka output plugin: it requires the asyncio
# ABOUTME: reactor and must disable itself under any other reactor.

from __future__ import annotations

import os
import unittest

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class KafkaReactorGateTests(unittest.TestCase):
    """Under a non-asyncio reactor the plugin must disable itself:
    write() must not schedule asyncio tasks and stop() must be a no-op."""

    def test_disabled_under_default_reactor(self) -> None:
        from cowrie.output.kafka import Output

        output = Output()
        self.assertFalse(output._enabled)

        # A write on a disabled plugin must not create tasks on an
        # asyncio loop that will never run.
        output.write({"eventid": "cowrie.test", "msg": "hello"})
        self.assertEqual(output._background_tasks, set())

        output.stop()
