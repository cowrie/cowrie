# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the kafka output plugin: reactor gating, and the
# ABOUTME: shutdown flush that delivers pending events before the loop stops.

from __future__ import annotations

import asyncio
import os
import unittest

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class LogRecorder:
    """Captures Logger.error calls so tests can assert on error output."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


def make_output():
    from cowrie.output.kafka import Output

    output = Output()
    output._log = LogRecorder()
    return output


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


class KafkaShutdownFlushTests(unittest.TestCase):
    """The before-shutdown flush must deliver pending sends and stop the
    producer while the asyncio loop still runs, bounded by a timeout so a
    dead broker cannot hang shutdown."""

    def test_flush_is_noop_without_a_producer(self) -> None:
        output = make_output()
        self.assertIsNone(output._flush())

    def test_flush_waits_for_pending_sends_then_stops_producer(self) -> None:
        output = make_output()
        calls: list[str] = []

        class FakeProducer:
            async def stop(self) -> None:
                calls.append("stop")

        async def scenario() -> None:
            output._producer = FakeProducer()

            async def pending_send() -> None:
                await asyncio.sleep(0)
                calls.append("send")

            task = asyncio.ensure_future(pending_send())
            output._background_tasks.add(task)
            task.add_done_callback(output._background_tasks.discard)

            await output._shutdown_flush()

        asyncio.run(scenario())
        self.assertEqual(calls, ["send", "stop"])
        self.assertIsNone(output._producer)
        self.assertEqual(output._log.errors, [])

    def test_flush_gives_up_when_the_broker_hangs(self) -> None:
        output = make_output()

        class HangingProducer:
            async def stop(self) -> None:
                await asyncio.Event().wait()

        async def scenario() -> None:
            output._producer = HangingProducer()
            output.FLUSH_TIMEOUT = 0.05
            await output._shutdown_flush()

        asyncio.run(scenario())
        self.assertIsNone(output._producer)
        self.assertEqual(len(output._log.errors), 1)
        self.assertIn("flush", output._log.errors[0])
