# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import asyncio
import json

from aiokafka import AIOKafkaProducer
from twisted.internet import reactor
from twisted.logger import Logger

import cowrie.core.output
import cowrie.python.logfile
from cowrie.core.config import CowrieConfig


class NotAsyncioError(Exception):
    def __init__(self):
        super().__init__(
            "asyncio loop is not running. This plugin requires Twisted to run an asyncio reactor."
        )


class Output(cowrie.core.output.Output):
    """
    Kafka output
    """

    _log = Logger()

    def start(self):
        self._host = CowrieConfig.get("output_kafka", "host", fallback="127.0.0.1")
        self._port = CowrieConfig.getint("output_kafka", "port", fallback=9092)
        self._topic = CowrieConfig.get("output_kafka", "topic", fallback="cowrie")

        # References to pending asyncio tasks.
        # https://docs.astral.sh/ruff/rules/asyncio-dangling-task/
        self._background_tasks = set()

        # Initialization must be delayed - it requires an asyncio loop to be running, which only
        # happens after the reactor starts.
        self._producer = None
        self._ready = asyncio.Event()

        # Start initialization when the asyncio reactor is already running
        reactor.callLater(0, self._start)

    def _start(self):
        """
        Initialize the Kafka producer in a background task.
        Must be called when the asyncio loop is already running.
        """
        self._assert_asyncio_running()

        async def _do_start():
            try:
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=f"{self._host}:{self._port}"
                )
                await self._producer.start()
            except Exception as e:
                self._log.error(f"kafka: Can't connect: {e}")
            finally:
                # Set the event even in case of failure to unblock waiting tasks.
                # They'll fail anyway, but at least they won't build up.
                self._ready.set()

        task = asyncio.ensure_future(_do_start())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _assert_asyncio_running(self):
        try:
            asyncio.get_running_loop()
        except RuntimeError as e:
            raise NotAsyncioError() from e

    def stop(self):
        if not self._producer:
            return

        async def _do_stop():
            await self._producer.stop()

        task = asyncio.ensure_future(_do_stop())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def write(self, event):
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]

        task = asyncio.ensure_future(self._write(json.dumps(event).encode("utf-8")))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _write(self, content):
        try:
            await self._ready.wait()
            await self._producer.send_and_wait(self._topic, content)
        except Exception as e:
            self._log.error(f"kafka: Can't write: {e}")
