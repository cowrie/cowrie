# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

from twisted.internet import asyncioreactor, reactor
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

try:
    from aiokafka import AIOKafkaProducer
except ImportError:
    AIOKafkaProducer = None


class Output(cowrie.core.output.Output):
    """
    Kafka output.

    aiokafka drives Kafka I/O on the asyncio event loop, so this plugin
    only works when Twisted runs the asyncio reactor
    (cowrie start -- --reactor=asyncio). Under any other reactor the
    plugin disables itself with an error message.
    """

    _log = Logger()

    def start(self) -> None:
        self._enabled: bool = False
        # AIOKafkaProducer, or None until the producer has connected
        # (aiokafka is untyped for mypy, so no annotation with it).
        self._producer: Any = None
        # References to pending asyncio tasks.
        # https://docs.astral.sh/ruff/rules/asyncio-dangling-task/
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._ready = asyncio.Event()

        # The reactor's static type is an interface; widen it so mypy
        # accepts the concrete-class check.
        if not isinstance(
            cast("object", reactor), asyncioreactor.AsyncioSelectorReactor
        ):
            self._log.error(
                "kafka: this plugin requires the asyncio reactor,"
                " start cowrie with: cowrie start -- --reactor=asyncio."
                " Kafka output disabled."
            )
            return

        if AIOKafkaProducer is None:
            self._log.error("kafka: aiokafka is not installed. Kafka output disabled.")
            return

        self._host: str = CowrieConfig.get("output_kafka", "host", fallback="127.0.0.1")
        self._port: int = CowrieConfig.getint("output_kafka", "port", fallback=9092)
        self._topic: str = CowrieConfig.get("output_kafka", "topic", fallback="cowrie")

        self._enabled = True

        # Producer initialization must be delayed - it requires an asyncio
        # loop to be running, which only happens after the reactor starts.
        reactor.callLater(0, self._start)

    def _start(self) -> None:
        """
        Initialize the Kafka producer in a background task.
        Must be called when the asyncio loop is already running.
        """

        async def _do_start() -> None:
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

    def stop(self) -> None:
        producer = self._producer
        if not producer:
            return

        async def _do_stop() -> None:
            await producer.stop()

        task = asyncio.ensure_future(_do_stop())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def write(self, event: dict[str, Any]) -> None:
        if not self._enabled:
            return

        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]

        task = asyncio.ensure_future(self._write(json.dumps(event).encode("utf-8")))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _write(self, content: bytes) -> None:
        await self._ready.wait()
        if self._producer is None:
            self._log.error("kafka: Can't write: not connected")
            return
        try:
            await self._producer.send_and_wait(self._topic, content)
        except Exception as e:
            self._log.error(f"kafka: Can't write: {e}")
