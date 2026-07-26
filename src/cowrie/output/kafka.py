# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import asyncio
import json
from typing import Any, cast

from twisted.internet import asyncioreactor, reactor
from twisted.internet.defer import Deferred
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

    # How long shutdown may wait for pending events to reach the broker.
    FLUSH_TIMEOUT: float = 5.0

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

        # Flush before reactor shutdown: Twisted waits for Deferreds from
        # "before" shutdown triggers while the asyncio loop still runs. By
        # the time the base class calls stop() (after shutdown) the loop no
        # longer executes tasks, so nothing can be delivered there.
        reactor.addSystemEventTrigger("before", "shutdown", self._flush)

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

    def _flush(self) -> Deferred[None] | None:
        if self._producer is None:
            return None
        return Deferred.fromFuture(asyncio.ensure_future(self._shutdown_flush()))

    async def _shutdown_flush(self) -> None:
        """
        Wait for pending sends, then stop the producer, which flushes its
        internal buffer. Bounded so an unreachable broker can't hang shutdown.
        """
        producer = self._producer

        async def _drain() -> None:
            if self._background_tasks:
                await asyncio.gather(*self._background_tasks, return_exceptions=True)
            await producer.stop()

        try:
            await asyncio.wait_for(_drain(), timeout=self.FLUSH_TIMEOUT)
        except Exception as e:
            self._log.error(f"kafka: Can't flush on shutdown: {e}")
        finally:
            self._producer = None

    def stop(self) -> None:
        """
        Producer teardown happens in _flush before reactor shutdown; once
        this runs (after shutdown) the asyncio loop no longer executes tasks.
        """

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
