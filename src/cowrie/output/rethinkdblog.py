# SPDX-FileCopyrightText: 2016 Dmitry Merkurev <didika914@gmail.com>
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: RethinkDB output plugin: inserts each event into a table through the
# ABOUTME: driver's Twisted mode, queueing events and reconnecting while the server is away.

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from rethinkdb import RethinkDB
from rethinkdb.errors import ReqlOpFailedError
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from twisted.internet.interfaces import IDelayedCall
    from twisted.python.failure import Failure


def iso8601_to_timestamp(value):
    """Unix timestamp for an event timestamp.

    The trailing Z marks the value as UTC, so it is read as UTC: the instant
    stored must not shift with the honeypot host's own timezone.
    """
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=UTC).timestamp()


RETHINK_DB_SEGMENT = "output_rethinkdblog"


class Output(cowrie.core.output.Output):
    """
    Keeps one connection to RethinkDB, retries with backoff when it goes
    away, and queues events in the meantime so that write() never blocks
    and events are inserted in order.
    """

    _log = Logger()

    initial_delay = 1.0
    max_delay = 60.0
    # Events kept while the server is unreachable. The oldest ones go
    # first, so a server that is down for a long time can't grow the
    # honeypot's memory without bound.
    max_queued = 10000

    # rethinkdb ships no type information, so its objects are typed Any.
    connection: Any = None
    retry: IDelayedCall | None = None

    def start(self) -> None:
        self.host = CowrieConfig.get(RETHINK_DB_SEGMENT, "host")
        self.port = CowrieConfig.getint(RETHINK_DB_SEGMENT, "port")
        self.db = CowrieConfig.get(RETHINK_DB_SEGMENT, "db")
        self.table = CowrieConfig.get(RETHINK_DB_SEGMENT, "table")
        self.password = CowrieConfig.get(RETHINK_DB_SEGMENT, "password", raw=True)

        # A private driver instance: set_loop_type() changes how every
        # connection made through that instance does its I/O.
        self.r: Any = RethinkDB()
        self.r.set_loop_type("twisted")
        self.stopped = False
        self.delay = self.initial_delay
        self.queue: deque[dict[str, Any]] = deque(maxlen=self.max_queued)
        self.dropped: int = 0
        self._connect()

    def _connect(self) -> None:
        self.retry = None
        d = self._open()
        d.addCallbacks(self._connected, self._connect_failed)

    @inlineCallbacks
    def _open(self) -> Any:
        connection = yield self.r.connect(
            host=self.host, port=self.port, db=self.db, password=self.password
        )
        try:
            for query in (
                self.r.db_create(self.db),
                self.r.db(self.db).table_create(self.table),
            ):
                try:
                    yield query.run(connection)
                except ReqlOpFailedError:
                    pass  # it already exists
            # A server that has just started accepts connections before
            # its tables can take writes.
            yield self.r.db(self.db).table(self.table).wait().run(connection)
        except Exception:
            connection.close(noreply_wait=False)
            raise
        return connection

    def _connected(self, connection: Any) -> None:
        if self.stopped:
            connection.close(noreply_wait=False)
            return
        self.connection = connection
        self.delay = self.initial_delay
        self._log.info("Connected to RethinkDB")
        if self.dropped:
            self._log.warn(
                "rethinkdblog: dropped {dropped} events while disconnected",
                dropped=self.dropped,
            )
            self.dropped = 0
        while self.queue:
            self._insert(self.queue.popleft())

    def _connect_failed(self, failure: Failure) -> None:
        if self.stopped:
            return
        self._log.warn(
            "rethinkdblog: could not connect to RethinkDB, retrying in {delay}s: {reason}",
            delay=self.delay,
            reason=failure.getErrorMessage(),
        )
        self.retry = reactor.callLater(self.delay, self._connect)
        self.delay = min(self.delay * 2, self.max_delay)

    def _insert(self, event: dict[str, Any]) -> None:
        d = self.r.table(self.table).insert(event).run(self.connection)
        d.addErrback(self._insert_failed)

    def _insert_failed(self, failure: Failure) -> None:
        self._log.warn(
            "rethinkdblog: insert failed: {reason}", reason=failure.getErrorMessage()
        )

    def stop(self) -> None:
        self.stopped = True
        if self.retry is not None:
            self.retry.cancel()
            self.retry = None
        if self.connection is not None:
            self.connection.close(noreply_wait=False)
            self.connection = None

    def write(self, event: dict[str, Any]) -> None:
        for i in list(event):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        if "timestamp" in event:
            event["timestamp"] = iso8601_to_timestamp(event["timestamp"])

        if self.connection is not None:
            if self.connection.is_open():
                self._insert(event)
                return
            # The driver only notices a lost connection when it is next
            # used; closing it fails the inserts still waiting on it.
            self._log.info("rethinkdblog: connection to RethinkDB lost, reconnecting")
            self.connection.close(noreply_wait=False)
            self.connection = None
            self._connect()

        if len(self.queue) == self.queue.maxlen:
            self.dropped += 1
        self.queue.append(event)
