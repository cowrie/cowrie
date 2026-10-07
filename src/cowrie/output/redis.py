# SPDX-FileCopyrightText: 2018 Sami Mokaddem <mokaddem.sami@gmail.com>
# SPDX-FileCopyrightText: 2018-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Redis output plugin: pushes or publishes each event as JSON through
# ABOUTME: txredisapi, in order, without blocking the reactor.

from __future__ import annotations

import json
from configparser import NoOptionError
from typing import TYPE_CHECKING, Any

import txredisapi
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from twisted.python.failure import Failure

SEND_METHODS = ("lpush", "rpush", "publish")


class Output(cowrie.core.output.Output):
    """
    redis output

    txredisapi reconnects by itself and holds commands until the server
    is back, sending them in the order they were made.
    """

    _log = Logger()

    # Commands waiting for the server. Past this many, new events are
    # dropped, so a server that is down for a long time can't grow the
    # honeypot's memory without bound.
    max_pending = 10000

    def start(self) -> None:
        host: str = CowrieConfig.get("output_redis", "host")
        port: int = CowrieConfig.getint("output_redis", "port")

        try:
            db = CowrieConfig.getint("output_redis", "db")
        except NoOptionError:
            db = 0

        try:
            password = CowrieConfig.get("output_redis", "password")
        except NoOptionError:
            password = None

        self.keyname = CowrieConfig.get("output_redis", "keyname")

        try:
            send_method = CowrieConfig.get("output_redis", "send_method")
        except NoOptionError:
            send_method = "lpush"
        if send_method not in SEND_METHODS:
            send_method = "lpush"

        self.pending: int = 0
        self.dropped: int = 0
        # txredisapi ships no type information, so its objects are typed Any.
        self.redis: Any = txredisapi.lazyConnection(
            host=host, port=port, dbid=db, password=password
        )
        self.send = getattr(self.redis, send_method)

    def stop(self) -> None:
        if hasattr(self, "redis"):
            self.redis.disconnect()

    def _done(self, _: Any) -> None:
        self.pending -= 1
        if self.dropped and self.pending == 0:
            self._log.warn(
                "output_redis: dropped {dropped} events while Redis was unavailable",
                dropped=self.dropped,
            )
            self.dropped = 0

    def _failed(self, failure: Failure) -> None:
        self._log.warn(
            "output_redis: write failed: {reason}", reason=failure.getErrorMessage()
        )
        self._done(None)

    def write(self, event: dict[str, Any]) -> None:
        """
        Push to redis
        """
        # Add the entry to redis
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        if self.pending >= self.max_pending:
            self.dropped += 1
            return
        self.pending += 1
        d = self.send(self.keyname, json.dumps(event))
        d.addCallbacks(self._done, self._failed)
