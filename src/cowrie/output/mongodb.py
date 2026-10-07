# SPDX-FileCopyrightText: 2017 Claud Xiao
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: MongoDB output plugin: writes each event to its collection through
# ABOUTME: txmongo, one server-side operation per event, without blocking the reactor.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from twisted.logger import Logger
from txmongo.connection import ConnectionPool

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Callable

    from twisted.python.failure import Failure


class Output(cowrie.core.output.Output):
    """
    mongodb output

    txmongo reconnects by itself and holds operations until the server is
    back, sending them in the order they were made. Each event is a single
    operation, so an update for a session can never overtake its insert.
    """

    _log = Logger()

    # Operations waiting for the server. Past this many, new events are
    # dropped, so a server that is down for a long time can't grow the
    # honeypot's memory without bound.
    max_pending = 10000

    def start(self) -> None:
        db_addr = CowrieConfig.get("output_mongodb", "connection_string")
        db_name = CowrieConfig.get("output_mongodb", "database")

        self.pending: int = 0
        self.dropped: int = 0
        # txmongo ships no type information, so its objects are typed Any.
        self.mongo_client: Any = ConnectionPool(db_addr)
        self.mongo_db = self.mongo_client[db_name]
        # Define Collections.
        self.col_sensors = self.mongo_db["sensors"]
        self.col_sessions = self.mongo_db["sessions"]
        self.col_auth = self.mongo_db["auth"]
        self.col_input = self.mongo_db["input"]
        self.col_downloads = self.mongo_db["downloads"]
        self.col_clients = self.mongo_db["clients"]
        self.col_ttylog = self.mongo_db["ttylog"]
        self.col_keyfingerprints = self.mongo_db["keyfingerprints"]
        self.col_event = self.mongo_db["event"]
        self.col_ipforwards = self.mongo_db["ipforwards"]
        self.col_ipforwardsdata = self.mongo_db["ipforwardsdata"]

    def stop(self) -> None:
        if hasattr(self, "mongo_client"):
            self.mongo_client.disconnect()

    def _submit(self, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        if self.pending >= self.max_pending:
            self.dropped += 1
            return
        self.pending += 1
        d = operation(*args, **kwargs)
        d.addCallbacks(self._done, self._failed)

    def _done(self, _: Any) -> None:
        self.pending -= 1
        if self.dropped and self.pending == 0:
            self._log.warn(
                "output_mongodb: dropped {dropped} events while MongoDB was unavailable",
                dropped=self.dropped,
            )
            self.dropped = 0

    def _failed(self, failure: Failure) -> None:
        self._log.warn(
            "output_mongodb: write failed: {reason}", reason=failure.getErrorMessage()
        )
        self._done(None)

    def insert_one(self, collection: Any, event: dict[str, Any]) -> None:
        self._submit(collection.insert_one, event)

    def update_session(self, session: str, fields: dict[str, Any]) -> None:
        self._submit(
            self.col_sessions.update_one, {"session": session}, {"$set": fields}
        )

    def write(self, event: dict[str, Any]) -> None:
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        match event["eventid"]:
            case "cowrie.session.connect":
                # Add the sensor unless it exists. The filter supplies the
                # sensor field of a new document.
                self._submit(
                    self.col_sensors.update_one,
                    {"sensor": self.sensor},
                    {"$setOnInsert": {k: v for k, v in event.items() if k != "sensor"}},
                    upsert=True,
                )

                # Prep extra elements just to make django happy later on
                event["starttime"] = event["timestamp"]
                event["endtime"] = None
                event["sshversion"] = None
                event["termsize"] = None
                self._log.info("Session Created")
                self.insert_one(self.col_sessions, event)

            case "cowrie.login.success" | "cowrie.login.failed":
                self.insert_one(self.col_auth, event)

            case "cowrie.command.input" | "cowrie.command.failed":
                self.insert_one(self.col_input, event)

            case "cowrie.session.file_download":
                self.insert_one(self.col_downloads, event)

            case "cowrie.client.version":
                self.update_session(event["session"], {"sshversion": event["version"]})

            case "cowrie.client.size":
                self.update_session(
                    event["session"],
                    {"termsize": f"{event['width']}x{event['height']}"},
                )

            case "cowrie.session.closed":
                self.update_session(event["session"], {"endtime": event["timestamp"]})

            case "cowrie.log.closed":
                # ToDo Compress to opimise the space and if your sending to remote db
                with open(event["ttylog"]) as ttylog:
                    event["ttylogpath"] = event["ttylog"]
                    event["ttylog"] = ttylog.read().encode().hex()
                self.insert_one(self.col_ttylog, event)

            case "cowrie.client.fingerprint":
                self.insert_one(self.col_keyfingerprints, event)

            case "cowrie.direct-tcpip.request":
                self.insert_one(self.col_ipforwards, event)

            case "cowrie.direct-tcpip.data":
                self.insert_one(self.col_ipforwardsdata, event)

            # Catch any other event types
            case _:
                self.insert_one(self.col_event, event)
