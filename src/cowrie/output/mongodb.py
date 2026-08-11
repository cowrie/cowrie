# SPDX-FileCopyrightText: 2017 Claud Xiao
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import pymongo
from twisted.internet import reactor, threads
from twisted.logger import Logger
from twisted.python.threadpool import ThreadPool

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    mongodb output
    """

    _log = Logger()
    pool: ThreadPool | None = None

    def insert_one(self, collection, event):
        try:
            object_id = collection.insert_one(event).inserted_id
        except Exception as e:
            self._log.info("mongo error - {error}", error=e)
        else:
            return object_id

    def update_one(self, collection, session, doc):
        try:
            object_id = collection.update_one({"session": session}, {"$set": doc})
        except Exception as e:
            self._log.info("mongo error - {error}", error=e)
        else:
            return object_id

    def start(self):
        db_addr = CowrieConfig.get("output_mongodb", "connection_string")
        db_name = CowrieConfig.get("output_mongodb", "database")

        try:
            # Bound worst-case blocking time per call so an unreachable host
            # can't hang the worker thread (or reactor shutdown) forever.
            self.mongo_client = pymongo.MongoClient(
                db_addr,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=5000,
            )
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

            # Dedicated single-worker pool: keeps writes off the reactor
            # thread while guaranteeing they execute in the order they were
            # logged, so the find/update pairs below can't race each other.
            self.pool = ThreadPool(
                minthreads=1, maxthreads=1, name="MongoDBOutputPool"
            )
            self.pool.start()
        except Exception as e:
            self._log.info("output_mongodb: Error: {error}", error=e)

    def stop(self):
        if self.pool:
            self.pool.stop()
        if hasattr(self, "mongo_client"):
            self.mongo_client.close()

    def write(self, event):
        d = threads.deferToThreadPool(reactor, self.pool, self._write_sync, event)
        d.addErrback(lambda f: self._log.failure("mongodb output error", f))
        return d

    def _write_sync(self, event):
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        match event["eventid"]:
            case "cowrie.session.connect":
                # Check if sensor exists, else add it.
                doc = self.col_sensors.find_one({"sensor": self.sensor})
                if not doc:
                    self.insert_one(self.col_sensors, event)

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
                self.update_one(
                    self.col_sessions,
                    event["session"],
                    {"sshversion": event["version"]},
                )

            case "cowrie.client.size":
                self.update_one(
                    self.col_sessions,
                    event["session"],
                    {"termsize": f"{event['width']}x{event['height']}"},
                )

            case "cowrie.session.closed":
                self.update_one(
                    self.col_sessions,
                    event["session"],
                    {"endtime": event["timestamp"]},
                )

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