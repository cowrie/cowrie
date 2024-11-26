from __future__ import annotations
import sqlite3
from typing import Any

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    sqlite output
    """

    db: Any

    def start(self):
        """
        Start sqlite3 logging module using Twisted ConnectionPool.
        Need to be started with check_same_thread=False. See
        https://twistedmatrix.com/trac/ticket/3629.
        """
        sqliteFilename = CowrieConfig.get("output_sqlite", "db_file")
        try:
            self.db = adbapi.ConnectionPool(
                "sqlite3", database=sqliteFilename, check_same_thread=False
            )
        except sqlite3.OperationalError as e:
            log.msg(e)

        self.db.start()

    def stop(self):
        """
        Close connection to db
        """
        self.db.close()

    def sqlerror(self, error):
        log.err("sqlite error")
        error.printTraceback()

    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    @defer.inlineCallbacks
    def write(self, event):
        if event["eventid"] == "cowrie.session.connect":
            r = yield self.db.runQuery(
                "SELECT `id` FROM `sensors` " "WHERE `ip` = ?", (self.sensor,)
            )

            if r and r[0][0]:
                sensorid = r[0][0]
            else:
                yield self.db.runQuery(
                    "INSERT INTO `sensors` (`ip`) " "VALUES (?)", (self.sensor,)
                )

                r = yield self.db.runQuery("SELECT LAST_INSERT_ROWID()")
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`) "
                "VALUES (?, ?, ?, ?)",
                (event["session"], event["timestamp"], sensorid, event["src_ip"]),
            )

        elif event["eventid"] == "cowrie.login.success":
            self.simpleQuery(
                "INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event["session"],
                    1,
                    event["username"],
                    event["password"],
                    event["timestamp"],
                ),
            )

        elif event["eventid"] == "cowrie.login.failed":
            self.simpleQuery(
                "INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event["session"],
                    0,
                    event["username"],
                    event["password"],
                    event["timestamp"],
                ),
            )

        elif event["eventid"] == "cowrie.command.input":
            self.simpleQuery(
                "INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) "
                "VALUES (?, ?, ?, ?)",
                (event["session"], event["timestamp"], 1, event["input"]),
            )

        elif event["eventid"] == "cowrie.command.failed":
            self.simpleQuery(
                "INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) "
                "VALUES (?, ?, ?, ?)",
                (event["session"], event["timestamp"], 0, event["input"]),
            )

        elif event["eventid"] == "cowrie.session.params":
            self.simpleQuery(
                "INSERT INTO `params` (`session`, `arch`) " "VALUES (?, ?)",
                (event["session"], event["arch"]),
            )

        elif event["eventid"] == "cowrie.session.file_download":
            self.simpleQuery(
                "INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event["session"],
                    event["timestamp"],
                    event["url"],
                    event["outfile"],
                    event["shasum"],
                ),
            )

        elif event["eventid"] == "cowrie.session.file_download.failed":
            self.simpleQuery(
                "INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) "
                "VALUES (?, ?, ?, ?, ?)",
                (event["session"], event["timestamp"], event["url"], "NULL", "NULL"),
            )

        elif event["eventid"] == "cowrie.client.version":
            r = yield self.db.runQuery(
                "SELECT `id` FROM `clients` " "WHERE `version` = ?", (event["version"],)
            )

            if r and r[0][0]:
                clientid = int(r[0][0])
            else:
                yield self.db.runQuery(
                    "INSERT INTO `clients` (`version`) " "VALUES (?)",
                    (event["version"],),
                )

                r = yield self.db.runQuery("SELECT LAST_INSERT_ROWID()")
                clientid = int(r[0][0])
            self.simpleQuery(
                "UPDATE `sessions` " "SET `client` = ? " "WHERE `id` = ?",
                (clientid, event["session"]),
            )

        elif event["eventid"] == "cowrie.client.size":
            self.simpleQuery(
                "UPDATE `sessions` " "SET `termsize` = ? " "WHERE `id` = ?",
                ("{}x{}".format(event["width"], event["height"]), event["session"]),
            )

        elif event["eventid"] == "cowrie.session.closed":
            self.simpleQuery(
                "UPDATE `sessions` " "SET `endtime` = ? " "WHERE `id` = ?",
                (event["timestamp"], event["session"]),
            )

        elif event["eventid"] == "cowrie.log.closed":
            self.simpleQuery(
                "INSERT INTO `ttylog` (`session`, `ttylog`, `size`) "
                "VALUES (?, ?, ?)",
                (event["session"], event["ttylog"], event["size"]),
            )

        elif event["eventid"] == "cowrie.client.fingerprint":
            self.simpleQuery(
                "INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) "
                "VALUES (?, ?, ?)",
                (event["session"], event["username"], event["fingerprint"]),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.request":
            self.simpleQuery(
                "INSERT INTO `ipforwards` (`session`, `timestamp`, `dst_ip`, `dst_port`) "
                "VALUES (?, ?, ?, ?)",
                (
                    event["session"],
                    event["timestamp"],
                    event["dst_ip"],
                    event["dst_port"],
                ),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.data":
            self.simpleQuery(
                "INSERT INTO `ipforwardsdata` (`session`, `timestamp`, `dst_ip`, `dst_port`, `data`) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event["session"],
                    event["timestamp"],
                    event["dst_ip"],
                    event["dst_port"],
                    event["data"],
                ),
            )
