"""
MySQL output connector. Writes audit logs to MySQL database
"""

from __future__ import annotations

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

# For exceptions: https://dev.mysql.com/doc/connector-python/en/connector-python-api-errors-error.html
import mysql.connector


class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for MySQL.

    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.

     CR_CONN_HOST_ERROR: 2003: Cant connect to MySQL server on server (10061)
     CR_SERVER_GONE_ERROR: 2006: MySQL server has gone away
     CR_SERVER_LOST 2013: Lost connection to MySQL server
     ER_LOCK_DEADLOCK 1213: Deadlock found when trying to get lock)

    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html
    """

    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(self, interaction, *args, **kw)
        except mysql.connector.Error as e:
            # except (MySQLdb.OperationalError, MySQLdb._exceptions.OperationalError) as e:
            if e.errno not in (
                mysql.connector.errorcode.CR_CONN_HOST_ERROR,
                mysql.connector.errorcode.CR_SERVER_GONE_ERROR,
                mysql.connector.errorcode.CR_SERVER_LOST,
                mysql.connector.errorcode.ER_LOCK_DEADLOCK,
            ):
                raise

            log.msg(f"output_mysql: got error {e!r}, retrying operation")
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(self, interaction, *args, **kw)


class Output(cowrie.core.output.Output):
    """
    MySQL output
    """

    debug: bool = False

    def start(self):
        self.debug = CowrieConfig.getboolean("output_mysql", "debug", fallback=False)
        port = CowrieConfig.getint("output_mysql", "port", fallback=3306)
        try:
            self.db = ReconnectingConnectionPool(
                "mysql.connector",
                host=CowrieConfig.get("output_mysql", "host"),
                db=CowrieConfig.get("output_mysql", "database"),
                user=CowrieConfig.get("output_mysql", "username"),
                passwd=CowrieConfig.get("output_mysql", "password", raw=True),
                port=port,
                cp_min=1,
                cp_max=1,
                charset="utf8mb4",
                cp_reconnect=True,
                use_unicode=True,
            )
        # except (MySQLdb.Error, MySQLdb._exceptions.Error) as e:
        except Exception as e:
            log.msg(f"output_mysql: Error {e.args[0]}: {e.args[1]}")

    def stop(self):
        self.db.close()

    def sqlerror(self, error):
        """
        1146, "Table '...' doesn't exist"
        1406, "Data too long for column '...' at row ..."
        """
        if error.value.args[0] in (1146, 1406):
            log.msg(f"output_mysql: MySQL Error: {error.value.args!r}")
            log.msg(
                "output_mysql: MySQL schema maybe misconfigured, doublecheck database!"
            )
        else:
            log.msg(f"output_mysql: MySQL Error: {error.value.args!r}")

    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        if self.debug:
            log.msg(f"output_mysql: MySQL query: {sql} {args!r}")
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    @defer.inlineCallbacks
    def write(self, event):
        if event["eventid"] == "cowrie.session.connect":
            if self.debug:
                log.msg(
                    f"output_mysql: SELECT `id` FROM `sensors` WHERE `ip` = '{self.sensor}'"
                )
            r = yield self.db.runQuery(
                "SELECT `id` FROM `sensors` WHERE `ip` = %s",
                (self.sensor,),
            )
            if r:
                sensorid = r[0][0]
            else:
                if self.debug:
                    log.msg(
                        f"output_mysql: INSERT INTO `sensors` (`ip`) VALUES ('{self.sensor}')"
                    )
                yield self.db.runQuery(
                    "INSERT INTO `sensors` (`ip`) VALUES (%s)",
                    (self.sensor,),
                )

                r = yield self.db.runQuery("SELECT LAST_INSERT_ID()")
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s)",
                (event["session"], event["time"], sensorid, event["src_ip"]),
            )

        elif event["eventid"] == "cowrie.login.success":
            self.simpleQuery(
                "INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) "
                "VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))",
                (
                    event["session"],
                    1,
                    event["username"],
                    event["password"],
                    event["time"],
                ),
            )

        elif event["eventid"] == "cowrie.login.failed":
            self.simpleQuery(
                "INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) "
                "VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))",
                (
                    event["session"],
                    0,
                    event["username"],
                    event["password"],
                    event["time"],
                ),
            )

        elif event["eventid"] == "cowrie.session.params":
            self.simpleQuery(
                "INSERT INTO `params` (`session`, `arch`) VALUES (%s, %s)",
                (event["session"], event["arch"]),
            )

        elif event["eventid"] == "cowrie.command.input":
            self.simpleQuery(
                "INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s , %s)",
                (event["session"], event["time"], 1, event["input"]),
            )

        elif event["eventid"] == "cowrie.command.failed":
            self.simpleQuery(
                "INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s , %s)",
                (event["session"], event["time"], 0, event["input"]),
            )

        elif event["eventid"] == "cowrie.session.file_download":
            self.simpleQuery(
                "INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    event["session"],
                    event["time"],
                    event.get("url", ""),
                    event["outfile"],
                    event["shasum"],
                ),
            )

        elif event["eventid"] == "cowrie.session.file_download.failed":
            self.simpleQuery(
                "INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (event["session"], event["time"], event.get("url", ""), "NULL", "NULL"),
            )

        elif event["eventid"] == "cowrie.session.file_upload":
            self.simpleQuery(
                "INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    event["session"],
                    event["time"],
                    "",
                    event["outfile"],
                    event["shasum"],
                ),
            )

        elif event["eventid"] == "cowrie.session.input":
            self.simpleQuery(
                "INSERT INTO `input` (`session`, `timestamp`, `realm`, `input`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s , %s)",
                (event["session"], event["time"], event["realm"], event["input"]),
            )

        elif event["eventid"] == "cowrie.client.version":
            r = yield self.db.runQuery(
                "SELECT `id` FROM `clients` WHERE `version` = %s",
                (event["version"],),
            )

            if r:
                clientid = int(r[0][0])
            else:
                yield self.db.runQuery(
                    "INSERT INTO `clients` (`version`) VALUES (%s)",
                    (event["version"],),
                )

                r = yield self.db.runQuery("SELECT LAST_INSERT_ID()")
                clientid = int(r[0][0])
            self.simpleQuery(
                "UPDATE `sessions` SET `client` = %s WHERE `id` = %s",
                (clientid, event["session"]),
            )

        elif event["eventid"] == "cowrie.client.size":
            self.simpleQuery(
                "UPDATE `sessions` SET `termsize` = %s WHERE `id` = %s",
                ("{}x{}".format(event["width"], event["height"]), event["session"]),
            )

        elif event["eventid"] == "cowrie.session.closed":
            self.simpleQuery(
                "UPDATE `sessions` "
                "SET `endtime` = FROM_UNIXTIME(%s) "
                "WHERE `id` = %s",
                (event["time"], event["session"]),
            )

        elif event["eventid"] == "cowrie.log.closed":
            self.simpleQuery(
                "INSERT INTO `ttylog` (`session`, `ttylog`, `size`) "
                "VALUES (%s, %s, %s)",
                (event["session"], event["ttylog"], event["size"]),
            )

        elif event["eventid"] == "cowrie.client.fingerprint":
            self.simpleQuery(
                "INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) "
                "VALUES (%s, %s, %s)",
                (event["session"], event["username"], event["fingerprint"]),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.request":
            self.simpleQuery(
                "INSERT INTO `ipforwards` (`session`, `timestamp`, `dst_ip`, `dst_port`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s)",
                (event["session"], event["time"], event["dst_ip"], event["dst_port"]),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.data":
            self.simpleQuery(
                "INSERT INTO `ipforwardsdata` (`session`, `timestamp`, `dst_ip`, `dst_port`, `data`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    event["session"],
                    event["time"],
                    event["dst_ip"],
                    event["dst_port"],
                    event["data"],
                ),
            )
