from __future__ import annotations

from psycopg2 import OperationalError
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class ReconnectingPostgreSQLConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for PostgreSQL.

    This handles reconnections on known transient errors like server disconnects or deadlocks.
    """

    def _runInteraction(self, interaction, *args, **kw):
        try:
            return super()._runInteraction(interaction, *args, **kw)
        except OperationalError as e:
            # Typical disconnection or restart issues
            transient_errors = (
                "08003",  # connection_does_not_exist
                "08006",  # connection_failure
                "40001",  # serialization_failure
                "57014",  # query_canceled
                "53300",  # too_many_connections
            )
            if e.pgcode not in transient_errors:
                raise

            log.msg(f"output_postgresql: transient error {e!r}, retrying interaction")
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            return super()._runInteraction(interaction, *args, **kw)


class Output(cowrie.core.output.Output):
    """
    PostgreSQL output for Cowrie
    """

    debug: bool = False

    def start(self):
        self.debug = CowrieConfig.getboolean("output_postgresql", "debug", fallback=False)
        port = CowrieConfig.getint("output_postgresql", "port", fallback=5432)

        try:
            self.db = ReconnectingPostgreSQLConnectionPool(
                "psycopg2",
                host=CowrieConfig.get("output_postgresql", "host"),
                database=CowrieConfig.get("output_postgresql", "database"),
                user=CowrieConfig.get("output_postgresql", "username"),
                password=CowrieConfig.get("output_postgresql", "password", raw=True),
                port=port,
                cp_min=1,
                cp_max=1,
            )
        except Exception as e:
            log.msg(f"output_mysql: Error {e.args[0]}: {e.args[1]}")

    def stop(self):
        self.db.close()

    def sqlerror(self, error):
        log.msg(f"output_postgresql: PostgreSQL Error: {error.value.args!r}")

    def simpleQuery(self, sql, args):
        if (
            sql.startswith("INSERT")
            or sql.startswith("UPDATE")
            or sql.startswith("DELETE")
        ):
            sql += " RETURNING id"

        if self.debug:
            log.msg(f"output_postgresql: PostgreSQL query: {sql} {args!r}")

        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    @defer.inlineCallbacks
    def write(self, event):
        if event["eventid"] == "cowrie.session.connect":
            if self.debug:
                log.msg(
                    f"output_postgresql: SELECT id FROM sensors WHERE ip = '{self.sensor}'"
                )
            r = yield self.db.runQuery(
                "SELECT id FROM sensors WHERE ip = %s",
                (self.sensor,),
            )
            if r:
                sensorid = r[0][0]
            else:
                if self.debug:
                    log.msg(
                        f"output_postgresql: INSERT INTO sensors (ip) VALUES ('{self.sensor}')"
                    )
                yield self.db.runQuery(
                    "INSERT INTO sensors (ip) VALUES (%s) ",
                    (self.sensor,),
                )

                r = yield self.db.runQuery("SELECT LASTVAL()")
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO sessions (id, starttime, sensor, ip) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s)",
                (event["session"], event["time"], sensorid, event["src_ip"]),
            )

        elif event["eventid"] == "cowrie.login.success":
            self.simpleQuery(
                "INSERT INTO auth (session, success, username, password, timestamp) "
                "VALUES (%s, %s, %s, %s, TO_TIMESTAMP(%s)) ",
                (
                    event["session"],
                    True,
                    event["username"],
                    event["password"],
                    event["time"],
                ),
            )

        elif event["eventid"] == "cowrie.login.failed":
            self.simpleQuery(
                "INSERT INTO auth (session, success, username, password, timestamp) "
                "VALUES (%s, %s, %s, %s, TO_TIMESTAMP(%s))",
                (
                    event["session"],
                    False,
                    event["username"],
                    event["password"],
                    event["time"],
                ),
            )

        elif event["eventid"] == "cowrie.session.params":
            self.simpleQuery(
                "INSERT INTO params (session, arch) VALUES (%s, %s)",
                (event["session"], event["arch"]),
            )

        elif event["eventid"] == "cowrie.command.input":
            self.simpleQuery(
                "INSERT INTO input (session, timestamp, success, input) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s , %s)",
                (event["session"], event["time"], True, event["input"]),
            )

        elif event["eventid"] == "cowrie.command.failed":
            self.simpleQuery(
                "INSERT INTO input (session, timestamp, success, input) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s , %s)",
                (event["session"], event["time"], False, event["input"]),
            )

        elif event["eventid"] == "cowrie.session.file_download":
            self.simpleQuery(
                "INSERT INTO downloads (session, timestamp, url, outfile, shasum) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s, %s)",
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
                "INSERT INTO downloads (session, timestamp, url, outfile, shasum) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s, %s)",
                (event["session"], event["time"], event.get("url", ""), None, None),
            )

        elif event["eventid"] == "cowrie.session.file_upload":
            self.simpleQuery(
                "INSERT INTO downloads (session, timestamp, url, outfile, shasum) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s, %s)",
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
                "INSERT INTO input (session, timestamp, realm, input) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s , %s)",
                (event["session"], event["time"], event["realm"], event["input"]),
            )

        elif event["eventid"] == "cowrie.client.version":
            r = yield self.db.runQuery(
                "SELECT id FROM clients WHERE version = %s",
                (event["version"],),
            )

            if r:
                clientid = int(r[0][0])
            else:
                yield self.db.runQuery(
                    "INSERT INTO clients (version) VALUES (%s)",
                    (event["version"],),
                )

                r = yield self.db.runQuery("SELECT LASTVAL()")
                clientid = int(r[0][0])
            self.simpleQuery(
                "UPDATE sessions SET client = %s WHERE id = %s",
                (clientid, event["session"]),
            )

        elif event["eventid"] == "cowrie.client.size":
            self.simpleQuery(
                "UPDATE sessions SET termsize = %s WHERE id = %s",
                ("{}x{}".format(event["width"], event["height"]), event["session"]),
            )

        elif event["eventid"] == "cowrie.session.closed":
            self.simpleQuery(
                "UPDATE sessions SET endtime = TO_TIMESTAMP(%s) WHERE id = %s",
                (event["time"], event["session"]),
            )

        elif event["eventid"] == "cowrie.log.closed":
            self.simpleQuery(
                "INSERT INTO ttylog (session, ttylog, size) VALUES (%s, %s, %s)",
                (event["session"], event["ttylog"], event["size"]),
            )

        elif event["eventid"] == "cowrie.client.fingerprint":
            self.simpleQuery(
                "INSERT INTO keyfingerprints (session, username, fingerprint) "
                "VALUES (%s, %s, %s)",
                (event["session"], event["username"], event["fingerprint"]),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.request":
            self.simpleQuery(
                "INSERT INTO ipforwards (session, timestamp, dst_ip, dst_port) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s)",
                (event["session"], event["time"], event["dst_ip"], event["dst_port"]),
            )

        elif event["eventid"] == "cowrie.direct-tcpip.data":
            self.simpleQuery(
                "INSERT INTO ipforwardsdata (session, timestamp, dst_ip, dst_port, data) "
                "VALUES (%s, TO_TIMESTAMP(%s), %s, %s, %s)",
                (
                    event["session"],
                    event["time"],
                    event["dst_ip"],
                    event["dst_port"],
                    event["data"],
                ),
            )
