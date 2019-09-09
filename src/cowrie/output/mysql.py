"""
MySQL output connector. Writes audit logs to MySQL database
"""

from __future__ import absolute_import, division

import MySQLdb

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for MySQL.

    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.

    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html
    """

    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)
        except MySQLdb.OperationalError as e:
            if e[0] not in (2003, 2006, 2013):
                raise e
            log.msg("RCP: got error {0}, retrying operation".format(e))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)


class Output(cowrie.core.output.Output):
    """
    mysql output
    """
    db = None

    def start(self):
        self.debug = CowrieConfig().getboolean('output_mysql', 'debug', fallback=False)
        port = CowrieConfig().getint('output_mysql', 'port', fallback=3306)
        try:
            self.db = ReconnectingConnectionPool(
                'MySQLdb',
                host=CowrieConfig().get('output_mysql', 'host'),
                db=CowrieConfig().get('output_mysql', 'database'),
                user=CowrieConfig().get('output_mysql', 'username'),
                passwd=CowrieConfig().get('output_mysql', 'password', raw=True),
                port=port,
                cp_min=1,
                cp_max=1,
                charset='utf8mb4',
                use_unicode=True
            )
        except MySQLdb.Error as e:
            log.msg("output_mysql: Error %d: %s" % (e.args[0], e.args[1]))

    def stop(self):
        self.db.close()

    def sqlerror(self, error):
        log.err('output_mysql: MySQL Error: {}'.format(error.value))

    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        if self.debug:
            log.msg("output_mysql: MySQL query: {} {}".format(sql, repr(args)))
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    @defer.inlineCallbacks
    def write(self, entry):
        if entry["eventid"] == 'cowrie.session.connect':
            r = yield self.db.runQuery(
                "SELECT `id`"
                "FROM `sensors`"
                "WHERE `ip` = %s",
                (self.sensor,))

            if r:
                sensorid = r[0][0]
            else:
                yield self.db.runQuery(
                    'INSERT INTO `sensors` (`ip`) '
                    'VALUES (%s)',
                    (self.sensor,))

                r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s)",
                (entry["session"], entry["time"], sensorid, entry["src_ip"]))

        elif entry["eventid"] == 'cowrie.login.success':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) '
                             'VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
                             (entry["session"], 1, entry['username'], entry['password'], entry["time"]))

        elif entry["eventid"] == 'cowrie.login.failed':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`, `username`, `password`, `timestamp`) '
                             'VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
                             (entry["session"], 0, entry['username'], entry['password'], entry["time"]))

        elif entry["eventid"] == 'cowrie.session.params':
            self.simpleQuery('INSERT INTO `params` (`session`, `arch`) '
                             'VALUES (%s, %s)',
                             (entry["session"], entry["arch"]))

        elif entry["eventid"] == 'cowrie.command.input':
            self.simpleQuery('INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s , %s)',
                             (entry["session"], entry["time"], 1, entry["input"]))

        elif entry["eventid"] == 'cowrie.command.failed':
            self.simpleQuery('INSERT INTO `input` (`session`, `timestamp`, `success`, `input`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s , %s)',
                             (entry["session"], entry["time"], 0, entry["input"]))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)',
                             (entry["session"], entry["time"], entry['url'], entry['outfile'], entry['shasum']))

        elif entry["eventid"] == 'cowrie.session.file_download.failed':
            self.simpleQuery('INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)',
                             (entry["session"], entry["time"], entry['url'], 'NULL', 'NULL'))

        elif entry["eventid"] == 'cowrie.session.file_upload':
            self.simpleQuery('INSERT INTO `downloads` (`session`, `timestamp`, `url`, `outfile`, `shasum`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)',
                             (entry["session"], entry["time"], '', entry['outfile'], entry['shasum']))

        elif entry["eventid"] == 'cowrie.session.input':
            self.simpleQuery('INSERT INTO `input` (`session`, `timestamp`, `realm`, `input`) '
                             'VALUES (%s, FROM_UNIXTIME(%s), %s , %s)',
                             (entry["session"], entry["time"], entry["realm"], entry["input"]))

        elif entry["eventid"] == 'cowrie.client.version':
            r = yield self.db.runQuery(
                'SELECT `id` FROM `clients` '
                'WHERE `version` = %s',
                (entry['version'],))

            if r:
                id = int(r[0][0])
            else:
                yield self.db.runQuery(
                    'INSERT INTO `clients` (`version`) '
                    'VALUES (%s)',
                    (entry['version'],))

                r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
                id = int(r[0][0])
            self.simpleQuery(
                'UPDATE `sessions` '
                'SET `client` = %s '
                'WHERE `id` = %s',
                (id, entry["session"]))

        elif entry["eventid"] == 'cowrie.client.size':
            self.simpleQuery(
                'UPDATE `sessions` '
                'SET `termsize` = %s '
                'WHERE `id` = %s',
                ('%sx%s' % (entry['width'], entry['height']), entry["session"]))

        elif entry["eventid"] == 'cowrie.session.closed':
            self.simpleQuery(
                'UPDATE `sessions` '
                'SET `endtime` = FROM_UNIXTIME(%s) '
                'WHERE `id` = %s',
                (entry["time"], entry["session"]))

        elif entry["eventid"] == 'cowrie.log.closed':
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`, `size`) '
                'VALUES (%s, %s, %s)',
                (entry["session"], entry["ttylog"], entry["size"]))

        elif entry["eventid"] == 'cowrie.client.fingerprint':
            self.simpleQuery(
                'INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) '
                'VALUES (%s, %s, %s)',
                (entry["session"], entry["username"], entry["fingerprint"]))

        elif entry["eventid"] == 'cowrie.direct-tcpip.request':
            self.simpleQuery(
                'INSERT INTO `ipforwards` (`session`, `timestamp`, `dst_ip`, `dst_port`) '
                'VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
                (entry["session"], entry["time"], entry["dst_ip"], entry["dst_port"]))

        elif entry["eventid"] == 'cowrie.direct-tcpip.data':
            self.simpleQuery(
                'INSERT INTO `ipforwardsdata` (`session`, `timestamp`, `dst_ip`, `dst_port`, `data`) '
                'VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)',
                (entry["session"], entry["time"], entry["dst_ip"], entry["dst_port"], entry["data"]))
