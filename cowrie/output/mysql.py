
"""
docstring
"""

import MySQLdb

from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.python import log

import cowrie.core.output

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
                raise log.msg("RCP: got error %s, retrying operation" %(e))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)



class Output(cowrie.core.output.Output):
    """
    docstring here
    """

    def __init__(self, cfg):
        self.cfg = cfg
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        docstring here
        """
        if self.cfg.has_option('output_mysql', 'port'):
            port = int(self.cfg.get('output_mysql', 'port'))
        else:
            port = 3306
        try:
            self.db = ReconnectingConnectionPool('MySQLdb',
                host = self.cfg.get('output_mysql', 'host'),
                db = self.cfg.get('output_mysql', 'database'),
                user = self.cfg.get('output_mysql', 'username'),
                passwd = self.cfg.get('output_mysql', 'password'),
                port = port,
                cp_min = 1,
                cp_max = 1)
        except MySQLdb.Error as e:
            log.msg("Error %d: %s" % (e.args[0], e.args[1]))

        self.db.start()


    def stop(self):
        """
        docstring here
        """
        self.db.close()


    def sqlerror(self, error):
        """
        docstring here
        """
        log.err( 'MySQL Error:', error.value )


    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)


    @defer.inlineCallbacks
    def write(self, entry):
        """
        docstring here
        """

        if entry["eventid"] == 'cowrie.session.connect':
            r = yield self.db.runQuery(
                "SELECT `id` FROM `sensors` WHERE `ip` = %s", (self.sensor,))
            if r:
                sensorid = r[0][0]
            else:
                yield self.db.runQuery(
                    'INSERT INTO `sensors` (`ip`) VALUES (%s)', (self.sensor,))
                r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`)"
                +  " VALUES (%s, STR_TO_DATE(%s, %s), %s, %s)",
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                    sensorid, entry["src_ip"]))

        elif entry["eventid"] == 'cowrie.login.success':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (%s, %s, %s, %s, STR_TO_DATE(%s, %s))',
                (entry["session"], 1, entry['username'], entry['password'],
                entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ'))

        elif entry["eventid"] == 'cowrie.login.failed':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (%s, %s, %s, %s, STR_TO_DATE(%s, %s))',
                (entry["session"], 0, entry['username'], entry['password'],
                entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ'))

        elif entry["eventid"] == 'cowrie.command.success':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                1, entry["input"]))

        elif entry["eventid"] == 'cowrie.command.failed':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                0, entry["input"]))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `downloads`' + \
                ' (`session`, `timestamp`, `url`, `outfile`, `shasum`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s, %s, %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                entry['url'], entry['outfile'], entry['shasum']))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `realm`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                entry["realm"], entry["input"]))

        elif entry["eventid"] == 'cowrie.client.version':
            r = yield self.db.runQuery(
                'SELECT `id` FROM `clients` WHERE `version` = %s', \
                (entry['version'],))
            if r:
                id = int(r[0][0])
            else:
                yield self.db.runQuery(
                    'INSERT INTO `clients` (`version`) VALUES (%s)', \
                    (entry['version'],))
                r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
                id = int(r[0][0])
            self.simpleQuery(
                'UPDATE `sessions` SET `client` = %s WHERE `id` = %s',
                (id, entry["session"]))

        elif entry["eventid"] == 'cowrie.client.size':
            self.simpleQuery(
                'UPDATE `sessions` SET `termsize` = %s WHERE `id` = %s',
                ('%sx%s' % (entry['width'], entry['height']),
                    entry["session"]))

        elif entry["eventid"] == 'cowrie.session.closed':
            self.simpleQuery(
                'UPDATE `sessions` SET `endtime` = STR_TO_DATE(%s, %s)' + \
                ' WHERE `id` = %s', (entry["timestamp"],
                    '%Y-%m-%dT%H:%i:%s.%fZ', entry["session"]))

        elif entry["eventid"] == 'cowrie.log.closed':
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`, `size`) VALUES (%s, %s, %s)',
                (entry["session"], entry["ttylog"], entry["size"]))

        elif entry["eventid"] == 'cowrie.client.fingerprint':
            self.simpleQuery(
                'INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) VALUES (%s, %s, %s)',
                (entry["session"], entry["username"], entry["fingerprint"]))

