from kippo.core import dblog
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log
import MySQLdb, uuid

class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """Reconnecting adbapi connection pool for MySQL.

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
        except MySQLdb.OperationalError, e:
            if e[0] not in (2006, 2013):
                raise
            log.msg("RCP: got error %s, retrying operation" %(e))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        if cfg.has_option('database_mysql', 'port'):
            port = int(cfg.get('database_mysql', 'port'))
        else:
            port = 3306
        self.db = ReconnectingConnectionPool('MySQLdb',
            host = cfg.get('database_mysql', 'host'),
            db = cfg.get('database_mysql', 'database'),
            user = cfg.get('database_mysql', 'username'),
            passwd = cfg.get('database_mysql', 'password'),
            port = port,
            cp_min = 1,
            cp_max = 1)

    def sqlerror(self, error):
        print 'SQL Error:', error.value

    def simpleQuery(self, sql, args):
        """ Just run a deferred sql query, only care about errors """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex
        self.createSessionWhenever(sid, peerIP, hostIP)
        return sid

    # This is separate since we can't return with a value
    @defer.inlineCallbacks
    def createSessionWhenever(self, sid, peerIP, hostIP):
        sensorname = self.getSensor() or hostIP
        r = yield self.db.runQuery(
            'SELECT `id` FROM `sensors` WHERE `ip` = %s', (sensorname,))
        if r:
            id = r[0][0]
        else:
            yield self.db.runQuery(
                'INSERT INTO `sensors` (`ip`) VALUES (%s)', (sensorname,))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        # now that we have a sensorID, continue creating the session
        self.simpleQuery(
            'INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (sid, self.nowUnix(), id, peerIP))

    def handleConnectionLost(self, session, args):
        ttylog = self.ttylog(session)
        if ttylog:
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`) VALUES (%s, %s)',
                (session, self.ttylog(session)))
        self.simpleQuery(
            'UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s)' + \
            ' WHERE `id` = %s',
            (self.nowUnix(), session))

    def handleLoginFailed(self, session, args):
        self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 0, args['username'], args['password'], self.nowUnix()))

    def handleLoginSucceeded(self, session, args):
        self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 1, args['username'], args['password'], self.nowUnix()))

    def handleCommand(self, session, args):
        self.simpleQuery('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), 1, args['input']))

    def handleUnknownCommand(self, session, args):
        self.simpleQuery('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), 0, args['input']))

    def handleInput(self, session, args):
        self.simpleQuery('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `realm`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), args['realm'], args['input']))

    def handleTerminalSize(self, session, args):
        self.simpleQuery('UPDATE `sessions` SET `termsize` = %s' + \
            ' WHERE `id` = %s',
            ('%sx%s' % (args['width'], args['height']), session))

    @defer.inlineCallbacks
    def handleClientVersion(self, session, args):
        r = yield self.db.runQuery(
            'SELECT `id` FROM `clients` WHERE `version` = %s', \
            (args['version'],))
        if r:
            id = int(r[0][0])
        else:
            yield self.db.runQuery(
                'INSERT INTO `clients` (`version`) VALUES (%s)', \
                (args['version'],))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        self.simpleQuery(
            'UPDATE `sessions` SET `client` = %s WHERE `id` = %s',
            (id, session))

    def handleFileDownload(self, session, args):
        self.simpleQuery('INSERT INTO `downloads`' + \
            ' (`session`, `timestamp`, `url`, `outfile`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), args['url'], args['outfile']))

# vim: set sw=4 et:
