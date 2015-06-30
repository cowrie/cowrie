
import MySQLdb
import uuid

from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.python import log

from cowrie.core import dblog

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
        except MySQLdb.OperationalError as e:
            if e[0] not in (2003, 2006, 2013):
                raise
            log.msg("RCP: got error %s, retrying operation" %(e))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)

class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        if cfg.has_option('output_mysql', 'port'):
            port = int(cfg.get('output_mysql', 'port'))
        else:
            port = 3306
        self.db = ReconnectingConnectionPool('MySQLdb',
            host = cfg.get('output_mysql', 'host'),
            db = cfg.get('output_mysql', 'database'),
            user = cfg.get('output_mysql', 'username'),
            passwd = cfg.get('output_mysql', 'password'),
            port = port,
            cp_min = 1,
            cp_max = 1)

    def __start__(self):
    	pass

    def sqlerror(self, error):
        log.msg( 'SQL Error:', error.value )

    def simpleQuery(self, sql, args):
        """ Just run a deferred sql query, only care about errors """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    def write(self, entry):
        if (entry.id == 'KIPP0001'):
            sid = uuid.uuid4().hex
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
    	elif (entry.id == 'KIPP-0002'):
             self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
	            ', `username`, `password`, `timestamp`)' + \
	            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
	            (session, 1, args['username'], args['password'], self.nowUnix()))
    	elif (entry.id == 'KIPP-0003'):
        	self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
	            ', `username`, `password`, `timestamp`)' + \
       		     ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
	       	     (session, 0, args['username'], args['password'], self.nowUnix()))
    	elif (entry.id == 'KIPP-0004'):
    		pass
    	elif (entry.id == 'KIPP-0005'):
        	self.simpleQuery('INSERT INTO `input`' + \
	            ' (`session`, `timestamp`, `success`, `input`)' + \
       		     ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
	            (session, self.nowUnix(), 1, args['input']))
    	elif (entry.id == 'KIPP-0006'):
	        self.simpleQuery('INSERT INTO `input`' + \
	            ' (`session`, `timestamp`, `success`, `input`)' + \
	            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
	            (session, self.nowUnix(), 0, args['input']))
    	elif (entry.id == 'KIPP-0009'):
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
	    elif (entry.id == 'KIPP-0008'):
        	self.simpleQuery('INSERT INTO `input`' + \
	            ' (`session`, `timestamp`, `realm`, `input`)' + \
	            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), args['realm'], args['input']))
    	elif (entry.id == 'KIPP-0007'):
	        self.simpleQuery('INSERT INTO `downloads`' + \
	            ' (`session`, `timestamp`, `url`, `outfile`, `shasum`)' + \
	            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
	            (session, self.nowUnix(), args['url'], args['outfile'], args['shasum']))
    	elif (entry.id == 'KIPP-0010'):
	        self.simpleQuery('UPDATE `sessions` SET `termsize` = %s' + \
	            ' WHERE `id` = %s',
	            ('%sx%s' % (args['width'], args['height']), session))
    	elif (entry.id == 'KIPP-0011'):
       		 ttylog = self.ttylog(session)
	        if ttylog:
	            self.simpleQuery(
	                'INSERT INTO `ttylog` (`session`, `ttylog`) VALUES (%s, %s)',
	                (session, self.ttylog(session)))
	        self.simpleQuery(
	            'UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s)' + \
	            ' WHERE `id` = %s',
	            (self.nowUnix(), session))

    # This is separate since we can't return with a value
    @defer.inlineCallbacks
    def createSessionWhenever(self, sid, peerIP, hostIP):

# vim: set sw=4 et:
