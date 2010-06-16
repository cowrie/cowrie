from kippo.core import dblog
import MySQLdb

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.db = MySQLdb.connect(
            host = cfg.get('database', 'host'),
            db = cfg.get('database', 'database'),
            user = cfg.get('database', 'username'),
            passwd = cfg.get('database', 'password'),
            reconnect = True)

    def query(self, sql, params = None):
        cursor = self.db.cursor()
        try:
            if params is None:
                cursor.execute(sql)
            else:
                cursor.execute(sql, params)
            return cursor
        except MySQLdb.MySQLError:
            return None

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sql = 'INSERT INTO `session` (`starttime`, `sensor`, `ip`)' + \
            ' VALUES (FROM_UNIXTIME(%s), %s, %s)'
        params = (self.nowUnix(), self.getSensor() or hostIP, peerIP)
        cursor = self.query(sql, params)
        if cursor is not None:
            return int(cursor.lastrowid)
        else:
            return None

    def handleConnectionLost(self, session, args):
        sql = 'UPDATE `session` SET `endtime` = FROM_UNIXTIME(%s)' + \
            ', `ttylog` = %s WHERE `id` = %s'
        params = (self.nowUnix(), self.ttylog(session), session)
        self.query(sql, params)

    def handleLoginFailed(self, session, args):
        sql = 'INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))'
        params = (session, 0, args['username'], args['password'],
            self.nowUnix())
        self.query(sql, params)

    def handleLoginSucceeded(self, session, args):
        sql = 'INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))'
        params = (session, 1, args['username'], args['password'],
            self.nowUnix())
        self.query(sql, params)

    def handleCommand(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), 1, args['input'])
        self.query(sql, params)

    def handleUnknownCommand(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), 0, args['input'])
        self.query(sql, params)

    def handleInput(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `realm`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), args['realm'], args['input'])
        self.query(sql, params)

# vim: set sw=4 et:
