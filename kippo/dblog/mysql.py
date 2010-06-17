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

    def query(self, sql, params):
        cursor = self.db.cursor()
        try:
            cursor.execute(sql, params)
            return cursor
        except MySQLdb.MySQLError, e:
            print 'MySQL error:', e
            return None

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sensorid = self.getSensorID(self.getSensor() or hostIP)
        cursor = self.query(
            'INSERT INTO `sessions` (`starttime`, `sensor`, `ip`)' + \
            ' VALUES (FROM_UNIXTIME(%s), %s, %s)',
            (self.nowUnix(), sensorid, peerIP))
        if not cursor:
            return None
        return int(cursor.lastrowid)

    def getSensorID(self, ip):
        cursor = self.query(
            'SELECT `id` FROM `sensors` WHERE `ip` = %s', (ip,))
        if cursor.rowcount:
            return cursor.fetchone()[0]
        
        cursor = self.query(
            'INSERT INTO `sensors` (`ip`) VALUES (%s)', (ip,))
        return cursor.lastrowid

    def handleConnectionLost(self, session, args):
        self.query(
            'INSERT INTO `ttylog` (`session`, `ttylog`) VALUES (%s, %s)',
            (session, self.ttylog(session)))
        self.query('UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s)' + \
            ' WHERE `id` = %s',
            (self.nowUnix(), session))

    def handleLoginFailed(self, session, args):
        self.query('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 0, args['username'], args['password'], self.nowUnix()))

    def handleLoginSucceeded(self, session, args):
        self.query('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 1, args['username'], args['password'], self.nowUnix()))

    def handleCommand(self, session, args):
        self.query('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), 1, args['input']))

    def handleUnknownCommand(self, session, args):
        self.query('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), 0, args['input']))

    def handleInput(self, session, args):
        self.query('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `realm`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), args['realm'], args['input']))

# vim: set sw=4 et:
