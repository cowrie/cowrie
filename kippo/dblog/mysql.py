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

    def createSession(self, ip):
        sql = 'INSERT INTO `session` (`starttime`, `sensor`, `ip`)' + \
            ' VALUES (FROM_UNIXTIME(%s), %s, %s)'
        params = (self.nowUnix(), self.sensor, ip)
        cursor = self.db.cursor()
        cursor.execute(sql, params)
        return int(cursor.lastrowid)

    def handleConnectionLost(self, session, args):
        ttylog = None
        if session in self.ttylogs:
            f = file(self.ttylogs[session])
            ttylog = f.read()
            f.close()
        sql = 'UPDATE `session` SET `endtime` = FROM_UNIXTIME(%s)' + \
            ', `ttylog` = %s WHERE `id` = %s'
        params = (self.nowUnix(), ttylog, session)
        cursor = self.db.cursor()
        cursor.execute(sql, params)

    def handleLoginFailed(self, session, args):
        sql = 'INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))'
        params = (session, 0, args['username'], args['password'],
            self.nowUnix())
        cursor = self.db.cursor()
        cursor.execute(sql, params)

    def handleLoginSucceeded(self, session, args):
        sql = 'INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))'
        params = (session, 1, args['username'], args['password'],
            self.nowUnix())
        cursor = self.db.cursor()
        cursor.execute(sql, params)

    def handleCommand(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), 1, args['input'])
        cursor = self.db.cursor()
        cursor.execute(sql, params)

    def handleUnknownCommand(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), 0, args['input'])
        cursor = self.db.cursor()
        cursor.execute(sql, params)

    def handleInput(self, session, args):
        sql = 'INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `realm`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)'
        params = (session, self.nowUnix(), args['realm'], args['input'])
        cursor = self.db.cursor()
        cursor.execute(sql, params)

# vim: set sw=4 et:
