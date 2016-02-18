import sqlite3

from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.python import log

import cowrie.core.output
class Output(cowrie.core.output.Output):
    """
    docstring here
    """

    def __init__(self, cfg):
        self.cfg = cfg
        cowrie.core.output.Output.__init__(self, cfg)

    def start(self):
        """
        Start sqlite3 logging module using Twisted ConnectionPool.
        Need to be started with check_same_thread=False. See
        https://twistedmatrix.com/trac/ticket/3629.
        """
        sqlite_file = self.cfg.get('output_sqlite', 'db_file')
        try:
            self.db = adbapi.ConnectionPool('sqlite3',
                    database = sqlite_file, check_same_thread=False)
        except sqlite3.OperationalError as e:
            log.msg(e)

        self.db.start()
        
    def stop(self):
        """
        Close connection to db
        """
        self.db.close()

    def sqlerror(self, error):
        """
        docstring here
        """
        log.err('sqlite error')
        error.printTraceback()

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
                "SELECT `id` FROM `sensors` WHERE `ip` = ?", (self.sensor,))
            if r and r[0][0]:
                sensorid = r[0][0]
            else:
                yield self.db.runQuery(
                    'INSERT INTO `sensors` (`ip`) VALUES (?)', (self.sensor,))
                r = yield self.db.runQuery('SELECT LAST_INSERT_ROWID()')
                sensorid = int(r[0][0])
            self.simpleQuery(
                "INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`)"
                +  " VALUES (?, ?, ?, ?)",
                (entry["session"], entry["timestamp"],
                    sensorid, entry["src_ip"]))

        elif entry["eventid"] == 'cowrie.login.success':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (?, ?, ?, ?, ?)',
                (entry["session"], 1, entry['username'], entry['password'],
                entry["timestamp"]))

        elif entry["eventid"] == 'cowrie.login.failed':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (?, ?, ?, ?, ?)',
                (entry["session"], 0, entry['username'], entry['password'],
                entry["timestamp"]))

        elif entry["eventid"] == 'cowrie.command.success':
            print str(entry)
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (?, ?, ?, ?)',
                (entry["session"], entry["timestamp"],
                1, entry["input"]))

        elif entry["eventid"] == 'cowrie.command.failed':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (?, ?, ?, ?)',
                (entry["session"], entry["timestamp"],
                0, entry["input"]))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `downloads`' + \
                ' (`session`, `timestamp`, `url`, `outfile`, `shasum`)' + \
                ' VALUES (?, ?, ?, ?, ?)',
                (entry["session"], entry["timestamp"],
                entry['url'], entry['outfile'], entry['shasum']))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `realm`, `input`)' + \
                ' VALUES (?, ?, ?, ?)',
                (entry["session"], entry["timestamp"],
                entry["realm"], entry["input"]))

        elif entry["eventid"] == 'cowrie.client.version':
            r = yield self.db.runQuery(
                'SELECT `id` FROM `clients` WHERE `version` = ?', \
                (entry['version'],))
            if r and r[0][0]:
                id = int(r[0][0])
            else:
                yield self.db.runQuery(
                    'INSERT INTO `clients` (`version`) VALUES (?)', \
                    (entry['version'],))
                r = yield self.db.runQuery('SELECT LAST_INSERT_ROWID()')
                id = int(r[0][0])
            self.simpleQuery(
                'UPDATE `sessions` SET `client` = ? WHERE `id` = ?',
                (id, entry["session"]))

        elif entry["eventid"] == 'cowrie.client.size':
            self.simpleQuery(
                'UPDATE `sessions` SET `termsize` = ? WHERE `id` = ?',
                ('%sx%s' % (entry['width'], entry['height']),
                    entry["session"]))

        elif entry["eventid"] == 'cowrie.session.closed':
            self.simpleQuery(
                'UPDATE `sessions` SET `endtime` = ?' + \
                ' WHERE `id` = ?', (entry["timestamp"], entry["session"]))

        elif entry["eventid"] == 'cowrie.log.closed':
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`, `size`) VALUES (?, ?, ?)',
                (entry["session"], entry["ttylog"], entry["size"]))

        elif entry["eventid"] == 'cowrie.client.fingerprint':
            self.simpleQuery(
                'INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) VALUES (?, ?, ?)',
                (entry["session"], entry["username"], entry["fingerprint"]))

