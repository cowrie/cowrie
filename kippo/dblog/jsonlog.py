#
# this module uses the dblog feature to create a "traditional" looking logfile
# ..so not exactly a dblog.
#

import datetime
import uuid
import json

from kippo.core import dblog
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.outfile = file(cfg.get('database_jsonlog', 'logfile'), 'a')

    def write(self, session, msg):
        json.dump(  { 'message' : msg, 'session' : session, 'timestamp' : datetime.datetime.now().isoformat() }, self.outfile )
        self.outfile.write( '\n' )
        self.outfile.flush()

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid4().hex
        sensorname = self.getSensor() or hostIP
        self.write(sid, 'New connection: %s:%s' % (peerIP, peerPort))
        return sid

    def handleConnectionLost(self, session, args):
        self.write(session, 'Connection lost')

    def handleLoginFailed(self, session, args):
        self.write(session, 'Login failed [%s/%s]' % \
            (args['username'], args['password']))

    def handleLoginSucceeded(self, session, args):
        self.write(session, 'Login succeeded [%s/%s]' % \
            (args['username'], args['password']))

    def handleCommand(self, session, args):
        self.write(session, 'Command [%s]' % (args['input'],))

    def handleUnknownCommand(self, session, args):
        self.write(session, 'Unknown command [%s]' % (args['input'],))

    def handleInput(self, session, args):
        self.write(session, 'Input [%s] @%s' % (args['input'], args['realm']))

    def handleTerminalSize(self, session, args):
        self.write(session, 'Terminal size: %sx%s' % \
            (args['width'], args['height']))

    def handleClientVersion(self, session, args):
        self.write(session, 'Client version: [%s]' % (args['version'],))

    def handleFileDownload(self, session, args):
        self.write(session, 'File download: [%s] -> %s' % \
            (args['url'], args['outfile']))

# vim: set sw=4 et:
