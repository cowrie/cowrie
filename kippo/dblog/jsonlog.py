#
# this module uses the dblog feature to create a JSON logfile
# ..so not exactly a dblog.
#

import datetime
import uuid
import json

from kippo.core import dblog
from twisted.python import log

class DBLogger(dblog.DBLogger):

    def start(self, cfg):
        self.outfile = file(cfg.get('database_jsonlog', 'logfile'), 'a')

    def write(self, session, logentry):
        _meta = {
                     'session' : session,
                     'sensor' : self.sensor,
                     'timestamp' : datetime.datetime.utcnow().isoformat() + 'Z'
                }
        logentry.update( _meta )
        json.dump( logentry,  self.outfile )
        self.outfile.write( '\n' )
        self.outfile.flush()

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid4().hex
        logentry = { 'message' : 'New connection: %s:%s' % (peerIP, peerPort), 'src_ip' : peerIP }
        self.sensor = self.getSensor() or hostIP
        self.write(sid, logentry )
        return sid

    def handleConnectionLost(self, session, args):
        logentry = { 'message': 'Connection lost' }
        self.write( session, logentry )

    def handleLoginFailed(self, session, args):
        logentry = { 'message' : 'Login failed [%s/%s]' % (args['username'], args['password']), 'username' : args['username'], 'password' : args['password'] }
        self.write( session, logentry )

    def handleLoginSucceeded(self, session, args):
        logentry = { 'message' : 'Login succeeded [%s/%s]' % (args['username'], args['password']), 'username' : args['username'], 'password' : args['password'] }
        self.write( session, logentry )

    def handleCommand(self, session, args):
        logentry = { 'message' : 'command [%s]' % (args['input'],), 'command' : args['input'] }
        self.write( session, logentry )

    def handleUnknownCommand(self, session, args):
        logentry = { 'message' : 'unknown command [%s]' % (args['input'],), 'command' : args['input'] }
        self.write( session, logentry )

    def handleInput(self, session, args):
        logentry = { 'message' : 'input [%s] @%s' % (args['input'], args['realm']), 'command' : args['input'] }
        self.write( session, logentry )

    def handleTerminalSize(self, session, args):
        logentry = { 'message' : 'Terminal size: %sx%s' % (args['width'], args['height']) }
        self.write( session, logentry )

    def handleClientVersion(self, session, args):
        logentry = { 'message' : 'Client version: [%s]' % (args['version']), 'client' : args['version'] }
        self.write( session, logentry )

    def handleFileDownload(self, session, args):
        logentry = { 'message' : 'File download: [%s] -> %s' % (args['url'], args['outfile']), 'url' : args['url'], 'shasum' : args['shasum'] }
        self.write( session, logentry )

# vim: set sw=4 et:
