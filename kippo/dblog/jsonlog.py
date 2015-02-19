# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import datetime
import uuid
import json

from ..core import dblog

class DBLogger(dblog.DBLogger):

    def __init__(self, cfg):
        self.sensor = ""
        self.outfile = ""
        dblog.DBLogger.__init__(self, cfg)

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
