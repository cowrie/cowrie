from slackclient import SlackClient
import sys
import os
from cowrie.core import dblog
import time
import uuid

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.slack_channel = cfg.get('database_slack', 'channel')
        #self.slack_token = os.environ["SLACK_API_TOKEN"]
        self.slack_token = cfg.get('database_slack', 'token')

    def write(self, session, msg):
        self.sc = SlackClient(self.slack_token)
        self.sc.api_call(
            "chat.postMessage",
            channel=self.slack_channel,
            text="%s %s %s"%(time.strftime('%Y-%m-%d %H:%M:%S'),session,msg)
        )

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
        self.write(session, 'File download: [%s] -> %s with SHA-256 %s' % \
            (args['url'], args['outfile'], args['shasum']))
