from __future__ import absolute_import, division

import json
import uuid

from twisted.application import service
from twisted.python import log
from twisted.words.protocols.jabber import jid
from twisted.words.protocols.jabber.jid import JID

from wokkel import muc
from wokkel.client import XMPPClient
from wokkel.xmppim import AvailablePresence

from cowrie.core import dblog
from cowrie.core.config import CONFIG


class XMPPLoggerProtocol(muc.MUCClient):

    def __init__(self, rooms, nick):
        muc.MUCClient.__init__(self)
        self.server = rooms.host
        self.jrooms = rooms
        self._roomOccupantMap = {}
        log.msg(rooms.user)
        log.msg(rooms.host)
        self.nick = nick
        self.last = {}
        self.activity = None

    def connectionInitialized(self):
        """
        The bot has connected to the xmpp server, now try to join the room.
        """
        self.join(self.jrooms, self.nick)

    def joinedRoom(self, room):
        log.msg('Joined room %s' % room.name)

    def connectionMade(self):
        log.msg('Connected!')

        # send initial presence
        self.send(AvailablePresence())

    def connectionLost(self):
        log.msg('Disconnected!')

    def onMessage(self, msg):
        pass

    def receivedGroupChat(self, room, user, body):
        pass

    def receivedHistory(self, room, user, body, dely, frm=None):
        pass


class DBLogger(dblog.DBLogger):
    def start(self):
        from random import choice
        import string

        server = CONFIG.get('database_xmpp', 'server')
        user = CONFIG.get('database_xmpp', 'user')
        password = CONFIG.get('database_xmpp', 'password')
        muc = CONFIG.get('database_xmpp', 'muc')
        channels = {}
        for i in ('createsession', 'connectionlost', 'loginfailed',
                  'loginsucceeded', 'command', 'clientversion'):
            x = CONFIG.get('database_xmpp', 'signal_' + i)
            if x not in channels:
                channels[x] = []
            channels[x].append(i)

        resource = ''.join([choice(string.ascii_letters) for i in range(8)])
        jid = user + '/' + resource
        application = service.Application('honeypot')
        self.run(application, jid, password, JID(None, [muc, server, None]), channels)

    def run(self, application, jidstr, password, muc, channels):
        self.xmppclient = XMPPClient(JID(jidstr), password)
        if CONFIG.has_option('database_xmpp', 'debug') and CONFIG.getboolean('database_xmpp', 'debug'):
            self.xmppclient.logTraffic = True  # DEBUG HERE
        (user, host, resource) = jid.parse(jidstr)
        self.muc = XMPPLoggerProtocol(
            muc, user + '-' + resource)
        self.muc.setHandlerParent(self.xmppclient)
        self.xmppclient.setServiceParent(application)
        self.signals = {}
        for channel in channels:
            for signal in channels[channel]:
                self.signals[signal] = channel
        self.anonymous = True
        self.xmppclient.startService()

    def broadcast(self, msgtype, msg):
        if msgtype in self.signals:
            self.report(msgtype, msg)

    def report(self, msgtype, xmsg):
        msg = {}
        msg['type'] = msgtype
        msg['message'] = xmsg
        msgJson = json.dumps(msg, indent=5)
        self.muc.groupChat(self.muc.jrooms, msgJson)

    # We have to return an unique ID
    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        session = uuid.uuid4().hex
        ses = {}
        ses['session'] = session
        ses['remote_host'] = peerIP
        ses['remote_port'] = str(peerPort)
        if self.anonymous:
            ses['local_host'] = '127.0.0.1'
        else:
            ses['local_host'] = hostIP
        ses['local_port'] = str(hostPort)

        self.broadcast('createsession', ses)
        return session

    def handleTTYLogOpened(self, session, args):
        pass

    def handleConnectionLost(self, session, args):
        ses = {}
        ses['session'] = session
        self.broadcast('connectionlost', ses)

    def handleLoginFailed(self, session, args):
        ses = {}
        ses['session'] = session
        ses['username'] = args['username']
        ses['password'] = args['password']
        self.broadcast('loginfailed', ses)

    def handleLoginSucceeded(self, session, args):
        ses = {}
        ses['session'] = session
        ses['username'] = args['username']
        ses['password'] = args['password']
        self.broadcast('loginsucceeded', ses)

    def handleCommand(self, session, args):
        ses = {}
        ses['session'] = session
        ses['command'] = 'known'
        ses['input'] = args['input']
        self.broadcast('command', ses)

    def handleUnknownCommand(self, session, args):
        ses = {}
        ses['session'] = session
        ses['command'] = 'unknown'
        ses['input'] = args['input']
        self.broadcast('command', ses)

    def handleInput(self, session, args):
        ses = {}
        ses['session'] = session
        ses['realm'] = args['realm']
        ses['input'] = args['input']
        self.broadcast('input', ses)

    def handleTerminalSize(self, session, args):
        pass

    def handleClientVersion(self, session, args):
        ses = {}
        ses['session'] = session
        ses['version'] = args['version']
        self.broadcast('clientversion', ses)
