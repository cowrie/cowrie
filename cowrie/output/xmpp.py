
from __future__ import division, absolute_import

import uuid
import json

from twisted.words.xish import domish
from twisted.python import log
from twisted.words.protocols.jabber.jid import JID
import cowrie.core.output
from wokkel.xmppim import AvailablePresence
from wokkel import muc
from cowrie.core.config import CONFIG

class XMPPLoggerProtocol(muc.MUCClient):

    def __init__(self, rooms, server, nick):
        muc.MUCClient.__init__(self)
        self.server   = rooms.host
        self.jrooms = rooms
        self._roomOccupantMap = {}
        log.msg(rooms.user)
        log.msg(rooms.host)
        self.nick     = nick
        self.last     = {}
        self.activity = None

    def connectionInitialized(self):
        """The bot has connected to the xmpp server, now try to join the room.
        """
        self.join(self.jrooms, self.nick);

    def joinedRoom(self, room):
        log.msg('Joined room {}'.format(room.name))

    def connectionMade(self):
        log.msg('Connected!')

        # send initial presence
        self.send(AvailablePresence())

    def connectionLost(self, reason):
        log.msg('Disconnected!')

    def onMessage(self, msg):
        pass

    def receivedGroupChat(self, room, user, body):
        pass

    def receivedHistory(self, room, user, body, dely, frm=None):
        pass

from twisted.internet import defer
from twisted.application import service
from twisted.words.protocols.jabber import jid
from wokkel.client import XMPPClient
from cowrie.core import dblog
from twisted.words.xish import domish


class Output(cowrie.core.output.Output):

    def __init__(self):
        cowrie.core.output.Output.__init__(self)

    def start(self):
        from random import choice
        import string

        server      = CONFIG.get('output_xmpp', 'server')
        user       =  CONFIG.get('output_xmpp', 'user')
        password    = CONFIG.get('output_xmpp', 'password')
        muc         = CONFIG.get('output_xmpp', 'muc')
        resource = ''.join([choice(string.ascii_letters)
                            for i in range(8)])
        jid = user + '/' + resource
        application = service.Application('honeypot')
        self.run(application, jid, password,JID(None,[muc,server,None]), server)

    def run(self, application, jidstr, password, muc, server):

        self.xmppclient = XMPPClient(JID(jidstr), password)
        if CONFIG.has_option('output_xmpp', 'debug') and \
                CONFIG.getboolean('output_xmpp', 'debug') == True:
            self.xmppclient.logTraffic = True # DEBUG HERE
        (user, host, resource) = jid.parse(jidstr)
        self.muc = XMPPLoggerProtocol(
            muc, server, user + '-' + resource)
        self.muc.setHandlerParent(self.xmppclient)
        self.xmppclient.setServiceParent(application)
        self.anonymous = True
        self.xmppclient.startService()

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]
            elif i == "time":
                del logentry[i]
        msgJson = json.dumps(logentry,indent=5)

        self.muc.groupChat(self.muc.jrooms, msgJson)

    def stop(self):
        self.xmppclient.stopService()

# vim: set sw=4 et:
