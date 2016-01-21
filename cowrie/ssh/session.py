# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os

from zope.interface import implementer

import twisted
from twisted.conch.interfaces import ISession
from twisted.conch.ssh import session
from twisted.python import log
from twisted.conch.ssh.common import getNS

from cowrie.core import protocol
from cowrie.core import pwd
from cowrie.insults import insults


class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        #self.__dict__['request_auth_agent_req@openssh.com'] = self.request_agent


    def request_env(self, data):
        """
        """
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg(eventid='cowrie.client.var', format='request_env: %(name)s=%(value)s',
            name=name, value=value)
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.environ[name] = value
        return 0


    def request_agent(self, data):
        """
        """
        log.msg('request_agent: %s' % (repr(data),))
        return 0


    def request_x11_req(self, data):
        """
        """
        log.msg('request_x11: %s' % (repr(data),))
        return 0


    def closed(self):
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        session.SSHSession.closed(self)
        self.client = None


    def sendEOF(self):
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)


    def sendClose(self):
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)


    def channelClosed(self):
        """
        """
        log.msg("Called channelClosed in SSHSession")



@implementer(ISession)
class SSHSessionForCowrieUser(object):
    """
    """

    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """
        self.protocol = None
        self.avatar = avatar
        self.server = avatar.server
        self.cfg = avatar.cfg
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username
        self.environ = {
            'LOGNAME': self.username,
            'USER': self.username,
            'HOME': self.avatar.home,
            'TMOUT': '1800'}
        if self.uid==0:
            self.environ['PATH']='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        else:
            self.environ['PATH']='/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'

    def openShell(self, processprotocol):
        """
        """
        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, self)
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))


    def getPty(self, terminal, windowSize, attrs):
        """
        """
        self.environ['TERM'] = terminal
        log.msg(eventid='cowrie.client.size', width=windowSize[0], height=windowSize[1],
            format='Terminal Size: %(width)s %(height)s')
        self.windowSize = windowSize
        return None


    def execCommand(self, processprotocol, cmd):
        """
        """
        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd)
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))


    def closed(self):
        """
        this is reliably called on both logout and disconnect
        we notify the protocol here we lost the connection
        """
        if self.protocol:
            self.protocol.connectionLost("disconnected")
            self.protocol = None


    def eofReceived(self):
        """
        """
        if self.protocol:
            self.protocol.eofReceived()


    def windowChanged(self, windowSize):
        """
        """
        self.windowSize = windowSize

