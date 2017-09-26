# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import os

from zope.interface import implementer

from twisted.python import log
from twisted.conch.interfaces import ISession
from twisted.conch.ssh import session

from cowrie.shell import protocol
from cowrie.insults import insults


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
            'SHELL': '/bin/bash',
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

