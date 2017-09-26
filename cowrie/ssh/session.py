# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import os

from zope.interface import implementer

from twisted.python import log
from twisted.conch.ssh import session
from twisted.conch.ssh.common import getNS


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

