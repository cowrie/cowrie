# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import absolute_import, division

from twisted.conch import avatar
from twisted.conch.interfaces import IConchUser, ISession
from twisted.python import components, log

from zope.interface import implementer

from cowrie.core.config import CowrieConfig
from cowrie.proxy import session as proxysession
from cowrie.shell import session as shellsession
from cowrie.ssh import forwarding


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):

    def __init__(self, username, server):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.server = server

        self.channelLookup[b'session'] = proxysession.ProxySSHSession

        # TODO: Is SFTP still supported? Check git commit 30949e0 for cleaned up code

        # SSH forwarding disabled only when option is explicitly set
        self.channelLookup[b'direct-tcpip'] = forwarding.cowrieOpenConnectForwardingClient
        if CowrieConfig().getboolean('ssh', 'forwarding', fallback=False) is False:
            del self.channelLookup[b'direct-tcpip']

    def logout(self):
        log.msg('avatar {} logging out'.format(self.username))


components.registerAdapter(shellsession.SSHSessionForCowrieUser, CowrieUser, ISession)
