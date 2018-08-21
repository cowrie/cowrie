from __future__ import absolute_import, division

from configparser import NoOptionError

from twisted.conch import avatar
from twisted.conch.interfaces import IConchUser, ISession
from twisted.python import components, log

from zope.interface import implementer

from cowrie.core.config import CONFIG
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
        try:
            if CONFIG.getboolean('ssh', 'forwarding') is False:
                del self.channelLookup[b'direct-tcpip']
        except NoOptionError:
            pass

    def logout(self):
        log.msg('avatar {} logging out'.format(self.username))


components.registerAdapter(shellsession.SSHSessionForCowrieUser, CowrieUser, ISession)
