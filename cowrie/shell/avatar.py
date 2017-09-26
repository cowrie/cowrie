# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

from zope.interface import implementer

from twisted.conch import avatar
from twisted.conch.interfaces import IConchUser, ISession, ISFTPServer
from twisted.conch.ssh import filetransfer as conchfiletransfer
from twisted.python import log, components

from cowrie.ssh import session as sshsession
from cowrie.ssh import forwarding
from cowrie.proxy import session as proxysession
from cowrie.shell import session as shellsession
from cowrie.shell import pwd
from cowrie.shell import filetransfer


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):
    """
    """

    def __init__(self, username, server):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.server = server
        self.cfg = self.server.cfg

        try:
            if self.cfg.get('honeypot', 'backend') == "proxy":
                self.channelLookup[b'session'] = proxysession.ProxySSHSession
            else:
                self.channelLookup[b'session'] = sshsession.HoneyPotSSHSession
        except:
            self.channelLookup[b'session'] = sshsession.HoneyPotSSHSession

        try:
            pwentry = pwd.Passwd(self.cfg).getpwnam(self.username)
            self.uid = pwentry["pw_uid"]
            self.gid = pwentry["pw_gid"]
            self.home = pwentry["pw_dir"]
        except:
            self.uid = 1001
            self.gid = 1001
            self.home = '/home'

        # SFTP support enabled only when option is explicitly set
        try:
            if self.cfg.getboolean('ssh', 'sftp_enabled') == True:
                self.subsystemLookup[b'sftp'] = conchfiletransfer.FileTransferServer
        except ValueError as e:
            pass

        # SSH forwarding disabled only when option is explicitly set
        self.channelLookup[b'direct-tcpip'] = forwarding.cowrieOpenConnectForwardingClient
        try:
            if self.cfg.getboolean('ssh', 'forwarding') == False:
                del self.channelLookup[b'direct-tcpip']
        except:
            pass


    def logout(self):
        """
        """
        log.msg('avatar {} logging out'.format(self.username))


components.registerAdapter(filetransfer.SFTPServerForCowrieUser, CowrieUser, ISFTPServer)
components.registerAdapter(shellsession.SSHSessionForCowrieUser, CowrieUser, ISession)

