# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from zope.interface import implementer

import twisted
from twisted.conch import avatar
from twisted.conch.interfaces import IConchUser, ISession, ISFTPServer
from twisted.conch.ssh import filetransfer as conchfiletransfer
from twisted.python import log, components

from cowrie.core import pwd
from cowrie.ssh import session
from cowrie.ssh import filetransfer
from cowrie.ssh import forwarding


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):
    """
    """

    def __init__(self, username, server):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.server = server
        self.cfg = self.server.cfg

        self.channelLookup.update(
            {"session": session.HoneyPotSSHSession,
             "direct-tcpip": forwarding.CowrieOpenConnectForwardingClient})

        try:
            pwentry = pwd.Passwd(self.cfg).getpwnam(self.username)
            self.uid = pwentry["pw_uid"]
            self.gid = pwentry["pw_gid"]
            self.home = pwentry["pw_dir"]
        except:
            self.uid = 1001
            self.gid = 1001
            self.home = '/home'

        # Sftp support enabled only when option is explicitly set
        try:
            if (self.cfg.get('honeypot', 'sftp_enabled') == "true"):
                self.subsystemLookup['sftp'] = conchfiletransfer.FileTransferServer
        except:
            pass


    def logout(self):
        """
        """
        log.msg('avatar {} logging out'.format(self.username))


components.registerAdapter(filetransfer.SFTPServerForCowrieUser, CowrieUser, ISFTPServer)
components.registerAdapter(session.SSHSessionForCowrieUser, CowrieUser, ISession)

