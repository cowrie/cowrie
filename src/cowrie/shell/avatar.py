# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import absolute_import, division

from twisted.conch import avatar
from twisted.conch.interfaces import IConchUser, ISFTPServer, ISession
from twisted.conch.ssh import filetransfer as conchfiletransfer
from twisted.python import components, log

from zope.interface import implementer

from cowrie.core.config import CONFIG
from cowrie.shell import filetransfer
from cowrie.shell import pwd
from cowrie.shell import session as shellsession
from cowrie.ssh import forwarding
from cowrie.ssh import session as sshsession


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):

    def __init__(self, username, server):
        avatar.ConchUser.__init__(self)
        self.username = username.decode('utf-8')
        self.server = server

        self.channelLookup[b'session'] = sshsession.HoneyPotSSHSession

        try:
            pwentry = pwd.Passwd().getpwnam(self.username)
            self.uid = pwentry['pw_uid']
            self.gid = pwentry['pw_gid']
            self.home = pwentry['pw_dir']
        except Exception:
            self.uid = 1001
            self.gid = 1001
            self.home = '/home'

        # SFTP support enabled only when option is explicitly set
        try:
            if CONFIG.getboolean('ssh', 'sftp_enabled') == True:
                self.subsystemLookup[b'sftp'] = conchfiletransfer.FileTransferServer
        except ValueError as e:
            pass

        # SSH forwarding disabled only when option is explicitly set
        self.channelLookup[b'direct-tcpip'] = forwarding.cowrieOpenConnectForwardingClient
        try:
            if CONFIG.getboolean('ssh', 'forwarding') == False:
                del self.channelLookup[b'direct-tcpip']
        except Exception:
            pass

    def logout(self):
        log.msg("avatar {} logging out".format(self.username))


components.registerAdapter(filetransfer.SFTPServerForCowrieUser, CowrieUser, ISFTPServer)
components.registerAdapter(shellsession.SSHSessionForCowrieUser, CowrieUser, ISession)
