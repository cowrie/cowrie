# Copyright (c) 2024 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information


from __future__ import annotations

from zope.interface import implementer

from twisted.conch import avatar
from twisted.conch.error import ConchError
from twisted.conch.interfaces import IConchUser, ISession, ISFTPServer
from twisted.conch.ssh import filetransfer as conchfiletransfer
from twisted.conch.ssh.connection import OPEN_UNKNOWN_CHANNEL_TYPE
from twisted.python import components, log

from cowrie.core.config import CowrieConfig
from cowrie.llm import server
from cowrie.llm import session as llmsession
from cowrie.ssh import session as sshsession


@implementer(IConchUser)
class CowrieUser(avatar.ConchUser):
    def __init__(self, username: bytes, server: server.CowrieServer) -> None:
        avatar.ConchUser.__init__(self)
        self.username: str = username.decode("utf-8")
        self.server = server
        self.channelLookup[b"session"] = sshsession.HoneyPotSSHSession

    def logout(self) -> None:
        log.msg(f"avatar {self.username} logging out")

    def lookupChannel(self, channelType, windowSize, maxPacket, data):
        """
        Override this to get more info on the unknown channel
        """
        klass = self.channelLookup.get(channelType, None)
        if not klass:
            raise ConchError(
                OPEN_UNKNOWN_CHANNEL_TYPE, f"unknown channel: {channelType}"
            )
        else:
            return klass(
                remoteWindow=windowSize,
                remoteMaxPacket=maxPacket,
                data=data,
                avatar=self,
            )


components.registerAdapter(llmsession.SSHSessionForCowrieUser, CowrieUser, ISession)
