# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from twisted.conch.ssh.common import getNS

from cowrie.ssh import userauth


# object is added for Python 2.7 compatibility (#1198) - as is super with args
class ProxySSHAuthServer(userauth.HoneyPotSSHUserAuthServer):
    def __init__(self):
        super().__init__()
        self.triedPassword = None

    def auth_password(self, packet):
        """
        Overridden to get password
        """
        self.triedPassword = getNS(packet[1:])[0]

        return super().auth_password(packet)

    def _cbFinishedAuth(self, result):
        """
        We only want to return a success to the user, no service needs to be set.
        Those will be proxied back to the backend.
        """
        self.transport.sendPacket(52, b"")
        self.transport.frontendAuthenticated = True

        # TODO store this somewhere else, and do not call from here
        if self.transport.sshParse.client:
            self.transport.sshParse.client.authenticateBackend(
                self.user, self.triedPassword
            )
