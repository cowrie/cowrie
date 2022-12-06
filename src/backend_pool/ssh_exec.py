from __future__ import annotations

from twisted.conch.ssh import channel, common, connection, transport, userauth
from twisted.internet import defer, protocol
from twisted.internet import reactor


class PasswordAuth(userauth.SSHUserAuthClient):
    def __init__(self, user, password, conn):
        super().__init__(user, conn)
        self.password = password

    def getPassword(self, prompt=None):
        return defer.succeed(self.password)


class CommandChannel(channel.SSHChannel):
    name = b"session"

    def __init__(self, command, done_deferred, callback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.command = command
        self.done_deferred = done_deferred
        self.callback = callback

        self.data = b""

    def channelOpen(self, data):
        self.conn.sendRequest(self, "exec", common.NS(self.command), wantReply=True)

    def dataReceived(self, data: bytes) -> None:
        self.data += data

    def extReceived(self, dataType, data):
        self.data += data

    def closeReceived(self):
        self.conn.transport.loseConnection()
        self.done_deferred.callback(self.data)

        # call the request client callback, if any
        if self.callback:
            self.callback(self.data)


class ClientConnection(connection.SSHConnection):
    def __init__(self, cmd, done_deferred, callback):
        super().__init__()
        self.command = cmd
        self.done_deferred = done_deferred
        self.callback = callback

    def serviceStarted(self):
        self.openChannel(
            CommandChannel(self.command, self.done_deferred, self.callback, conn=self)
        )


class ClientCommandTransport(transport.SSHClientTransport):
    def __init__(self, username, password, command, done_deferred, callback):
        self.username = username
        self.password = password
        self.command = command
        self.done_deferred = done_deferred
        self.callback = callback

    def verifyHostKey(self, pub_key, fingerprint):
        return defer.succeed(True)

    def connectionSecure(self):
        self.requestService(
            PasswordAuth(
                self.username,
                self.password,
                ClientConnection(self.command, self.done_deferred, self.callback),
            )
        )


class ClientCommandFactory(protocol.ClientFactory):
    def __init__(self, username, password, command, done_deferred, callback):
        self.username = username
        self.password = password
        self.command = command
        self.done_deferred = done_deferred
        self.callback = callback

    def buildProtocol(self, addr):
        return ClientCommandTransport(
            self.username,
            self.password,
            self.command,
            self.done_deferred,
            self.callback,
        )


def execute_ssh(host, port, username, password, command, callback=None):
    done_deferred = defer.Deferred()

    factory = ClientCommandFactory(username, password, command, done_deferred, callback)
    reactor.connectTCP(host, port, factory)

    return done_deferred
