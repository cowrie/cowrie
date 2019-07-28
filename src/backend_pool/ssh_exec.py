from twisted.conch.ssh import transport, connection, userauth, channel, common
from twisted.internet import defer, protocol, reactor


class PasswordAuth(userauth.SSHUserAuthClient):
    def __init__(self, user, password, conn):
        super().__init__(user, conn)
        self.password = password

    def getPassword(self, prompt=None):
        return defer.succeed(self.password)


class CommandChannel(channel.SSHChannel):
    name = 'session'

    def __init__(self, command, callback, callback_data, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.command = command
        self.callback = callback
        self.callback_data = callback_data

        self.data = b''

    def channelOpen(self, data):
        self.conn.sendRequest(self, 'exec', common.NS(self.command), wantReply=True)

    def dataReceived(self, data):
        self.data += data

    def extReceived(self, dataType, data):
        self.data += data

    def closeReceived(self):
        if self.callback is not None:
            self.callback(self.callback_data, self.data)


class ClientConnection(connection.SSHConnection):
    def __init__(self, cmd, callback, callback_data):
        super().__init__()
        self.command = cmd
        self.callback = callback
        self.callback_data = callback_data

    def serviceStarted(self):
        self.openChannel(CommandChannel(self.command, self.callback, self.callback_data, conn=self))


class ClientCommandTransport(transport.SSHClientTransport):
    def __init__(self, username, password, command, callback, callback_data):
        self.username = username
        self.password = password
        self.command = command
        self.callback = callback
        self.callback_data = callback_data

    def verifyHostKey(self, pub_key, fingerprint):
        return defer.succeed(True)

    def connectionSecure(self):
        self.requestService(PasswordAuth(self.username, self.password,
                                         ClientConnection(self.command, self.callback, self.callback_data)))


class ClientCommandFactory(protocol.ClientFactory):
    def __init__(self, username, password, command, callback, callback_data):
        self.username = username
        self.password = password
        self.command = command
        self.callback = callback
        self.callback_data = callback_data

    def buildProtocol(self, addr):
        return ClientCommandTransport(self.username, self.password, self.command, self.callback, self.callback_data)


def execute_ssh(host, port, username, password, command, callback=None, callback_data=None):
    factory = ClientCommandFactory(username, password, command, callback, callback_data)
    reactor.connectTCP(host, port, factory)
