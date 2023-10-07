# Based on https://github.com/fjogstad/twisted-telnet-client
from __future__ import annotations

import re

from twisted.conch.telnet import StatefulTelnetProtocol, TelnetTransport
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory
from twisted.python import log


class TelnetConnectionError(Exception):
    pass


class TelnetClient(StatefulTelnetProtocol):
    def __init__(self):
        # output from server
        self.response: bytes = b""

        # callLater instance to wait until we have stop getting output for some time
        self.done_callback = None

        self.command: bytes | None = None

    def connectionMade(self):
        """
        Set rawMode since we do not receive the login and password prompt in line mode.
        We return to default line mode when we detect the prompt in the received data stream.
        """
        self.setRawMode()

    def rawDataReceived(self, data):
        """
        The login and password prompt on some systems are not received in lineMode.
        Therefore we do the authentication in raw mode and switch back to line mode
        when we detect the shell prompt.
        TODO: Need to handle authentication failure
        """
        if self.factory.prompt.strip() == rb"#":
            self.re_prompt = re.compile(rb"#")
        else:
            self.re_prompt = re.compile(self.factory.prompt.encode())

        if re.search(rb"([Ll]ogin:\s+$)", data):
            self.sendLine(self.factory.username.encode())
        elif re.search(rb"([Pp]assword:\s+$)", data):
            self.sendLine(self.factory.password.encode())
        elif self.re_prompt.search(data):
            self.setLineMode()

            # auth is done, send command to server
            self.send_command(self.transport.factory.command)

    def lineReceived(self, line: bytes) -> None:
        # ignore data sent by server before command is sent
        # ignore command echo from server
        if not self.command or line == self.command:
            return

        # trim control characters
        if line.startswith(b"\x1b"):
            line = line[4:]

        self.response += line + b"\r\n"

        # start countdown to command done (when reached, consider the output was completely received and close)
        if not self.done_callback:
            self.done_callback = reactor.callLater(0.5, self.close)  # type: ignore
        else:
            self.done_callback.reset(0.5)

    def send_command(self, command: str) -> None:
        """
        Sends a command via Telnet using line mode
        """
        self.command = command.encode()
        self.sendLine(self.command)  # ignore: attr-defined

    def close(self):
        """
        Sends exit to the Telnet server and closes connection.
        Fires the deferred with the command's output.
        """
        self.sendLine(b"exit")
        self.transport.loseConnection()

        # deferred to signal command's output was fully received
        self.factory.done_deferred.callback(self.response)

        # call the request client callback, if any
        if self.factory.callback:
            self.factory.callback(self.response)


class TelnetFactory(ClientFactory):
    def __init__(self, username, password, prompt, command, done_deferred, callback):
        self.username = username
        self.password = password
        self.prompt = prompt
        self.command = command

        # called on command done
        self.done_deferred = done_deferred
        self.callback = callback

    def buildProtocol(self, addr):
        transport = TelnetTransport(TelnetClient)
        transport.factory = self
        return transport

    def clientConnectionFailed(self, connector, reason):
        log.err(f"Telnet connection failed. Reason: {reason}")


class TelnetClientCommand:
    def __init__(self, callback, prompt, command):
        # callback to be called when execution is done
        self.callback = callback
        self.prompt = prompt
        self.command = command

    def connect(self, host, port, username, password):
        # deferred to signal command and its output is done
        done_deferred: defer.Deferred = defer.Deferred()

        # start connection to the Telnet server
        factory = TelnetFactory(
            username, password, self.prompt, self.command, done_deferred, self.callback
        )
        reactor.connectTCP(host, port, factory)

        return done_deferred


def execute_telnet(host, port, username, password, command, callback=None):
    """
    Executes a command over Telnet. For that, it performs authentication beforehand,
    and waits some time to get all of the output (slow machines might need the time
    parameter adjusted.

    Returns a deferred that is fired upon receiving the command's output.
    """
    telnet = TelnetClientCommand(callback, ":~#", command)
    return telnet.connect(host, port, username, password)
