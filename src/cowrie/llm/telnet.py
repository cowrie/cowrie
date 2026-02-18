# ABOUTME: Telnet session management for the LLM backend.
# ABOUTME: Handles Telnet connections using LLM-powered shell simulation.

from __future__ import annotations

import traceback

from twisted.conch.ssh import session
from twisted.conch.telnet import ECHO, SGA, TelnetBootstrapProtocol
from twisted.internet import interfaces, protocol
from twisted.internet.protocol import connectionDone
from twisted.python import failure, log
from zope.interface import implementer

from cowrie.insults import insults
from cowrie.llm import protocol as llmproto


class HoneyPotTelnetSession(TelnetBootstrapProtocol):
    id = 0  # telnet can only have 1 simultaneous session, unlike SSH

    def __init__(self, username, server):
        self.transportId = None
        self.windowSize = [40, 80]
        self.username = username.decode()
        self.server = server

        self.environ = {
            "LOGNAME": self.username,
            "USER": self.username,
            "SHELL": "/bin/bash",
            "HOME": "/root" if self.username == "root" else f"/home/{self.username}",
            "TMOUT": "1800",
        }

        if self.username == "root":
            self.environ["PATH"] = (
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        else:
            self.environ["PATH"] = (
                "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
            )

        # required because HoneyPotBaseProtocol relies on avatar.avatar.home
        self.avatar = self

    def connectionMade(self):
        processprotocol = TelnetSessionProcessProtocol(self)

        # If we are dealing with a proper Telnet client: enable server echo
        if self.transport.options:
            self.transport.willChain(SGA)
            self.transport.willChain(ECHO)

        self.protocol = insults.LoggingTelnetServerProtocol(
            llmproto.HoneyPotInteractiveTelnetProtocol, self
        )

        try:
            self.protocol.makeConnection(processprotocol)
            processprotocol.makeConnection(session.wrapProtocol(self.protocol))
        except Exception:
            log.msg(traceback.format_exc())

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        TelnetBootstrapProtocol.connectionLost(self, reason)
        self.server = None
        self.avatar = None
        self.protocol = None

    def logout(self) -> None:
        log.msg(f"avatar {self.username} logging out")


@implementer(interfaces.ITransport)
class TelnetSessionProcessProtocol(protocol.ProcessProtocol):
    """
    Both an IProcessProtocol and an ITransport.
    Transport to the remote endpoint and process protocol to the local subsystem.
    """

    def __init__(self, sess):
        self.session = sess
        self.lostOutOrErrFlag = False

    def outReceived(self, data: bytes) -> None:
        self.session.write(data)

    def errReceived(self, data: bytes) -> None:
        log.msg(f"Error received: {data.decode()}")

    def outConnectionLost(self) -> None:
        """
        EOF should only be sent when both STDOUT and STDERR have been closed.
        """
        if self.lostOutOrErrFlag:
            self.session.conn.sendEOF(self.session)
        else:
            self.lostOutOrErrFlag = True

    def errConnectionLost(self) -> None:
        self.outConnectionLost()

    def connectionLost(self, reason=None):
        self.session.loseConnection()
        self.session = None

    def processEnded(self, reason=None):
        log.msg(f"Process ended. Telnet Session disconnected: {reason}")
        self.session.loseConnection()

    def getHost(self):
        return self.session.transport.getHost()

    def getPeer(self):
        return self.session.transport.getPeer()

    def write(self, data):
        self.session.write(data)

    def writeSequence(self, seq):
        self.session.write(b"".join(seq))

    def loseConnection(self):
        self.session.loseConnection()
