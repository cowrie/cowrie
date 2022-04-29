# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# All rights reserved.

from __future__ import annotations

from twisted.conch.telnet import TelnetTransport
from twisted.internet import protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log


class BackendTelnetTransport(TelnetTransport, TimeoutMixin):
    def __init__(self):
        # self.delayedPacketsToFrontend = []
        self.backendConnected = False
        self.telnetHandler = None
        super().__init__()

    def connectionMade(self):
        log.msg(f"Connected to Telnet backend at {self.transport.getPeer().host}")
        self.telnetHandler = self.factory.server.telnetHandler
        self.telnetHandler.setClient(self)

        self.backendConnected = True
        self.factory.server.client = self

        for packet in self.factory.server.delayedPacketsToBackend:
            self.transport.write(packet)
        self.factory.server.delayedPacketsToBackend = []

        super(TelnetTransport, self).connectionMade()
        # TODO timeout if no backend available

    def connectionLost(self, reason):
        # close transport on frontend
        self.factory.server.loseConnection()

        # signal that we're closing to the handler
        self.telnetHandler.close()

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in BackendTelnetTransport")

        # close transports on both sides
        self.transport.loseConnection()
        self.factory.server.transport.loseConnection()

        # signal that we're closing to the handler
        self.telnetHandler.close()

    def dataReceived(self, data):
        self.telnetHandler.addPacket("backend", data)

    def write(self, data):
        self.transport.write(data)

    def packet_buffer(self, payload):
        """
        We can only proceed if authentication has been performed between client and proxy.
        Meanwhile we hold packets in here.
        """
        self.factory.server.transport.write(payload)


class BackendTelnetFactory(protocol.ClientFactory):
    protocol = BackendTelnetTransport
