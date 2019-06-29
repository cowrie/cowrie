# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import absolute_import, division

import time
import uuid

from twisted.conch.telnet import TelnetTransport
from twisted.internet import reactor
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.telnet_proxy import client_transport
from cowrie.telnet_proxy.handler import TelnetHandler


class FrontendTelnetTransport(TelnetTransport, TimeoutMixin):
    def __init__(self):
        super().__init__()

        self.peer_ip = None
        self.peer_port = 0
        self.local_ip = None
        self.local_port = 0

        self.honey_ip = CowrieConfig().get('proxy', 'backend_telnet_host')
        self.honey_port = CowrieConfig().getint('proxy', 'backend_telnet_port')

        self.client = None
        self.frontendAuthenticated = False
        self.delayedPacketsToBackend = []

        self.telnetHandler = TelnetHandler(self)

    def connectionMade(self):
        self.transportId = uuid.uuid4().hex[:12]
        sessionno = self.transport.sessionno

        self.startTime = time.time()
        self.setTimeout(CowrieConfig().getint('honeypot', 'authentication_timeout', fallback=120))

        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port + 1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port

        # connection to the backend starts here
        client_factory = client_transport.BackendTelnetFactory()
        client_factory.server = self

        reactor.connectTCP(self.honey_ip, self.honey_port, client_factory,
                           bindAddress=('0.0.0.0', 0),
                           timeout=10)

        log.msg(eventid='cowrie.session.connect',
                format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]',
                src_ip=self.transport.getPeer().host,
                src_port=self.transport.getPeer().port,
                dst_ip=self.transport.getHost().host,
                dst_port=self.transport.getHost().port,
                session=self.transportId,
                sessionno='T{0}'.format(str(sessionno)),
                protocol='telnet')
        TelnetTransport.connectionMade(self)

    def dataReceived(self, data):
        self.telnetHandler.addPacket('frontend', data)

    def write(self, data):
        self.transport.write(data)

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg('Timeout reached in FrontendTelnetTransport')

        # close transports on both sides
        self.transport.loseConnection()
        self.client.transport.loseConnection()

        # signal that we're closing to the handler
        self.telnetHandler.close()

    def connectionLost(self, reason):
        """
        Fires on pre-authentication disconnects
        """
        self.setTimeout(None)
        TelnetTransport.connectionLost(self, reason)

        # close transport on backend
        self.client.transport.loseConnection()

        # signal that we're closing to the handler
        self.telnetHandler.close()

        duration = time.time() - self.startTime
        log.msg(eventid='cowrie.session.closed',
                format='Connection lost after %(duration)d seconds',
                duration=duration)

    def packet_buffer(self, payload):
        """
        We have to wait until we have a connection to the backend ready. Meanwhile, we hold packets from client
        to server in here.
        """
        if not self.client.backendConnected:
            # wait till backend connects to send packets to them
            log.msg('Connection to backend not ready, buffering packet from frontend')
            self.delayedPacketsToBackend.append(payload)
        else:
            if len(self.delayedPacketsToBackend) > 0:
                self.delayedPacketsToBackend.append(payload)
            else:
                self.client.transport.write(payload)
