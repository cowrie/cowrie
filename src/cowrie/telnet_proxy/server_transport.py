# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations

import time
import uuid

from twisted.conch.telnet import TelnetTransport
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.telnet_proxy import client_transport
from cowrie.telnet_proxy.handler import TelnetHandler


# object is added for Python 2.7 compatibility (#1198) - as is super with args
class FrontendTelnetTransport(TimeoutMixin, TelnetTransport):
    def __init__(self):
        super().__init__()

        self.peer_ip = None
        self.peer_port = 0
        self.local_ip = None
        self.local_port = 0

        self.startTime = None

        self.pool_interface = None
        self.client = None
        self.frontendAuthenticated = False
        self.delayedPacketsToBackend = []

        # this indicates whether the client effectively connected to the backend
        # if they did we recycle the VM, else the VM can be considered "clean"
        self.client_used_backend = False

        # only used when simple proxy (no pool) set
        self.backend_ip = None
        self.backend_port = None

        self.telnetHandler = TelnetHandler(self)

    def connectionMade(self):
        self.transportId = uuid.uuid4().hex[:12]
        sessionno = self.transport.sessionno

        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port + 1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port

        log.msg(
            eventid="cowrie.session.connect",
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=self.transport.getPeer().host,
            src_port=self.transport.getPeer().port,
            dst_ip=self.transport.getHost().host,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno=f"T{sessionno!s}",
            protocol="telnet",
        )

        TelnetTransport.connectionMade(self)

        # if we have a pool connect to it and later request a backend, else just connect to a simple backend
        # when pool is set we can just test self.pool_interface to the same effect of getting the config
        proxy_backend = CowrieConfig.get("proxy", "backend", fallback="simple")

        if proxy_backend == "pool":
            # request a backend
            d = self.factory.pool_handler.request_interface()
            d.addCallback(self.pool_connection_success)
            d.addErrback(self.pool_connection_error)
        else:
            # simply a proxy, no pool
            backend_ip = CowrieConfig.get("proxy", "backend_telnet_host")
            backend_port = CowrieConfig.getint("proxy", "backend_telnet_port")
            self.connect_to_backend(backend_ip, backend_port)

    def pool_connection_error(self, reason):
        log.msg(
            f"Connection to backend pool refused: {reason.value}. Disconnecting frontend..."
        )
        self.transport.loseConnection()

    def pool_connection_success(self, pool_interface):
        log.msg("Connected to backend pool")

        self.pool_interface = pool_interface
        self.pool_interface.set_parent(self)

        # now request a backend
        self.pool_interface.send_vm_request(self.peer_ip)

    def received_pool_data(self, operation, status, *data):
        if operation == b"r":
            honey_ip = data[0]
            snapshot = data[1]
            telnet_port = data[3]

            log.msg(f"Got backend data from pool: {honey_ip.decode()}:{telnet_port}")
            log.msg(f"Snapshot file: {snapshot.decode()}")

            self.connect_to_backend(honey_ip, telnet_port)

    def backend_connection_error(self, reason):
        log.msg(
            f"Connection to honeypot backend refused: {reason.value}. Disconnecting frontend..."
        )
        self.transport.loseConnection()

    def backend_connection_success(self, backendTransport):
        log.msg("Connected to honeypot backend")

        self.startTime = time.time()
        self.setTimeout(
            CowrieConfig.getint("honeypot", "authentication_timeout", fallback=120)
        )

    def connect_to_backend(self, ip, port):
        # connection to the backend starts here
        client_factory = client_transport.BackendTelnetFactory()
        client_factory.server = self

        point = TCP4ClientEndpoint(reactor, ip, port, timeout=20)
        d = point.connect(client_factory)
        d.addCallback(self.backend_connection_success)
        d.addErrback(self.backend_connection_error)

    def dataReceived(self, data: bytes) -> None:
        self.telnetHandler.addPacket("frontend", data)

    def write(self, data):
        self.transport.write(data)

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in FrontendTelnetTransport")

        # close transports on both sides
        if self.transport:
            self.transport.loseConnection()

        if self.client and self.client.transport:
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
        if self.client and self.client.transport:
            self.client.transport.loseConnection()

        # signal that we're closing to the handler
        self.telnetHandler.close()

        if self.pool_interface:
            # free VM from pool (VM was used if auth was performed successfully)
            self.pool_interface.send_vm_free(self.telnetHandler.authDone)

            # close transport connection to pool
            self.pool_interface.transport.loseConnection()

        if self.startTime is not None:  # startTime is not set when auth fails
            duration = time.time() - self.startTime
            log.msg(
                eventid="cowrie.session.closed",
                format="Connection lost after %(duration)d seconds",
                duration=duration,
            )

    def packet_buffer(self, payload):
        """
        We have to wait until we have a connection to the backend ready. Meanwhile, we hold packets from client
        to server in here.
        """
        if not self.client.backendConnected:
            # wait till backend connects to send packets to them
            log.msg("Connection to backend not ready, buffering packet from frontend")
            self.delayedPacketsToBackend.append(payload)
        else:
            if len(self.delayedPacketsToBackend) > 0:
                self.delayedPacketsToBackend.append(payload)
            else:
                self.client.transport.write(payload)
