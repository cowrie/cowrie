# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations


import time
import uuid

from twisted.conch.telnet import AlreadyNegotiating, TelnetTransport
from twisted.internet.protocol import connectionDone
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig


class CowrieTelnetTransport(TelnetTransport, TimeoutMixin):
    """
    CowrieTelnetTransport
    """

    def connectionMade(self):
        self.transportId: str = uuid.uuid4().hex[:12]
        sessionno = self.transport.sessionno
        self.startTime = time.time()
        self.setTimeout(
            CowrieConfig.getint("honeypot", "authentication_timeout", fallback=120)
        )

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

    def write(self, data):
        """
        Because of the presence of two ProtocolTransportMixin in the protocol
        stack once authenticated, I need to override write() and remove a \r
        otherwise we end up with \r\r\n on the wire.

        It is kind of a hack. I asked for a better solution here:
        http://stackoverflow.com/questions/35087250/twisted-telnet-server-how-to-avoid-nested-crlf
        """
        self.transport.write(data.replace(b"\r\n", b"\n"))

    def timeoutConnection(self) -> None:
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in CowrieTelnetTransport")
        if self.transport:
            self.transport.loseConnection()

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Fires on pre-authentication disconnects
        """
        self.setTimeout(None)
        TelnetTransport.connectionLost(self, reason)
        duration = time.time() - self.startTime
        log.msg(
            eventid="cowrie.session.closed",
            format="Connection lost after %(duration)d seconds",
            duration=duration,
        )

    def willChain(self, option):
        return self._chainNegotiation(None, self.will, option)

    def wontChain(self, option):
        return self._chainNegotiation(None, self.wont, option)

    def doChain(self, option):
        return self._chainNegotiation(None, self.do, option)

    def dontChain(self, option):
        return self._chainNegotiation(None, self.dont, option)

    def _handleNegotiationError(self, f, func, option):
        if f.type is AlreadyNegotiating:
            s = self.getOptionState(option)
            if func in (self.do, self.dont):
                s.him.onResult.addCallback(self._chainNegotiation, func, option)
                s.him.onResult.addErrback(self._handleNegotiationError, func, option)
            if func in (self.will, self.wont):
                s.us.onResult.addCallback(self._chainNegotiation, func, option)
                s.us.onResult.addErrback(self._handleNegotiationError, func, option)
        # We only care about AlreadyNegotiating, everything else can be ignored
        # Possible other types include OptionRefused, AlreadyDisabled, AlreadyEnabled, ConnectionDone, ConnectionLost
        elif f.type is AssertionError:
            log.msg(
                "Client tried to illegally refuse to disable an option; ignoring, but undefined behavior may result"
            )
            # TODO: Is ignoring this violation of the protocol the proper behavior?
            # Should the connection be terminated instead?
            # The telnetd package on Ubuntu (netkit-telnet) does all negotiation before sending the login prompt,
            # but does handle client-initiated negotiation at any time.

    def _chainNegotiation(self, res, func, option):
        return func(option).addErrback(self._handleNegotiationError, func, option)
