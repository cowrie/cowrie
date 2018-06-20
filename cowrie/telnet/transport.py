# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import division, absolute_import

import struct
import time
import uuid

from twisted.python import log
from twisted.internet import protocol
from twisted.conch.telnet import AuthenticatingTelnetProtocol, ECHO, \
                                 ITelnetProtocol, \
                                 SGA, NAWS, LINEMODE, TelnetTransport, AlreadyNegotiating
from twisted.protocols.policies import TimeoutMixin

from cowrie.core.credentials import UsernamePasswordIP
from cowrie.core.config import CONFIG


class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """
    tac = None

    # TODO logging clarity can be improved: see what SSH does
    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'T'+str(args['sessionno'])
        for dblog in self.tac.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)


    def startFactory(self):
        """
        """
        try:
            honeyfs = CONFIG.get('honeypot', 'contents_path')
            issuefile = honeyfs + "/etc/issue.net"
            self.banner = open(issuefile, 'rb').read()
        except IOError:
            self.banner = ""

        # For use by the uptime command
        self.starttime = time.time()

        # hook protocol
        self.protocol = lambda: CowrieTelnetTransport(HoneyPotTelnetAuthProtocol,
                                         self.portal)
        protocol.ServerFactory.startFactory(self)
        log.msg("Ready to accept Telnet connections")


    def stopFactory(self):
        """
        Stop output plugins
        """
        protocol.ServerFactory.stopFactory(self)



class HoneyPotTelnetAuthProtocol(AuthenticatingTelnetProtocol):
    """
    TelnetAuthProtocol that takes care of Authentication. Once authenticated this
    protocol is replaced with HoneyPotTelnetSession.
    """

    loginPrompt = b'login: '
    passwordPrompt = b'Password: '
    windowSize = [40, 80]

    def connectionMade(self):
        """
        """
        self.transport.negotiationMap[NAWS] = self.telnet_NAWS
        # Initial option negotation. Want something at least for Mirai
        for opt in (NAWS,):
            self.transport.doChain(opt).addErrback(log.err)

        # I need to doubly escape here since my underlying
        # CowrieTelnetTransport hack would remove it and leave just \n
        self.transport.write(self.factory.banner.replace(b'\n', b'\r\r\n'))
        self.transport.write(self.loginPrompt)


    def connectionLost(self, reason):
        """
        Fires on pre-authentication disconnects
        """
        AuthenticatingTelnetProtocol.connectionLost(self, reason)


    def telnet_User(self, line):
        """
        Overridden to conditionally kill 'WILL ECHO' which confuses clients
        that don't implement a proper Telnet protocol (most malware)
        """
        self.username = line  # .decode()
        # only send ECHO option if we are chatting with a real Telnet client
        #if self.transport.options: <-- doesn't work
        self.transport.willChain(ECHO)
        # FIXME: this should be configurable or provided via filesystem
        self.transport.write(self.passwordPrompt)
        return 'Password'


    def telnet_Password(self, line):
        """
        """
        username, password = self.username, line  # .decode()
        del self.username
        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)

        # are we dealing with a real Telnet client?
        if self.transport.options:
            # stop ECHO
            # even if ECHO negotiation fails we still want to attempt a login
            # this allows us to support dumb clients which is common in malware
            # thus the addBoth: on success and on exception (AlreadyNegotiating)
            self.transport.wontChain(ECHO).addBoth(login)
        else:
            # process login
            login('')

        return 'Discard'


    def telnet_Command(self, command):
        """
        """
        self.transport.protocol.dataReceived(command+b'\r')
        return "Command"


    def _cbLogin(self, ial):
        """
        Fired on a successful login
        """
        interface, protocol, logout = ial
        protocol.windowSize = self.windowSize
        self.protocol = protocol
        self.logout = logout
        self.state = 'Command'

        self.transport.write(b'\n')

        # Remove the short timeout of the login prompt. Timeout will be
        # provided later by the HoneyPotBaseProtocol class.
        self.transport.setTimeout(None)

        # replace myself with avatar protocol
        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol


    def _ebLogin(self, failure):
        """
        """
    # TODO: provide a way to have user configurable strings for wrong password
        self.transport.wontChain(ECHO)
        self.transport.write(b"\nLogin incorrect\n")
        self.transport.write(self.loginPrompt)
        self.state = "User"


    def telnet_NAWS(self, data):
        """
        From TelnetBootstrapProtocol in twisted/conch/telnet.py
        """
        if len(data) == 4:
            width, height = struct.unpack('!HH', b''.join(data))
            self.windowSize = [height, width]
        else:
            log.msg("Wrong number of NAWS bytes")


    def enableLocal(self, opt):
        """
        """
        if opt == ECHO:
            return True
        elif opt == SGA:
            return False
            #return True
        else:
            return False


    def enableRemote(self, opt):
        """
        """
        if opt == LINEMODE:
            return False
            #self.transport.requestNegotiation(LINEMODE, MODE + chr(TRAPSIG))
            #return True
        elif opt == NAWS:
            return True
        elif opt == SGA:
            return True
        else:
            return False



class CowrieTelnetTransport(TelnetTransport, TimeoutMixin):
    """
    """

    def connectionMade(self):
        """
        """
        self.transportId = uuid.uuid4().hex[:12]
        sessionno = self.transport.sessionno
        self.startTime = time.time()
        self.setTimeout(300)

        log.msg(eventid='cowrie.session.connect',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]',
           src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           session=self.transportId, sessionno='T'+str(sessionno), protocol='telnet')
        TelnetTransport.connectionMade(self)


    def write(self, data):
        """
        Because of the presence of two ProtocolTransportMixin in the protocol
        stack once authenticated, I need to override write() and remove a \r
        otherwise we end up with \r\r\n on the wire.

        It is kind of a hack. I asked for a better solution here:
        http://stackoverflow.com/questions/35087250/twisted-telnet-server-how-to-avoid-nested-crlf
        """
        self.transport.write(data.replace(b'\r\n', b'\n'))


    def connectionLost(self, reason):
        """
        Fires on pre-authentication disconnects
        """
        self.setTimeout(None)
        TelnetTransport.connectionLost(self, reason)
        duration = time.time() - self.startTime
        log.msg(eventid='cowrie.session.closed',
            format='Connection lost after %(duration)d seconds',
            duration=duration)


    def willChain(self, option):
        """
        """
        return self._chainNegotiation(None, self.will, option)


    def wontChain(self, option):
        """
        """
        return self._chainNegotiation(None, self.wont, option)


    def doChain(self, option):
        """
        """
        return self._chainNegotiation(None, self.do, option)


    def dontChain(self, option):
        """
        """
        return self._chainNegotiation(None, self.dont, option)


    def _handleNegotiationError(self, f, func, option):
        """
        """
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
            log.err('Client tried to illegally refuse to disable an option; ignoring, but undefined behavior may result')
            # TODO: Is ignoring this violation of the protocol the proper behavior?
            # Should the connection be terminated instead?
            # The telnetd package on Ubuntu (netkit-telnet) does all negotiation before sending the login prompt,
            # but does handle client-initiated negotiation at any time.
        return None  # This Failure has been handled, no need to continue processing errbacks


    def _chainNegotiation(self, res, func, option):
        return func(option).addErrback(self._handleNegotiationError, func, option)
