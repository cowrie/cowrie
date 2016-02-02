# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

import time
import uuid

from twisted.python import log
from twisted.internet import protocol
from twisted.conch.telnet import AuthenticatingTelnetProtocol, ECHO, \
                                 ITelnetProtocol, ProtocolTransportMixin, \
                                 SGA, TelnetTransport
from twisted.protocols.policies import TimeoutMixin

from cowrie.core.credentials import UsernamePasswordIP

class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """

    def __init__(self, cfg):
        self.cfg = cfg

    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        for dblog in self.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.output_plugins:
            output.logDispatch(*msg, **args)

    def startFactory(self):
        """
        """
        # The banner to serve
        honeyfs = self.portal.realm.cfg.get('honeypot', 'contents_path')
        issuefile = honeyfs + "/etc/issue.net"
        self.banner = file(issuefile).read()

        # Interactive protocols are kept here for the interact feature
        self.sessions = {}

        # For use by the uptime command
        self.starttime = time.time()

        # Load db loggers
        self.dbloggers = []
        for x in self.cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            try:
                dblogger = __import__( 'cowrie.dblog.{}'.format(engine),
                    globals(), locals(), ['dblog']).DBLogger(self.cfg)
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
                log.msg("Loaded dblog engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load dblog engine: {}".format(engine))

        # Load output modules
        self.output_plugins = []
        for x in self.cfg.sections():
            if not x.startswith('output_'):
                continue
            engine = x.split('_')[1]
            try:
                output = __import__( 'cowrie.output.{}'.format(engine),
                    globals(), locals(), ['output']).Output(self.cfg)
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg("Loaded output engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load output engine: {}".format(engine))

        # hook protocol
        self.protocol = lambda: StripCrTelnetTransport(HoneyPotTelnetAuthProtocol,
                                         self.portal)
        protocol.ServerFactory.startFactory(self)


    def stopFactory(self):
        """
        Stop output plugins
        """
        for output in self.output_plugins:
            output.stop()
        protocol.ServerFactory.stopFactory(self)


class HoneyPotTelnetAuthProtocol(AuthenticatingTelnetProtocol, TimeoutMixin):
    """
    Telnet Transport that takes care of Authentication. Once authenticated this
    transport is replaced with HoneyPotTelnetSession.
    """

    def connectionMade(self):

        self.transportId = uuid.uuid4().hex[:8]
        sessionno = self.transport.transport.sessionno
        self.factory.sessions[sessionno] = self.transportId

        log.msg(eventid='cowrie.session.connect',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(sessionno)s]',
           src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           session=self.transportId, sessionno=sessionno)

        # I need to doubly escape here since my underlying
        # StripCrTelnetTransport hack would remove it and leave just \n
        self.transport.write(self.factory.banner.replace('\n', '\r\r\n'))
        self.transport.write("User Access Verification\n\nUsername: ".replace('\n', '\r\r\n'))

        self.setTimeout(120)


    # FIXME TelnetTransport is throwing an exception when client disconnects
    #       Not sure if this is true anymore
    def connectionLost(self, reason):
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        if self.transport.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.transport.sessionno]
        log.msg(eventid='cowrie.session.closed', format='Connection lost')

        AuthenticatingTelnetProtocol.connectionLost(self, reason)


    def telnet_User(self, line):
        """
        Overridden to conditionally kill 'WILL ECHO' which confuses clients
        that don't implement a proper Telnet protocol (most malware)
        """
        self.username = line
        # only send ECHO option if we are chatting with a real Telnet client
        if self.transport.options:
            self.transport.will(ECHO)
        self.transport.write("Password: ")
        return 'Password'


    def telnet_Password(self, line):
        username, password = self.username, line
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
            self.transport.wont(ECHO).addBoth(login)
        else:
            # process login
            login('')

        return 'Discard'

    def _cbLogin(self, ial):
        """
        """
        interface, protocol, logout = ial
        self.protocol = protocol
        self.logout = logout
        self.state = 'Command'

        # transfer important state info to new transport
        protocol.transportId = self.transportId

        # replace myself with avatar protocol
        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol


class StripCrTelnetTransport(TelnetTransport):
    """Sole purpose is to override write() and fix a CRLF nesting bug"""

    # Because of the presence of two ProtocolTransportMixin in the protocol
    # stack once authenticated, I need to override write() and remove a \r
    # otherwise we end up with \r\r\n on the wire.
    #
    # It is kind of a hack. I asked for a better solution here:
    # http://stackoverflow.com/questions/35087250/twisted-telnet-server-how-to-avoid-nested-crlf
    def write(self, bytes):
        self.transport.write(bytes.replace('\r\n', '\n'))
