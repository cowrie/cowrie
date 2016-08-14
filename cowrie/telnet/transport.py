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
                                 TelnetTransport
from twisted.protocols.policies import TimeoutMixin

from cowrie.core.credentials import UsernamePasswordIP

class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthTransport instances
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
        self.protocol = lambda: TelnetTransport(HoneyPotTelnetAuthTransport,
                                                self.portal)

        protocol.ServerFactory.startFactory(self)

    def stopFactory(self):
        """
        Stop output plugins
        """
        for output in self.output_plugins:
            output.stop()
        protocol.ServerFactory.stopFactory(self)


class HoneyPotTelnetAuthTransport(AuthenticatingTelnetProtocol, ProtocolTransportMixin, TimeoutMixin):
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

        # p/Cisco telnetd/ d/router/ o/IOS/ cpe:/a:cisco:telnet/ cpe:/o:cisco:ios/a
        # NB _write() is for raw data and write() handles telnet special bytes
        self.transport._write("\xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd\0\xff\xfd\x1f\r\n")
        self.transport.write(self.factory.banner)
        self.transport._write("User Access Verification\r\n\r\nUsername: ")

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
        self.transport.connectionLost(reason)
        self.transport = None
        log.msg(eventid='cowrie.session.closed', format='Connection lost')

    def telnet_Password(self, line):
        username, password = self.username, line
        del self.username
        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)
        self.transport.wont(ECHO).addCallback(login)

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
