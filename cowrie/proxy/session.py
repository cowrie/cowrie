# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

from twisted.internet import reactor, protocol
from twisted.python import log
from twisted.conch.ssh import common, keys, session
from twisted.conch.client.knownhosts import KnownHostsFile
#from twisted.conch import endpoints

from cowrie.core.config import CONFIG
from cowrie.proxy import endpoints
from cowrie.ssh import channel

class _ProtocolFactory():
    """
    Factory to return the (existing) ssh session to pass to ssh command endpoint
    It does not actually function as a factory
    """

    def __init__(self, protocol):
        self.protocol = protocol


    def buildProtocol(self, addr):
        """
        """
        return self.protocol



class ProxyClient(object):
    """
    Dummy object because SSHSession expects a .client with an attached transport

    TODO: Forward ssh-exit-status
    """
    transport = None
    session = None

    def __init__(self, session):
        self.session = session
        self.transport = InBetween()
        self.transport.client = self.session



class InBetween(protocol.Protocol):
    """
    This is the glue between the SSH server one one side and the
    SSH client on the other side
    """

    transport = None # Transport is the back-end the ssh-server
    client = None # Client is the front-end, the ssh-client
    buf = "" # buffer to send to back-end

    def makeConnection(self, transport):
        protocol.Protocol.makeConnection(self, transport)


    def connectionMade(self):
        log.msg("IB: connection Made")
        if len(self.buf) and self.transport != None:
            #self.transport.dataReceived(self.buf)
            self.transport.write(self.buf)
            self.buf = None


    def write(self, bytes):
        """
        This is data going from the end-user to the back-end
        """
        if not self.transport:
            self.buf += bytes
            return
        log.msg( "IB: write: "+repr(bytes)+" to transport "+repr(self.transport))
        self.transport.write(bytes)


    def dataReceived(self, data):
        """
        This is data going from the back-end to the end-user
        """
        log.msg( "IB: dataReceived: "+repr(data))
        self.client.write(data)


    def closed(self):
        """
        """
        log.msg("IB: closed")


    def closeReceived(self):
        """
        """
        log.msg("IB: closeRecieved")


    def loseConnection(self):
        """
        Frontend disconnected
        """
        log.msg("IB: loseConnection")


    def connectionLost(self, reason):
        """
        Backend has disconnected
        """
        log.msg("IB: ConnectionLost")
        self.client.loseConnection()


    def eofReceived(self):
        """
        """
        log.msg("IB: eofReceived")



class ProxySSHSession(channel.CowrieSSHChannel):
    """
    For SSH sessions that are proxied to a back-end, this is the
    SSHSession object that speaks to the client. It is responsible
    for forwarding incoming requests to the backend.
    """
    name = b'proxy-frontend-session'
    buf = b''

    keys = []
    host = ""
    port = 22
    user = ""
    password = ""
    knownHosts = None

    def __init__(self, *args, **kw):
        channel.CowrieSSHChannel.__init__(self, *args, **kw)
        #self.__dict__['request_auth_agent_req@openssh.com'] = self.request_agent

        try:
            keyPath = CONFIG.get('proxy', 'private_key')
            self.keys.append(keys.Key.fromFile(keyPath))
        except:
            self.keys = None

        knownHostsPath = CONFIG.get('proxy', 'known_hosts')
        self.knownHosts = KnownHostsFile.fromPath(knownHostsPath)
        log.msg( "knownHosts = "+repr(self.knownHosts))

        self.host = CONFIG.get('proxy', 'host')
        self.port = CONFIG.getint('proxy', 'port')
        self.user = CONFIG.get('proxy', 'user')
        try:
            self.password = CONFIG.get('proxy', 'password')
        except:
            self.password = None

        log.msg( "host = "+self.host)
        log.msg( "port = "+str(self.port))
        log.msg( "user = "+self.user)

        self.client = ProxyClient(self)


    def channelOpen(self, specificData):
        """
        Once we open the frontend-session, also start connecting to back end
        """
        channel.CowrieSSHChannel.channelOpen(self, specificData)
        return
        log.msg("channelOpen")
        helper = endpoints._NewConnectionHelper(reactor, self.host, self.port,
            self.user, self.keys, self.password, None, self.knownHosts, None)
        log.msg( "helper = "+repr(helper))
        d = helper.secureConnection()
        d.addCallback(self._cbConnect)
        d.addErrback(self._ebConnect)
        log.msg( "d = "+repr(d))
        return d


    def _ebConnect(self):
        """
        """
        log.msg("ERROR CONNECTED TO BACKEND")
        self._state = b'ERROR'


    def _cbConnect(self):
        """
        """
        log.msg("CONNECTED TO BACKEND")
        self._state = b'CONNECTED'


    def request_env(self, data):
        """
        """
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg(eventid='cowrie.client.var', format='request_env: %(name)s=%(value)s',
            name=name, value=value)
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.environ[name] = value
        return 0


    def request_pty_req(self, data):
        """
        """
        term, windowSize, modes = session.parseRequest_pty_req(data)
        log.msg('pty request: %r %r' % (term, windowSize))
        return 1


    def request_window_change(self, data):
        """
        """
        winSize = session.parseRequest_window_change(data)
        return 1


    def request_subsystem(self, data):
        """
        """
        subsystem, _ = common.getNS(data)
        log.msg('asking for subsystem "{}"'.format(subsystem))
        return 0


    def request_exec(self, data):
        """
        """
        cmd, data = common.getNS(data)
        log.msg('request_exec "{}"'.format(cmd))
        pf = _ProtocolFactory(self.client.transport)
        #ep = endpoints.SSHCommandClientEndpoint.existingConnection(self.conn, cmd).connect(pf)
        ep = endpoints.SSHCommandClientEndpoint.newConnection(reactor, cmd,
            self.user, self.host, port=self.port, password=self.password).connect(pf)
        return 1


    def request_shell(self, data):
        """
        """
        log.msg('request_shell')
        pf = _ProtocolFactory(self.client.transport)
        ep = endpoints.SSHShellClientEndpoint.newConnection(reactor,
            self.user, self.host, port=self.port,
            password=self.password).connect(pf)
        return 1


    def extReceived(self, dataType, data):
        """
        """
        log.msg('weird extended data: {}'.format(dataType))


    def request_agent(self, data):
        """
        """
        log.msg('request_agent: {}'.format(repr(data),))
        return 0


    def request_x11_req(self, data):
        """
        """
        log.msg('request_x11: %s' % (repr(data),))
        return 0


    def sendClose(self):
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)


    def closed(self):
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        channel.CowrieSSHChannel.closed(self)
        self.client = None


    def channelClosed(self):
        """
        """
        log.msg("Called channelClosed in SSHSession")


    def closeReceived(self):
        """
        """
        log.msg("closeReceived")


    def sendEOF(self):
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)


    def dataReceived(self, data):
        if not self.client:
            #self.conn.sendClose(self)
            self.buf += data
            return
        self.client.transport.write(data)


    def eofReceived(self):
        """
        """
        log.msg("RECEIVED EOF")
        return
        if self.client:
            self.conn.sendClose(self)

