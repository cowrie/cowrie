# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import re
import time
import uuid
import zlib

import twisted
from twisted.conch.ssh import factory
from twisted.conch.ssh import keys
from twisted.conch.ssh import transport
from twisted.python import log
from twisted.conch.openssh_compat import primes
from twisted.conch.ssh.common import getNS
from twisted.protocols.policies import TimeoutMixin

from cowrie.ssh import connection
from cowrie.ssh import userauth
from cowrie.core import keys as cowriekeys


class HoneyPotSSHFactory(factory.SSHFactory):
    """
    This factory creates HoneyPotTransport instances
    They listen directly to the TCP port
    """

    services = {
        'ssh-userauth': userauth.HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.CowrieSSHConnection,
        }

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

        # Interactive protocols are kept here for the interact feature
        self.sessions = {}

        # For use by the uptime command
        self.starttime = time.time()

        # Load/create keys
        rsaPubKeyString, rsaPrivKeyString = cowriekeys.getRSAKeys(self.cfg)
        dsaPubKeyString, dsaPrivKeyString = cowriekeys.getDSAKeys(self.cfg)
        self.publicKeys = {
          'ssh-rsa': keys.Key.fromString(data=rsaPubKeyString),
          'ssh-dss': keys.Key.fromString(data=dsaPubKeyString)}
        self.privateKeys = {
          'ssh-rsa': keys.Key.fromString(data=rsaPrivKeyString),
          'ssh-dss': keys.Key.fromString(data=dsaPrivKeyString)}

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

        factory.SSHFactory.startFactory(self)


    def stopFactory(self):
        """
        """
        factory.SSHFactory.stopFactory(self)
        for output in self.output_plugins:
            output.stop()


    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        @type addr: L{twisted.internet.interfaces.IAddress} provider
        @param addr: The address at which the server will listen.

        @rtype: L{cowrie.core.HoneyPotTransport}
        @return: The built transport.
        """

        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'

        t = HoneyPotTransport()

        try:
            t.ourVersionString = self.cfg.get('honeypot', 'ssh_version_string')
        except:
            t.ourVersionString = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"

        t.supportedPublicKeys = list(self.privateKeys.keys())

        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError as err:
                pass

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
            log.msg("No moduli, disabled diffie-hellman-group-exchange-sha1")

        # Reorder supported ciphers to resemble current openssh more
        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr',
            'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc',
            'aes192-cbc', 'aes256-cbc']
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = ['hmac-md5', 'hmac-sha1']
        t.supportedCompressions = ['zlib@openssh.com', 'zlib', 'none']

        t.factory = self
        return t



class HoneyPotTransport(transport.SSHServerTransport, TimeoutMixin):
    """
    """

    def connectionMade(self):
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.transportId = uuid.uuid4().hex[:8]

        src_ip = self.transport.getPeer().host
        ipv4rex = re.compile( '^::ffff:(\d+\.\d+\.\d+\.\d+)$')
        ipv4_search = ipv4rex.search(src_ip)
        if ipv4_search != None:
            src_ip = ipv4_search.group(1)

        log.msg(eventid='cowrie.session.connect',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]',
           src_ip=src_ip, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           session=self.transportId, sessionno=self.transport.sessionno)

        self.transport.write('{}\r\n'.format(self.ourVersionString))
        self.currentEncryptions = transport.SSHCiphers('none', 'none', 'none', 'none')
        self.currentEncryptions.setKeys('', '', '', '', '', '')
        self.setTimeout(120)
        self.logintime = time.time()


    def sendKexInit(self):
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)


    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if not '\n' in self.buf:
                return
            self.otherVersionString = self.buf.split('\n')[0].strip()
            if self.buf.startswith('SSH-'):
                self.gotVersion = True
                remoteVersion = self.buf.split('-')[1]
                if remoteVersion not in self.supportedVersions:
                    self._unsupportedVersionReceived(remoteVersion)
                    return
                i = self.buf.index('\n')
                self.buf = self.buf[i+1:]
                self.sendKexInit()
            else:
                self.transport.write('Protocol mismatch.\n')
                log.msg('Bad protocol version identification: %s' % (self.otherVersionString,))
                self.transport.loseConnection()
                return
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

        # Later versions seem to call sendKexInit again on their own
        if twisted.version.major < 11 and \
                not self._hadVersion and self.gotVersion:
            self.sendKexInit()
            self._hadVersion = True


    def ssh_KEXINIT(self, packet):
        """
        """
        k = getNS(packet[16:], 10)
        strings, rest = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, encSC, macCS, macSC, compCS, compSC, langCS,
            langSC) = [s.split(',') for s in strings]
        log.msg(eventid='cowrie.client.version', version=self.otherVersionString,
            kexAlgs=kexAlgs, keyAlgs=keyAlgs, encCS=encCS, macCS=macCS,
            compCS=compCS, format='Remote SSH version: %(version)s')

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)


    def timeoutConnection(self):
        """
        """
        log.msg( "Authentication Timeout reached" )
        self.transport.loseConnection()


    def setService(self, service):
        """
        Remove login grace timeout, set zlib compression after auth
        """

        # Remove authentication timeout
        if service.name == "ssh-connection":
            self.setTimeout(None)

        # when auth is successful we enable compression
        # this is called right after MSG_USERAUTH_SUCCESS
        if service.name == "ssh-connection":
            if self.outgoingCompressionType == 'zlib@openssh.com':
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == 'zlib@openssh.com':
                self.incomingCompression = zlib.decompressobj()

        transport.SSHServerTransport.setService(self, service)


    def connectionLost(self, reason):
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        transport.SSHServerTransport.connectionLost(self, reason)
        self.transport.connectionLost(reason)
        self.transport = None
        duration = time.time() - self.logintime
        log.msg(eventid='cowrie.session.closed',
            format='Connection lost after %(duration)d seconds',
            duration=duration)


    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Packet corrupt\n')
            log.msg('[SERVER] - Disconnecting with error, code %s\nreason: %s'
                % (reason, desc))
            self.transport.loseConnection()

