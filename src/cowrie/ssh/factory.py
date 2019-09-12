# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import absolute_import, division

import time
from configparser import NoOptionError

from twisted.conch.openssh_compat import primes
from twisted.conch.ssh import factory
from twisted.conch.ssh import keys
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh import connection
from cowrie.ssh import keys as cowriekeys
from cowrie.ssh import transport as shellTransport
from cowrie.ssh.userauth import HoneyPotSSHUserAuthServer
from cowrie.ssh_proxy import server_transport as proxyTransport
from cowrie.ssh_proxy.userauth import ProxySSHAuthServer


# object is added for Python 2.7 compatibility (#1198) - as is super with args
class CowrieSSHFactory(factory.SSHFactory, object):
    """
    This factory creates HoneyPotSSHTransport instances
    They listen directly to the TCP port
    """

    starttime = None
    privateKeys = None
    publicKeys = None
    primes = None
    tac = None  # gets set later
    ourVersionString = CowrieConfig().get('ssh', 'version',
                                          fallback='SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2')

    def __init__(self, backend, pool_handler):
        self.pool_handler = pool_handler
        self.backend = backend
        self.services = {
            b'ssh-userauth': ProxySSHAuthServer if self.backend == 'proxy' else HoneyPotSSHUserAuthServer,
            b'ssh-connection': connection.CowrieSSHConnection,
        }
        super(CowrieSSHFactory, self).__init__()

    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'S{0}'.format(args['sessionno'])
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)

    def startFactory(self):
        # For use by the uptime command
        self.starttime = time.time()

        # Load/create keys
        rsaPubKeyString, rsaPrivKeyString = cowriekeys.getRSAKeys()
        dsaPubKeyString, dsaPrivKeyString = cowriekeys.getDSAKeys()
        self.publicKeys = {
            b'ssh-rsa': keys.Key.fromString(data=rsaPubKeyString),
            b'ssh-dss': keys.Key.fromString(data=dsaPubKeyString)
        }
        self.privateKeys = {
            b'ssh-rsa': keys.Key.fromString(data=rsaPrivKeyString),
            b'ssh-dss': keys.Key.fromString(data=dsaPrivKeyString)
        }

        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'
        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError:
                pass

        # this can come from backend in the future, check HonSSH's slim client
        self.ourVersionString = CowrieConfig().get('ssh', 'version', fallback='SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2')

        factory.SSHFactory.startFactory(self)
        log.msg("Ready to accept SSH connections")

    def stopFactory(self):
        factory.SSHFactory.stopFactory(self)

    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        @type addr: L{twisted.internet.interfaces.IAddress} provider
        @param addr: The address at which the server will listen.

        @rtype: L{cowrie.ssh.transport.HoneyPotSSHTransport}
        @return: The built transport.
        """
        if self.backend == 'proxy':
            t = proxyTransport.FrontendSSHTransport()
        else:
            t = shellTransport.HoneyPotSSHTransport()

        t.ourVersionString = self.ourVersionString
        t.supportedPublicKeys = list(self.privateKeys.keys())

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if b'diffie-hellman-group-exchange-sha1' in ske:
                ske.remove(b'diffie-hellman-group-exchange-sha1')
                log.msg("No moduli, no diffie-hellman-group-exchange-sha1")
            if b'diffie-hellman-group-exchange-sha256' in ske:
                ske.remove(b'diffie-hellman-group-exchange-sha256')
                log.msg("No moduli, no diffie-hellman-group-exchange-sha256")
            t.supportedKeyExchanges = ske

        try:
            t.supportedCiphers = [i.encode('utf-8') for i in CowrieConfig().get('ssh', 'ciphers').split(',')]
        except NoOptionError:
            # Reorder supported ciphers to resemble current openssh more
            t.supportedCiphers = [
                b'aes128-ctr',
                b'aes192-ctr',
                b'aes256-ctr',
                b'aes256-cbc',
                b'aes192-cbc',
                b'aes128-cbc',
                b'3des-cbc',
                b'blowfish-cbc',
                b'cast128-cbc',
            ]

        try:
            t.supportedMACs = [i.encode('utf-8') for i in CowrieConfig().get('ssh', 'macs').split(',')]
        except NoOptionError:
            # SHA1 and MD5 are considered insecure now. Use better algos
            # like SHA-256 and SHA-384
            t.supportedMACs = [
                    b'hmac-sha2-512',
                    b'hmac-sha2-384',
                    b'hmac-sha2-256',
                    b'hmac-sha1',
                    b'hmac-md5'
                ]

        try:
            t.supportedCompressions = [i.encode('utf-8') for i in CowrieConfig().get('ssh', 'compression').split(',')]
        except NoOptionError:
            t.supportedCompressions = [b'zlib@openssh.com', b'zlib', b'none']

        # TODO: Newer versions of SSH will use ECDSA keys too as mentioned
        # at https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.2.2
        #
        # Twisted only supports below two keys
        t.supportedPublicKeys = [b'ssh-rsa', b'ssh-dss']

        t.factory = self

        return t
