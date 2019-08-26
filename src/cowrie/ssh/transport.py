# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
The lowest level SSH protocol. This handles the key negotiation, the
encryption and the compression. The transport layer is described in
RFC 4253.
"""

from __future__ import absolute_import, division

import re
import struct
import time
import uuid
import zlib
from hashlib import md5

from twisted.conch.ssh import transport
from twisted.conch.ssh.common import getNS
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log, randbytes
from twisted.python.compat import _bytesChr as chr

from cowrie.core.config import CowrieConfig


class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    startTime = None
    gotVersion = False
    ipv4rex = re.compile(r'^::ffff:(\d+\.\d+\.\d+\.\d+)$')
    auth_timeout = CowrieConfig().getint('honeypot', 'authentication_timeout', fallback=120)
    interactive_timeout = CowrieConfig().getint('honeypot', 'interactive_timeout', fallback=300)

    def __repr__(self):
        """
        Return a pretty representation of this object.

        @return Pretty representation of this object as a string
        @rtype: L{str}
        """
        return "Cowrie SSH Transport to {}".format(self.transport.getPeer().host)

    def connectionMade(self):
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.transportId = uuid.uuid4().hex[:12]
        src_ip = self.transport.getPeer().host

        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        log.msg(
            eventid='cowrie.session.connect',
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=src_ip,
            src_port=self.transport.getPeer().port,
            dst_ip=self.transport.getHost().host,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno='S{0}'.format(self.transport.sessionno),
            protocol='ssh'
        )

        self.transport.write('{0}\r\n'.format(self.ourVersionString).encode('ascii'))
        self.currentEncryptions = transport.SSHCiphers(b'none', b'none', b'none', b'none')
        self.currentEncryptions.setKeys(b'', b'', b'', b'', b'', b'')

        self.startTime = time.time()
        self.setTimeout(self.auth_timeout)

    def sendKexInit(self):
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def _unsupportedVersionReceived(self, remoteVersion):
        """
        Change message to be like OpenSSH
        """
        self.transport.write(b'Protocol major versions differ.\n')
        self.transport.loseConnection()

    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if b'\n' not in self.buf:
                return
            self.otherVersionString = self.buf.split(b'\n')[0].strip()
            log.msg(eventid='cowrie.client.version', version=repr(self.otherVersionString),
                    format="Remote SSH version: %(version)s")
            m = re.match(br'SSH-(\d+.\d+)-(.*)', self.otherVersionString)
            if m is None:
                log.msg("Bad protocol version identification: {}".format(repr(self.otherVersionString)))
                self.transport.write(b'Protocol mismatch.\n')
                self.transport.loseConnection()
                return
            else:
                self.gotVersion = True
                remote_version = m.group(1)
                if remote_version not in self.supportedVersions:
                    self._unsupportedVersionReceived(None)
                    return
                i = self.buf.index(b'\n')
                self.buf = self.buf[i + 1:]
                self.sendKexInit()
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, message_num, payload):
        transport.SSHServerTransport.dispatchMessage(self, message_num, payload)

    def sendPacket(self, messageType, payload):
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = chr(messageType) + payload
        if self.outgoingCompression:
            payload = (self.outgoingCompression.compress(payload)
                       + self.outgoingCompression.flush(2))
        bs = self.currentEncryptions.encBlockSize
        # 4 for the packet length and 1 for the padding length
        totalSize = 5 + len(payload)
        lenPad = bs - (totalSize % bs)
        if lenPad < 4:
            lenPad = lenPad + bs
        if messageType == transport.MSG_KEXINIT:
            padding = b'\0' * lenPad
        else:
            padding = randbytes.secureRandom(lenPad)

        packet = (struct.pack(b'!LB',
                              totalSize + lenPad - 4, lenPad) +
                  payload + padding)
        encPacket = (self.currentEncryptions.encrypt(packet) +
                     self.currentEncryptions.makeMAC(
                         self.outgoingPacketSequence, packet))
        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1

    def ssh_KEXINIT(self, packet):
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS,
         _) = [s.split(b',') for s in strings]

        # hassh SSH client fingerprint
        # https://github.com/salesforce/hassh
        ckexAlgs = ','.join([alg.decode('utf-8') for alg in kexAlgs])
        cencCS = ','.join([alg.decode('utf-8') for alg in encCS])
        cmacCS = ','.join([alg.decode('utf-8') for alg in macCS])
        ccompCS = ','.join([alg.decode('utf-8') for alg in compCS])
        hasshAlgorithms = "{kex};{enc};{mac};{cmp}".format(
            kex=ckexAlgs,
            enc=cencCS,
            mac=cmacCS,
            cmp=ccompCS)
        hassh = md5(hasshAlgorithms.encode('utf-8')).hexdigest()

        log.msg(eventid='cowrie.client.kex',
                format="SSH client hassh fingerprint: %(hassh)s",
                hassh=hassh,
                hasshAlgorithms=hasshAlgorithms,
                kexAlgs=kexAlgs, keyAlgs=keyAlgs, encCS=encCS, macCS=macCS,
                compCS=compCS, langCS=langCS)

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in HoneyPotSSHTransport")
        self.transport.loseConnection()

    def setService(self, service):
        """
        Remove login grace timeout, set zlib compression after auth
        """
        # Reset timeout. Not everyone opens shell so need timeout at transport level
        if service.name == b'ssh-connection':
            self.setTimeout(self.interactive_timeout)

        # when auth is successful we enable compression
        # this is called right after MSG_USERAUTH_SUCCESS
        if service.name == 'ssh-connection':
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
        duration = time.time() - self.startTime
        log.msg(eventid='cowrie.session.closed',
                format="Connection lost after %(duration)d seconds",
                duration=duration)

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a description of the reason for the disconnection.
        @type desc: C{str}
        """
        if b'bad packet length' not in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write(b'Packet corrupt\n')
            log.msg("[SERVER] - Disconnecting with error, code {} reason: {}".format(reason, desc))
            self.transport.loseConnection()

    def receiveError(self, reasonCode, description):
        """
        Called when we receive a disconnect error message from the other side.

        @param reasonCode: the reason for the disconnect, one of the
                           DISCONNECT_ values.
        @type reasonCode: L{int}
        @param description: a human-readable description of the
                            disconnection.
        @type description: L{str}
        """
        log.msg('Got remote error, code %s reason: %s' % (reasonCode, description))
