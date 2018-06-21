# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
The lowest level SSH protocol. This handles the key negotiation, the
encryption and the compression. The transport layer is described in
RFC 4253.
"""

from __future__ import division, absolute_import

import re
import time
import struct
import uuid
from hashlib import md5
import zlib

from twisted.conch.ssh import transport
from twisted.python import log, randbytes
from twisted.conch.ssh.common import getNS
from twisted.protocols.policies import TimeoutMixin
from twisted.python.compat import _bytesChr as chr



class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    """
    """
    logintime = None
    gotVersion = False

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
        ipv4rex = re.compile(r'^::ffff:(\d+\.\d+\.\d+\.\d+)$')
        ipv4_search = ipv4rex.search(src_ip)
        if ipv4_search != None:
            src_ip = ipv4_search.group(1)

        log.msg(eventid='cowrie.session.connect',
           format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
           src_ip=src_ip, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           session=self.transportId, sessionno='S'+str(self.transport.sessionno), protocol='ssh')

        self.transport.write(b''+self.ourVersionString+b'\r\n')
        self.currentEncryptions = transport.SSHCiphers(b'none', b'none', b'none', b'none')
        self.currentEncryptions.setKeys(b'', b'', b'', b'', b'', b'')
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
            if not b'\n' in self.buf:
                return
            #self.otherVersionString = self.buf.split(b'\n')[0].strip().encode('string-escape')
            self.otherVersionString = self.buf.split(b'\n')[0].strip()
            if self.buf.startswith(b'SSH-'):
                self.gotVersion = True
                remoteVersion = self.buf.split(b'-')[1]
                if remoteVersion not in self.supportedVersions:
                    self._unsupportedVersionReceived(remoteVersion)
                    return
                i = self.buf.index(b'\n')
                self.buf = self.buf[i+1:]
                self.sendKexInit()
            else:
                self.transport.write(b'Protocol mismatch.\n')
                log.msg("Bad protocol version identification: {}".format(repr(self.otherVersionString)))
                self.transport.loseConnection()
                return
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()


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
        encPacket = (
            self.currentEncryptions.encrypt(packet) +
            self.currentEncryptions.makeMAC(
                self.outgoingPacketSequence, packet))
        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1


    def ssh_KEXINIT(self, packet):
        """
        """
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS,
            _) = [s.split(b',') for s in strings]

        client_fingerprint = md5(packet[16:]).hexdigest()
        log.msg(eventid='cowrie.client.fingerprint',
                format="Remote SSH client fingerprint: %(client_fingerprint)s",
                client_fingerprint=client_fingerprint)
        log.msg(eventid='cowrie.client.version', version=self.otherVersionString,
            kexAlgs=kexAlgs, keyAlgs=keyAlgs, encCS=encCS, macCS=macCS,
            compCS=compCS, langCS=langCS, format="Remote SSH version: %(version)s")

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

        # Reset timeout. Not everyone opens shell so need timeout here also
        if service.name == 'ssh-connection':
            self.setTimeout(300)

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
        duration = time.time() - self.logintime
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
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Packet corrupt\n')
            log.msg("[SERVER] - Disconnecting with error, code {}\nreason: {}".format(reason, desc))
            self.transport.loseConnection()
