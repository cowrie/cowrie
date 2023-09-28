# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
The lowest level SSH protocol. This handles the key negotiation, the
encryption and the compression. The transport layer is described in
RFC 4253.
"""

from __future__ import annotations

import re
import struct
import time
import uuid
import zlib
from hashlib import md5
from typing import Any

from twisted.conch.ssh import transport
from twisted.conch.ssh.common import getNS
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log, randbytes

from cowrie.core.config import CowrieConfig


class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    startTime: float = 0.0
    gotVersion: bool = False
    buf: bytes
    transportId: str
    ipv4rex = re.compile(r"^::ffff:(\d+\.\d+\.\d+\.\d+)$")
    auth_timeout: int = CowrieConfig.getint(
        "honeypot", "authentication_timeout", fallback=120
    )
    interactive_timeout: int = CowrieConfig.getint(
        "honeypot", "interactive_timeout", fallback=300
    )
    ourVersionString: bytes  # set by factory
    transport: Any
    outgoingCompression: Any
    _blockedByKeyExchange: Any

    def __repr__(self) -> str:
        """
        Return a pretty representation of this object.

        @return Pretty representation of this object as a string
        @rtype: L{str}
        """
        return f"Cowrie SSH Transport to {self.transport.getPeer().host}"

    def connectionMade(self) -> None:
        """
        Called when the connection is made from the other side.
        We send our version, but wait with sending KEXINIT
        """
        self.buf = b""

        self.transportId = uuid.uuid4().hex[:12]
        src_ip: str = self.transport.getPeer().host

        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        log.msg(
            eventid="cowrie.session.connect",
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=src_ip,
            src_port=self.transport.getPeer().port,
            dst_ip=self.transport.getHost().host,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno=f"S{self.transport.sessionno}",
            protocol="ssh",
        )

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        self.startTime: float = time.time()
        self.setTimeout(self.auth_timeout)

    def sendKexInit(self) -> None:
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def _unsupportedVersionReceived(self, remoteVersion: bytes) -> None:
        """
        Change message to be like OpenSSH
        """
        self.transport.write(b"Protocol major versions differ.\n")
        self.transport.loseConnection()

    def dataReceived(self, data: bytes) -> None:
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString: bytes = self.buf.split(b"\n")[0].strip()
            log.msg(
                eventid="cowrie.client.version",
                version=self.otherVersionString.decode(
                    "utf-8", errors="backslashreplace"
                ),
                format="Remote SSH version: %(version)s",
            )
            m = re.match(rb"SSH-(\d+.\d+)-(.*)", self.otherVersionString)
            if m is None:
                log.msg(
                    f"Bad protocol version identification: {self.otherVersionString!r}"
                )
                # OpenSSH sending the same message
                self.transport.write(b"Invalid SSH identification string.\n")
                self.transport.loseConnection()
                return
            self.gotVersion = True
            remote_version = m.group(1)
            if remote_version not in self.supportedVersions:
                self._unsupportedVersionReceived(self.otherVersionString)
                return
            i = self.buf.index(b"\n")
            self.buf = self.buf[i + 1 :]
            self.sendKexInit()
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0:1])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)

    def sendPacket(self, messageType: int, payload: bytes) -> None:
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = bytes((messageType,)) + payload
        if self.outgoingCompression:
            payload = self.outgoingCompression.compress(
                payload
            ) + self.outgoingCompression.flush(2)
        bs = self.currentEncryptions.encBlockSize
        # 4 for the packet length and 1 for the padding length
        totalSize = 5 + len(payload)
        lenPad = bs - (totalSize % bs)
        if lenPad < 4:
            lenPad = lenPad + bs
        padding: bytes
        if messageType == transport.MSG_KEXINIT:
            padding = b"\0" * lenPad
        else:
            padding = randbytes.secureRandom(lenPad)

        packet = struct.pack(b"!LB", totalSize + lenPad - 4, lenPad) + payload + padding
        encPacket = self.currentEncryptions.encrypt(
            packet
        ) + self.currentEncryptions.makeMAC(self.outgoingPacketSequence, packet)
        self.transport.write(encPacket)
        self.outgoingPacketSequence += 1

    def ssh_KEXINIT(self, packet: bytes) -> Any:
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS, _) = (
            s.split(b",") for s in strings
        )

        # hassh SSH client fingerprint
        # https://github.com/salesforce/hassh
        ckexAlgs = ",".join([alg.decode("utf-8") for alg in kexAlgs])
        cencCS = ",".join([alg.decode("utf-8") for alg in encCS])
        cmacCS = ",".join([alg.decode("utf-8") for alg in macCS])
        ccompCS = ",".join([alg.decode("utf-8") for alg in compCS])
        hasshAlgorithms = f"{ckexAlgs};{cencCS};{cmacCS};{ccompCS}"
        hassh = md5(hasshAlgorithms.encode("utf-8")).hexdigest()

        log.msg(
            eventid="cowrie.client.kex",
            format="SSH client hassh fingerprint: %(hassh)s",
            hassh=hassh,
            hasshAlgorithms=hasshAlgorithms,
            kexAlgs=kexAlgs,
            keyAlgs=keyAlgs,
            encCS=encCS,
            macCS=macCS,
            compCS=compCS,
            langCS=langCS,
        )

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self) -> None:
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
        if service.name == b"ssh-connection":
            self.setTimeout(self.interactive_timeout)

        # when auth is successful we enable compression
        # this is called right after MSG_USERAUTH_SUCCESS
        if service.name == b"ssh-connection":
            if self.outgoingCompressionType == b"zlib@openssh.com":
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == b"zlib@openssh.com":
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
        log.msg(
            eventid="cowrie.session.closed",
            format="Connection lost after %(duration)d seconds",
            duration=duration,
        )

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
        if b"bad packet length" not in desc:
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            # this message is used to detect Cowrie behaviour
            # self.transport.write(b"Packet corrupt\n")
            log.msg(
                f"[SERVER] - Disconnecting with error, code {reason} reason: {desc}"
            )
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
        log.msg(f"Got remote error, code {reasonCode} reason: {description}")
