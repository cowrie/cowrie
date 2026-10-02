# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

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
from typing import Any

from twisted.conch.ssh import transport
from twisted.conch.ssh.common import getNS
from twisted.internet.protocol import connectionDone
from twisted.logger import Logger
from twisted.protocols.policies import ProtocolWrapper, TimeoutMixin
from twisted.python import failure, randbytes

from cowrie.core.config import CowrieConfig
from cowrie.core.events import EventLog, transport_events
from cowrie.core.utils import escape_nonprintable, hassh_client


class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    _log = Logger()
    startTime: float = 0.0
    gotVersion: bool = False
    buf: bytes
    transportId: str
    # The session's event emitter, bound in connectionMade (or, under the
    # PROXY protocol, on the first dataReceived) when the running application
    # provides a dispatcher.
    events: EventLog | None = None
    # Set when running behind a PROXY-protocol proxy: cowrie.session.connect is
    # held back until the PROXY header has been parsed and getPeer() reflects
    # the real client.
    _emit_connect_pending: bool = False
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

        if isinstance(self.transport, ProtocolWrapper):
            # A protocol wrapper in front of us (the haproxy: endpoint's PROXY
            # parser) only resolves the real client address once it has read
            # the header, which happens on the first dataReceived(). Defer
            # cowrie.session.connect until then so it carries the real IP
            # rather than the proxy's.
            self._emit_connect_pending = True
        else:
            self._emit_connect()

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        self.startTime = time.time()
        self.setTimeout(self.auth_timeout)

    def _emit_connect(self) -> None:
        """
        Bind the session event log and announce cowrie.session.connect using
        the current (possibly PROXY-resolved) peer address.
        """
        src_ip: str = self.transport.getPeer().host
        ipv4_search = self.ipv4rex.search(src_ip)
        if ipv4_search is not None:
            src_ip = ipv4_search.group(1)

        self.events = transport_events(
            self.factory,
            self.transport,
            session=self.transportId,
            protocol="ssh",
            src_ip=src_ip,
        )

    def sendKexInit(self) -> None:
        """
        Don't send key exchange prematurely
        """
        if not self.gotVersion:
            return
        # A client that sends a second KEXINIT before the first key exchange
        # completes drives the base sendKexInit into raising a RuntimeError.
        # Disconnect such a protocol violation cleanly instead.
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            self._log.info("Duplicate KEXINIT during key exchange, disconnecting")
            self.transport.loseConnection()
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
        if self._emit_connect_pending:
            # First bytes have arrived, which under the PROXY protocol means
            # the header has been parsed and getPeer() now reflects the real
            # client. Announce the connection before processing the data.
            self._emit_connect_pending = False
            self._emit_connect()

        self.buf = self.buf + data
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString: bytes = self.buf.split(b"\n")[0].strip()
            if self.events:
                self.events.dispatch(
                    "cowrie.client.version",
                    "Remote SSH version: %(version)s",
                    version=escape_nonprintable(self.otherVersionString),
                )
            m = re.match(rb"SSH-(\d+\.\d+)-(.*)", self.otherVersionString)
            if m is None:
                self._log.info(
                    "Bad protocol version identification: {version!r}",
                    version=self.otherVersionString,
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
        try:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
        except struct.error:
            # A truncated or garbage message body underflows getNS()/struct
            # parsing inside a handler (any message type: service-request,
            # userauth, channel ops, ...). Real OpenSSH treats this as a fatal
            # protocol error, logging server-side and dropping the connection
            # without a SSH_MSG_DISCONNECT; match that (which also avoids a
            # cowrie-specific disconnect string), and record the probe -- these
            # malformed pre-auth packets are a common exploit/scanner signal.
            if self.events:
                self.events.dispatch(
                    "cowrie.client.malformed_packet",
                    "Malformed SSH packet (message %(messagenum)d, %(datalen)d bytes); disconnecting",
                    messagenum=messageNum,
                    datalen=len(payload),
                    data=payload[:256].hex(),
                )
            self.transport.loseConnection()

    def sendPacket(self, messageType: int, payload: bytes) -> None:
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self.transport is None:
            return
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

        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)

        if self.events:
            self.events.dispatch(
                "cowrie.client.kex",
                "SSH client hassh fingerprint: %(hassh)s",
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
        self._log.info("Timeout reached in HoneyPotSSHTransport")
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

    def connectionLost(self, reason: failure.Failure | None = connectionDone) -> None:
        """
        This seems to be the only reliable place of catching lost connection
        """
        self.setTimeout(None)
        transport.SSHServerTransport.connectionLost(self, reason)
        if self._emit_connect_pending:
            # A proxied connection whose PROXY header carried no trailing data
            # never reached dataReceived(), so the deferred announce never
            # fired. getPeer() is resolved by now; announce it before closing
            # so the connection is still logged (as a direct one would be).
            self._emit_connect_pending = False
            self._emit_connect()
        self.transport = None
        duration_ms = round((time.time() - self.startTime) * 1000)
        if self.events is not None:
            self.events.session_closed(duration_ms)

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
            self._log.info(
                "[SERVER] - Disconnecting with error, code {code} reason: {desc}",
                code=reason,
                desc=desc,
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
        self._log.info(
            "Got remote error, code {code} reason: {description}",
            code=reasonCode,
            description=description,
        )
