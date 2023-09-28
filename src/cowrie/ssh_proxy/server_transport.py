# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>, 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations

import re
import struct
import time
import uuid
import zlib
from hashlib import md5

from twisted.conch.ssh import transport
from twisted.conch.ssh.common import getNS
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log, randbytes

from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy import client_transport
from cowrie.ssh_proxy.protocols import ssh


class FrontendSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    """
    Represents a connection from the frontend (a client or attacker).
    When such connection is received, start the connection to the backend (the VM that will provide the session);
    at the same time, perform the userauth service via ProxySSHAuthServer (built-in Cowrie's mechanism).
    After both sides are authenticated, forward all things from one side to another.
    """

    buf: bytes
    ourVersionString: bytes
    gotVersion: bool

    # TODO merge this with HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin)
    # maybe create a parent class with common methods for the two
    def __init__(self):
        self.timeoutCount = 0

        self.sshParse = None
        self.disconnected = False  # what was this used for

        self.peer_ip = None
        self.peer_port: int = 0
        self.local_ip = None
        self.local_port: int = 0

        self.startTime = None
        self.transportId = None

        self.pool_interface = None
        self.backendConnected = False
        self.frontendAuthenticated = False
        self.delayedPackets = []

        # only used when simple proxy (no pool) set
        self.backend_ip = None
        self.backend_port = None

    def connectionMade(self):
        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        self.sshParse = ssh.SSH(self)
        self.transportId = uuid.uuid4().hex[:12]

        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port + 1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port

        self.transport.write(self.ourVersionString + b"\r\n")
        self.currentEncryptions = transport.SSHCiphers(
            b"none", b"none", b"none", b"none"
        )
        self.currentEncryptions.setKeys(b"", b"", b"", b"", b"", b"")

        log.msg(
            eventid="cowrie.session.connect",
            format="New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: %(session)s]",
            src_ip=self.peer_ip,
            src_port=self.transport.getPeer().port,
            dst_ip=self.local_ip,
            dst_port=self.transport.getHost().port,
            session=self.transportId,
            sessionno=f"S{self.transport.sessionno}",
            protocol="ssh",
        )

        # if we have a pool connect to it and later request a backend, else just connect to a simple backend
        # when pool is set we can just test self.pool_interface to the same effect of getting the CowrieConfig
        proxy_backend = CowrieConfig.get("proxy", "backend", fallback="simple")

        if proxy_backend == "pool":
            # request a backend
            d = self.factory.pool_handler.request_interface()
            d.addCallback(self.pool_connection_success)
            d.addErrback(self.pool_connection_error)
        else:
            # simply a proxy, no pool
            backend_ip = CowrieConfig.get("proxy", "backend_ssh_host")
            backend_port = CowrieConfig.getint("proxy", "backend_ssh_port")
            self.connect_to_backend(backend_ip, backend_port)

    def pool_connection_error(self, reason):
        log.msg(
            f"Connection to backend pool refused: {reason.value}. Disconnecting frontend..."
        )
        self.transport.loseConnection()

    def pool_connection_success(self, pool_interface):
        log.msg("Connected to backend pool")

        self.pool_interface = pool_interface
        self.pool_interface.set_parent(self)

        # now request a backend
        self.pool_interface.send_vm_request(self.peer_ip)

    def received_pool_data(self, operation, status, *data):
        if operation == b"r":
            honey_ip = data[0]
            snapshot = data[1]
            ssh_port = data[2]

            log.msg(f"Got backend data from pool: {honey_ip.decode()}:{ssh_port}")
            log.msg(f"Snapshot file: {snapshot.decode()}")

            self.connect_to_backend(honey_ip, ssh_port)

    def backend_connection_error(self, reason):
        log.msg(
            f"Connection to honeypot backend refused: {reason.value}. Disconnecting frontend..."
        )
        self.transport.loseConnection()

    def backend_connection_success(self, backendTransport):
        log.msg("Connected to honeypot backend")

        self.startTime = time.time()

        # this timeout is replaced with `interactive_timeout` in ssh.py
        self.setTimeout(
            CowrieConfig.getint("honeypot", "authentication_timeout", fallback=120)
        )

    def connect_to_backend(self, ip, port):
        # connection to the backend starts here
        client_factory = client_transport.BackendSSHFactory()
        client_factory.server = self

        point = TCP4ClientEndpoint(reactor, ip, port, timeout=10)
        d = point.connect(client_factory)
        d.addCallback(self.backend_connection_success)
        d.addErrback(self.backend_connection_error)

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
        self.transport.write(b"Protocol major versions differ.\n")
        self.transport.loseConnection()

    def dataReceived(self, data: bytes) -> None:
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf += data

        # get version from start of communication; check if valid and supported by Twisted
        if not self.gotVersion:
            if b"\n" not in self.buf:
                return
            self.otherVersionString = self.buf.split(b"\n")[0].strip()
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
                if self.transport:
                    self.transport.write(b"Protocol mismatch.\n")
                    self.transport.loseConnection()
                return
            else:
                self.gotVersion = True
                remote_version = m.group(1)
                if remote_version not in self.supportedVersions:
                    self._unsupportedVersionReceived(None)
                    return
                i = self.buf.index(b"\n")
                self.buf = self.buf[i + 1 :]
                self.sendKexInit()
        packet = self.getPacket()
        while packet:
            message_num = ord(packet[0:1])
            self.dispatchMessage(message_num, packet[1:])
            packet = self.getPacket()

    def dispatchMessage(self, message_num, payload):
        # overriden dispatchMessage sets services, we do that here too then
        # we're particularly interested in userauth, since Twisted does most of that for us
        if message_num == 5:
            self.ssh_SERVICE_REQUEST(payload)
        elif 50 <= message_num <= 79:  # userauth numbers
            self.frontendAuthenticated = False
            transport.SSHServerTransport.dispatchMessage(
                self, message_num, payload
            )  # let userauth deal with it

        # TODO delay userauth until backend is connected?

        elif transport.SSHServerTransport.isEncrypted(self, "both"):
            self.packet_buffer(message_num, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, message_num, payload)

    def sendPacket(self, messageType, payload):
        """
        Override because OpenSSH pads with 0 on KEXINIT
        """
        if self._keyExchangeState != self._KEY_EXCHANGE_NONE:
            if not self._allowedKeyExchangeMessageType(messageType):
                self._blockedByKeyExchange.append((messageType, payload))
                return

        payload = chr(messageType).encode() + payload
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

    def ssh_KEXINIT(self, packet):
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

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in FrontendSSHTransport")

        if self.transport:
            self.transport.loseConnection()

        if self.sshParse.client and self.sshParse.client.transport:
            self.sshParse.client.transport.loseConnection()

    def setService(self, service):
        """
        Remove login grace timeout, set zlib compression after auth
        """
        # when auth is successful we enable compression
        # this is called right after MSG_USERAUTH_SUCCESS
        if service.name == "ssh-connection":
            if self.outgoingCompressionType == "zlib@openssh.com":
                self.outgoingCompression = zlib.compressobj(6)
            if self.incomingCompressionType == "zlib@openssh.com":
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

        # if connection from backend is not closed, do it here
        if self.sshParse.client and self.sshParse.client.transport:
            self.sshParse.client.transport.loseConnection()

        if self.pool_interface:
            # free VM from pool (VM was used if we performed SSH authentication to the backend)
            vm_dirty = self.sshParse.client.authDone if self.sshParse.client else False
            self.pool_interface.send_vm_free(vm_dirty)

            # close transport connection to pool
            self.pool_interface.transport.loseConnection()

        if self.startTime is not None:  # startTime is not set when auth fails
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
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write(b"Packet corrupt\n")
            log.msg(f"Disconnecting with error, code {reason}\nreason: {desc}")
            self.transport.loseConnection()

    def receiveError(self, reasonCode: str, description: str) -> None:
        """
        Called when we receive a disconnect error message from the other
        side.

        @param reasonCode: the reason for the disconnect, one of the
                           DISCONNECT_ values.
        @type reasonCode: L{int}
        @param description: a human-readable description of the
                            disconnection.
        @type description: L{str}
        """
        log.msg(f"Got remote error, code {reasonCode} reason: {description}")

    def packet_buffer(self, message_num: int, payload: bytes) -> None:
        """
        We have to wait until we have a connection to the backend is ready. Meanwhile, we hold packets from client
        to server in here.
        """
        if not self.backendConnected:
            # wait till backend connects to send packets to them
            log.msg("Connection to backend not ready, buffering packet from frontend")
            self.delayedPackets.append([message_num, payload])
        else:
            if len(self.delayedPackets) > 0:
                self.delayedPackets.append([message_num, payload])
            else:
                self.sshParse.parse_num_packet("[SERVER]", message_num, payload)
