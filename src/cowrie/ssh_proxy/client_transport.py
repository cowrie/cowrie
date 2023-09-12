# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# All rights reserved.

from __future__ import annotations

from typing import Any

from twisted.conch.ssh import transport
from twisted.internet import defer, protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.util import bin_string_to_hex, string_to_hex


def get_int(data: bytes, length: int = 4) -> int:
    return int.from_bytes(data[:length], byteorder="big")


def get_bool(data: bytes) -> bool:
    return bool(get_int(data, length=1))


def get_string(data: bytes) -> tuple[int, bytes]:
    length = get_int(data, 4)
    value = data[4 : length + 4]
    return length + 4, value


class BackendSSHFactory(protocol.ClientFactory):
    server: Any

    def buildProtocol(self, addr):
        return BackendSSHTransport(self)


class BackendSSHTransport(transport.SSHClientTransport, TimeoutMixin):
    """
    This class represents the transport layer from Cowrie's proxy to the backend SSH server. It is responsible for
    authentication to that server, and sending messages it gets to the handler.
    """

    def __init__(self, factory: BackendSSHFactory):
        self.delayedPackets: list[tuple[int, bytes]] = []
        self.factory: BackendSSHFactory = factory
        self.canAuth: bool = False
        self.authDone: bool = False

        # keep these from when frontend authenticates
        self.frontendTriedUsername = None
        self.frontendTriedPassword = None

    def connectionMade(self):
        log.msg(f"Connected to SSH backend at {self.transport.getPeer().host}")
        self.factory.server.client = self
        self.factory.server.sshParse.set_client(self)
        transport.SSHClientTransport.connectionMade(self)

    def verifyHostKey(self, pub_key, fingerprint):
        return defer.succeed(True)

    def connectionSecure(self):
        log.msg("Backend Connection Secured")
        self.canAuth = True
        self.authenticateBackend()

    def authenticateBackend(self, tried_username=None, tried_password=None):
        """
        This is called when the frontend is authenticated, so as to give us the option to authenticate with the
        username and password given by the attacker.
        """

        # we keep these here in case frontend has authenticated and backend hasn't established the secure channel yet;
        # in that case, tried credentials are stored to be used whenever usearauth with backend can be performed
        if tried_username and tried_password:
            self.frontendTriedUsername = tried_username
            self.frontendTriedPassword = tried_password

        # do nothing if frontend is not authenticated, or backend has not established a secure channel
        if not self.factory.server.frontendAuthenticated or not self.canAuth:
            return

        # we authenticate with the backend using the credentials provided
        # TODO create the account in the backend before (contact the pool of VMs for example)
        # so these credentials from the config may not be needed after all
        username = CowrieConfig.get("proxy", "backend_user")
        password = CowrieConfig.get("proxy", "backend_pass")
        log.msg(f"Will auth with backend: {username}/{password}")

        self.sendPacket(5, bin_string_to_hex(b"ssh-userauth"))
        payload = (
            bin_string_to_hex(username.encode())
            + string_to_hex("ssh-connection")
            + string_to_hex("password")
            + b"\x00"
            + bin_string_to_hex(password.encode())
        )
        self.sendPacket(50, payload)
        self.factory.server.backendConnected = True

        # send packets from the frontend that were waiting to go to the backend
        for packet in self.factory.server.delayedPackets:
            self.factory.server.sshParse.parse_num_packet(
                "[SERVER]", packet[0], packet[1]
            )
        self.factory.server.delayedPackets = []

        # backend auth is done, attackers will now be connected to the backend
        self.authDone = True

    def connectionLost(self, reason):
        if self.factory.server.pool_interface:
            log.msg(
                eventid="cowrie.proxy.client_disconnect",
                format="Lost connection with the pool backend: id %(vm_id)s",
                vm_id=self.factory.server.pool_interface.vm_id,
                protocol="ssh",
            )
        else:
            log.msg(
                eventid="cowrie.proxy.client_disconnect",
                format="Lost connection with the proxy's backend: %(honey_ip)s:%(honey_port)s",
                honey_ip=self.factory.server.backend_ip,
                honey_port=self.factory.server.backend_port,
                protocol="ssh",
            )

        self.transport.connectionLost(reason)
        self.transport = None

        # if connection from frontend is not closed, do it here
        if self.factory.server.transport:
            self.factory.server.transport.loseConnection()

    def timeoutConnection(self):
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in BackendSSHTransport")
        self.transport.loseConnection()
        self.factory.server.transport.loseConnection()

    def dispatchMessage(self, message_num, payload):
        if message_num in [6, 52]:
            return  # TODO consume these in authenticateBackend

        if message_num == 98:
            # looking for RFC 4254 - 6.10. Returning Exit Status
            pointer = 4  # ignore recipient_channel
            leng, message = get_string(payload[pointer:])

            if message == b"exit-status":
                pointer += leng + 1  # also boolean ignored
                exit_status = get_int(payload[pointer:])
                log.msg(f"exitCode: {exit_status}")

        if transport.SSHClientTransport.isEncrypted(self, "both"):
            self.packet_buffer(message_num, payload)
        else:
            transport.SSHClientTransport.dispatchMessage(self, message_num, payload)

    def packet_buffer(self, message_num: int, payload: bytes) -> None:
        """
        We can only proceed if authentication has been performed between client and proxy. Meanwhile we hold packets
        from the backend to the frontend in here.
        """
        if not self.factory.server.frontendAuthenticated:
            # wait till frontend connects and authenticates to send packets to them
            log.msg("Connection to client not ready, buffering packet from backend")
            self.delayedPackets.append((message_num, payload))
        else:
            if len(self.delayedPackets) > 0:
                self.delayedPackets.append((message_num, payload))
                for packet in self.delayedPackets:
                    self.factory.server.sshParse.parse_num_packet(
                        "[CLIENT]", packet[0], packet[1]
                    )
                self.delayedPackets = []
            else:
                self.factory.server.sshParse.parse_num_packet(
                    "[CLIENT]", message_num, payload
                )
