from __future__ import annotations
from threading import Lock
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.python import failure
    from twisted.internet.interfaces import IAddress
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet.protocol import connectionDone


class ClientProtocol(protocol.Protocol):
    server_protocol: ServerProtocol

    def dataReceived(self, data: bytes) -> None:
        assert self.server_protocol.transport is not None
        self.server_protocol.transport.write(data)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        assert self.server_protocol.transport is not None
        self.server_protocol.transport.loseConnection()


class ClientFactory(protocol.ClientFactory):
    def __init__(self, server_protocol: ServerProtocol) -> None:
        self.server_protocol = server_protocol

    def buildProtocol(self, addr: IAddress) -> ClientProtocol:
        client_protocol = ClientProtocol()
        client_protocol.server_protocol = self.server_protocol
        self.server_protocol.client_protocol = client_protocol
        return client_protocol


class ServerProtocol(protocol.Protocol):
    def __init__(self, dst_ip: str, dst_port: int):
        self.dst_ip: str = dst_ip
        self.dst_port: int = dst_port
        self.client_protocol: ClientProtocol
        self.buffer: list[bytes] = []

    def connectionMade(self):
        reactor.connectTCP(self.dst_ip, self.dst_port, ClientFactory(self))

    def dataReceived(self, data: bytes) -> None:
        self.buffer.append(data)
        self.sendData()

    def sendData(self) -> None:
        if not self.client_protocol:
            reactor.callLater(0.5, self.sendData)  # type: ignore[attr-defined]
            return

        assert self.client_protocol.transport is not None
        for packet in self.buffer:
            self.client_protocol.transport.write(packet)
        self.buffer = []

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        assert self.client_protocol.transport is not None
        self.client_protocol.transport.loseConnection()


class ServerFactory(protocol.Factory):
    def __init__(self, dst_ip: str, dst_port: int) -> None:
        self.dst_ip: str = dst_ip
        self.dst_port: int = dst_port

    def buildProtocol(self, addr: IAddress) -> ServerProtocol:
        return ServerProtocol(self.dst_ip, self.dst_port)


class NATService:
    """
    This service provides a NAT-like service when the backend pool
    is located in a remote machine.  Guests are bound to a local
    IP (e.g., 192.168.150.0/24), and so not accessible from a remote
    Cowrie.  This class provides TCP proxies that associate accessible
    IPs in the backend pool's machine to the internal IPs used by
    guests, like a NAT.
    """

    def __init__(self):
        self.bindings: dict[int, Any] = {}
        self.lock = (
            Lock()
        )  # we need to be thread-safe just in case, this is accessed from multiple clients

    def request_binding(
        self, guest_id: int, dst_ip: str, ssh_port: int, telnet_port: int
    ) -> tuple[int, int]:
        with self.lock:
            # see if binding is already created
            if guest_id in self.bindings:
                # increase connected
                self.bindings[guest_id][0] += 1

                return (
                    self.bindings[guest_id][1]._realPortNumber,
                    self.bindings[guest_id][2]._realPortNumber,
                )
            else:
                nat_ssh = reactor.listenTCP(  # type: ignore[attr-defined]
                    0, ServerFactory(dst_ip, ssh_port), interface="0.0.0.0"
                )
                nat_telnet = reactor.listenTCP(  # type: ignore[attr-defined]
                    0, ServerFactory(dst_ip, telnet_port), interface="0.0.0.0"
                )
                self.bindings[guest_id] = [1, nat_ssh, nat_telnet]

                return nat_ssh._realPortNumber, nat_telnet._realPortNumber

    def free_binding(self, guest_id: int) -> None:
        with self.lock:
            self.bindings[guest_id][0] -= 1

            # stop listening if no one is connected
            if self.bindings[guest_id][0] <= 0:
                self.bindings[guest_id][1].stopListening()
                self.bindings[guest_id][2].stopListening()
                del self.bindings[guest_id]

    def free_all(self):
        with self.lock:
            for guest_id in self.bindings:
                self.bindings[guest_id][1].stopListening()
                self.bindings[guest_id][2].stopListening()
