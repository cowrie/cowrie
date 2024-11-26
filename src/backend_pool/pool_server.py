"""
The main interface of the backend pool is exposed as a TCP server
in _pool_server.py_. The protocol is a very simple wire protocol,
always composed of an op-code, a status code (for responses), and
any needed data thereafter.
"""

# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import struct

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.protocol import Factory, Protocol
from twisted.python import log

from cowrie.core.config import CowrieConfig

from backend_pool.nat import NATService
from backend_pool.pool_service import NoAvailableVMs, PoolService
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.internet.interfaces import IAddress

RES_OP_I = b"i"
RES_OP_R = b"r"
RES_OP_F = b"f"
RES_OP_U = b"u"


class PoolServer(Protocol):
    """
    Main PoolServer
    """

    def __init__(self, factory: PoolServerFactory) -> None:
        self.factory: PoolServerFactory = factory
        self.local_pool: bool = (
            CowrieConfig.get("proxy", "pool", fallback="local") == "local"
        )
        self.pool_only: bool = CowrieConfig.getboolean(
            "backend_pool", "pool_only", fallback=False
        )
        self.use_nat: bool = CowrieConfig.getboolean(
            "backend_pool", "use_nat", fallback=True
        )
        if self.use_nat:
            self.nat_public_ip: str = CowrieConfig.get("backend_pool", "nat_public_ip")

    def dataReceived(self, data: bytes) -> None:
        res_op: bytes = struct.unpack("!c", bytes([data[0]]))[
            0
        ]  # yes, this needs to be done to extract the op code correctly
        response: bytes = b""

        if res_op == RES_OP_I:
            recv = struct.unpack("!II?", data[1:])

            # set the pool service thread configs
            max_vm = recv[0]
            vm_unused_timeout = recv[1]
            share_guests = recv[2]
            self.factory.pool_service.set_configs(
                max_vm, vm_unused_timeout, share_guests
            )

            # respond with ok
            self.factory.initialised = True
            response = struct.pack("!cI", RES_OP_I, 0)

        elif res_op == RES_OP_R:
            # receives: attacker ip (used to serve same VM to same attacker)
            # sends: status code, guest_id, guest_ip, guest's ssh and telnet port

            recv = struct.unpack("!H", data[1:3])
            ip_len = recv[0]

            recv = struct.unpack(f"!{ip_len}s", data[3:])
            attacker_ip = recv[0].decode()

            log.msg(
                eventid="cowrie.backend_pool.server",
                format="Requesting a VM for attacker @ %(attacker_ip)s",
                attacker_ip=attacker_ip,
            )

            try:
                (
                    guest_id,
                    guest_ip,
                    guest_snapshot,
                ) = self.factory.pool_service.request_vm(attacker_ip)
                log.msg(
                    eventid="cowrie.backend_pool.server",
                    format="Providing VM id %(guest_id)s",
                    guest_id=guest_id,
                )

                ssh_port: int = CowrieConfig.getint(
                    "backend_pool", "guest_ssh_port", fallback=22
                )
                telnet_port: int = CowrieConfig.getint(
                    "backend_pool", "guest_telnet_port", fallback=23
                )

                # after we receive ip and ports, expose ports in the pool's public interface
                # we use NAT if this pool is being run remotely, and if users choose so
                if (not self.local_pool and self.use_nat) or self.pool_only:
                    nat_ssh_port, nat_telnet_port = self.factory.nat.request_binding(
                        guest_id, guest_ip, ssh_port, telnet_port
                    )

                    fmt = f"!cIIH{len(self.nat_public_ip)}sHHH{len(guest_snapshot)}s"
                    response = struct.pack(
                        fmt,
                        RES_OP_R,
                        0,
                        guest_id,
                        len(self.nat_public_ip),
                        self.nat_public_ip.encode(),
                        nat_ssh_port,
                        nat_telnet_port,
                        len(guest_snapshot),
                        guest_snapshot.encode(),
                    )
                else:
                    fmt = f"!cIIH{len(guest_ip)}sHHH{len(guest_snapshot)}s"
                    response = struct.pack(
                        fmt,
                        RES_OP_R,
                        0,
                        guest_id,
                        len(guest_ip),
                        guest_ip.encode(),
                        ssh_port,
                        telnet_port,
                        len(guest_snapshot),
                        guest_snapshot.encode(),
                    )
            except NoAvailableVMs:
                log.msg(
                    eventid="cowrie.backend_pool.server",
                    format="No VM available, returning error code",
                )
                response = struct.pack("!cI", RES_OP_R, 1)

        elif res_op == RES_OP_F:
            # receives: guest_id
            recv = struct.unpack("!I", data[1:])
            guest_id = recv[0]

            log.msg(
                eventid="cowrie.backend_pool.server",
                format="Freeing VM %(guest_id)s",
                guest_id=guest_id,
            )

            # free the NAT
            if (not self.local_pool and self.use_nat) or self.pool_only:
                self.factory.nat.free_binding(guest_id)

            # free the vm
            self.factory.pool_service.free_vm(guest_id)

        elif res_op == RES_OP_U:
            # receives: guest_id
            recv = struct.unpack("!I", data[1:])
            guest_id = recv[0]

            log.msg(
                eventid="cowrie.backend_pool.server",
                format="Re-using VM %(guest_id)s (not used by attacker)",
                guest_id=guest_id,
            )

            # free the NAT
            if (not self.local_pool and self.use_nat) or self.pool_only:
                self.factory.nat.free_binding(guest_id)

            # free this connection and allow VM to be re-used
            self.factory.pool_service.reuse_vm(guest_id)

        if response and self.transport:
            self.transport.write(response)


class PoolServerFactory(Factory):
    """
    Factory for PoolServer
    """

    def __init__(self) -> None:
        self.initialised: bool = False

        # pool handling
        self.pool_service: PoolService

        self.tac = None

        # NAT service
        self.nat = NATService()

    def startFactory(self) -> None:
        # start the pool thread with default configs
        self.pool_service = PoolService(self.nat)
        if self.pool_service:
            self.pool_service.start_pool()

    def stopFactory(self) -> None:
        log.msg(eventid="cowrie.backend_pool.server", format="Stopping backend pool...")
        if self.pool_service:
            self.pool_service.shutdown_pool()

    def buildProtocol(self, addr: IAddress) -> PoolServer:
        assert isinstance(addr, (IPv4Address, IPv6Address))
        log.msg(
            eventid="cowrie.backend_pool.server",
            format="Received connection from %(host)s:%(port)s",
            host=addr.host,
            port=addr.port,
        )
        return PoolServer(self)
